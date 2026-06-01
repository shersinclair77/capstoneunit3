# =============================================================================
# Remove-M365Users.ps1
# Offboards M365 users in this exact sequence:
#
#   1. Convert user mailbox to Shared Mailbox  (Exchange Online REST API)
#   2. Remove all licenses
#   3. Block sign-in
#   4. Revoke all active sessions
#   5. Remove from all groups
#   6. Disable / remove all MFA methods
#
# NOTE: Step 1 uses the Exchange Online Admin REST API directly via
# Invoke-RestMethod — NO ExchangeOnlineManagement module required.
# This avoids all module version compatibility issues on GitHub runners.
#
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Group.ReadWrite.All
#   - UserAuthenticationMethod.ReadWrite.All
#   - Mail.Send
#   - Application.Read.All
#   - Exchange.ManageAsApp  (for shared mailbox conversion via REST)
#
# Required Entra role on App Service Principal:
#   - Exchange Recipient Administrator
# =============================================================================

param (
    [Parameter(Mandatory = $true)]  [string]$TenantId,
    [Parameter(Mandatory = $true)]  [string]$ClientId,
    [Parameter(Mandatory = $true)]  [string]$ClientSecret,
    [Parameter(Mandatory = $false)] [string]$NotificationEmail = "RenaeHarewood@Renah.onmicrosoft.com",
    [Parameter(Mandatory = $false)] [string]$RunId    = "local",
    [Parameter(Mandatory = $false)] [string]$CommitSha = "local",
    [Parameter(Mandatory = $false)] [string]$CsvPath  = "./offboarding/users-to-offboard.csv",

    # Set to $true when mailboxes have already been converted manually in
    # Microsoft 365 admin center (Users > Convert to shared mailbox).
    # This bypasses the Exchange Online REST API call which requires
    # delegated auth and cannot be performed with app-only credentials.
    [Parameter(Mandatory = $false)] [switch]$SkipMailboxConversion
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain      = "renah.onmicrosoft.com"
$SenderEmail = $NotificationEmail
$SecretExpiryWarningDays = 30

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/offboarding_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# LOAD OFFBOARDING CSV
# Required column: UserPrincipalName
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "Offboarding CSV not found at: $CsvPath"
    exit 1
}

$CsvData = Import-Csv -Path $CsvPath
Write-Host "Loaded $($CsvData.Count) user(s) from: $CsvPath" -ForegroundColor Cyan

# =============================================================================
# HELPER — Email notification
# =============================================================================

function Send-EmailNotification {
    param ([string]$Subject, [string]$Body)
    try {
        $Payload = @{
            message = @{
                subject      = $Subject
                body         = @{ contentType = "HTML"; content = $Body }
                toRecipients = @(@{ emailAddress = @{ address = $NotificationEmail } })
            }
            saveToSentItems = $false
        }
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri    "https://graph.microsoft.com/v1.0/users/$SenderEmail/sendMail" `
            -Body   ($Payload | ConvertTo-Json -Depth 10)
        Write-Host "  [OK] Email sent to $NotificationEmail" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Email FAILED — Sender: $SenderEmail | Error: $($_.Exception.Message)"
        try {
            $e = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Warning "  Code: $($e.error.code) | Msg: $($e.error.message)"
        } catch { }
    }
}

# =============================================================================
# STEP 1 HELPER — Convert-ToSharedMailbox
# -----------------------------------------------------------------------------
# Converts the user mailbox to a Shared Mailbox using the Exchange Online
# Admin REST API directly. No ExchangeOnlineManagement PowerShell module
# is used — Invoke-RestMethod only.
#
# Why REST instead of EXO module:
#   The ExchangeOnlineManagement module version available on GitHub-hosted
#   runners does not consistently support app-only parameters:
#     v2: -AccessToken worked with plain string
#     v3: -AccessToken requires SecureString (changed behaviour)
#     v3.2+: -ClientSecret added, but not always installed
#   Using Invoke-RestMethod eliminates all module version dependencies.
#
# API used:
#   GET/PATCH https://outlook.office365.com/adminapi/beta/{tenantId}/mailbox('{UPN}')
#
# Required:
#   App Registration: Exchange.ManageAsApp (Application) + admin consent
#   Entra role on App SP: Exchange Recipient Administrator
# =============================================================================

function Convert-ToSharedMailbox {
    param ([string]$UPN)

    Write-Host "  Acquiring Exchange Online token..." -ForegroundColor DarkGray

    # Get OAuth 2.0 token for Exchange Online
    $exoToken = $null
    try {
        $tokenResp = Invoke-RestMethod `
            -Method      POST `
            -Uri         "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body        @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://outlook.office365.com/.default"
            }
        if (-not $tokenResp.access_token) {
            throw "No access_token in token response."
        }
        $exoToken = $tokenResp.access_token
        Write-Host "  [OK] EXO token acquired." -ForegroundColor Green
    }
    catch {
        Write-Warning "  EXO token failed: $($_.Exception.Message)"
        Write-Warning "  Ensure Exchange.ManageAsApp (Application) is added to the App Registration with admin consent."
        return "Failed — EXO token error"
    }

    # Build REST headers and URL
    $headers = @{
        "Authorization" = "Bearer $exoToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
    $encodedUPN = [Uri]::EscapeDataString($UPN)
    # Exchange Admin REST API requires the tenant PRIMARY DOMAIN in the URL path,
    # not the tenant GUID. Using the GUID causes 401 even with valid permissions.
    $mbUrl      = "https://outlook.office365.com/adminapi/beta/$Domain/mailbox('$encodedUPN')"

    # Read current mailbox type
    try {
        $mb = Invoke-RestMethod -Method GET -Uri $mbUrl -Headers $headers -ErrorAction Stop
        Write-Host "  Current mailbox type: $($mb.MailboxType)" -ForegroundColor DarkGray
        if ($mb.MailboxType -eq "SharedMailbox") {
            Write-Host "  [--] Mailbox is already Shared — no conversion needed." -ForegroundColor DarkGray
            return "Already Shared"
        }
    }
    catch {
        $sc = $_.Exception.Response.StatusCode.value__
        Write-Warning "  Could not read mailbox type (HTTP $sc): $($_.Exception.Message)"
        if ($sc -eq 403) {
            Write-Warning "  403: Exchange.ManageAsApp permission or Exchange Recipient Administrator role missing."
            Write-Warning "  Entra admin center > App registrations > API permissions > Exchange.ManageAsApp"
            Write-Warning "  Entra admin center > Roles > Exchange Recipient Administrator > Add app SP"
            return "Failed — 403 Forbidden (missing Exchange permission or role)"
        }
    }

    # Convert to Shared Mailbox
    try {
        Invoke-RestMethod `
            -Method  PATCH `
            -Uri     $mbUrl `
            -Headers $headers `
            -Body    '{"MailboxType":"Shared"}' `
            -ErrorAction Stop

        Start-Sleep -Seconds 6

        $verify = Invoke-RestMethod -Method GET -Uri $mbUrl -Headers $headers -ErrorAction SilentlyContinue
        if ($verify -and $verify.MailboxType -eq "SharedMailbox") {
            Write-Host "  [OK] Mailbox converted to Shared (verified)." -ForegroundColor Green
        }
        else {
            Write-Host "  [OK] Conversion request accepted." -ForegroundColor Green
        }
        return "Converted"
    }
    catch {
        $sc      = $_.Exception.Response.StatusCode.value__
        $errMsg  = $_.Exception.Message
        Write-Warning "  Mailbox conversion failed (HTTP $sc): $errMsg"
        try {
            $eb = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Warning "  Error code   : $($eb.error.code)"
            Write-Warning "  Error message: $($eb.error.message)"
        } catch { }
        if ($sc -eq 401) {
            Write-Warning "  401 Unauthorized — two possible causes:"
            Write-Warning ""
            Write-Warning "  CAUSE 1 — Propagation delay (most likely if role was just assigned):"
            Write-Warning "  Exchange Online role assignments take up to 30 minutes to propagate."
            Write-Warning "  Wait 30 minutes after adding the App to Recipient Management,"
            Write-Warning "  then re-run this workflow."
            Write-Warning ""
            Write-Warning "  CAUSE 2 — Role not assigned (if this is the first run after setup):"
            Write-Warning "  Exchange Online has its own role system separate from Entra."
            Write-Warning "  Exchange.ManageAsApp Entra permission alone is not enough."
            Write-Warning "  Fix: Exchange admin center > Roles > Admin roles >"
            Write-Warning "       Recipient Management > Members > Add > [your app name] > Save"
            Write-Warning ""
            Write-Warning "  CAUSE 3 — Wrong role group member type:"
            Write-Warning "  When adding to the role group, ensure you are adding the"
            Write-Warning "  APP (service principal), not a user. Search by your App name."
        }
        elseif ($sc -eq 403) {
            Write-Warning "  403 Forbidden — Exchange.ManageAsApp permission may be missing."
            Write-Warning "  Entra > App registrations > API permissions > Exchange.ManageAsApp > Grant admin consent"
        }
        return "Failed — HTTP $sc"
    }
}

# =============================================================================
# STEP 6 HELPER — Disable-UserMfa
# Resets perUserMfaState to disabled and removes all registered auth methods.
# =============================================================================

function Disable-UserMfa {
    param ([string]$UserId, [string]$UPN)

    $BaseUri   = "https://graph.microsoft.com/v1.0/users/$UserId/authentication"
    $MfaStatus = "Disabled"
    $Removed   = 0

    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "$BaseUri/requirements" `
            -Body (@{ perUserMfaState = "disabled" } | ConvertTo-Json)
        Write-Host "  [OK] perUserMfaState set to disabled." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not reset perUserMfaState: $($_.Exception.Message)"
        $MfaStatus = "Partial"
    }

    $endpoints = @(
        @{ Name = "Microsoft Authenticator"; Uri = "$BaseUri/microsoftAuthenticatorMethods" },
        @{ Name = "Phone (SMS/Call)";        Uri = "$BaseUri/phoneMethods"                  },
        @{ Name = "Software OATH (TOTP)";    Uri = "$BaseUri/softwareOathMethods"            },
        @{ Name = "Temp Access Pass (TAP)";  Uri = "$BaseUri/temporaryAccessPassMethods"     },
        @{ Name = "FIDO2 Security Key";      Uri = "$BaseUri/fido2Methods"                   },
        @{ Name = "Windows Hello";           Uri = "$BaseUri/windowsHelloForBusinessMethods" }
    )

    foreach ($ep in $endpoints) {
        try {
            $methods = Invoke-MgGraphRequest -Method GET -Uri $ep.Uri -ErrorAction SilentlyContinue
            if ($methods -and $methods.value -and $methods.value.Count -gt 0) {
                foreach ($method in $methods.value) {
                    try {
                        Invoke-MgGraphRequest -Method DELETE -Uri "$($ep.Uri)/$($method.id)" -ErrorAction Stop
                        Write-Host "  [OK] Removed $($ep.Name) method." -ForegroundColor Green
                        $Removed++
                    }
                    catch {
                        Write-Warning "  Could not remove $($ep.Name): $($_.Exception.Message)"
                        $MfaStatus = "Partial"
                    }
                }
            }
        }
        catch { }
    }

    Write-Host "  [OK] MFA: $Removed method(s) removed. State: $MfaStatus" -ForegroundColor Green
    return $MfaStatus
}

# =============================================================================
# CONNECT TO MICROSOFT GRAPH
# =============================================================================

Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

try {
    $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

    Connect-MgGraph `
        -TenantId               $TenantId `
        -ClientSecretCredential $Credential `
        -NoWelcome `
        -ErrorAction            Stop

    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "No Graph context returned — credentials may be incorrect."
    }
    Write-Host "  [OK] Connected as AppOnly to tenant: $($ctx.TenantId)" -ForegroundColor Green
}
catch {
    Write-Host "  [FATAL] Graph connection failed: $_" -ForegroundColor Red
    Write-Host "  Check M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET secrets." -ForegroundColor Red
    exit 1
}

# =============================================================================
# SECRET EXPIRY CHECK
# =============================================================================

Write-Host "`nChecking client secret expiry..." -ForegroundColor Cyan

try {
    $App     = Invoke-MgGraphRequest -Method GET `
                   -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ClientId'"
    $AppId   = $App.value[0].id
    $AppObj  = Invoke-MgGraphRequest -Method GET `
                   -Uri "https://graph.microsoft.com/v1.0/applications/$AppId"

    foreach ($Secret in $AppObj.passwordCredentials) {
        $ExpiryDate = [datetime]$Secret.endDateTime
        $DaysLeft   = ($ExpiryDate - (Get-Date)).Days
        if ($DaysLeft -le $SecretExpiryWarningDays) {
            Write-Warning "Secret expires in $DaysLeft day(s). Sending alert."
            Send-EmailNotification `
                -Subject "ACTION REQUIRED: M365 App Secret Expires in $DaysLeft Day(s)" `
                -Body    "<h2>Secret Expiry Warning</h2><p>Rotate before $($ExpiryDate.ToString('yyyy-MM-dd')).</p>"
        }
        else {
            Write-Host "  [OK] Secret valid — expires in $DaysLeft day(s)." -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Could not check secret expiry: $_"
}

# =============================================================================
# OFFBOARD USERS
# =============================================================================

$Results    = @()
$Offboarded = 0
$Skipped    = 0

foreach ($Row in $CsvData) {
    $UPN = $Row.UserPrincipalName.Trim()
    Write-Host "`n$("=" * 62)" -ForegroundColor DarkGray
    Write-Host "  Offboarding: $UPN" -ForegroundColor Yellow
    Write-Host "$("=" * 62)" -ForegroundColor DarkGray

    $User = Get-MgUser `
        -Filter   "userPrincipalName eq '$UPN'" `
        -Property "Id,DisplayName,AccountEnabled" `
        -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Warning "  User $UPN not found — skipping."
        $Results += [PSCustomObject]@{
            Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId            = $RunId; CommitSha = $CommitSha
            UPN              = $UPN;   DisplayName = "Not found"
            MailboxConverted = "N/A";  LicenseRemoved  = "N/A"
            SignInBlocked    = "N/A";  SessionsRevoked = "N/A"
            GroupsRemoved    = "N/A";  MfaDisabled     = "N/A"
            Status           = "Skipped — user not found"
        }
        $Skipped++
        continue
    }

    $DisplayName     = $User.DisplayName
    $MailboxConverted = "Failed"
    $LicenseRemoved  = "Failed"
    $SignInBlocked   = "Failed"
    $SessionsRevoked = "Failed"
    $GroupsRemoved   = "Failed"
    $MfaDisabled     = "Failed"
    $OverallStatus   = "Completed"

    # ── STEP 1: Convert mailbox to Shared ────────────────────────────────────
    # The Exchange Online REST API (adminapi/beta) requires a delegated (user)
    # token and cannot be called with app-only credentials. When -SkipMailboxConversion
    # is set, the conversion is assumed to have been done manually in the
    # Microsoft 365 admin center before this workflow was triggered.
    Write-Host "`n  [Step 1/6] Converting mailbox to Shared..." -ForegroundColor Cyan

    if ($SkipMailboxConversion) {
        Write-Host "  [--] -SkipMailboxConversion set — assuming mailbox was already" -ForegroundColor DarkGray
        Write-Host "       converted manually in Microsoft 365 admin center." -ForegroundColor DarkGray
        $MailboxConverted = "Skipped — manually confirmed"
    }
    else {
        $MailboxConverted = Convert-ToSharedMailbox -UPN $UPN
    }

    # HARD STOP — do not remove license if conversion failed.
    # Removing the license before converting starts a 30-day Exchange soft-delete
    # countdown that permanently destroys all mailbox data.
    if ($MailboxConverted -like "Failed*") {
        Write-Host ""
        Write-Host "  !! BLOCKED: License removal skipped — mailbox not converted. !!" -ForegroundColor Red
        Write-Host "  Reason : $MailboxConverted" -ForegroundColor Red
        Write-Host ""
        Write-Host "  The Exchange Online REST API (adminapi/beta) requires a delegated" -ForegroundColor Yellow
        Write-Host "  (user) token and cannot be called with app-only credentials." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  TO COMPLETE THIS OFFBOARDING:" -ForegroundColor Yellow
        Write-Host "  1. Go to Microsoft 365 admin center > Users > Active users" -ForegroundColor Yellow
        Write-Host "  2. Select $UPN > three-dot menu > Convert to shared mailbox" -ForegroundColor Yellow
        Write-Host "  3. Re-run this workflow with SkipMailboxConversion = true" -ForegroundColor Yellow
        Write-Host ""
        $LicenseRemoved  = "SKIPPED — convert mailbox first, then re-run with SkipMailboxConversion=true"
        $SignInBlocked   = "SKIPPED"
        $SessionsRevoked = "SKIPPED"
        $GroupsRemoved   = "SKIPPED"
        $MfaDisabled     = "SKIPPED"
        $OverallStatus   = "Blocked — mailbox conversion failed"
        $Results += [PSCustomObject]@{
            Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId            = $RunId; CommitSha = $CommitSha
            UPN              = $UPN;   DisplayName = $DisplayName
            MailboxConverted = $MailboxConverted; LicenseRemoved  = $LicenseRemoved
            SignInBlocked    = $SignInBlocked;    SessionsRevoked = $SessionsRevoked
            GroupsRemoved    = $GroupsRemoved;    MfaDisabled     = $MfaDisabled
            Status           = $OverallStatus
        }
        $Offboarded++
        continue
    }

    # ── STEP 2: Remove all licenses ──────────────────────────────────────────
    Write-Host "`n  [Step 2/6] Removing licenses..." -ForegroundColor Cyan
    try {
        $Assigned = (Get-MgUser -UserId $User.Id -Property "assignedLicenses").AssignedLicenses
        if ($Assigned -and $Assigned.Count -gt 0) {
            $SkuIds = $Assigned | Select-Object -ExpandProperty SkuId
            Set-MgUserLicense -UserId $User.Id -AddLicenses @() -RemoveLicenses $SkuIds
            Write-Host "  [OK] $($SkuIds.Count) license(s) removed." -ForegroundColor Green
            $LicenseRemoved = "Yes ($($SkuIds.Count) SKU(s))"
        }
        else {
            Write-Host "  [--] No licenses assigned." -ForegroundColor DarkGray
            $LicenseRemoved = "None assigned"
        }
    }
    catch {
        Write-Warning "  License removal failed: $_"
        $OverallStatus = "Partial"
    }

    # ── STEP 3: Block sign-in ────────────────────────────────────────────────
    Write-Host "`n  [Step 3/6] Blocking sign-in..." -ForegroundColor Cyan
    try {
        Update-MgUser -UserId $User.Id -AccountEnabled $false
        Write-Host "  [OK] Sign-in blocked." -ForegroundColor Green
        $SignInBlocked = "Yes"
    }
    catch {
        Write-Warning "  Block sign-in failed: $_"
        $OverallStatus = "Partial"
    }

    # ── STEP 4: Revoke active sessions ───────────────────────────────────────
    Write-Host "`n  [Step 4/6] Revoking active sessions..." -ForegroundColor Cyan
    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Write-Host "  [OK] Sessions revoked." -ForegroundColor Green
        $SessionsRevoked = "Yes"
    }
    catch {
        Write-Warning "  Session revocation failed: $_"
        $OverallStatus = "Partial"
    }

    # ── STEP 5: Remove from all groups ───────────────────────────────────────
    Write-Host "`n  [Step 5/6] Removing from all groups..." -ForegroundColor Cyan
    $GroupCount = 0
    try {
        $Memberships = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/memberOf"
        $Groups = $Memberships.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
        if ($Groups -and $Groups.Count -gt 0) {
            foreach ($Group in $Groups) {
                try {
                    Invoke-MgGraphRequest -Method DELETE `
                        -Uri "https://graph.microsoft.com/v1.0/groups/$($Group.id)/members/$($User.Id)/`$ref"
                    Write-Host "  [OK] Removed from: $($Group.displayName)" -ForegroundColor Green
                    $GroupCount++
                }
                catch {
                    Write-Warning "  Could not remove from '$($Group.displayName)': $_"
                    $OverallStatus = "Partial"
                }
            }
            $GroupsRemoved = "Yes ($GroupCount group(s))"
        }
        else {
            Write-Host "  [--] No group memberships found." -ForegroundColor DarkGray
            $GroupsRemoved = "None"
        }
    }
    catch {
        Write-Warning "  Group retrieval failed: $_"
        $OverallStatus = "Partial"
    }

    # ── STEP 6: Disable all MFA methods ─────────────────────────────────────
    Write-Host "`n  [Step 6/6] Disabling MFA..." -ForegroundColor Cyan
    $MfaDisabled = Disable-UserMfa -UserId $User.Id -UPN $UPN

    # ── Audit entry ──────────────────────────────────────────────────────────
    $Results += [PSCustomObject]@{
        Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId            = $RunId; CommitSha = $CommitSha
        UPN              = $UPN;   DisplayName = $DisplayName
        MailboxConverted = $MailboxConverted; LicenseRemoved  = $LicenseRemoved
        SignInBlocked    = $SignInBlocked;    SessionsRevoked = $SessionsRevoked
        GroupsRemoved    = $GroupsRemoved;    MfaDisabled     = $MfaDisabled
        Status           = $OverallStatus
    }
    Write-Host "`n  ✔ $DisplayName — $OverallStatus" -ForegroundColor Green
    $Offboarded++
}

# =============================================================================
# WRITE AUDIT LOG
# =============================================================================

Write-Host "`nWriting audit log to $AuditLogPath..." -ForegroundColor Cyan
$Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
Write-Host "  [OK] Audit log written." -ForegroundColor Green

# =============================================================================
# CONSOLE SUMMARY
# =============================================================================

Write-Host "`n$("=" * 42)" -ForegroundColor Yellow
Write-Host "        USER OFFBOARDING SUMMARY"         -ForegroundColor Yellow
Write-Host "$("=" * 42)" -ForegroundColor Yellow
Write-Host "  Run ID     : $RunId"
Write-Host "  Commit SHA : $CommitSha"
Write-Host "  Timestamp  : $RunTimestamp"
Write-Host "  Offboarded : $Offboarded"
Write-Host "  Skipped    : $Skipped"
Write-Host "$("=" * 42)" -ForegroundColor Yellow
$Results | Format-Table Timestamp, DisplayName, MailboxConverted, LicenseRemoved, SignInBlocked, GroupsRemoved, MfaDisabled, Status -AutoSize

# =============================================================================
# EMAIL SUMMARY — sent to RenaeHarewood@Renah.onmicrosoft.com
# =============================================================================

Write-Host "`nSending offboarding summary email to $NotificationEmail..." -ForegroundColor Cyan

$TableRows = $Results | ForEach-Object {
    $bg = switch ($_.Status) {
        { $_ -like "*Completed*" } { "#e6f4ea" }
        { $_ -like "*Blocked*"   } { "#fce8e6" }
        default                    { "#fff8e1" }
    }
    "<tr style='background:$bg'>
      <td>$($_.DisplayName)</td><td>$($_.UPN)</td>
      <td align='center'>$($_.MailboxConverted)</td>
      <td align='center'>$($_.LicenseRemoved)</td>
      <td align='center'>$($_.SignInBlocked)</td>
      <td align='center'>$($_.SessionsRevoked)</td>
      <td align='center'>$($_.GroupsRemoved)</td>
      <td align='center'>$($_.MfaDisabled)</td>
      <td align='center'><b>$($_.Status)</b></td>
    </tr>"
}

$SummaryBody = @"
<h2 style='color:#1A3C5E;font-family:Calibri,sans-serif'>M365 User Offboarding Summary</h2>
<p style='font-family:Calibri,sans-serif'>
  <b>Run ID:</b> $RunId<br><b>Commit SHA:</b> $CommitSha<br><b>Timestamp:</b> $RunTimestamp
</p>
<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-family:Calibri,sans-serif;font-size:13px'>
  <tr style='background:#1A3C5E;color:white'>
    <th>Display Name</th><th>UPN</th><th>Mailbox→Shared</th><th>License Removed</th>
    <th>Sign-in Blocked</th><th>Sessions Revoked</th><th>Groups Removed</th>
    <th>MFA Disabled</th><th>Status</th>
  </tr>
  $($TableRows -join "`n")
</table>
<br>
<p style='font-family:Calibri,sans-serif'>
  <b>Offboarded:</b> $Offboarded &nbsp; <b>Skipped:</b> $Skipped
</p>
<p style='font-family:Calibri,sans-serif;color:#555'>
  <i>Audit log (CSV) saved as artifact in GitHub Actions run $RunId linked to commit $CommitSha.</i>
</p>
"@

Send-EmailNotification `
    -Subject "M365 Offboarding — $Offboarded Processed, $Skipped Skipped ($RunTimestamp)" `
    -Body    $SummaryBody

Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan
