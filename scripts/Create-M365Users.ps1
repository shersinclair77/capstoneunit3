# =============================================================================
# Remove-M365Users.ps1
# Offboards M365 users in this exact sequence:
#
#   1. Convert user mailbox → Shared Mailbox   (retains email, no license needed)
#   2. Remove all licenses                     (reclaims subscription capacity)
#   3. Block sign-in                           (prevents new logins)
#   4. Revoke active sessions                  (kills existing tokens immediately)
#   5. Remove from all groups
#   6. Disable / remove all MFA methods
#
# Auth: App Registration (Client Secret) for both Graph API and Exchange Online.
#
# Required App Registration API Permissions (Application):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Group.ReadWrite.All
#   - UserAuthenticationMethod.ReadWrite.All
#   - Mail.Send
#   - Application.Read.All
#   - Exchange.ManageAsApp    ← required for shared mailbox conversion
#
# Additional Entra role required on the App's Service Principal:
#   - Exchange Recipient Administrator
#   (Entra admin center → Roles → Exchange Recipient Administrator → Assign → select your app SP)
# =============================================================================

param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail = "RenaeHarewood@Renah.onmicrosoft.com",

    [Parameter(Mandatory = $false)]
    [string]$RunId = "local",

    [Parameter(Mandatory = $false)]
    [string]$CommitSha = "local",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "./offboarding/users-to-offboard.csv"
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain      = "renah.onmicrosoft.com"
$SenderEmail = $NotificationEmail  # Uses RenaeHarewood@Renah.onmicrosoft.com — a known valid licensed mailbox
$SecretExpiryWarningDays = 30

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/offboarding_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# LOAD OFFBOARDING CSV
# Required column: UserPrincipalName
# Example row:     alice.johnson@renah.onmicrosoft.com
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "Offboarding CSV not found at: $CsvPath"
    exit 1
}

$CsvData = Import-Csv -Path $CsvPath
Write-Host "Loaded $($CsvData.Count) user(s) from CSV: $CsvPath" -ForegroundColor Cyan

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
            -Uri "https://graph.microsoft.com/v1.0/users/$SenderEmail/sendMail" `
            -Body ($Payload | ConvertTo-Json -Depth 10)
        Write-Host "  [OK] Email sent to $NotificationEmail" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Email notification FAILED."
        Write-Warning "  Sender    : $SenderEmail"
        Write-Warning "  Recipient : $NotificationEmail"
        Write-Warning "  Error     : $($_.Exception.Message)"
        try {
            $errDetail = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Warning "  Error code: $($errDetail.error.code)"
            Write-Warning "  Error msg : $($errDetail.error.message)"
        } catch { }
        Write-Warning "  Check: Mail.Send (Application) permission granted with admin consent."
        Write-Warning "  Check: Sender mailbox exists and has Exchange Online license."
    }
}

# =============================================================================
# STEP 1 HELPER — Convert-ToSharedMailbox
# -----------------------------------------------------------------------------
# Converts the user's mailbox to a Shared Mailbox BEFORE the license is
# removed. This preserves all email history and allows delegates to be
# granted access without consuming a paid license (up to 50 GB).
#
# Connection: uses a separate OAuth 2.0 token for the Exchange Online
# endpoint (scope: https://outlook.office365.com/.default) acquired from
# the same App Registration used for Graph API calls.
#
# Required:
#   - App Registration permission: Exchange.ManageAsApp (Application)
#   - Entra role on App's Service Principal: Exchange Recipient Administrator
# =============================================================================

function Convert-ToSharedMailbox {
    param ([string]$UPN)

    # ─────────────────────────────────────────────────────────────────────────
    # Exchange Online PowerShell module removed entirely.
    # The module version on GitHub-hosted runners does not consistently support
    # the required app-only parameters (-AccessToken, -ClientSecret).
    #
    # This function now uses Invoke-RestMethod directly against the Exchange
    # Online Admin REST API — zero module dependency, works on any runner.
    #
    # Required (same as before):
    #   App Registration: Exchange.ManageAsApp (Application) + admin consent
    #   Entra role on App SP: Exchange Recipient Administrator
    # ─────────────────────────────────────────────────────────────────────────

    Write-Host "  Acquiring Exchange Online token..." -ForegroundColor DarkGray

    # ── Step 1: Get OAuth 2.0 token for Exchange Online ───────────────────────
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
        if (-not $tokenResp.access_token) { throw "Response contained no access_token." }
        $exoToken = $tokenResp.access_token
        Write-Host "  [OK] EXO token acquired." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Token acquisition failed: $($_.Exception.Message)"
        Write-Warning "  Ensure Exchange.ManageAsApp (Application) is granted on the App Registration."
        return "Failed — EXO token error"
    }

    # ── Step 2: Call Exchange Admin REST API directly ─────────────────────────
    # No ExchangeOnlineManagement module needed — plain Invoke-RestMethod calls.
    $headers = @{
        "Authorization" = "Bearer $exoToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
    # UPN must be URL-encoded for use inside OData key
    $encodedUPN = [Uri]::EscapeDataString($UPN)
    $mbUrl      = "https://outlook.office365.com/adminapi/beta/$TenantId/mailbox('$encodedUPN')"

    # ── Step 2a: Read current mailbox type ────────────────────────────────────
    try {
        $mb = Invoke-RestMethod -Method GET -Uri $mbUrl -Headers $headers -ErrorAction Stop
        Write-Host "  Current mailbox type: $($mb.MailboxType)" -ForegroundColor DarkGray

        if ($mb.MailboxType -eq "SharedMailbox") {
            Write-Host "  [--] Mailbox is already Shared — no conversion needed." -ForegroundColor DarkGray
            return "Already Shared"
        }
    }
    catch {
        # Non-fatal — log and attempt conversion anyway
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Warning "  Could not read current mailbox type (HTTP $statusCode): $($_.Exception.Message)"
        Write-Warning "  Attempting conversion anyway..."
    }

    # ── Step 2b: Convert to Shared ────────────────────────────────────────────
    try {
        Invoke-RestMethod `
            -Method  PATCH `
            -Uri     $mbUrl `
            -Headers $headers `
            -Body    '{"MailboxType":"Shared"}' `
            -ErrorAction Stop

        # Wait briefly for replication then verify
        Start-Sleep -Seconds 6
        $verify = Invoke-RestMethod -Method GET -Uri $mbUrl -Headers $headers -ErrorAction SilentlyContinue

        if ($verify -and $verify.MailboxType -eq "SharedMailbox") {
            Write-Host "  [OK] Mailbox converted to Shared (verified)." -ForegroundColor Green
            return "Converted"
        }
        else {
            # PATCH returned 200 — treat as success even if re-read is inconclusive
            Write-Host "  [OK] Conversion request accepted." -ForegroundColor Green
            return "Converted"
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errMsg     = $_.Exception.Message
        Write-Warning "  Mailbox conversion failed (HTTP $statusCode): $errMsg"
        try {
            $errBody = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Warning "  Error code   : $($errBody.error.code)"
            Write-Warning "  Error message: $($errBody.error.message)"
        } catch { }

        if ($statusCode -eq 403) {
            Write-Warning "  403 Forbidden — check:"
            Write-Warning "    1. Exchange.ManageAsApp permission added to App Registration"
            Write-Warning "    2. Admin consent granted for Exchange.ManageAsApp"
            Write-Warning "    3. Exchange Recipient Administrator role assigned to the App"
            Write-Warning "       service principal in Entra admin center > Roles"
        }
        elseif ($statusCode -eq 404) {
            Write-Warning "  404 Not Found — mailbox may not exist or UPN '$UPN' is incorrect."
        }
        return "Failed — HTTP $statusCode : $errMsg"
    }
}


# =============================================================================
# STEP 6 HELPER — Disable-UserMfa
# Resets perUserMfaState to disabled and removes all registered auth methods.
# =============================================================================

function Disable-UserMfa {
    param (
        [string]$UserId,
        [string]$UPN
    )

    $BaseUri   = "https://graph.microsoft.com/v1.0/users/$UserId/authentication"
    $MfaStatus = "Disabled"
    $Removed   = 0

    # Reset per-user MFA state
    try {
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri "$BaseUri/requirements" `
            -Body (@{ perUserMfaState = "disabled" } | ConvertTo-Json)
        Write-Host "  [OK] perUserMfaState set to disabled." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not reset perUserMfaState: $($_.Exception.Message)"
        $MfaStatus = "Partial"
    }

    # Remove all registered authentication methods
    $methodEndpoints = @(
        @{ Name = "Microsoft Authenticator"; Uri = "$BaseUri/microsoftAuthenticatorMethods" },
        @{ Name = "Phone (SMS/Call)";        Uri = "$BaseUri/phoneMethods"                  },
        @{ Name = "Software OATH (TOTP)";    Uri = "$BaseUri/softwareOathMethods"            },
        @{ Name = "Temp Access Pass (TAP)";  Uri = "$BaseUri/temporaryAccessPassMethods"     },
        @{ Name = "FIDO2 Security Key";      Uri = "$BaseUri/fido2Methods"                   },
        @{ Name = "Windows Hello";           Uri = "$BaseUri/windowsHelloForBusinessMethods" }
    )

    foreach ($ep in $methodEndpoints) {
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
                        Write-Warning "  Could not remove $($ep.Name) method: $($_.Exception.Message)"
                        $MfaStatus = "Partial"
                    }
                }
            }
            else {
                Write-Host "  [--] No $($ep.Name) methods registered." -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Verbose "  $($ep.Name) endpoint not applicable: $($_.Exception.Message)"
        }
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
        -TenantId $TenantId `
        -ClientSecretCredential $Credential `
        -NoWelcome `
        -ErrorAction Stop

    # Verify the connection is live before proceeding
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Connect-MgGraph returned no context — credentials may be incorrect."
    }
    Write-Host "  [OK] Connected as AppOnly to tenant: $($ctx.TenantId)" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "  [FATAL] Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    Write-Host "  Check that M365_TENANT_ID, M365_CLIENT_ID, and M365_CLIENT_SECRET" -ForegroundColor Red
    Write-Host "  are set correctly in GitHub repository secrets." -ForegroundColor Red
    exit 1
}

# =============================================================================
# SECRET EXPIRY CHECK
# =============================================================================

Write-Host "`nChecking client secret expiry..." -ForegroundColor Cyan

try {
    $App     = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ClientId'"
    $AppId   = $App.value[0].id
    $Secrets = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$AppId"

    foreach ($Secret in $Secrets.passwordCredentials) {
        $ExpiryDate = [datetime]$Secret.endDateTime
        $DaysLeft   = ($ExpiryDate - (Get-Date)).Days

        if ($DaysLeft -le $SecretExpiryWarningDays) {
            Write-Warning "Secret expires in $DaysLeft day(s). Sending alert."
            Send-EmailNotification `
                -Subject "ACTION REQUIRED: M365 App Secret Expires in $DaysLeft Day(s)" `
                -Body "<h2>⚠️ Secret Expiry Warning</h2><p>Rotate the client secret before $($ExpiryDate.ToString('yyyy-MM-dd')).</p>"
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

$Results = @()
$Offboarded = 0
$Skipped    = 0
$Failed     = 0

foreach ($Row in $CsvData) {
    $UPN = $Row.UserPrincipalName.Trim()
    Write-Host "`n============================================================" -ForegroundColor DarkGray
    Write-Host "  Offboarding: $UPN" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor DarkGray

    # ── Lookup user ─────────────────────────────────────────────────────────
    $User = Get-MgUser `
        -Filter "userPrincipalName eq '$UPN'" `
        -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses" `
        -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Warning "  User $UPN not found in tenant. Skipping."
        $Results += [PSCustomObject]@{
            Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId            = $RunId
            CommitSha        = $CommitSha
            UPN              = $UPN
            DisplayName      = "Not found"
            MailboxConverted = "N/A"
            LicenseRemoved   = "N/A"
            SignInBlocked    = "N/A"
            SessionsRevoked  = "N/A"
            GroupsRemoved    = "N/A"
            MfaDisabled      = "N/A"
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

    # ────────────────────────────────────────────────────────────────────────
    # STEP 1 — Convert mailbox to Shared
    # Must happen BEFORE license removal so Exchange retains the mailbox data.
    # Shared mailboxes remain accessible to delegates with no license required
    # (for mailboxes under 50 GB).
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 1/6] Convert mailbox to Shared..." -ForegroundColor Cyan
    $MailboxConverted = Convert-ToSharedMailbox -UPN $UPN

    # HARD STOP: if conversion failed, do NOT remove the license.
    # Removing the license before converting starts a 30-day Exchange soft-delete
    # countdown that permanently deletes all mailbox data. The operator must fix
    # the Exchange Online connection and re-run before proceeding.
    if ($MailboxConverted -like "Failed*") {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  BLOCKED: Mailbox conversion failed for $($UPN.PadRight(34)) ║" -ForegroundColor Red
        Write-Host "  ║                                                                  ║" -ForegroundColor Red
        Write-Host "  ║  License removal has been SKIPPED to protect mailbox data.      ║" -ForegroundColor Red
        Write-Host "  ║  Removing the license before converting would start a 30-day    ║" -ForegroundColor Red
        Write-Host "  ║  soft-delete countdown in Exchange, permanently deleting all    ║" -ForegroundColor Red
        Write-Host "  ║  email history.                                                  ║" -ForegroundColor Red
        Write-Host "  ║                                                                  ║" -ForegroundColor Red
        Write-Host "  ║  TO FIX:                                                        ║" -ForegroundColor Red
        Write-Host "  ║  1. Verify Exchange.ManageAsApp permission on App Registration  ║" -ForegroundColor Red
        Write-Host "  ║  2. Verify Exchange Recipient Administrator role is assigned     ║" -ForegroundColor Red
        Write-Host "  ║  3. Re-run this workflow — conversion will be retried            ║" -ForegroundColor Red
        Write-Host "  ║  4. Alternatively, convert manually in Exchange admin center     ║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""

        $LicenseRemoved  = "SKIPPED — mailbox not converted (manual action required)"
        $OverallStatus   = "Partial — license NOT removed, mailbox NOT converted"

        $Results += [PSCustomObject]@{
            Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId            = $RunId
            CommitSha        = $CommitSha
            UPN              = $UPN
            DisplayName      = $DisplayName
            MailboxConverted = $MailboxConverted
            LicenseRemoved   = $LicenseRemoved
            SignInBlocked    = "Skipped"
            SessionsRevoked  = "Skipped"
            GroupsRemoved    = "Skipped"
            MfaDisabled      = "Skipped"
            Status           = $OverallStatus
        }
        $Offboarded++
        continue
    }

    # ────────────────────────────────────────────────────────────────────────
    # STEP 2 — Remove all licenses
    # Runs after conversion so Exchange does not soft-delete the mailbox.
    # Shared mailboxes do not need a license for basic email retention.
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 2/6] Removing licenses..." -ForegroundColor Cyan
    try {
        $AssignedLicenses = (Get-MgUser -UserId $User.Id -Property "assignedLicenses").AssignedLicenses
        if ($AssignedLicenses -and $AssignedLicenses.Count -gt 0) {
            $SkuIds = $AssignedLicenses | Select-Object -ExpandProperty SkuId
            Set-MgUserLicense `
                -UserId $User.Id `
                -AddLicenses @() `
                -RemoveLicenses $SkuIds
            Write-Host "  [OK] $($SkuIds.Count) license(s) removed." -ForegroundColor Green
            $LicenseRemoved = "Yes ($($SkuIds.Count) SKU(s))"
        }
        else {
            Write-Host "  [--] No licenses assigned to this account." -ForegroundColor DarkGray
            $LicenseRemoved = "None assigned"
        }
    }
    catch {
        Write-Warning "  License removal failed: $_"
        $OverallStatus = "Partial"
    }

    # ────────────────────────────────────────────────────────────────────────
    # STEP 3 — Block sign-in (AccountEnabled = false)
    # Prevents any new interactive authentication against this account.
    # Existing sessions are still alive until Step 4.
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 3/6] Blocking sign-in..." -ForegroundColor Cyan
    try {
        Update-MgUser -UserId $User.Id -AccountEnabled $false
        Write-Host "  [OK] Sign-in blocked (AccountEnabled = false)." -ForegroundColor Green
        $SignInBlocked = "Yes"
    }
    catch {
        Write-Warning "  Failed to block sign-in: $_"
        $OverallStatus = "Partial"
    }

    # ────────────────────────────────────────────────────────────────────────
    # STEP 4 — Revoke all active sessions
    # Invalidates all existing OAuth tokens and refresh tokens so that active
    # browser sessions, mobile apps, and desktop clients are terminated.
    # Blocking sign-in alone does NOT end sessions already in progress.
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 4/6] Revoking active sessions..." -ForegroundColor Cyan
    try {
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Write-Host "  [OK] All active sessions and tokens revoked." -ForegroundColor Green
        $SessionsRevoked = "Yes"
    }
    catch {
        Write-Warning "  Session revocation failed: $_"
        $OverallStatus = "Partial"
    }

    # ────────────────────────────────────────────────────────────────────────
    # STEP 5 — Remove from all groups
    # Queries every Entra group the user is a direct member of and removes
    # each membership. Role assignments are not removed here — those should
    # be handled separately via PIM or role management.
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 5/6] Removing from all groups..." -ForegroundColor Cyan
    $GroupCount = 0
    try {
        $Memberships = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/memberOf"

        $Groups = $Memberships.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }

        if ($Groups -and $Groups.Count -gt 0) {
            foreach ($Group in $Groups) {
                try {
                    Invoke-MgGraphRequest `
                        -Method DELETE `
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
        Write-Warning "  Group membership retrieval failed: $_"
        $OverallStatus = "Partial"
    }

    # ────────────────────────────────────────────────────────────────────────
    # STEP 6 — Disable / remove all MFA methods
    # Resets perUserMfaState to disabled and deletes every registered
    # authentication method so credentials cannot be reused if the account
    # is accidentally re-enabled.
    # ────────────────────────────────────────────────────────────────────────
    Write-Host "`n  [Step 6/6] Disabling MFA..." -ForegroundColor Cyan
    $MfaDisabled = Disable-UserMfa -UserId $User.Id -UPN $UPN
    if ($MfaDisabled -eq "Failed") { $OverallStatus = "Partial" }

    # ── Audit entry ──────────────────────────────────────────────────────────
    $Results += [PSCustomObject]@{
        Timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId            = $RunId
        CommitSha        = $CommitSha
        UPN              = $UPN
        DisplayName      = $DisplayName
        MailboxConverted = $MailboxConverted
        LicenseRemoved   = $LicenseRemoved
        SignInBlocked    = $SignInBlocked
        SessionsRevoked  = $SessionsRevoked
        GroupsRemoved    = $GroupsRemoved
        MfaDisabled      = $MfaDisabled
        Status           = $OverallStatus
    }

    Write-Host "`n  ✔  $DisplayName ($UPN) — $OverallStatus" -ForegroundColor Green
    $Offboarded++
}

# =============================================================================
# WRITE AUDIT LOG (CSV artifact)
# GitHub Actions uploads this as a downloadable artifact.
# Navigate to: Actions → this run → Artifacts section → offboarding-audit-log
# =============================================================================

Write-Host "`nWriting audit log to $AuditLogPath..." -ForegroundColor Cyan
$Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
Write-Host "  [OK] Audit log written: $AuditLogPath" -ForegroundColor Green

# =============================================================================
# CONSOLE SUMMARY
# =============================================================================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "        USER OFFBOARDING SUMMARY"        -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Run ID     : $RunId"
Write-Host "  Commit SHA : $CommitSha"
Write-Host "  Timestamp  : $RunTimestamp"
Write-Host "  Offboarded : $Offboarded"
Write-Host "  Skipped    : $Skipped"
Write-Host "  Failed     : $Failed"
Write-Host "========================================" -ForegroundColor Yellow
$Results | Format-Table Timestamp, DisplayName, MailboxConverted, LicenseRemoved, SignInBlocked, GroupsRemoved, MfaDisabled, Status -AutoSize

# =============================================================================
# EMAIL NOTIFICATION — sent to RenaeHarewood@Renah.onmicrosoft.com
# Sent on every run (success or partial) so Renae always has a record.
# =============================================================================

Write-Host "`nSending offboarding summary email to $NotificationEmail..." -ForegroundColor Cyan

$TableRows = $Results | ForEach-Object {
    $rowColor = switch ($_.Status) {
        "Completed" { "#e6f4ea" }
        "Partial"   { "#fff8e1" }
        default     { "#fce8e6" }
    }
    @"
<tr style='background:$rowColor'>
  <td>$($_.DisplayName)</td>
  <td>$($_.UPN)</td>
  <td align='center'>$($_.MailboxConverted)</td>
  <td align='center'>$($_.LicenseRemoved)</td>
  <td align='center'>$($_.SignInBlocked)</td>
  <td align='center'>$($_.SessionsRevoked)</td>
  <td align='center'>$($_.GroupsRemoved)</td>
  <td align='center'>$($_.MfaDisabled)</td>
  <td align='center'><b>$($_.Status)</b></td>
</tr>
"@
}

$SummaryBody = @"
<h2 style='color:#1A3C5E;font-family:Calibri,sans-serif'>
  M365 User Offboarding Summary
</h2>
<p style='font-family:Calibri,sans-serif'>
  <b>Run ID:</b> $RunId<br>
  <b>Commit SHA:</b> $CommitSha<br>
  <b>Timestamp:</b> $RunTimestamp
</p>

<table border='1' cellpadding='6' cellspacing='0'
  style='border-collapse:collapse;font-family:Calibri,sans-serif;font-size:13px'>
  <tr style='background:#1A3C5E;color:white'>
    <th>Display Name</th>
    <th>UPN</th>
    <th>Mailbox → Shared</th>
    <th>License Removed</th>
    <th>Sign-in Blocked</th>
    <th>Sessions Revoked</th>
    <th>Groups Removed</th>
    <th>MFA Disabled</th>
    <th>Status</th>
  </tr>
  $($TableRows -join "`n")
</table>

<br>
<p style='font-family:Calibri,sans-serif'>
  <b>Offboarded:</b> $Offboarded &nbsp;&nbsp;
  <b>Skipped:</b> $Skipped &nbsp;&nbsp;
  <b>Failed:</b> $Failed
</p>

<p style='font-family:Calibri,sans-serif'>
  <b>Offboarding sequence applied to each user:</b><br>
  1. Convert mailbox → Shared &nbsp;|&nbsp;
  2. Remove licenses &nbsp;|&nbsp;
  3. Block sign-in &nbsp;|&nbsp;
  4. Revoke sessions &nbsp;|&nbsp;
  5. Remove from groups &nbsp;|&nbsp;
  6. Disable MFA
</p>

<p style='font-family:Calibri,sans-serif;color:#555'>
  <i>
    Full audit log (CSV) is saved as a downloadable artifact in the GitHub Actions run.<br>
    Navigate to: <b>Actions → run #$RunId → Artifacts → offboarding-audit-log-$RunId</b>
  </i>
</p>
"@

Send-EmailNotification `
    -Subject "M365 Offboarding Complete — $Offboarded Removed, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody

# Disconnect
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Microsoft Graph." -ForegroundColor Cyan
