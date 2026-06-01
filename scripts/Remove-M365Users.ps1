
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
    param (
        [string]$UPN
    )
 
    Write-Host "  Converting mailbox to Shared..." -ForegroundColor Cyan
 
    # ── Acquire Exchange Online access token ─────────────────────────────────
    try {
        $tokenBody = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://outlook.office365.com/.default"
        }
        $tokenResponse = Invoke-RestMethod `
            -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $tokenBody
 
        if (-not $tokenResponse.access_token) {
            throw "Token response did not contain an access_token."
        }
    }
    catch {
        Write-Warning "  Could not acquire Exchange Online token: $_"
        return "Failed — token error"
    }
 
    # ── Connect to Exchange Online (app-only, no MFA prompt) ─────────────────
    try {
        Connect-ExchangeOnline `
            -AccessToken $tokenResponse.access_token `
            -Organization $Domain `
            -AppId $ClientId `
            -ShowBanner:$false `
            -ErrorAction Stop
        Write-Host "  [OK] Connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not connect to Exchange Online: $_"
        return "Failed — EXO connection error"
    }
 
    # ── Convert mailbox type ──────────────────────────────────────────────────
    $ConversionStatus = "Failed"
    try {
        # Verify the mailbox exists and is currently a UserMailbox
        $mailbox = Get-Mailbox -Identity $UPN -ErrorAction Stop
 
        if ($mailbox.RecipientTypeDetails -eq "SharedMailbox") {
            Write-Host "  [--] Mailbox is already a SharedMailbox. No conversion needed." -ForegroundColor DarkGray
            $ConversionStatus = "Already Shared"
        }
        elseif ($mailbox.RecipientTypeDetails -eq "UserMailbox") {
            Set-Mailbox -Identity $UPN -Type Shared -ErrorAction Stop
            Write-Host "  [OK] Mailbox converted to Shared." -ForegroundColor Green
            $ConversionStatus = "Converted"
        }
        else {
            Write-Warning "  Mailbox type is '$($mailbox.RecipientTypeDetails)'. Skipping conversion."
            $ConversionStatus = "Skipped — type: $($mailbox.RecipientTypeDetails)"
        }
    }
    catch {
        Write-Warning "  Mailbox conversion failed for $UPN`: $_"
        $ConversionStatus = "Failed — $($_.Exception.Message)"
    }
    finally {
        # Always disconnect from Exchange Online cleanly
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
        catch { }
    }
 
    return $ConversionStatus
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
        @{ Name = "Windows Hello";           Uri = "$BaseUri/windowsHelloForBusinessMethods" },
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
 
$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
 
Connect-MgGraph `
    -TenantId $TenantId `
    -ClientSecretCredential $Credential `
    -NoWelcome
 
Write-Host "Connected." -ForegroundColor Green
 
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
    if ($MailboxConverted -like "Failed*") { $OverallStatus = "Partial" }
 
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
