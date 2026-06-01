# =============================================================================
# Remove-M365Users.ps1
# Offboards M365 users — disables accounts, revokes sessions, removes licenses
# and group memberships. Reads from a CSV file.
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application, not Delegated):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Organization.Read.All
#   - Group.ReadWrite.All
#   - Mail.Send                  (email notifications)
# =============================================================================

param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$NotificationEmail,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "./offboarding/users-to-offboard.csv",

    [Parameter(Mandatory = $false)]
    [string]$RunId = "local",

    [Parameter(Mandatory = $false)]
    [string]$CommitSha = "local"
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain      = "renah.onmicrosoft.com"
$SenderEmail = "admin@$Domain"   # Must be a licensed mailbox in the tenant

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/offboarding_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# HELPERS
# =============================================================================

function Send-EmailNotification {
    param (
        [string]$Subject,
        [string]$Body
    )
    try {
        $EmailPayload = @{
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
            -Body ($EmailPayload | ConvertTo-Json -Depth 10)
        Write-Host "  [OK] Email notification sent to $NotificationEmail" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Email notification failed: $_"
    }
}

# =============================================================================
# CONNECT
# =============================================================================

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

Connect-MgGraph `
    -TenantId $TenantId `
    -ClientSecretCredential $Credential `
    -NoWelcome

Write-Host "Connected." -ForegroundColor Green

# =============================================================================
# LOAD CSV
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found at path: $CsvPath"
    exit 1
}

$UsersToOffboard = Import-Csv -Path $CsvPath
Write-Host "Loaded $($UsersToOffboard.Count) user(s) from CSV." -ForegroundColor Cyan

# =============================================================================
# OFFBOARD USERS
# =============================================================================

$Results  = @()
$Removed  = 0
$Skipped  = 0
$Failed   = 0

foreach ($Row in $UsersToOffboard) {
    $UPN = $Row.UPN.Trim()

    Write-Host "`nOffboarding: $UPN" -ForegroundColor Cyan

    # --- Verify user exists ---
    $User = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Warning "User $UPN not found in tenant. Skipping."
        $Results += [PSCustomObject]@{
            Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId       = $RunId
            CommitSha   = $CommitSha
            UPN         = $UPN
            Disabled    = "N/A"
            SessionsRevoked = "N/A"
            LicenseRemoved  = "N/A"
            GroupsRemoved   = "N/A"
            Status      = "Skipped (user not found)"
        }
        $Skipped++
        continue
    }

    $DisabledStatus        = "Failed"
    $SessionsRevokedStatus = "Failed"
    $LicenseRemovedStatus  = "Failed"
    $GroupsRemovedStatus   = "N/A"

    # --- Disable account ---
    try {
        Update-MgUser -UserId $User.Id -AccountEnabled $false
        Write-Host "  [OK] Account disabled." -ForegroundColor Green
        $DisabledStatus = "Yes"
    }
    catch {
        Write-Warning "  Failed to disable account: $_"
    }

    # --- Revoke all active sessions ---
    try {
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Write-Host "  [OK] Sign-in sessions revoked." -ForegroundColor Green
        $SessionsRevokedStatus = "Yes"
    }
    catch {
        Write-Warning "  Failed to revoke sessions: $_"
    }

    # --- Remove all licenses ---
    try {
        $AssignedLicenses = (Get-MgUserLicenseDetail -UserId $User.Id).SkuId
        if ($AssignedLicenses) {
            Set-MgUserLicense -UserId $User.Id -AddLicenses @() -RemoveLicenses $AssignedLicenses
            Write-Host "  [OK] License(s) removed." -ForegroundColor Green
            $LicenseRemovedStatus = "Yes"
        }
        else {
            Write-Host "  No licenses assigned. Skipping license removal." -ForegroundColor Gray
            $LicenseRemovedStatus = "None assigned"
        }
    }
    catch {
        Write-Warning "  Failed to remove licenses: $_"
    }

    # --- Remove from all groups ---
    try {
        $MemberOf = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/memberOf"

        $GroupCount = 0
        foreach ($Group in $MemberOf.value) {
            if ($Group.'@odata.type' -eq "#microsoft.graph.group") {
                try {
                    Invoke-MgGraphRequest `
                        -Method DELETE `
                        -Uri "https://graph.microsoft.com/v1.0/groups/$($Group.id)/members/$($User.Id)/`$ref"
                    $GroupCount++
                }
                catch {
                    Write-Warning "  Could not remove from group $($Group.displayName): $_"
                }
            }
        }
        Write-Host "  [OK] Removed from $GroupCount group(s)." -ForegroundColor Green
        $GroupsRemovedStatus = $GroupCount
    }
    catch {
        Write-Warning "  Failed to retrieve group memberships: $_"
    }

    $Results += [PSCustomObject]@{
        Timestamp           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId               = $RunId
        CommitSha           = $CommitSha
        UPN                 = $UPN
        Disabled            = $DisabledStatus
        SessionsRevoked     = $SessionsRevokedStatus
        LicenseRemoved      = $LicenseRemovedStatus
        GroupsRemoved       = $GroupsRemovedStatus
        Status              = "Offboarded"
    }
    $Removed++
}

# =============================================================================
# WRITE AUDIT LOG
# =============================================================================

Write-Host "`nWriting offboarding audit log to $AuditLogPath..." -ForegroundColor Cyan
$Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
Write-Host "  [OK] Audit log written." -ForegroundColor Green

# =============================================================================
# CONSOLE SUMMARY
# =============================================================================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "        USER OFFBOARDING SUMMARY"         -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Run ID   : $RunId"
Write-Host "  Commit   : $CommitSha"
Write-Host "  Timestamp: $RunTimestamp"
Write-Host "  Offboarded: $Removed"
Write-Host "  Skipped  : $Skipped"
Write-Host "  Failed   : $Failed"
Write-Host "========================================" -ForegroundColor Yellow
$Results | Format-Table Timestamp, UPN, Disabled, SessionsRevoked, LicenseRemoved, GroupsRemoved, Status -AutoSize

# =============================================================================
# EMAIL NOTIFICATION — OFFBOARDING SUMMARY
# =============================================================================

Write-Host "`nSending offboarding summary email..." -ForegroundColor Cyan

$TableRows = $Results | ForEach-Object {
    "<tr><td>$($_.UPN)</td><td>$($_.Disabled)</td><td>$($_.SessionsRevoked)</td><td>$($_.LicenseRemoved)</td><td>$($_.GroupsRemoved)</td><td>$($_.Status)</td></tr>"
}

$SummaryBody = @"
<h2>M365 User Offboarding Summary</h2>
<p><b>Run ID:</b> $RunId<br>
<b>Commit SHA:</b> $CommitSha<br>
<b>Timestamp:</b> $RunTimestamp</p>
<table border='1' cellpadding='5' cellspacing='0'>
  <tr style='background:#f2f2f2'>
    <th>UPN</th><th>Disabled</th><th>Sessions Revoked</th><th>License Removed</th><th>Groups Removed</th><th>Status</th>
  </tr>
  $($TableRows -join "`n")
</table>
<br>
<p><b>Offboarded:</b> $Removed &nbsp; <b>Skipped:</b> $Skipped &nbsp; <b>Failed:</b> $Failed</p>
<p><i>Audit log is attached to the GitHub Actions run as a downloadable artifact.</i></p>
"@

Send-EmailNotification `
    -Subject "M365 Offboarding Complete — $Removed Offboarded, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody

# Disconnect
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
