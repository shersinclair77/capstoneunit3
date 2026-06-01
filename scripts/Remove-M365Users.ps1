# =============================================================================
# Remove-M365Users.ps1
# Offboards M365 users: removes license, removes from all groups, blocks sign-in
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application, not Delegated):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Group.ReadWrite.All
#   - Mail.Send                  (email notifications)
#   - Application.Read.All       (secret expiry check)
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
$SenderEmail = $NotificationEmail
$SecretExpiryWarningDays = 30

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/offboarding_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# LOAD USERS FROM CSV
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
# HELPERS
# =============================================================================

function Send-EmailNotification {
    param ([string]$Subject, [string]$Body)
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

    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Connect-MgGraph returned no context — credentials may be incorrect."
    }
    Write-Host "  [OK] Connected as AppOnly to tenant: $($ctx.TenantId)" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "  [FATAL] Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    Write-Host "  Check that M365_TENANT_ID, M365_CLIENT_ID, and M365_CLIENT_SECRET are correct" -ForegroundColor Red
    Write-Host "  and that the App Registration client secret has not expired." -ForegroundColor Red
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
            Write-Warning "Client secret expires in $DaysLeft day(s). Sending alert..."
            $ExpiryBody = @"
<h2>⚠️ Azure App Registration Secret Expiry Warning</h2>
<p>The client secret for the M365 offboarding app registration is expiring soon.</p>
<table border='1' cellpadding='5'>
  <tr><td><b>App Client ID</b></td><td>$ClientId</td></tr>
  <tr><td><b>Secret Expiry Date</b></td><td>$($ExpiryDate.ToString('yyyy-MM-dd'))</td></tr>
  <tr><td><b>Days Remaining</b></td><td>$DaysLeft</td></tr>
</table>
<p>Please rotate the secret in Azure Entra ID and update the GitHub repository secret before expiry.</p>
"@
            Send-EmailNotification `
                -Subject "ACTION REQUIRED: M365 Offboarding App Secret Expires in $DaysLeft Day(s)" `
                -Body $ExpiryBody
        }
        else {
            Write-Host "  [OK] Secret valid — expires in $DaysLeft day(s) on $($ExpiryDate.ToString('yyyy-MM-dd'))." -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Could not check secret expiry: $_"
}

# =============================================================================
# OFFBOARD USERS
# =============================================================================

$Results  = @()
$Removed  = 0
$Skipped  = 0
$Failed   = 0

foreach ($Row in $CsvData) {
    $UPN = $Row.UserPrincipalName.Trim()

    Write-Host "`nProcessing: $UPN" -ForegroundColor Cyan

    # --- Lookup user ---
    $User = Get-MgUser `
        -Filter "userPrincipalName eq '$UPN'" `
        -Property "Id,DisplayName,UserPrincipalName,AccountEnabled" `
        -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Warning "User $UPN not found in tenant. Skipping."
        $Results += [PSCustomObject]@{
            Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId          = $RunId
            CommitSha      = $CommitSha
            DisplayName    = "Not found"
            UPN            = $UPN
            LicenseRemoved = "N/A"
            GroupsRemoved  = "N/A"
            SignInBlocked  = "N/A"
            Status         = "Skipped — user not found"
        }
        $Skipped++
        continue
    }

    $DisplayName   = $User.DisplayName
    $LicenseRemoved = "Failed"
    $GroupsRemoved  = "Failed"
    $SignInBlocked  = "Failed"
    $OverallStatus  = "Completed"

    # --- Remove all licenses ---
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
        Write-Warning "  License removal failed for $UPN`: $_"
        $OverallStatus = "Partial"
    }

    # --- Remove from all groups ---
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
                    Write-Host "  [OK] Removed from group: $($Group.displayName)" -ForegroundColor Green
                    $GroupCount++
                }
                catch {
                    Write-Warning "  Could not remove from group '$($Group.displayName)'`: $_"
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
        Write-Warning "  Group membership retrieval failed for $UPN`: $_"
        $OverallStatus = "Partial"
    }

    # --- Block sign-in ---
    try {
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)" `
            -ContentType "application/json" `
            -Body (@{ accountEnabled = $false } | ConvertTo-Json -Depth 3)
        Write-Host "  [OK] Sign-in blocked (accountEnabled = false)." -ForegroundColor Green
        $SignInBlocked = "Yes"
    }
    catch {
        Write-Warning "  Failed to block sign-in for $UPN`: $_"
        $OverallStatus = "Partial"
    }

    # --- Audit entry ---
    $Results += [PSCustomObject]@{
        Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId          = $RunId
        CommitSha      = $CommitSha
        DisplayName    = $DisplayName
        UPN            = $UPN
        LicenseRemoved = $LicenseRemoved
        GroupsRemoved  = $GroupsRemoved
        SignInBlocked  = $SignInBlocked
        Status         = $OverallStatus
    }
    $Removed++
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

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "         USER OFFBOARDING SUMMARY"       -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Run ID   : $RunId"
Write-Host "  Commit   : $CommitSha"
Write-Host "  Timestamp: $RunTimestamp"
Write-Host "  Removed  : $Removed"
Write-Host "  Skipped  : $Skipped"
Write-Host "  Failed   : $Failed"
Write-Host "========================================" -ForegroundColor Yellow
$Results | Format-Table Timestamp, DisplayName, UPN, LicenseRemoved, GroupsRemoved, SignInBlocked, Status -AutoSize

# =============================================================================
# EMAIL SUMMARY
# =============================================================================

Write-Host "`nSending offboarding summary email to $NotificationEmail..." -ForegroundColor Cyan

$TableRows = $Results | ForEach-Object {
    $rowColor = switch ($_.Status) {
        "Completed" { "#e6f4ea" }
        "Partial"   { "#fff8e1" }
        default     { "#fce8e6" }
    }
    "<tr style='background:$rowColor'><td>$($_.DisplayName)</td><td>$($_.UPN)</td><td>$($_.LicenseRemoved)</td><td>$($_.GroupsRemoved)</td><td>$($_.SignInBlocked)</td><td>$($_.Status)</td></tr>"
}

$SummaryBody = @"
<h2 style='color:#1A3C5E;font-family:Calibri,sans-serif'>M365 User Offboarding Summary</h2>
<p style='font-family:Calibri,sans-serif'>
  <b>Run ID:</b> $RunId<br>
  <b>Commit SHA:</b> $CommitSha<br>
  <b>Timestamp:</b> $RunTimestamp
</p>
<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-family:Calibri,sans-serif;font-size:13px'>
  <tr style='background:#1A3C5E;color:white'>
    <th>Display Name</th><th>UPN</th><th>License Removed</th><th>Groups Removed</th><th>Sign-in Blocked</th><th>Status</th>
  </tr>
  $($TableRows -join "`n")
</table>
<br>
<p style='font-family:Calibri,sans-serif'>
  <b>Removed:</b> $Removed &nbsp; <b>Skipped:</b> $Skipped &nbsp; <b>Failed:</b> $Failed
</p>
<p style='font-family:Calibri,sans-serif;color:#555'>
  <i>Audit log (CSV) is saved as a downloadable artifact in the GitHub Actions run linked to commit $CommitSha.</i>
</p>
"@

Send-EmailNotification `
    -Subject "M365 Offboarding Complete — $Removed Removed, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
