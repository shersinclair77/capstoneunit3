# =============================================================================
# Remove-UserLicensesAndGroups.ps1
# Removes all licenses and group memberships from M365 users.
# Does NOT delete accounts, block sign-in, or modify mailboxes.
#
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Group.ReadWrite.All
# =============================================================================

param (
    [Parameter(Mandatory = $true)]  [string]$TenantId,
    [Parameter(Mandatory = $true)]  [string]$ClientId,
    [Parameter(Mandatory = $true)]  [string]$ClientSecret,
    [Parameter(Mandatory = $false)] [string]$NotificationEmail = "RenaeHarewood@Renah.onmicrosoft.com",
    [Parameter(Mandatory = $false)] [string]$RunId    = "local",
    [Parameter(Mandatory = $false)] [string]$CommitSha = "local",
    [Parameter(Mandatory = $false)] [string]$CsvPath  = "./onboarding/users-to-onboard.csv"
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain       = "renah.onmicrosoft.com"
$SenderEmail  = $NotificationEmail

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/cleanup_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# LOAD CSV
# Reads the onboarding CSV so you don't need a separate file.
# Builds UPNs from FirstName + LastName columns.
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV not found at: $CsvPath"
    exit 1
}

$CsvData = Import-Csv -Path $CsvPath
Write-Host "Loaded $($CsvData.Count) user(s) from: $CsvPath" -ForegroundColor Cyan

# =============================================================================
# HELPERS
# =============================================================================

function Send-EmailNotification {
    param ([string]$Subject, [string]$Body)
    try {
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri    "https://graph.microsoft.com/v1.0/users/$SenderEmail/sendMail" `
            -Body   (@{
                message = @{
                    subject      = $Subject
                    body         = @{ contentType = "HTML"; content = $Body }
                    toRecipients = @(@{ emailAddress = @{ address = $NotificationEmail } })
                }
                saveToSentItems = $false
            } | ConvertTo-Json -Depth 10)
        Write-Host "  [OK] Email sent to $NotificationEmail" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Email failed: $($_.Exception.Message)"
    }
}

# =============================================================================
# CONNECT
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
    if (-not $ctx -or -not $ctx.TenantId) { throw "No context returned." }
    Write-Host "  [OK] Connected to tenant: $($ctx.TenantId)" -ForegroundColor Green
}
catch {
    Write-Host "  [FATAL] Connection failed: $_" -ForegroundColor Red
    exit 1
}

# =============================================================================
# PROCESS USERS
# =============================================================================

$Results  = @()
$Cleaned  = 0
$Skipped  = 0

foreach ($Row in $CsvData) {
    $UPN         = "$($Row.FirstName.Trim().ToLower()).$($Row.LastName.Trim().ToLower())@$Domain"
    $DisplayName = "$($Row.FirstName.Trim()) $($Row.LastName.Trim())"

    Write-Host "`n$("─" * 55)" -ForegroundColor DarkGray
    Write-Host "  Processing: $DisplayName ($UPN)" -ForegroundColor Cyan
    Write-Host "$("─" * 55)" -ForegroundColor DarkGray

    # Lookup user
    $User = Get-MgUser `
        -Filter   "userPrincipalName eq '$UPN'" `
        -Property "Id,DisplayName,UserPrincipalName" `
        -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Warning "  User $UPN not found — skipping."
        $Results += [PSCustomObject]@{
            Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId          = $RunId; CommitSha = $CommitSha
            DisplayName    = $DisplayName; UPN = $UPN
            LicenseRemoved = "N/A — user not found"
            GroupsRemoved  = "N/A — user not found"
            Status         = "Skipped"
        }
        $Skipped++
        continue
    }

    $LicenseRemoved = "None assigned"
    $GroupsRemoved  = "None"
    $Status         = "Completed"

    # ── Remove all licenses ───────────────────────────────────────────────────
    Write-Host "  Removing licenses..." -ForegroundColor Cyan
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
        }
    }
    catch {
        Write-Warning "  License removal failed: $_"
        $LicenseRemoved = "Failed: $($_.Exception.Message)"
        $Status = "Partial"
    }

    # ── Remove from all groups ────────────────────────────────────────────────
    Write-Host "  Removing from groups..." -ForegroundColor Cyan
    $GroupCount = 0
    try {
        $Memberships = Invoke-MgGraphRequest `
            -Method GET `
            -Uri    "https://graph.microsoft.com/v1.0/users/$($User.Id)/memberOf"
        $Groups = $Memberships.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }

        if ($Groups -and $Groups.Count -gt 0) {
            foreach ($Group in $Groups) {
                try {
                    Invoke-MgGraphRequest `
                        -Method DELETE `
                        -Uri    "https://graph.microsoft.com/v1.0/groups/$($Group.id)/members/$($User.Id)/`$ref"
                    Write-Host "  [OK] Removed from: $($Group.displayName)" -ForegroundColor Green
                    $GroupCount++
                }
                catch {
                    Write-Warning "  Could not remove from '$($Group.displayName)': $_"
                    $Status = "Partial"
                }
            }
            $GroupsRemoved = "Yes ($GroupCount group(s))"
        }
        else {
            Write-Host "  [--] No group memberships found." -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Warning "  Group retrieval failed: $_"
        $GroupsRemoved = "Failed: $($_.Exception.Message)"
        $Status = "Partial"
    }

    $Results += [PSCustomObject]@{
        Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId          = $RunId; CommitSha = $CommitSha
        DisplayName    = $DisplayName; UPN = $UPN
        LicenseRemoved = $LicenseRemoved
        GroupsRemoved  = $GroupsRemoved
        Status         = $Status
    }

    Write-Host "  ✔ $DisplayName — $Status" -ForegroundColor Green
    $Cleaned++
}

# =============================================================================
# AUDIT LOG
# =============================================================================

$Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
Write-Host "`n[OK] Audit log written to $AuditLogPath" -ForegroundColor Green

# =============================================================================
# SUMMARY
# =============================================================================

Write-Host "`n$("=" * 45)" -ForegroundColor Yellow
Write-Host "         CLEANUP SUMMARY"               -ForegroundColor Yellow
Write-Host "$("=" * 45)" -ForegroundColor Yellow
Write-Host "  Run ID    : $RunId"
Write-Host "  Commit SHA: $CommitSha"
Write-Host "  Timestamp : $RunTimestamp"
Write-Host "  Cleaned   : $Cleaned"
Write-Host "  Skipped   : $Skipped"
Write-Host "$("=" * 45)" -ForegroundColor Yellow
$Results | Format-Table DisplayName, UPN, LicenseRemoved, GroupsRemoved, Status -AutoSize

# =============================================================================
# EMAIL
# =============================================================================

Write-Host "`nSending summary email to $NotificationEmail..." -ForegroundColor Cyan

$Rows = $Results | ForEach-Object {
    $bg = if ($_.Status -eq "Completed") { "#e6f4ea" } else { "#fff8e1" }
    "<tr style='background:$bg'><td>$($_.DisplayName)</td><td>$($_.UPN)</td><td>$($_.LicenseRemoved)</td><td>$($_.GroupsRemoved)</td><td>$($_.Status)</td></tr>"
}

Send-EmailNotification `
    -Subject "M365 User Cleanup — $Cleaned Processed, $Skipped Skipped ($RunTimestamp)" `
    -Body    @"
<h2 style='color:#1A3C5E;font-family:Calibri,sans-serif'>M365 User Cleanup Summary</h2>
<p style='font-family:Calibri,sans-serif'><b>Run ID:</b> $RunId &nbsp; <b>Commit:</b> $CommitSha &nbsp; <b>Timestamp:</b> $RunTimestamp</p>
<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-family:Calibri,sans-serif;font-size:13px'>
  <tr style='background:#1A3C5E;color:white'><th>Display Name</th><th>UPN</th><th>License Removed</th><th>Groups Removed</th><th>Status</th></tr>
  $($Rows -join "`n")
</table>
<br><p style='font-family:Calibri,sans-serif'><b>Cleaned:</b> $Cleaned &nbsp; <b>Skipped:</b> $Skipped</p>
<p style='font-family:Calibri,sans-serif;color:#555'><i>Full audit log saved as artifact in GitHub Actions run $RunId.</i></p>
"@

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected." -ForegroundColor Cyan
