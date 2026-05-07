# =============================================================================
# Create-M365Users.ps1
# Creates M365 users with licenses, group membership, MFA, and password policies
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application, not Delegated):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Organization.Read.All
#   - Group.ReadWrite.All
#   - Policy.ReadWrite.AuthenticationMethod  (MFA enforcement)
#   - Mail.Send                              (email notifications)
#   - Application.Read.All                  (secret expiry check)
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

    # Injected by GitHub Actions workflow for run metadata
    [Parameter(Mandatory = $false)]
    [string]$RunId = "local",

    [Parameter(Mandatory = $false)]
    [string]$CommitSha = "local",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "./onboarding/users-to-onboard.csv"
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain           = "renah.onmicrosoft.com"
$LicenseSkuId     = "SPB"    # Microsoft 365 Business Premium
$UsageLocation    = "BB"     # Barbados (ISO 3166-1 alpha-2)
$PasswordPolicies = "DisablePasswordExpiration"
$SenderEmail      = "admin@$Domain"   # Must be a licensed mailbox in the tenant
$SecretExpiryWarningDays = 30         # Warn if secret expires within this many days

# Audit log path — picked up as a workflow artifact
$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$AuditLogPath = "./audit-logs/provisioning_$RunTimestamp.csv"
New-Item -ItemType Directory -Force -Path "./audit-logs" | Out-Null

# =============================================================================
# LOAD USERS FROM CSV
# Edit onboarding/users-to-onboard.csv to add or remove users.
# UPN is auto-built as firstname.lastname@domain
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "Onboarding CSV not found at: $CsvPath"
    exit 1
}

$CsvData = Import-Csv -Path $CsvPath
Write-Host "Loaded $($CsvData.Count) user(s) from CSV: $CsvPath" -ForegroundColor Cyan

# Convert CSV rows to user objects
$Users = $CsvData | ForEach-Object {
    @{
        FirstName  = $_.FirstName.Trim()
        LastName   = $_.LastName.Trim()
        Department = $_.Department.Trim()
        JobTitle   = $_.JobTitle.Trim()
        GroupIds   = if ($_.GroupIds -and $_.GroupIds.Trim() -ne "") {
                         $_.GroupIds.Split(",") | ForEach-Object { $_.Trim() }
                     } else { $null }
    }
}

# =============================================================================
# HELPERS
# =============================================================================

function New-RandomPassword {
    $upper   = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ" | Get-Random -Count 3
    $lower   = [char[]]"abcdefghijklmnopqrstuvwxyz" | Get-Random -Count 5
    $digits  = [char[]]"0123456789"                  | Get-Random -Count 3
    $special = [char[]]"!@#$%^&*"                    | Get-Random -Count 2
    $all     = ($upper + $lower + $digits + $special) | Sort-Object { Get-Random }
    return -join $all
}

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
# 1. SECRET EXPIRY CHECK
# Checks if the app registration client secret is nearing expiry and emails
# an alert if it expires within $SecretExpiryWarningDays days
# =============================================================================

Write-Host "`nChecking client secret expiry..." -ForegroundColor Cyan

try {
    $App     = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ClientId'"
    $AppId   = $App.value[0].id
    $Secrets = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$AppId"
    
    foreach ($Secret in $Secrets.passwordCredentials) {
        $ExpiryDate  = [datetime]$Secret.endDateTime
        $DaysLeft    = ($ExpiryDate - (Get-Date)).Days

        if ($DaysLeft -le $SecretExpiryWarningDays) {
            Write-Warning "Client secret expires in $DaysLeft day(s) on $($ExpiryDate.ToString('yyyy-MM-dd')). Sending alert..."

            $ExpiryBody = @"
<h2>⚠️ Azure App Registration Secret Expiry Warning</h2>
<p>The client secret for the M365 provisioning app registration is expiring soon.</p>
<table border='1' cellpadding='5'>
  <tr><td><b>App Client ID</b></td><td>$ClientId</td></tr>
  <tr><td><b>Secret Expiry Date</b></td><td>$($ExpiryDate.ToString('yyyy-MM-dd'))</td></tr>
  <tr><td><b>Days Remaining</b></td><td>$DaysLeft</td></tr>
</table>
<p>Please rotate the secret in Azure Entra ID and update the GitHub repository secret before expiry to avoid pipeline failures.</p>
"@
            Send-EmailNotification `
                -Subject "ACTION REQUIRED: M365 Provisioning App Secret Expires in $DaysLeft Day(s)" `
                -Body $ExpiryBody
        }
        else {
            Write-Host "  [OK] Client secret is valid. Expires in $DaysLeft day(s) on $($ExpiryDate.ToString('yyyy-MM-dd'))." -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Could not check secret expiry: $_"
}

# =============================================================================
# RESOLVE LICENSE SKU ID
# =============================================================================

Write-Host "`nResolving license SKU for '$LicenseSkuId'..." -ForegroundColor Cyan

$Sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq $LicenseSkuId }

if (-not $Sku) {
    Write-Error "License SKU '$LicenseSkuId' not found in tenant. Check your license assignments in the M365 admin center."
    exit 1
}

Write-Host "License SKU resolved: $($Sku.SkuId)" -ForegroundColor Green

# =============================================================================
# CREATE USERS
# =============================================================================

$Results  = @()
$Created  = 0
$Skipped  = 0
$Failed   = 0

foreach ($User in $Users) {
    $UPN          = "$($User.FirstName.ToLower()).$($User.LastName.ToLower())@$Domain"
    $DisplayName  = "$($User.FirstName) $($User.LastName)"
    $TempPassword = New-RandomPassword

    Write-Host "`nProcessing: $DisplayName ($UPN)" -ForegroundColor Cyan

    # --- Check if user already exists ---
    $Existing = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

    if ($Existing) {
        Write-Warning "User $UPN already exists. Skipping creation."
        $Results += [PSCustomObject]@{
            Timestamp    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId        = $RunId
            CommitSha    = $CommitSha
            DisplayName  = $DisplayName
            UPN          = $UPN
            Department   = $User.Department
            JobTitle     = $User.JobTitle
            Status       = "Skipped (already exists)"
            MFA          = "N/A"
            LicenseAssigned = "N/A"
            TempPassword = "N/A"
        }
        $Skipped++
        continue
    }

    # --- Create user ---
    try {
        $NewUser = New-MgUser -BodyParameter @{
            DisplayName       = $DisplayName
            GivenName         = $User.FirstName
            Surname           = $User.LastName
            UserPrincipalName = $UPN
            MailNickname      = "$($User.FirstName.ToLower()).$($User.LastName.ToLower())"
            Department        = $User.Department
            JobTitle          = $User.JobTitle
            UsageLocation     = $UsageLocation
            AccountEnabled    = $true
            PasswordProfile   = @{
                Password                      = $TempPassword
                ForceChangePasswordNextSignIn = $true
            }
            PasswordPolicies  = $PasswordPolicies
        }
        Write-Host "  [OK] User created." -ForegroundColor Green
    }
    catch {
        Write-Error "  Failed to create user $UPN`: $_"
        $Results += [PSCustomObject]@{
            Timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId           = $RunId
            CommitSha       = $CommitSha
            DisplayName     = $DisplayName
            UPN             = $UPN
            Department      = $User.Department
            JobTitle        = $User.JobTitle
            Status          = "Failed - creation error"
            MFA             = "N/A"
            LicenseAssigned = "N/A"
            TempPassword    = "N/A"
        }
        $Failed++
        continue
    }

    # --- Assign license ---
    $LicenseStatus = "Failed"
    try {
        Set-MgUserLicense -UserId $NewUser.Id -AddLicenses @{ SkuId = $Sku.SkuId } -RemoveLicenses @()
        Write-Host "  [OK] License assigned (Business Premium)." -ForegroundColor Green
        $LicenseStatus = "Business Premium"
    }
    catch {
        Write-Warning "  License assignment failed for $UPN`: $_"
    }

    # --- Assign to groups (optional) ---
    if ($User.GroupIds) {
        foreach ($GroupId in $User.GroupIds) {
            try {
                New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $NewUser.Id
                Write-Host "  [OK] Added to group: $GroupId" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to add to group $GroupId`: $_"
            }
        }
    }

    # --- Enforce MFA (per-user) ---
    $MfaStatus = "Failed"
    try {
        $MfaBody = @{
            strongAuthenticationRequirements = @(
                @{
                    rememberDevicesNotIssuedBefore = (Get-Date).ToUniversalTime().ToString("o")
                    state                          = "Enforced"
                }
            )
        }
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri "https://graph.microsoft.com/beta/users/$($NewUser.Id)" `
            -Body ($MfaBody | ConvertTo-Json -Depth 5)
        Write-Host "  [OK] MFA enforced." -ForegroundColor Green
        $MfaStatus = "Enforced"
    }
    catch {
        Write-Warning "  MFA enforcement failed for $UPN`: $_"
    }

    # --- 2. Audit log entry ---
    $Results += [PSCustomObject]@{
        Timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId           = $RunId
        CommitSha       = $CommitSha
        DisplayName     = $DisplayName
        UPN             = $UPN
        Department      = $User.Department
        JobTitle        = $User.JobTitle
        Status          = "Created"
        MFA             = $MfaStatus
        LicenseAssigned = $LicenseStatus
        TempPassword    = $TempPassword
    }
    $Created++
}

# =============================================================================
# 2. WRITE AUDIT LOG (CSV)
# Saved as artifact in GitHub Actions for immutable run history
# =============================================================================

Write-Host "`nWriting audit log to $AuditLogPath..." -ForegroundColor Cyan
$Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
Write-Host "  [OK] Audit log written." -ForegroundColor Green

# =============================================================================
# CONSOLE SUMMARY
# =============================================================================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "         USER PROVISIONING SUMMARY"       -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Run ID   : $RunId"
Write-Host "  Commit   : $CommitSha"
Write-Host "  Timestamp: $RunTimestamp"
Write-Host "  Created  : $Created"
Write-Host "  Skipped  : $Skipped"
Write-Host "  Failed   : $Failed"
Write-Host "========================================" -ForegroundColor Yellow
$Results | Format-Table Timestamp, DisplayName, UPN, Status, MFA, LicenseAssigned -AutoSize
Write-Host "`nNOTE: Temp passwords are one-time use. Users must change on first login." -ForegroundColor Magenta

# =============================================================================
# 9. EMAIL NOTIFICATION — PROVISIONING SUMMARY
# =============================================================================

Write-Host "`nSending provisioning summary email..." -ForegroundColor Cyan

$TableRows = $Results | ForEach-Object {
    "<tr><td>$($_.DisplayName)</td><td>$($_.UPN)</td><td>$($_.Status)</td><td>$($_.MFA)</td><td>$($_.LicenseAssigned)</td></tr>"
}

$SummaryBody = @"
<h2>M365 User Provisioning Summary</h2>
<p><b>Run ID:</b> $RunId<br>
<b>Commit SHA:</b> $CommitSha<br>
<b>Timestamp:</b> $RunTimestamp</p>
<table border='1' cellpadding='5' cellspacing='0'>
  <tr style='background:#f2f2f2'>
    <th>Display Name</th><th>UPN</th><th>Status</th><th>MFA</th><th>License</th>
  </tr>
  $($TableRows -join "`n")
</table>
<br>
<p><b>Created:</b> $Created &nbsp; <b>Skipped:</b> $Skipped &nbsp; <b>Failed:</b> $Failed</p>
<p><i>Audit log is attached to the GitHub Actions run as a downloadable artifact.</i></p>
"@

Send-EmailNotification `
    -Subject "M365 Provisioning Complete — $Created Created, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody

# Disconnect
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
