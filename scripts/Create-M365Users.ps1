# =============================================================================
# Create-M365Users.ps1
# Creates M365 users with licenses, group membership, and password policies
# Auth: App Registration (Client Secret)
# Tenant: renah.onmicrosoft.com
#
# Required App Registration API Permissions (Application, not Delegated):
#   - User.ReadWrite.All
#   - Directory.ReadWrite.All
#   - Organization.Read.All
#   - Group.ReadWrite.All
#   - Policy.ReadWrite.AuthenticationMethod  (required for MFA enforcement)
# =============================================================================

param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Domain         = "renah.onmicrosoft.com"
$LicenseSkuId   = "SPB"   # Microsoft 365 Business Premium
$UsageLocation  = "BB"    # Barbados — change if needed (ISO 3166-1 alpha-2)

# Password policy applied to all created users
$PasswordPolicies = "DisablePasswordExpiration"

# =============================================================================
# USER LIST
# Add or remove users here. UPN is auto-built as firstname.lastname@domain
# =============================================================================

$Users = @(
    @{
        FirstName  = "Zuri"
        LastName   = "Jackson"
        Department = "Engineering"
        JobTitle   = "Software Engineer"
        # GroupIds   = @("your-group-object-id")  # Optional: assign to groups
    },
    @{
        FirstName  = "Lisa"
        LastName   = "Smorm"
        Department = "Finance"
        JobTitle   = "Financial Analyst"
        # GroupIds   = @("your-group-object-id")
    },
    @{
        FirstName  = "Jenkin"
        LastName   = "Whitter"
        Department = "HR"
        JobTitle   = "HR Manager"
        # GroupIds   = @("your-group-object-id")
    }
)

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
# RESOLVE LICENSE SKU ID
# =============================================================================

Write-Host "Resolving license SKU for '$LicenseSkuId'..." -ForegroundColor Cyan

$Sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq $LicenseSkuId }

if (-not $Sku) {
    Write-Error "License SKU '$LicenseSkuId' not found in tenant. Check your license assignments in the M365 admin center."
    exit 1
}

Write-Host "License SKU resolved: $($Sku.SkuId)" -ForegroundColor Green

# =============================================================================
# CREATE USERS
# =============================================================================

$Results = @()

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
            DisplayName = $DisplayName
            UPN         = $UPN
            Status      = "Skipped (already exists)"
            TempPassword = "N/A"
        }
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
            DisplayName  = $DisplayName
            UPN          = $UPN
            Status       = "Failed - creation error"
            TempPassword = "N/A"
        }
        continue
    }

    # --- Assign license ---
    try {
        Set-MgUserLicense -UserId $NewUser.Id -AddLicenses @{ SkuId = $Sku.SkuId } -RemoveLicenses @()
        Write-Host "  [OK] License assigned (Business Premium)." -ForegroundColor Green
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
    }
    catch {
        Write-Warning "  MFA enforcement failed for $UPN`: $_"
    }

    $Results += [PSCustomObject]@{
        DisplayName  = $DisplayName
        UPN          = $UPN
        Status       = "Created"
        MFA          = "Enforced"
        TempPassword = $TempPassword
    }
}

# =============================================================================
# SUMMARY
# =============================================================================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "         USER PROVISIONING SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
$Results | Format-Table -AutoSize

Write-Host "`nNOTE: Temp passwords above are one-time use. Users must change on first login." -ForegroundColor Magenta

# Disconnect
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
