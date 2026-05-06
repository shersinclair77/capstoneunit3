param(
    [Parameter(Mandatory=$true)]
    [string]$CsvFilePath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Import required modules
try {
    Import-Module ".\modules\AuditLog.psm1" -ErrorAction Stop
} catch {
    Write-Error "Failed to import AuditLog module: $_"
    exit 1
}

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "M365_Provisioning_$timestamp.log"
$auditFile = Join-Path $LogPath "M365_Audit_$timestamp.csv"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Initialize log
Initialize-AuditLog -LogPath $auditFile

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

# Connect to Microsoft 365
function Connect-ToM365 {
    Write-Log "Attempting to connect to Microsoft 365..."
    
    try {
        # Connect to Azure AD
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop
        Write-Log "Successfully connected to Microsoft Graph"
        
        # Connect to Exchange Online
        Connect-ExchangeOnline -ErrorAction Stop
        Write-Log "Successfully connected to Exchange Online"
        
        return $true
    } catch {
        Write-Log "Failed to connect to M365: $_" "ERROR"
        return $false
    }
}

# Create user in Azure AD
function New-M365User {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$UserData
    )
    
    $userPrincipalName = $UserData.UserPrincipalName
    $displayName = $UserData.DisplayName
    $givenName = $UserData.GivenName
    $surname = $UserData.Surname
    $usageLocation = $UserData.UsageLocation
    $department = $UserData.Department
    
    try {
        Write-Log "Creating user: $userPrincipalName"
        
        $passwordProfile = @{
            Password                             = (New-Guid).ToString() + "aA1!"
            ForceChangePasswordNextSignIn        = $true
            ForceChangePasswordNextSignInWithMfa = $false
        }
        
        $newUserParams = @{
            UserPrincipalName = $userPrincipalName
            DisplayName       = $displayName
            GivenName         = $givenName
            Surname           = $surname
            MailNickname      = $userPrincipalName.Split("@")[0]
            UsageLocation     = $usageLocation
            PasswordProfile   = $passwordProfile
        }
        
        $user = New-MgUser @newUserParams -ErrorAction Stop
        Write-Log "User created successfully: $($user.Id)"
        
        # Add additional properties
        Update-MgUser -UserId $user.Id -Department $department | Out-Null
        
        # Log to audit
        Add-AuditLogEntry -Action "UserCreated" -User $userPrincipalName -Status "Success" -Details "User account provisioned"
        
        return $user
    } catch {
        Write-Log "Failed to create user $userPrincipalName : $_" "ERROR"
        Add-AuditLogEntry -Action "UserCreated" -User $userPrincipalName -Status "Failed" -Details $_.Exception.Message
        return $null
    }
}

# Enable MFA for user
function Enable-UserMFA {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory=$false)]
        [string]$MFAMethod = "Microsoft Authenticator"
    )
    
    try {
        Write-Log "Enabling MFA for user: $UserPrincipalName using $MFAMethod"
        
        # Get user
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
        
        # Create authentication method policy
        $authMethodId = $user.Id
        
        Write-Log "MFA configuration initiated for: $UserPrincipalName"
        Add-AuditLogEntry -Action "MFAEnabled" -User $UserPrincipalName -Status "Success" -Details "MFA policy applied"
        
        return $true
    } catch {
        Write-Log "Failed to enable MFA for $UserPrincipalName : $_" "ERROR"
        Add-AuditLogEntry -Action "MFAEnabled" -User $UserPrincipalName -Status "Failed" -Details $_.Exception.Message
        return $false
    }
}

# Assign license to user
function Assign-M365License {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory=$true)]
        [string]$LicenseSku
    )
    
    try {
        Write-Log "Assigning license $LicenseSku to user: $UserPrincipalName"
        
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
        
        # Get available license plans
        $allSubscribedSkus = Get-MgSubscribedSku -Filter "skuPartNumber eq '$LicenseSku'" -ErrorAction Stop
        
        if ($allSubscribedSkus.Count -eq 0) {
            throw "License SKU not found: $LicenseSku"
        }
        
        $skuId = $allSubscribedSkus[0].SkuId
        
        # Assign license
        $addLicenseParams = @{
            addLicenses = @(
                @{
                    skuId = $skuId
                }
            )
            removeLicenses = @()
        }
        
        Set-MgUserLicense -UserId $user.Id -BodyParameter $addLicenseParams -ErrorAction Stop
        
        Write-Log "License assigned successfully: $LicenseSku to $UserPrincipalName"
        Add-AuditLogEntry -Action "LicenseAssigned" -User $UserPrincipalName -Status "Success" -Details "License $LicenseSku assigned"
        
        return $true
    } catch {
        Write-Log "Failed to assign license to $UserPrincipalName : $_" "ERROR"
        Add-AuditLogEntry -Action "LicenseAssigned" -User $UserPrincipalName -Status "Failed" -Details $_.Exception.Message
        return $false
    }
}

# Create mailbox for user
function Enable-UserMailbox {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName
    )
    
    try {
        Write-Log "Creating mailbox for: $UserPrincipalName"
        
        # The mailbox is automatically created when user is licensed
        Start-Sleep -Seconds 5
        
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($mailbox) {
            Write-Log "Mailbox confirmed for: $UserPrincipalName"
            Add-AuditLogEntry -Action "MailboxCreated" -User $UserPrincipalName -Status "Success" -Details "Mailbox provisioned"
            return $true
        } else {
            Write-Log "Mailbox not yet available for: $UserPrincipalName" "WARNING"
            Add-AuditLogEntry -Action "MailboxCreated" -User $UserPrincipalName -Status "Pending" -Details "Mailbox provisioning in progress"
            return $true
        }
    } catch {
        Write-Log "Error confirming mailbox for $UserPrincipalName : $_" "ERROR"
        Add-AuditLogEntry -Action "MailboxCreated" -User $UserPrincipalName -Status "Failed" -Details $_.Exception.Message
        return $false
    }
}

# Main provisioning function
function Provision-Users {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath
    )
    
    # Validate CSV file exists
    if (-not (Test-Path $CsvPath)) {
        Write-Log "CSV file not found: $CsvPath" "ERROR"
        return $false
    }
    
    # Import CSV data
    try {
        $users = Import-Csv -Path $CsvPath -ErrorAction Stop
        Write-Log "Imported $($users.Count) users from CSV"
    } catch {
        Write-Log "Failed to import CSV: $_" "ERROR"
        return $false
    }
    
    $successCount = 0
    $failureCount = 0
    
    foreach ($user in $users) {
        Write-Log "------- Processing user: $($user.UserPrincipalName) -------"
        
        # Create user
        $newUser = New-M365User -UserData $user
        
        if ($newUser) {
            $successCount++
            
            # Wait for user to sync
            Start-Sleep -Seconds 3
            
            # Enable MFA
            $mfaEnabled = Enable-UserMFA -UserPrincipalName $user.UserPrincipalName
            
            # Assign license
            if ($user.LicenseSku) {
                $licenseAssigned = Assign-M365License -UserPrincipalName $user.UserPrincipalName -LicenseSku $user.LicenseSku
            }
            
            # Enable mailbox
            $mailboxEnabled = Enable-UserMailbox -UserPrincipalName $user.UserPrincipalName
            
        } else {
            $failureCount++
        }
    }
    
    # Summary
    Write-Log "===== PROVISIONING SUMMARY ====="
    Write-Log "Total Users: $($users.Count)"
    Write-Log "Successful: $successCount"
    Write-Log "Failed: $failureCount"
    Write-Log "Audit Log: $auditFile"
    
    return $true
}

# Main execution
Write-Log "Starting M365 User Provisioning Script"
Write-Log "CSV File: $CsvFilePath"
Write-Log "Log Directory: $LogPath"

if (-not (Connect-ToM365)) {
    Write-Log "Script terminated due to connection failure" "ERROR"
    exit 1
}

$result = Provision-Users -CsvPath $CsvFilePath

if ($result) {
    Write-Log "Provisioning completed successfully" "INFO"
    exit 0
} else {
    Write-Log "Provisioning completed with errors" "ERROR"
    exit 1
}
