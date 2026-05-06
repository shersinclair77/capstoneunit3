# Audit Logging Module for M365 User Provisioning

$auditLogPath = $null

<#
.SYNOPSIS
Initialize the audit log file

.PARAMETER LogPath
Path to the audit log CSV file
#>
function Initialize-AuditLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath
    )
    
    $script:auditLogPath = $LogPath
    
    # Create CSV header
    $header = "Timestamp,Action,User,Status,Details,PerformedBy,IPAddress"
    Add-Content -Path $LogPath -Value $header -Encoding UTF8
}

<#
.SYNOPSIS
Add an entry to the audit log

.PARAMETER Action
The action performed (UserCreated, MFAEnabled, LicenseAssigned, etc.)

.PARAMETER User
The user principal name or object affected

.PARAMETER Status
Status of the action (Success, Failed, Pending)

.PARAMETER Details
Additional details about the action
#>
function Add-AuditLogEntry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Action,
        
        [Parameter(Mandatory=$true)]
        [string]$User,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Success", "Failed", "Pending")]
        [string]$Status,
        
        [Parameter(Mandatory=$false)]
        [string]$Details = "",
        
        [Parameter(Mandatory=$false)]
        [string]$PerformedBy = $env:USERNAME,
        
        [Parameter(Mandatory=$false)]
        [string]$IPAddress = "127.0.0.1"
    )
    
    if (-not $script:auditLogPath) {
        Write-Warning "Audit log not initialized. Call Initialize-AuditLog first."
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Escape special characters in details
    $Details = $Details -replace '"', '""'
    
    # Create CSV entry
    $entry = @"
"$timestamp","$Action","$User","$Status","$Details","$PerformedBy","$IPAddress"
"@
    
    Add-Content -Path $script:auditLogPath -Value $entry -Encoding UTF8
}

<#
.SYNOPSIS
Export audit log to alternate format

.PARAMETER Format
Export format (JSON, Excel)

.PARAMETER OutputPath
Path for the export file
#>
function Export-AuditLog {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("JSON", "Excel")]
        [string]$Format,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    if (-not (Test-Path $script:auditLogPath)) {
        Write-Error "Audit log file not found: $script:auditLogPath"
        return
    }
    
    $auditData = Import-Csv -Path $script:auditLogPath
    
    switch ($Format) {
        "JSON" {
            $auditData | ConvertTo-Json | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Audit log exported to JSON: $OutputPath"
        }
        "Excel" {
            # Requires ImportExcel module
            try {
                $auditData | Export-Excel -Path $OutputPath -WorksheetName "Audit Log" -AutoSize
                Write-Host "Audit log exported to Excel: $OutputPath"
            } catch {
                Write-Error "Failed to export to Excel. Install ImportExcel module: Install-Module ImportExcel"
            }
        }
    }
}

<#
.SYNOPSIS
Get audit log statistics

.PARAMETER Action
Filter by specific action
#>
function Get-AuditLogStatistics {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Action
    )
    
    if (-not (Test-Path $script:auditLogPath)) {
        Write-Error "Audit log file not found: $script:auditLogPath"
        return
    }
    
    $auditData = Import-Csv -Path $script:auditLogPath
    
    if ($Action) {
        $auditData = $auditData | Where-Object { $_.Action -eq $Action }
    }
    
    $stats = $auditData | Group-Object -Property Status | Select-Object Name, Count
    
    return $stats
}

# Export module functions
Export-ModuleMember -Function @(
    'Initialize-AuditLog',
    'Add-AuditLogEntry',
    'Export-AuditLog',
    'Get-AuditLogStatistics'
)
