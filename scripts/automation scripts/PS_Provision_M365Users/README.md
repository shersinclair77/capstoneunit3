# M365 User Provisioning Automation Script

Automated PowerShell solution for provisioning Microsoft 365 users with MFA enablement, license assignment, and comprehensive audit logging.

## Features

- **User Creation**: Automated creation of Azure AD users with configurable properties
- **MFA Enablement**: Automatic Multi-Factor Authentication configuration
- **License Assignment**: Assign Microsoft 365 licenses to users
- **Mailbox Provisioning**: Enable Exchange Online mailboxes
- **Audit Logging**: Comprehensive audit trail of all provisioning activities
- **Error Handling**: Robust error handling and reporting
- **Batch Processing**: Process multiple users from CSV file

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK
- Exchange Online PowerShell Module
- Administrator access to M365 tenant
- CSV file with user data

## Installation

### 1. Install Required Modules

```powershell
Install-Module Microsoft.Graph -Force
Install-Module ExchangeOnlineManagement -Force
```

### 2. Configure Tenant Credentials

Update `config/provisioning-config.json` with your M365 tenant information:

```json
{
  "m365": {
    "tenantId": "YOUR_TENANT_ID",
    "clientId": "YOUR_CLIENT_ID",
    "clientSecret": "YOUR_CLIENT_SECRET"
  }
}
```

### 3. Prepare User Data

Create a CSV file with the following columns:

| Column | Required | Example |
|--------|----------|---------|
| UserPrincipalName | Yes | john.smith@company.com |
| DisplayName | Yes | John Smith |
| GivenName | Yes | John |
| Surname | Yes | Smith |
| Department | No | Engineering |
| UsageLocation | Yes | US |
| LicenseSku | Yes | ENTERPRISEPACK |

Use the template at `config/users-template.csv` as a starting point.

## Usage

### Basic Usage

```powershell
.\Provision-M365Users.ps1 -CsvFilePath ".\config\users.csv"
```

### With Custom Log Path

```powershell
.\Provision-M365Users.ps1 -CsvFilePath ".\config\users.csv" -LogPath "D:\Logs"
```

### WhatIf Mode (Preview)

```powershell
.\Provision-M365Users.ps1 -CsvFilePath ".\config\users.csv" -WhatIf
```

## Script Structure

```
M365-User-Provisioning/
├── Provision-M365Users.ps1      # Main provisioning script
├── modules/
│   └── AuditLog.psm1             # Audit logging module
├── config/
│   ├── users-template.csv        # User data template
│   └── provisioning-config.json  # Configuration file
├── logs/                         # Audit logs (auto-created)
└── README.md                     # This file
```

## Output Files

### Audit Log (CSV)

Located in the `logs` directory with format: `M365_Audit_YYYYMMDD_HHMMSS.csv`

Contains:
- Timestamp
- Action performed
- User affected
- Status (Success/Failed/Pending)
- Details
- Performed by
- IP Address

### Provisioning Log (TXT)

Located in the `logs` directory with format: `M365_Provisioning_YYYYMMDD_HHMMSS.log`

Contains detailed step-by-step execution logs.

## Audit Log Module Functions

### Initialize-AuditLog
Initialize the audit log file for a provisioning session.

```powershell
Initialize-AuditLog -LogPath "C:\logs\audit.csv"
```

### Add-AuditLogEntry
Add an entry to the audit log.

```powershell
Add-AuditLogEntry -Action "UserCreated" -User "john@company.com" -Status "Success" -Details "User account created"
```

### Export-AuditLog
Export audit log to JSON or Excel format.

```powershell
Export-AuditLog -Format JSON -OutputPath "C:\reports\audit.json"
```

### Get-AuditLogStatistics
Get statistics from the audit log.

```powershell
Get-AuditLogStatistics -Action "UserCreated"
```

## Common Actions in Audit Log

| Action | Description |
|--------|-------------|
| UserCreated | User account created in Azure AD |
| MFAEnabled | MFA policy applied to user |
| LicenseAssigned | Microsoft 365 license assigned |
| MailboxCreated | Exchange Online mailbox provisioned |

## Error Handling

The script includes comprehensive error handling:
- Connection failures are logged and script terminates
- Individual user creation failures don't stop the batch process
- All errors are recorded in both the provisioning log and audit log
- Summary statistics provided at completion

## Security Considerations

- Temporary passwords are generated and users forced to change on first login
- All administrative actions are logged with timestamp and performer
- Sensitive information (passwords, tokens) not stored in logs
- Configure with least-privilege service account
- Regularly review audit logs for suspicious activity

## Troubleshooting

### Connection Issues

Ensure you have proper permissions:
```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"
```

### License Assignment Failures

Verify license SKU is available in your tenant:
```powershell
Get-MgSubscribedSku
```

### Mailbox Not Provisioning

Mailbox provisioning can take time. The script includes a 5-second delay. If issues persist, verify user is licensed and try again later.

## Support

For issues or questions, refer to the audit logs for detailed error messages.

## License

Internal Use Only

## Version History

- **v1.0** - Initial release with user provisioning, MFA, licensing, and audit logging
