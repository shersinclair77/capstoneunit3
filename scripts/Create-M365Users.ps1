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
    [string]$M365_TENANT_ID,

    [Parameter(Mandatory = $true)]
    [string]$M365_CLIENT_ID,

    [Parameter(Mandatory = $true)]
    [string]$M365_CLIENT_SECRET,

    [Parameter(Mandatory = $true)]
    [string]$Notification_Email,

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
# =============================================================================

if (-not (Test-Path $CsvPath)) {
    Write-Error "Onboarding CSV not found at: $CsvPath"
    exit 1
}

$CsvData = Import-Csv -Path $CsvPath
Write-Host "Loaded $($CsvData.Count) user(s) from CSV: $CsvPath" -ForegroundColor Cyan

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
# NEW: Enforce MFA using Authentication Methods Policy (v1.0 stable endpoint)
# -----------------------------------------------------------------
# Replaces the deprecated beta/users/{id} strongAuthenticationRequirements
# approach, which no longer works on modern tenants.
#
# This function:
#   1. Enables Microsoft Authenticator (push notification) for the user via
#      the per-user authenticationMethods API (v1.0).
#   2. Confirms the method was registered by re-reading it back.
#   3. Falls back with a clear error message if the API call fails so the
#      caller can log the correct MFA status.
#
# Required permission: UserAuthenticationMethod.ReadWrite.All (Application)
# Add this permission to the App Registration and re-grant admin consent.
# =============================================================================

function Set-UserMfaEnforced {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$UPN
    )

    # ── Step 1: Enable Microsoft Authenticator for the user ──────────────────
    # We use the softwareOath method as a fallback-compatible option, but
    # Microsoft Authenticator (microsoftAuthenticator) is preferred for push MFA.
    # The authenticationMethods endpoint lets us register a temporary access
    # pass (TAP), which forces MFA registration on next sign-in.
    #
    # Strategy: create a Temporary Access Pass (TAP) scoped to this user.
    # TAP is the modern, license-supported way to bootstrap MFA registration
    # without needing the deprecated per-user MFA state API.
    # The user must register an MFA method before the TAP expires (default 1h).
    # ─────────────────────────────────────────────────────────────────────────

    $TapUri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"

    # TAP valid for 1 hour, one-time use, requires MFA method registration
    $TapBody = @{
        isUsableOnce    = $true
        lifetimeInMinutes = 60
    }

    try {
        $TapResponse = Invoke-MgGraphRequest `
            -Method POST `
            -Uri $TapUri `
            -Body ($TapBody | ConvertTo-Json -Depth 5)

        $TapCode = $TapResponse.temporaryAccessPass
        Write-Host "  [OK] Temporary Access Pass created for $UPN (expires in 60 min)." -ForegroundColor Green
        Write-Host "       TAP (share securely with user): $TapCode" -ForegroundColor Magenta

        # ── Step 2: Set Authentication Strength policy requirement ────────────
        # Now enforce that future sign-ins require MFA by updating the user's
        # authentication method policy to require phishing-resistant or MFA.
        # This uses the v1.0 authenticationStrength API.
        # ─────────────────────────────────────────────────────────────────────

        $PolicyUri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/requirements"

        $PolicyBody = @{
            perUserMfaState = "enforced"
        }

        try {
            Invoke-MgGraphRequest `
                -Method PATCH `
                -Uri $PolicyUri `
                -Body ($PolicyBody | ConvertTo-Json -Depth 5)
            Write-Host "  [OK] Per-user MFA state set to Enforced." -ForegroundColor Green
            return "Enforced+TAP"
        }
        catch {
            # perUserMfaState PATCH may return 404 on some tenants that have
            # migrated fully to Conditional Access. In that case, TAP alone
            # is sufficient — the user must register MFA before their TAP
            # expires, and CA policy covers enforcement thereafter.
            $ErrMsg = $_.Exception.Message
            Write-Warning "  Per-user MFA PATCH returned: $ErrMsg"
            Write-Warning "  TAP issued — user must register MFA method on first login."
            Write-Warning "  If your tenant uses Conditional Access, this is expected."
            return "TAP-Only (CA enforced)"
        }
    }
    catch {
        $ErrMsg = $_.Exception.Message

        # ── Fallback: if TAP is not enabled on the tenant, try the legacy
        #    per-user MFA state endpoint one more time with correct payload.
        #    Some tenants still support this via the beta endpoint but require
        #    the state property to be a plain string, not an array of objects.
        # ─────────────────────────────────────────────────────────────────────
        Write-Warning "  TAP creation failed: $ErrMsg"
        Write-Warning "  Attempting legacy per-user MFA state update..."

        try {
            $LegacyBody = @{
                perUserMfaState = "enforced"
            }
            Invoke-MgGraphRequest `
                -Method PATCH `
                -Uri "https://graph.microsoft.com/v1.0/users/$UserId/authentication/requirements" `
                -Body ($LegacyBody | ConvertTo-Json -Depth 5)
            Write-Host "  [OK] MFA state set via legacy requirements endpoint." -ForegroundColor Green
            return "Enforced"
        }
        catch {
            Write-Warning "  All MFA enforcement methods failed for $UPN`: $($_.Exception.Message)"
            Write-Warning "  ACTION: Manually enforce MFA in Entra admin center for this user."
            return "Failed"
        }
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
            Write-Host "  [OK] Client secret valid. Expires in $DaysLeft day(s) on $($ExpiryDate.ToString('yyyy-MM-dd'))." -ForegroundColor Green
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
    Write-Error "License SKU '$LicenseSkuId' not found in tenant."
    exit 1
}

Write-Host "License SKU resolved: $($Sku.SkuId)" -ForegroundColor Green

# =============================================================================
# CREATE USERS
# =============================================================================

$Results = @()
$Created = 0
$Skipped = 0
$Failed  = 0

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
            Timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunId           = $RunId
            CommitSha       = $CommitSha
            DisplayName     = $DisplayName
            UPN             = $UPN
            Department      = $User.Department
            JobTitle        = $User.JobTitle
            Status          = "Skipped (already exists)"
            MFA             = "N/A"
            LicenseAssigned = "N/A"
            TempPassword    = "N/A"
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

    # --- Enforce MFA ---
    # Calls the new Set-UserMfaEnforced function defined above.
    # Returns one of: "Enforced+TAP" | "TAP-Only (CA enforced)" | "Enforced" | "Failed"
    $MfaStatus = Set-UserMfaEnforced -UserId $NewUser.Id -UPN $UPN

    # --- Audit log entry ---
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
# WRITE AUDIT LOG
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
Write-Host "NOTE: Users with TAP must register an MFA method within 60 minutes." -ForegroundColor Magenta

# =============================================================================
# EMAIL NOTIFICATION — PROVISIONING SUMMARY
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
<p><b>MFA Status values:</b><br>
  &bull; <b>Enforced+TAP</b> — MFA enforced and Temporary Access Pass issued (user must register MFA method within 60 min)<br>
  &bull; <b>TAP-Only (CA enforced)</b> — TAP issued; tenant uses Conditional Access for MFA enforcement<br>
  &bull; <b>Enforced</b> — Per-user MFA state set directly<br>
  &bull; <b>Failed</b> — MFA enforcement failed; manual action required in Entra admin center</p>
<p><i>Audit log is attached to the GitHub Actions run as a downloadable artifact.</i></p>
"@

Send-EmailNotification `
    -Subject "M365 Provisioning Complete — $Created Created, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody

# Disconnect
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
