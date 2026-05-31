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
#   - Policy.ReadWrite.AuthenticationMethod    (perUserMfaState enforcement)
#   - UserAuthenticationMethod.ReadWrite.All   (TAP creation + method removal)
#   - Mail.Send                                (email notifications)
#   - Application.Read.All                     (secret expiry check)
#   - Policy.Read.All                           (Security Defaults pre-flight check)
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
    [string]$CsvPath = "./onboarding/users-to-onboard.csv"
)
 
# =============================================================================
# CONFIGURATION
# =============================================================================
 
$Domain           = "renah.onmicrosoft.com"
$LicenseSkuId     = "SPB"
$UsageLocation    = "BB"
$PasswordPolicies = "DisablePasswordExpiration"
$SenderEmail      = "admin@$Domain"
$SecretExpiryWarningDays = 30
 
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
        Write-Warning "  Email notification failed: $_"
    }
}
 
# =============================================================================
# Set-UserMfaEnforced  — FIXED
# -----------------------------------------------------------------------------
# Previous version had five bugs:
#   1. TAP was attempted first; perUserMfaState was nested inside TAP success,
#      so if TAP failed for any reason MFA enforcement was never attempted.
#   2. No GET verification after PATCH — some tenants return HTTP 200 but
#      do not actually apply the change.
#   3. -ContentType was not explicitly set, causing 400/415 on some tenants.
#   4. UserAuthenticationMethod.ReadWrite.All was missing from the permission
#      list even though TAP requires it.
#   5. The "TAP-Only (CA enforced)" fallback silently logged success in the
#      audit log while MFA was not actually enforced.
#
# Fixed approach — three independent sequential steps:
#   Step 1  PATCH /v1.0/.../authentication/requirements  perUserMfaState=enforced
#           then GET to verify the value actually changed.
#   Step 2  If Step 1 fails, PATCH /beta/users/{id} with
#           strongAuthenticationRequirements (legacy fallback, still works on
#           many tenants even though Microsoft deprecated it).
#   Step 3  POST a Temporary Access Pass (one-use, 60 min) so the user has
#           a secure first-login credential and must register an MFA method
#           before the TAP expires.
#
# Steps 1/2 and Step 3 are independent — TAP creation failure does NOT
# prevent MFA enforcement, and MFA enforcement failure does NOT prevent
# TAP issuance. The return value accurately reflects what actually succeeded.
#
# Required permissions (Application):
#   Policy.ReadWrite.AuthenticationMethod   — Steps 1 & 2
#   UserAuthenticationMethod.ReadWrite.All  — Step 3 (TAP)
# =============================================================================
 
function Set-UserMfaEnforced {
    param (
        [Parameter(Mandatory = $true)] [string]$UserId,
        [Parameter(Mandatory = $true)] [string]$UPN
    )
 
    # ─────────────────────────────────────────────────────────────────────────
    # ROOT CAUSE OF "Enabled but not Enforced":
    #
    # The Entra portal "Per-user MFA" page reads from:
    #   beta/users/{id}.strongAuthenticationRequirements[].state
    #   Valid values: Disabled | Enabled | Enforced  (PascalCase)
    #
    # The v1.0 authentication/requirements perUserMfaState property controls
    # the NEW per-user MFA system and on many tenants maps to "Enabled" in the
    # legacy portal — NOT "Enforced" — because they are separate mechanisms.
    #
    # Fix: beta strongAuthenticationRequirements state="Enforced" is now the
    # PRIMARY method. v1.0 perUserMfaState is kept as a secondary supplement.
    # A 10-second delay after account creation prevents the MFA write being
    # overwritten by the account's own provisioning pipeline completing.
    #
    # Requires (Application permissions):
    #   Policy.ReadWrite.AuthenticationMethod  — Steps 1 & 2
    #   UserAuthenticationMethod.ReadWrite.All — Step 3 (TAP)
    # ─────────────────────────────────────────────────────────────────────────
 
    $BetaUserUri     = "https://graph.microsoft.com/beta/users/$UserId"
    $RequirementsUri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/requirements"
    $TapUri          = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"
 
    $MfaEnforced = $false
    $MfaMethod   = $null
    $TapCode     = $null
 
    # ── Propagation delay ─────────────────────────────────────────────────────
    # New accounts need ~10 s to fully replicate across Entra ID backend nodes.
    # Without this delay, MFA writes can be overwritten by the account's own
    # provisioning completing after our PATCH. This is the most common cause
    # of MFA appearing as Enabled immediately after account creation.
    Write-Host "  [MFA] Waiting 10 s for account to propagate before enforcing MFA..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 10
 
    # ── STEP 1 (PRIMARY): beta strongAuthenticationRequirements state=Enforced ─
    # This is the ONLY property the Entra portal "Per-user MFA" page reads.
    # state="Enforced" means the user cannot skip MFA registration on first login.
    # state="Enabled"  means the user CAN skip — this is what showed previously.
    # Requires: Policy.ReadWrite.AuthenticationMethod (Application)
    Write-Host "  [MFA Step 1] Setting strongAuthenticationRequirements = Enforced (beta)..." -ForegroundColor Cyan
    try {
        $BetaBody = @{
            strongAuthenticationRequirements = @(
                @{
                    state                          = "Enforced"
                    rememberDevicesNotIssuedBefore = (Get-Date).ToUniversalTime().ToString("o")
                }
            )
        }
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri $BetaUserUri `
            -ContentType "application/json" `
            -Body ($BetaBody | ConvertTo-Json -Depth 5)
 
        # Verify: GET and confirm state is exactly "Enforced" (not "Enabled")
        Start-Sleep -Seconds 3
        $BetaGet   = Invoke-MgGraphRequest -Method GET `
                         -Uri "$BetaUserUri`?`$select=strongAuthenticationRequirements"
        $BetaState = ($BetaGet.strongAuthenticationRequirements |
                      Select-Object -First 1).state
 
        if ($BetaState -eq "Enforced") {
            Write-Host "  [OK] strongAuthenticationRequirements.state verified = Enforced." -ForegroundColor Green
            $MfaEnforced = $true
            $MfaMethod   = "beta-strongAuth-Enforced"
        }
        elseif ($BetaState -eq "Enabled") {
            # PATCH accepted but wrote Enabled instead of Enforced.
            # Retry once with an explicit array replace.
            Write-Warning "  State came back as Enabled — retrying with explicit Enforced..."
            Start-Sleep -Seconds 5
            Invoke-MgGraphRequest `
                -Method PATCH `
                -Uri $BetaUserUri `
                -ContentType "application/json" `
                -Body ($BetaBody | ConvertTo-Json -Depth 5)
            Start-Sleep -Seconds 3
            $Retry = Invoke-MgGraphRequest -Method GET `
                         -Uri "$BetaUserUri`?`$select=strongAuthenticationRequirements"
            $RetryState = ($Retry.strongAuthenticationRequirements | Select-Object -First 1).state
            if ($RetryState -eq "Enforced") {
                Write-Host "  [OK] Retry succeeded — state verified = Enforced." -ForegroundColor Green
                $MfaEnforced = $true
                $MfaMethod   = "beta-strongAuth-Enforced-retry"
            }
            else {
                Write-Warning "  Retry state = $RetryState. Tenant may enforce via Conditional Access."
                Write-Warning "  ACTION: Verify MFA state for $UPN in Entra admin center."
                # Still mark as attempted so TAP is issued
            }
        }
        else {
            Write-Warning "  Unexpected state returned: $BetaState"
            Write-Warning "  ACTION: Manually check MFA state for $UPN in Entra admin center."
        }
    }
    catch {
        Write-Warning "  Step 1 failed: $($_.Exception.Message)"
    }
 
    # ── STEP 2 (SUPPLEMENT): v1.0 perUserMfaState = enforced ─────────────────
    # Sets the new per-user MFA flag in addition to Step 1.
    # This ensures enforcement via both the legacy and new MFA systems.
    # Does NOT replace Step 1 — the portal still reads strongAuthenticationRequirements.
    # Requires: Policy.ReadWrite.AuthenticationMethod (Application)
    Write-Host "  [MFA Step 2] Setting perUserMfaState = enforced (v1.0 supplement)..." -ForegroundColor Cyan
    try {
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri $RequirementsUri `
            -ContentType "application/json" `
            -Body (@{ perUserMfaState = "enforced" } | ConvertTo-Json -Depth 3)
 
        $V1Get   = Invoke-MgGraphRequest -Method GET -Uri $RequirementsUri
        $V1State = $V1Get.perUserMfaState
        if ($V1State -eq "enforced") {
            Write-Host "  [OK] perUserMfaState verified = enforced (v1.0)." -ForegroundColor Green
            if (-not $MfaEnforced) {
                $MfaEnforced = $true
                $MfaMethod   = "v1.0-requirements-only"
            }
        }
        else {
            Write-Warning "  v1.0 perUserMfaState = $V1State (expected enforced)."
        }
    }
    catch {
        Write-Warning "  Step 2 (v1.0 supplement) failed: $($_.Exception.Message)"
    }
 
    # ── STEP 3: Temporary Access Pass ────────────────────────────────────────
    # Independent of Steps 1 & 2. One-use, 60-minute credential for first login.
    # User must register an MFA method (Authenticator app) before TAP expires.
    # Requires: UserAuthenticationMethod.ReadWrite.All (Application)
    Write-Host "  [MFA Step 3] Issuing Temporary Access Pass (60 min, one-use)..." -ForegroundColor Cyan
    try {
        $TapResponse = Invoke-MgGraphRequest `
            -Method POST `
            -Uri $TapUri `
            -ContentType "application/json" `
            -Body (@{ isUsableOnce = $true; lifetimeInMinutes = 60 } | ConvertTo-Json -Depth 3)
 
        $TapCode = $TapResponse.temporaryAccessPass
        Write-Host "  [OK] TAP issued for $UPN (expires 60 min)." -ForegroundColor Green
        Write-Host "       TAP (share securely): $TapCode" -ForegroundColor Magenta
        Write-Host "       User must register an authenticator app within 60 minutes." -ForegroundColor Magenta
    }
    catch {
        Write-Warning "  TAP creation failed: $($_.Exception.Message)"
        Write-Warning "  Ensure UserAuthenticationMethod.ReadWrite.All (Application) is granted."
    }
 
    # ── Return status ─────────────────────────────────────────────────────────
    if ($MfaEnforced -and $TapCode) {
        return "Enforced+TAP ($MfaMethod)"
    }
    elseif ($MfaEnforced) {
        return "Enforced ($MfaMethod) — TAP failed"
    }
    elseif ($TapCode) {
        return "TAP issued — MFA enforcement FAILED (manual action required)"
    }
    else {
        return "FAILED — MFA not enforced and TAP not issued (check permissions)"
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
# PRE-FLIGHT: SECURITY DEFAULTS CHECK
# -----------------------------------------------------------------------------
# Security Defaults and per-user MFA management are MUTUALLY EXCLUSIVE.
# When Security Defaults is ON, all PATCH calls to strongAuthenticationRequirements
# return HTTP 200 but are silently discarded — the state stays "disabled".
# This is the most common reason MFA appears as disabled after provisioning.
# =============================================================================
 
Write-Host "`nRunning pre-flight checks..." -ForegroundColor Cyan
 
try {
    $SecDefaults = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
 
    if ($SecDefaults.isEnabled -eq $true) {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  BLOCKING ERROR: Security Defaults is ENABLED on this tenant.   ║" -ForegroundColor Red
        Write-Host "  ║                                                                  ║" -ForegroundColor Red
        Write-Host "  ║  Per-user MFA cannot be enforced via the API while Security     ║" -ForegroundColor Red
        Write-Host "  ║  Defaults is active. All MFA PATCH calls return HTTP 200 but    ║" -ForegroundColor Red
        Write-Host "  ║  the state is silently reset to 'disabled' by the platform.     ║" -ForegroundColor Red
        Write-Host "  ║                                                                  ║" -ForegroundColor Red
        Write-Host "  ║  TO FIX — disable Security Defaults before re-running:          ║" -ForegroundColor Red
        Write-Host "  ║  Entra admin center > Properties >                              ║" -ForegroundColor Red
        Write-Host "  ║  Manage security defaults > Set to Disabled > Save              ║" -ForegroundColor Red
        Write-Host "  ║                                                                  ║" -ForegroundColor Red
        Write-Host "  ║  NOTE: After disabling, create a Conditional Access policy      ║" -ForegroundColor Red
        Write-Host "  ║  to require MFA for all users so tenant security is maintained. ║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
 
        # Send alert email before exiting
        $SecDefaultsAlertBody = @"
<h2 style='color:#C0392B;font-family:Calibri,sans-serif'>⛔ Provisioning Blocked: Security Defaults Enabled</h2>
<p style='font-family:Calibri,sans-serif'>
The provisioning pipeline attempted to run but was blocked because
<b>Security Defaults is enabled</b> on the <b>$Domain</b> tenant.
</p>
<p style='font-family:Calibri,sans-serif'>
Security Defaults and per-user MFA management are mutually exclusive.
While Security Defaults is active, all MFA enforcement API calls return HTTP 200
but are silently discarded — the per-user MFA state remains <b>disabled</b>.
</p>
<h3 style='font-family:Calibri,sans-serif'>How to fix</h3>
<ol style='font-family:Calibri,sans-serif'>
  <li>Sign in to <a href='https://entra.microsoft.com'>Entra admin center</a></li>
  <li>Go to <b>Identity &gt; Overview &gt; Properties</b></li>
  <li>Click <b>Manage security defaults</b></li>
  <li>Set Security defaults to <b>Disabled</b> and save</li>
  <li>Create a <b>Conditional Access policy</b> requiring MFA for all users</li>
  <li>Re-run the provisioning pipeline</li>
</ol>
<p style='font-family:Calibri,sans-serif;color:#555'>
  <b>Run ID:</b> $RunId &nbsp; <b>Commit SHA:</b> $CommitSha &nbsp; <b>Timestamp:</b> $RunTimestamp
</p>
"@
        Send-EmailNotification `
            -Subject "BLOCKED: M365 Provisioning Failed — Security Defaults Enabled ($RunTimestamp)" `
            -Body $SecDefaultsAlertBody
 
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    else {
        Write-Host "  [OK] Security Defaults is DISABLED — per-user MFA management is available." -ForegroundColor Green
    }
}
catch {
    # Policy.Read.All might not be granted — warn but continue
    Write-Warning "  Could not check Security Defaults status: $($_.Exception.Message)"
    Write-Warning "  Add Policy.Read.All (Application) to the App Registration to enable this check."
    Write-Warning "  Continuing — if MFA states remain disabled after this run, Security Defaults"
    Write-Warning "  is likely enabled. Disable it in Entra admin center and re-run."
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
<p>The client secret for the M365 provisioning app registration is expiring soon.</p>
<table border='1' cellpadding='5'>
  <tr><td><b>App Client ID</b></td><td>$ClientId</td></tr>
  <tr><td><b>Secret Expiry Date</b></td><td>$($ExpiryDate.ToString('yyyy-MM-dd'))</td></tr>
  <tr><td><b>Days Remaining</b></td><td>$DaysLeft</td></tr>
</table>
<p>Please rotate the secret in Azure Entra ID and update the GitHub repository secret before expiry.</p>
"@
            Send-EmailNotification `
                -Subject "ACTION REQUIRED: M365 Provisioning App Secret Expires in $DaysLeft Day(s)" `
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
# RESOLVE LICENSE SKU
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
 
    # --- Duplicate check ---
    $Existing = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue
 
    if ($Existing) {
        Write-Warning "User $UPN already exists. Skipping."
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
 
    # --- Create account ---
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
            Status          = "Failed — creation error"
            MFA             = "N/A"
            LicenseAssigned = "N/A"
            TempPassword    = "N/A"
        }
        $Failed++
        continue
    }
 
    # --- License ---
    $LicenseStatus = "Failed"
    try {
        Set-MgUserLicense -UserId $NewUser.Id -AddLicenses @{ SkuId = $Sku.SkuId } -RemoveLicenses @()
        Write-Host "  [OK] License assigned (Business Premium)." -ForegroundColor Green
        $LicenseStatus = "Business Premium"
    }
    catch {
        Write-Warning "  License assignment failed: $_"
    }
 
    # --- Groups ---
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
 
    # --- MFA (fixed function — three independent steps with verification) ---
    $MfaStatus = Set-UserMfaEnforced -UserId $NewUser.Id -UPN $UPN
 
    # --- Audit entry ---
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
 
Write-Host "`nNOTE: Users with TAP must register an MFA method within 60 minutes." -ForegroundColor Magenta
Write-Host "NOTE: Any MFA status containing 'manual action required' needs follow-up in Entra." -ForegroundColor Red
 
# =============================================================================
# EMAIL SUMMARY
# =============================================================================
 
Write-Host "`nSending provisioning summary email to $NotificationEmail..." -ForegroundColor Cyan
 
$TableRows = $Results | ForEach-Object {
    $mfaColor = if ($_.MFA -like "Enforced*") { "#e6f4ea" }
                elseif ($_.MFA -like "*FAILED*" -or $_.MFA -like "*manual action*") { "#fce8e6" }
                else { "#fff8e1" }
    "<tr style='background:$mfaColor'><td>$($_.DisplayName)</td><td>$($_.UPN)</td><td>$($_.Status)</td><td>$($_.MFA)</td><td>$($_.LicenseAssigned)</td></tr>"
}
 
$SummaryBody = @"
<h2 style='color:#1A3C5E;font-family:Calibri,sans-serif'>M365 User Provisioning Summary</h2>
<p style='font-family:Calibri,sans-serif'>
  <b>Run ID:</b> $RunId<br>
  <b>Commit SHA:</b> $CommitSha<br>
  <b>Timestamp:</b> $RunTimestamp
</p>
<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-family:Calibri,sans-serif;font-size:13px'>
  <tr style='background:#1A3C5E;color:white'>
    <th>Display Name</th><th>UPN</th><th>Status</th><th>MFA</th><th>License</th>
  </tr>
  $($TableRows -join "`n")
</table>
<br>
<p style='font-family:Calibri,sans-serif'>
  <b>Created:</b> $Created &nbsp; <b>Skipped:</b> $Skipped &nbsp; <b>Failed:</b> $Failed
</p>
<p style='font-family:Calibri,sans-serif'><b>MFA status key:</b><br>
  <span style='background:#e6f4ea;padding:2px 6px'>Enforced+TAP</span> — MFA enforced and verified; TAP issued for first login (60 min)<br>
  <span style='background:#fff8e1;padding:2px 6px'>TAP issued — MFA enforcement FAILED</span> — TAP created but MFA NOT enforced; manual action needed<br>
  <span style='background:#fce8e6;padding:2px 6px'>FAILED</span> — Neither MFA nor TAP succeeded; check App Registration permissions
</p>
<p style='font-family:Calibri,sans-serif;color:#555'>
  <i>Audit log (CSV) is saved as a downloadable artifact in the GitHub Actions run linked to commit $CommitSha.</i>
</p>
"@
 
Send-EmailNotification `
    -Subject "M365 Provisioning Complete — $Created Created, $Skipped Skipped, $Failed Failed ($RunTimestamp)" `
    -Body $SummaryBody
 
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
 
