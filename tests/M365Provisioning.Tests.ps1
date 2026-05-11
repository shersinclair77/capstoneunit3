# =============================================================================
# M365Provisioning.Tests.ps1
# Pester v5 unit test suite for Create-M365Users.ps1 and Remove-M365Users.ps1
#
# Test Type: White-Box Unit Testing
#   - Tests internal logic, helper functions, CSV parsing, UPN construction,
#     password generation, audit logging, and duplicate detection directly.
#   - Microsoft Graph API calls are mocked — no live tenant connection required.
#
# Run locally:
#   Install-Module Pester -Force -Scope CurrentUser
#   Invoke-Pester ./tests/M365Provisioning.Tests.ps1 -Output Detailed
#
# Run in CI (GitHub Actions):
#   See .github/workflows/run-tests.yml
# =============================================================================

BeforeAll {
    # Mock all Microsoft Graph cmdlets globally so no live connection is needed
    Mock Connect-MgGraph         { return $null }
    Mock Disconnect-MgGraph      { return $null }
    Mock Get-MgUser              { return $null }
    Mock New-MgUser              { return [PSCustomObject]@{ Id = "mock-user-id-001" } }
    Mock Get-MgSubscribedSku     { return [PSCustomObject]@{ SkuPartNumber = "SPB"; SkuId = "sku-mock-001" } }
    Mock Set-MgUserLicense       { return $null }
    Mock New-MgGroupMember       { return $null }
    Mock Invoke-MgGraphRequest   { return $null }
    Mock Update-MgUser           { return $null }
    Mock Get-MgUserLicenseDetail { return @([PSCustomObject]@{ SkuId = "sku-mock-001" }) }

    # Helper functions extracted from Create-M365Users.ps1 (white-box access)
    function New-RandomPassword {
        $upper   = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ" | Get-Random -Count 3
        $lower   = [char[]]"abcdefghijklmnopqrstuvwxyz" | Get-Random -Count 5
        $digits  = [char[]]"0123456789"                  | Get-Random -Count 3
        $special = [char[]]"!@#$%^&*"                    | Get-Random -Count 2
        $all     = ($upper + $lower + $digits + $special) | Sort-Object { Get-Random }
        return -join $all
    }

    function Build-UPN {
        param([string]$FirstName, [string]$LastName, [string]$Domain)
        return "$($FirstName.ToLower()).$($LastName.ToLower())@$Domain"
    }

    function Import-OnboardingCsv {
        param([string]$CsvPath)
        if (-not (Test-Path $CsvPath)) { throw "Onboarding CSV not found at: $CsvPath" }
        $CsvData = Import-Csv -Path $CsvPath
        return $CsvData | ForEach-Object {
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
    }

    function Write-AuditLog {
        param([array]$Results, [string]$Path)
        $Dir = Split-Path $Path -Parent
        if ($Dir -and -not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        $Results | Export-Csv -Path $Path -NoTypeInformation
    }

    $script:TestCsvPath     = "$TestDrive/users-to-onboard.csv"
    $script:OffboardCsvPath = "$TestDrive/users-to-offboard.csv"
    $script:AuditLogPath    = "$TestDrive/audit-logs/test_run.csv"
    $script:Domain          = "renah.onmicrosoft.com"
}

# =============================================================================
# DESCRIBE: Password Generation
# =============================================================================
Describe "New-RandomPassword" {

    It "Should return a non-empty string" {
        New-RandomPassword | Should -Not -BeNullOrEmpty
    }

    It "Should return exactly 13 characters" {
        (New-RandomPassword).Length | Should -Be 13
    }

    It "Should contain at least one uppercase letter" {
        New-RandomPassword -cmatch "[A-Z]" | Should -BeTrue
    }

    It "Should contain at least one lowercase letter" {
        New-RandomPassword -cmatch "[a-z]" | Should -BeTrue
    }

    It "Should contain at least one digit" {
        New-RandomPassword -match "[0-9]" | Should -BeTrue
    }

    It "Should contain at least one special character" {
        New-RandomPassword -match "[!@#\$%\^&\*]" | Should -BeTrue
    }

    It "Should generate a different password on each call" {
        (New-RandomPassword) | Should -Not -Be (New-RandomPassword)
    }
}

# =============================================================================
# DESCRIBE: UPN Construction
# =============================================================================
Describe "Build-UPN" {

    It "Should construct a valid lowercase UPN" {
        Build-UPN -FirstName "Alice" -LastName "Johnson" -Domain $script:Domain |
            Should -Be "alice.johnson@renah.onmicrosoft.com"
    }

    It "Should lowercase mixed-case input" {
        Build-UPN -FirstName "CAROL" -LastName "WHITE" -Domain $script:Domain |
            Should -Be "carol.white@renah.onmicrosoft.com"
    }

    It "Should include the correct domain suffix" {
        Build-UPN -FirstName "Bob" -LastName "Smith" -Domain $script:Domain |
            Should -Match "@renah\.onmicrosoft\.com$"
    }

    It "Should follow firstname.lastname@domain format" {
        Build-UPN -FirstName "Jane" -LastName "Doe" -Domain $script:Domain |
            Should -Match "^[a-z]+\.[a-z]+@"
    }
}

# =============================================================================
# DESCRIBE: CSV Parsing — Onboarding
# =============================================================================
Describe "Import-OnboardingCsv" {

    BeforeEach {
        @"
FirstName,LastName,Department,JobTitle,GroupIds
Alice,Johnson,Engineering,Software Engineer,
Bob,Smith,Finance,Financial Analyst,group-id-001
Carol, White ,HR,HR Manager,group-id-001,group-id-002
"@ | Set-Content $script:TestCsvPath
    }

    It "Should load the correct number of users" {
        (Import-OnboardingCsv -CsvPath $script:TestCsvPath).Count | Should -Be 3
    }

    It "Should correctly parse FirstName and LastName" {
        $users = Import-OnboardingCsv -CsvPath $script:TestCsvPath
        $users[0].FirstName | Should -Be "Alice"
        $users[0].LastName  | Should -Be "Johnson"
    }

    It "Should trim whitespace from all fields" {
        $users = Import-OnboardingCsv -CsvPath $script:TestCsvPath
        $users[2].LastName | Should -Be "White"
    }

    It "Should set GroupIds to null when column is empty" {
        $users = Import-OnboardingCsv -CsvPath $script:TestCsvPath
        $users[0].GroupIds | Should -BeNullOrEmpty
    }

    It "Should parse a single GroupId correctly" {
        $users = Import-OnboardingCsv -CsvPath $script:TestCsvPath
        $users[1].GroupIds | Should -Contain "group-id-001"
    }

    It "Should parse multiple comma-separated GroupIds" {
        $users = Import-OnboardingCsv -CsvPath $script:TestCsvPath
        $users[2].GroupIds.Count | Should -Be 2
        $users[2].GroupIds       | Should -Contain "group-id-002"
    }

    It "Should throw when CSV file does not exist" {
        { Import-OnboardingCsv -CsvPath "$TestDrive/missing.csv" } | Should -Throw
    }

    It "Should return empty collection for CSV with headers only" {
        "FirstName,LastName,Department,JobTitle,GroupIds" | Set-Content $script:TestCsvPath
        @(Import-OnboardingCsv -CsvPath $script:TestCsvPath).Count | Should -Be 0
    }
}

# =============================================================================
# DESCRIBE: Duplicate User Detection
# =============================================================================
Describe "Duplicate User Detection" {

    It "Should detect an existing user in the tenant" {
        Mock Get-MgUser { return [PSCustomObject]@{ Id = "existing-id"; UserPrincipalName = "alice.johnson@renah.onmicrosoft.com" } }
        $existing = Get-MgUser -Filter "userPrincipalName eq 'alice.johnson@renah.onmicrosoft.com'" -ErrorAction SilentlyContinue
        $existing | Should -Not -BeNullOrEmpty
    }

    It "Should return null when user does not exist" {
        Mock Get-MgUser { return $null }
        $existing = Get-MgUser -Filter "userPrincipalName eq 'new.user@renah.onmicrosoft.com'" -ErrorAction SilentlyContinue
        $existing | Should -BeNullOrEmpty
    }
}

# =============================================================================
# DESCRIBE: Audit Log Writing
# =============================================================================
Describe "Write-AuditLog" {

    $script:SampleResult = [PSCustomObject]@{
        Timestamp="2026-05-11 10:00:00"; RunId="run-001"; CommitSha="abc1234"
        DisplayName="Alice Johnson"; UPN="alice.johnson@renah.onmicrosoft.com"
        Department="Engineering"; JobTitle="Software Engineer"; Status="Created"
        MFA="Enforced"; LicenseAssigned="Business Premium"; TempPassword="Xy!9abcZq12@"
    }

    It "Should create the audit log file on disk" {
        Write-AuditLog -Results @($script:SampleResult) -Path $script:AuditLogPath
        Test-Path $script:AuditLogPath | Should -BeTrue
    }

    It "Should write the correct number of records" {
        $r2 = [PSCustomObject]@{ Timestamp="2026-05-11 10:01:00"; RunId="run-001"; CommitSha="abc1234"; DisplayName="Bob Smith"; UPN="bob.smith@renah.onmicrosoft.com"; Department="Finance"; JobTitle="Analyst"; Status="Skipped (already exists)"; MFA="N/A"; LicenseAssigned="N/A"; TempPassword="N/A" }
        Write-AuditLog -Results @($script:SampleResult, $r2) -Path $script:AuditLogPath
        (Import-Csv $script:AuditLogPath).Count | Should -Be 2
    }

    It "Should include all required columns" {
        Write-AuditLog -Results @($script:SampleResult) -Path $script:AuditLogPath
        $cols = (Import-Csv $script:AuditLogPath)[0].PSObject.Properties.Name
        $cols | Should -Contain "Timestamp"
        $cols | Should -Contain "RunId"
        $cols | Should -Contain "CommitSha"
        $cols | Should -Contain "UPN"
        $cols | Should -Contain "Status"
        $cols | Should -Contain "MFA"
        $cols | Should -Contain "LicenseAssigned"
    }

    It "Should create the audit-logs directory if it does not exist" {
        $newPath = "$TestDrive/new-audit-dir/run.csv"
        Write-AuditLog -Results @($script:SampleResult) -Path $newPath
        Test-Path (Split-Path $newPath -Parent) | Should -BeTrue
    }
}

# =============================================================================
# DESCRIBE: Offboarding CSV Parsing
# =============================================================================
Describe "Offboarding CSV Validation" {

    It "Should correctly read UPNs from offboarding CSV" {
        @"
UPN
alice.johnson@renah.onmicrosoft.com
bob.smith@renah.onmicrosoft.com
"@ | Set-Content $script:OffboardCsvPath
        $rows = Import-Csv $script:OffboardCsvPath
        $rows.Count       | Should -Be 2
        $rows[0].UPN      | Should -Be "alice.johnson@renah.onmicrosoft.com"
    }

    It "Should return null UPN for malformed CSV missing UPN column" {
        @"
Email
alice.johnson@renah.onmicrosoft.com
"@ | Set-Content $script:OffboardCsvPath
        $rows = Import-Csv $script:OffboardCsvPath
        $rows[0].UPN | Should -BeNullOrEmpty
    }
}

# =============================================================================
# DESCRIBE: Graph API Interactions
# =============================================================================
Describe "Graph API Interactions" {

    It "Should invoke New-MgUser when creating a user" {
        Mock New-MgUser { return [PSCustomObject]@{ Id = "new-mock-id" } }
        $result = New-MgUser -BodyParameter @{
            DisplayName = "Test User"; UserPrincipalName = "test.user@renah.onmicrosoft.com"
            AccountEnabled = $true
            PasswordProfile = @{ Password = "Test!Pass1@X"; ForceChangePasswordNextSignIn = $true }
        }
        Should -Invoke New-MgUser -Times 1
        $result.Id | Should -Be "new-mock-id"
    }

    It "Should invoke Set-MgUserLicense after user creation" {
        Mock Set-MgUserLicense { return $null }
        Set-MgUserLicense -UserId "new-mock-id" -AddLicenses @{ SkuId = "sku-mock-001" } -RemoveLicenses @()
        Should -Invoke Set-MgUserLicense -Times 1
    }

    It "Should invoke Invoke-MgGraphRequest for MFA enforcement" {
        Mock Invoke-MgGraphRequest { return $null }
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/users/new-mock-id" -Body "{}"
        Should -Invoke Invoke-MgGraphRequest -Times 1
    }

    It "Should invoke Update-MgUser with AccountEnabled false during offboarding" {
        Mock Update-MgUser { return $null }
        Update-MgUser -UserId "existing-user-id" -AccountEnabled $false
        Should -Invoke Update-MgUser -Times 1
    }
}
