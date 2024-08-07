<#
.DESCRIPTION
    The Browser Forensics Collection script gathers comprehensive forensic data from web browsers (Chrome, Edge, Firefox) on a Windows system. It collects internet history, saved passwords (domains and usernames), and other relevant web-related data if the browsers are installed on the host system.

.NOTES
    Created by codebyharri
#>

$Version = '1.0.0'
$ASCIIBanner = @"
 ____                                       ______                       _          
|  _ \                                     |  ____|                     (_)         
| |_) |_ __ _____      _____  ___ _ __     | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
|  _ <| '__/ _ \ \ /\ / / __|/ _ \ '__|    |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
| |_) | | | (_) \ V  V /\__ \  __/ |       | | | (_) | | |  __/ | | \__ \ | (__\__ \
|____/|_|  \___/ \_/\_/ |___/\___|_|       |_|  \___/|_|  \___|_| |_|___/_|\___|___/                                   
"@
Write-Host $ASCIIBanner
Write-Host "Version: $Version"
Write-Host "By twitter: @codebyharri, Github: codebyharri"
Write-Host "===========================================`n"

param (
    [Parameter(Mandatory = $true)]
    [int]$Days
)

# Ensure the PSSQLite module is installed
if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
    Install-Module -Name PSSQLite -Force -Scope CurrentUser
}

Import-Module PSSQLite

# Calculate the start date for the look-back period
$startDate = (Get-Date).AddDays(-$Days)
$startDateEpoch = [int][double]::Parse(($startDate - (Get-Date "1970-01-01")).TotalSeconds) * 1000000

# Function to safely query SQLite databases with retry logic and read-only mode
function Invoke-SqliteQuerySafe {
    param (
        [string]$DataSource,
        [string]$Query
    )
    $maxRetries = 5
    $retryDelay = 2
    $retryCount = 0
    $result = $null

    while ($retryCount -lt $maxRetries -and $result -eq $null) {
        try {
            $result = Invoke-SqliteQuery -DataSource $DataSource -Query $Query -ReadOnly -ErrorAction Stop
        } catch {
            Write-Warning "Database is locked, retrying in $retryDelay seconds..."
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
    }

    if ($result -eq $null) {
        Write-Error "Failed to query SQLite database after $maxRetries attempts."
    }

    return $result
}

# Function to get Chrome history
function Get-ChromeHistory {
    $chromeHistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    if (Test-Path $chromeHistoryPath) {
        Write-Host "Collecting Chrome history..."
        $chromeHistoryQuery = "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') as last_visit_time FROM urls WHERE last_visit_time >= $startDateEpoch"
        $chromeHistory = Invoke-SqliteQuerySafe -DataSource $chromeHistoryPath -Query $chromeHistoryQuery
        if ($chromeHistory) {
            $chromeHistory | Export-Csv -Path "$outputDir\ChromeHistory.csv" -NoTypeInformation
        } else {
            Write-Host "No Chrome history found for the specified period."
        }
    } else {
        Write-Host "Chrome history not found."
    }
}

# Function to get Edge history
function Get-EdgeHistory {
    $edgeHistoryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    if (Test-Path $edgeHistoryPath) {
        Write-Host "Collecting Edge history..."
        $edgeHistoryQuery = "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') as last_visit_time FROM urls WHERE last_visit_time >= $startDateEpoch"
        $edgeHistory = Invoke-SqliteQuerySafe -DataSource $edgeHistoryPath -Query $edgeHistoryQuery
        if ($edgeHistory) {
            $edgeHistory | Export-Csv -Path "$outputDir\EdgeHistory.csv" -NoTypeInformation
        } else {
            Write-Host "No Edge history found for the specified period."
        }
    } else {
        Write-Host "Edge history not found."
    }
}

# Function to get Firefox history
function Get-FirefoxHistory {
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $firefoxHistoryFiles = Get-ChildItem -Path $firefoxProfilePath -Recurse -Filter "places.sqlite"
    if ($firefoxHistoryFiles) {
        foreach ($historyFile in $firefoxHistoryFiles) {
            Write-Host "Collecting Firefox history from $($historyFile.FullName)..."
            $firefoxHistoryQuery = "SELECT url, title, visit_count, datetime(last_visit_date/1000000, 'unixepoch') as last_visit_date FROM moz_places WHERE last_visit_date >= $startDateEpoch"
            $firefoxHistory = Invoke-SqliteQuerySafe -DataSource $historyFile.FullName -Query $firefoxHistoryQuery
            if ($firefoxHistory) {
                $firefoxHistory | Export-Csv -Path "$outputDir\FirefoxHistory_$($historyFile.Name).csv" -NoTypeInformation
            } else {
                Write-Host "No Firefox history found for the specified period in $($historyFile.FullName)."
            }
        }
    } else {
        Write-Host "Firefox history not found."
    }
}

# Function to get saved passwords (domains and usernames) for Chrome
function Get-ChromePasswords {
    $chromeLoginDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    if (Test-Path $chromeLoginDataPath) {
        Write-Host "Collecting Chrome saved passwords..."
        $chromeLoginQuery = "SELECT origin_url, username_value FROM logins"
        $chromeLogins = Invoke-SqliteQuerySafe -DataSource $chromeLoginDataPath -Query $chromeLoginQuery
        if ($chromeLogins) {
            $chromeLogins | Export-Csv -Path "$outputDir\ChromePasswords.csv" -NoTypeInformation
        } else {
            Write-Host "No Chrome saved passwords found."
        }
    } else {
        Write-Host "Chrome saved passwords not found."
    }
}

# Function to get saved passwords (domains and usernames) for Edge
function Get-EdgePasswords {
    $edgeLoginDataPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    if (Test-Path $edgeLoginDataPath) {
        Write-Host "Collecting Edge saved passwords..."
        $edgeLoginQuery = "SELECT origin_url, username_value FROM logins"
        $edgeLogins = Invoke-SqliteQuerySafe -DataSource $edgeLoginDataPath -Query $edgeLoginQuery
        if ($edgeLogins) {
            $edgeLogins | Export-Csv -Path "$outputDir\EdgePasswords.csv" -NoTypeInformation
        } else {
            Write-Host "No Edge saved passwords found."
        }
    } else {
        Write-Host "Edge saved passwords not found."
    }
}

# Function to get saved passwords (domains and usernames) for Firefox
function Get-FirefoxPasswords {
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $firefoxLoginFiles = Get-ChildItem -Path $firefoxProfilePath -Recurse -Filter "logins.json"
    if ($firefoxLoginFiles) {
        foreach ($loginFile in $firefoxLoginFiles) {
            Write-Host "Collecting Firefox saved passwords from $($loginFile.FullName)..."
            $firefoxLogins = Get-Content -Path $loginFile.FullName | ConvertFrom-Json
            $firefoxLogins.logins | Select-Object -Property hostname, encryptedUsername | Export-Csv -Path "$outputDir\FirefoxPasswords_$($loginFile.Name).csv" -NoTypeInformation
        }
    } else {
        Write-Host "Firefox saved passwords not found."
    }
}

# Main script
$timestamp = Get-Date -Format "yyyy-MM-dd"
$hostname = $env:COMPUTERNAME
$outputDir = "C:\Forensics\BrowserForensics-$hostname-$timestamp"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

Write-Host "Starting browser forensics collection..."

# Collect data for each browser
Get-ChromeHistory
Get-EdgeHistory
Get-FirefoxHistory
# Get-ChromePasswords
# Get-EdgePasswords
# Get-FirefoxPasswords

Write-Host "Browser forensics collection complete. Data saved to $outputDir"