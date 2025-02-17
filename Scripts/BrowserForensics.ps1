<#
.DESCRIPTION
    The Browser Forensics Collection script gathers comprehensive forensic data from web browsers (Chrome, Edge, Firefox) on a Windows system.
    It collects both browser history and saved usernames (portal link and username, not passwords).
    CSV files are generated with a timestamp appended to their file names.
.NOTES
    Created by codebyharri x chatgpt
#>

$Version = '2.0.1'
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

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

#---------------------------------------------------
# FUNCTION: Find-Sqlite3
#---------------------------------------------------
function Find-Sqlite3 {
    # Check if sqlite3.exe is in the current PATH
    $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Search common directories
    $searchPaths = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:LOCALAPPDATA",
        "$env:windir"
    )
    foreach ($base in $searchPaths) {
        if (Test-Path $base) {
            try {
                $result = Get-ChildItem -Path $base -Filter "sqlite3.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($result) { return $result.FullName }
            } catch {
                continue
            }
        }
    }
    return $null
}

# Attempt to locate sqlite3.exe
$sqlitePath = Find-Sqlite3
if (-not $sqlitePath) {
    Write-Error "sqlite3.exe is not found on this system. Please install sqlite3 and ensure it is accessible."
    exit
}

#---------------------------------------------------
# HISTORY COLLECTION FUNCTIONS
#---------------------------------------------------
function Get-ChromeHistory {
    $chromeHistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    if (-Not (Test-Path $chromeHistoryPath)) {
        Write-Verbose "Chrome history file not found at $chromeHistoryPath."
        return @()
    }
    $tempPath = Join-Path $env:TEMP ("ChromeHistory_{0}.db" -f (Get-Random))
    Copy-Item $chromeHistoryPath $tempPath -ErrorAction Stop
    $query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') as last_visit FROM urls;"
    $output = & $sqlitePath -separator "||" $tempPath $query
    Remove-Item $tempPath -Force
    $results = @()
    foreach ($line in $output) {
        if ($line.Trim()) {
            $parts = $line -split "\|\|"
            $results += [PSCustomObject]@{
                Browser     = "Chrome"
                URL         = $parts[0]
                Title       = $parts[1]
                LastVisited = $parts[2]
            }
        }
    }
    return $results
}

function Get-EdgeHistory {
    $edgeHistoryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    if (-Not (Test-Path $edgeHistoryPath)) {
        Write-Verbose "Edge history file not found at $edgeHistoryPath."
        return @()
    }
    $tempPath = Join-Path $env:TEMP ("EdgeHistory_{0}.db" -f (Get-Random))
    Copy-Item $edgeHistoryPath $tempPath -ErrorAction Stop
    $query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') as last_visit FROM urls;"
    $output = & $sqlitePath -separator "||" $tempPath $query
    Remove-Item $tempPath -Force
    $results = @()
    foreach ($line in $output) {
        if ($line.Trim()) {
            $parts = $line -split "\|\|"
            $results += [PSCustomObject]@{
                Browser     = "Edge"
                URL         = $parts[0]
                Title       = $parts[1]
                LastVisited = $parts[2]
            }
        }
    }
    return $results
}

function Get-FirefoxHistory {
    $firefoxProfilesPath = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (-Not (Test-Path $firefoxProfilesPath)) {
        Write-Verbose "Firefox profiles directory not found at $firefoxProfilesPath."
        return @()
    }
    $results = @()
    Get-ChildItem -Path $firefoxProfilesPath -Directory | ForEach-Object {
        $profileDir = $_.FullName
        $placesFile = Join-Path $profileDir "places.sqlite"
        if (Test-Path $placesFile) {
            $tempPath = Join-Path $env:TEMP ("FirefoxHistory_{0}_{1}.sqlite" -f $_.Name, (Get-Random))
            Copy-Item $placesFile $tempPath -ErrorAction SilentlyContinue
            $query = "SELECT p.url, p.title, datetime(v.visit_date/1000000, 'unixepoch') as last_visit FROM moz_places p INNER JOIN moz_historyvisits v ON p.id = v.place_id;"
            $output = & $sqlitePath -separator "||" $tempPath $query
            Remove-Item $tempPath -Force
            foreach ($line in $output) {
                if ($line.Trim()) {
                    $parts = $line -split "\|\|"
                    $results += [PSCustomObject]@{
                        Browser     = "Firefox"
                        Profile     = $_.Name
                        URL         = $parts[0]
                        Title       = $parts[1]
                        LastVisited = $parts[2]
                    }
                }
            }
        }
    }
    return $results
}

#---------------------------------------------------
# USERNAME COLLECTION FUNCTIONS
#---------------------------------------------------
function Get-ChromeUsernames {
    $chromeLoginPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    if (-Not (Test-Path $chromeLoginPath)) {
        Write-Verbose "Chrome Login Data not found at $chromeLoginPath."
        return @()
    }
    $tempPath = Join-Path $env:TEMP ("ChromeLogin_{0}.db" -f (Get-Random))
    Copy-Item $chromeLoginPath $tempPath -ErrorAction Stop
    $query = "SELECT origin_url, username_value FROM logins WHERE username_value != '';"
    $output = & $sqlitePath -separator "||" $tempPath $query
    Remove-Item $tempPath -Force
    $results = @()
    foreach ($line in $output) {
        if ($line.Trim()) {
            $parts = $line -split "\|\|"
            $results += [PSCustomObject]@{
                Browser    = "Chrome"
                PortalLink = $parts[0]
                Username   = $parts[1]
            }
        }
    }
    return $results
}

function Get-EdgeUsernames {
    $edgeLoginPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    if (-Not (Test-Path $edgeLoginPath)) {
        Write-Verbose "Edge Login Data not found at $edgeLoginPath."
        return @()
    }
    $tempPath = Join-Path $env:TEMP ("EdgeLogin_{0}.db" -f (Get-Random))
    Copy-Item $edgeLoginPath $tempPath -ErrorAction Stop
    $query = "SELECT origin_url, username_value FROM logins WHERE username_value != '';"
    $output = & $sqlitePath -separator "||" $tempPath $query
    Remove-Item $tempPath -Force
    $results = @()
    foreach ($line in $output) {
        if ($line.Trim()) {
            $parts = $line -split "\|\|"
            $results += [PSCustomObject]@{
                Browser    = "Edge"
                PortalLink = $parts[0]
                Username   = $parts[1]
            }
        }
    }
    return $results
}

function Get-FirefoxUsernames {
    $firefoxProfilesPath = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (-Not (Test-Path $firefoxProfilesPath)) {
        Write-Verbose "Firefox profiles directory not found at $firefoxProfilesPath."
        return @()
    }
    $results = @()
    Get-ChildItem -Path $firefoxProfilesPath -Directory | ForEach-Object {
        $profileDir = $_.FullName
        $profileName = $_.Name
        $loginsFile = Join-Path $profileDir "logins.json"
        if (Test-Path $loginsFile) {
            try {
                $json = Get-Content $loginsFile -Raw | ConvertFrom-Json
                foreach ($login in $json.logins) {
                    $results += [PSCustomObject]@{
                        Browser    = "Firefox"
                        Profile    = $profileName
                        PortalLink = $login.hostname
                        Username   = $login.encryptedUsername
                    }
                }
            } catch {
                Write-Verbose "Failed to process ${loginsFile}: $($_.Exception.Message)"
            }
        }
    }
    return $results
}

#---------------------------------------------------
# MAIN SCRIPT EXECUTION
#---------------------------------------------------
$chromeHistory  = Get-ChromeHistory
$edgeHistory    = Get-EdgeHistory
$firefoxHistory = Get-FirefoxHistory

$chromeUsernames  = Get-ChromeUsernames
$edgeUsernames    = Get-EdgeUsernames
$firefoxUsernames = Get-FirefoxUsernames

# Save browser history CSV files with timestamp
if ($chromeHistory.Count -gt 0) {
    $chromeHistory | Export-Csv -Path "ChromeHistory_$timestamp.csv" -NoTypeInformation
    Write-Host "Chrome history saved to ChromeHistory_$timestamp.csv"
} else {
    Write-Host "No Chrome history found."
}

if ($edgeHistory.Count -gt 0) {
    $edgeHistory | Export-Csv -Path "EdgeHistory_$timestamp.csv" -NoTypeInformation
    Write-Host "Edge history saved to EdgeHistory_$timestamp.csv"
} else {
    Write-Host "No Edge history found."
}

if ($firefoxHistory.Count -gt 0) {
    $firefoxHistory | Export-Csv -Path "FirefoxHistory_$timestamp.csv" -NoTypeInformation
    Write-Host "Firefox history saved to FirefoxHistory_$timestamp.csv"
} else {
    Write-Host "No Firefox history found."
}

# Save usernames CSV files with timestamp
if ($chromeUsernames.Count -gt 0) {
    $chromeUsernames | Export-Csv -Path "ChromeUsernames_$timestamp.csv" -NoTypeInformation
    Write-Host "Chrome usernames saved to ChromeUsernames_$timestamp.csv"
} else {
    Write-Host "No Chrome usernames found."
}

if ($edgeUsernames.Count -gt 0) {
    $edgeUsernames | Export-Csv -Path "EdgeUsernames_$timestamp.csv" -NoTypeInformation
    Write-Host "Edge usernames saved to EdgeUsernames_$timestamp.csv"
} else {
    Write-Host "No Edge usernames found."
}

if ($firefoxUsernames.Count -gt 0) {
    $firefoxUsernames | Export-Csv -Path "FirefoxUsernames_$timestamp.csv" -NoTypeInformation
    Write-Host "Firefox usernames saved to FirefoxUsernames_$timestamp.csv"
} else {
    Write-Host "No Firefox usernames found."
}
