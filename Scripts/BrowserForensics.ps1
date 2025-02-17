<#
.DESCRIPTION
    The Browser Forensics Collection script gathers comprehensive forensic data from web browsers (Chrome, Edge, Firefox) on a Windows system. 
    - BrowserHistory
.NOTES
    Created by codebyharri
#>

$Version = '2.0.0'
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

# Function to locate sqlite3.exe on the system
function Find-Sqlite3 {
    # Check if sqlite3.exe is in the current PATH
    $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    # List of common directories to search
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
                if ($result) {
                    return $result.FullName
                }
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

# Function to extract Google Chrome history
function Get-ChromeHistory {
    $chromeHistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    if (-Not (Test-Path $chromeHistoryPath)) {
        Write-Verbose "Chrome history file not found at $chromeHistoryPath."
        return @()
    }
    # Copy the database to a temporary location (in case Chrome has a lock on it)
    $tempPath = Join-Path $env:TEMP ("ChromeHistory_{0}.db" -f (Get-Random))
    Copy-Item $chromeHistoryPath $tempPath -ErrorAction Stop

    # Query to extract URL, title and convert last_visit_time to a human-readable datetime
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

# Function to extract Microsoft Edge history
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

# Function to extract Mozilla Firefox history
function Get-FirefoxHistory {
    $firefoxProfilesPath = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (-Not (Test-Path $firefoxProfilesPath)) {
        Write-Verbose "Firefox profiles directory not found at $firefoxProfilesPath."
        return @()
    }
    $results = @()
    # Iterate over each Firefox profile folder
    Get-ChildItem -Path $firefoxProfilesPath -Directory | ForEach-Object {
        $profileDir = $_.FullName
        $placesFile = Join-Path $profileDir "places.sqlite"
        if (Test-Path $placesFile) {
            $tempPath = Join-Path $env:TEMP ("FirefoxHistory_{0}_{1}.sqlite" -f $_.Name, (Get-Random))
            Copy-Item $placesFile $tempPath -ErrorAction SilentlyContinue
            # Firefox stores visit_date in microseconds; convert it to Unix epoch datetime
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

# Main script execution
$chromeHistory  = Get-ChromeHistory
$edgeHistory    = Get-EdgeHistory
$firefoxHistory = Get-FirefoxHistory

# Save each browser's history to a separate CSV file
if ($chromeHistory.Count -gt 0) {
    $chromeHistory | Export-Csv -Path "ChromeHistory.csv" -NoTypeInformation
    Write-Host "Chrome history saved to ChromeHistory.csv"
} else {
    Write-Host "No Chrome history found."
}

if ($edgeHistory.Count -gt 0) {
    $edgeHistory | Export-Csv -Path "EdgeHistory.csv" -NoTypeInformation
    Write-Host "Edge history saved to EdgeHistory.csv"
} else {
    Write-Host "No Edge history found."
}

if ($firefoxHistory.Count -gt 0) {
    $firefoxHistory | Export-Csv -Path "FirefoxHistory.csv" -NoTypeInformation
    Write-Host "Firefox history saved to FirefoxHistory.csv"
} else {
    Write-Host "No Firefox history found."
}
