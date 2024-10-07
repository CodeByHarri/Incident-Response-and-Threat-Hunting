<#
.DESCRIPTION
    The Comprehensive OS Forensics Script is a tool to perform detailed forensic analysis via PowerShell on devices running a Windows Operating System (Workstation & Server). The information collected by the script depends on the permissions of the user executing it; if run with admin privileges, more forensic artifacts can be gathered.
    Run this script at your own risk. I'm not responsible for anything that goes wrong. 
.EXAMPLE
    Run Script without any parameters. 
    .\ComprehensiveOSForensics.ps1

.LINK

    https://github.com/CodeByHarri/Incident-Response-Hunting-and-Automation

#>

param(
    [Parameter(Mandatory=$false)][int]$sw = 2 # Defines the custom search window, this is done in days.
)

$Version = '1.0.0'
$ASCIIBanner = @"
  ____   _____      ______                       _          
 / __ \ / ____|    |  ____|                     (_)         
| |  | | (___      | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
| |  | |\___ \     |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
| |__| |____) |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 \____/|_____/     |_|  \___/|_|  \___|_| |_|___/_|\___|___/                                      
"@
Write-Host $ASCIIBanner
Write-Host "Version: $Version"
Write-Host "By twitter: @codebyharri, Github: codebyharri"
Write-Host "===========================================`n"

# Creating output directory
$timestamp = Get-Date -Format "yyyy-MM-dd"
$hostname = $env:COMPUTERNAME
$outputDir = "C:\Forensics\Forensics-$hostname-$timestamp"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

# Function to handle permission denied errors gracefully
function Get-ChildItemSafe {
    param (
        [string]$Path,
        [switch]$Recurse
    )
    try {
        if ($Recurse) {
            Get-ChildItem -Path $Path -Recurse -ErrorAction Stop
        } else {
            Get-ChildItem -Path $Path -ErrorAction Stop
        }
    } catch {
        Write-Warning "Access to the path '$Path' is denied."
    }
}

# Calculate the start date for the look-back period
$startDate = (Get-Date).AddDays(-$sw)

# Collecting file system information
Write-Host "1/13 Collecting file system information..."
$fileSystemInfo = Get-ChildItemSafe -Path "C:\" -Recurse | Select-Object FullName, Length, CreationTime, LastAccessTime, LastWriteTime
$fileSystemInfo | Export-Csv -Path "$outputDir\FileSystemInfo.csv" -NoTypeInformation

# Collecting file permissions
Write-Host "2/13 Collecting file permissions..."
$filePermissions = Get-ChildItemSafe -Path "C:\" -Recurse | Get-Acl | Select-Object Path, Owner, Access
$filePermissions | Export-Csv -Path "$outputDir\FilePermissions.csv" -NoTypeInformation

# Collecting process information
Write-Host "3/13 Collecting process information..."
$processInfo = Get-Process | Select-Object Name, Id, StartTime, CPU, Threads
$processInfo | Export-Csv -Path "$outputDir\ProcessInfo.csv" -NoTypeInformation

# Collecting thread information
Write-Host "4/13 Collecting thread information..."
$threadInfo = Get-Process | ForEach-Object {
    $_.Threads | Select-Object ProcessId, Id, StartAddress, ThreadState, WaitReason
}
$threadInfo | Export-Csv -Path "$outputDir\ThreadInfo.csv" -NoTypeInformation

# Collecting service information
Write-Host "5/13 Collecting service information..."
$serviceInfo = Get-Service | Select-Object Name, Status, DisplayName, DependentServices
$serviceInfo | Export-Csv -Path "$outputDir\ServiceInfo.csv" -NoTypeInformation

# Collecting registry information
Write-Host "6/13 Collecting registry information..."
$registryKeys = Get-ChildItemSafe -Path "HKLM:\SOFTWARE" -Recurse
$registryKeys | Export-Csv -Path "$outputDir\RegistryKeys.csv" -NoTypeInformation

$registryPermissions = Get-ChildItemSafe -Path "HKLM:\SOFTWARE" -Recurse | Get-Acl | Select-Object Path, Owner, Access
$registryPermissions | Export-Csv -Path "$outputDir\RegistryPermissions.csv" -NoTypeInformation

# Collecting system information
Write-Host "7/13 Collecting system information..."
$systemInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsArchitecture, BiosManufacturer, BiosVersion
$systemInfo | Export-Csv -Path "$outputDir\SystemInfo.csv" -NoTypeInformation

# Collecting installed software
Write-Host "8/13 Collecting installed software..."
$installedSoftware = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$installedSoftware | Export-Csv -Path "$outputDir\InstalledSoftware.csv" -NoTypeInformation

# Collecting event logs
Write-Host "9/13 Collecting security event logs..."
$securityEventLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startDate} | Select-Object Id, TimeCreated, LevelDisplayName, Message
$securityEventLogs | Export-Csv -Path "$outputDir\SecurityEventLogs.csv" -NoTypeInformation

Write-Host "10/13 Collecting application event logs..."
$applicationEventLogs = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startDate} | Select-Object Id, TimeCreated, LevelDisplayName, Message
$applicationEventLogs | Export-Csv -Path "$outputDir\ApplicationEventLogs.csv" -NoTypeInformation

# Collecting network information
Write-Host "11/13 Collecting network connections..."
$networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
$networkConnections | Export-Csv -Path "$outputDir\NetworkConnections.csv" -NoTypeInformation

Write-Host "12/13 Collecting network interfaces..."
$networkInterfaces = Get-NetAdapter | Select-Object Name, InterfaceDescription, MACAddress, Status
$networkInterfaces | Export-Csv -Path "$outputDir\NetworkInterfaces.csv" -NoTypeInformation

# Compressing the output directory
Write-Host "13/13 Compressing the output directory..."
Compress-Archive -Path $outputDir -DestinationPath "$outputDir.zip" -Force

Write-Host "Forensic data collection complete. Output saved to $outputDir and compressed to $outputDir.zip"
