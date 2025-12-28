# Windows DFIR Notes

- [1. Discovery](#1-discovery)
  * [1.1 String Search](#11-string-search)
  * [1.2 Console History](#12-console-history)
  * [1.3 Rare File Extensions](#13-rare-file-extensions)
  * [1.4 PowerShell Location/ Module](#14-powershell-location--module)
      - [Enumerate a PowerShell Profile](#enumerate-a-powershell-profile)
      - [PowerShell Modules](#powershell-modules)
  * [1.5 System Profile](#15-system-profile)
  * [1.6 User and Sessions](#16-user-and-sessions)
  * [1.7 Network Discovery](#17-network-discovery)
  * [1.8 Services Items](#18-services-items)
  * [1.9 Scheduled Tasks/ Items](#19-scheduled-tasks--items)
  * [1.10 Start Up and Registry](#110-start-up-and-registry)
  * [1.11 Processes and Directories](#111-processes-and-directories)
- [2 Registry Explorer and Tools](#2-registry-explorer-and-tools)
  * [2.1 Eric Zimmerman Tools](#21-eric-zimmerman-tools)
      - [NTDS.dit Export](#ntdsdit-export)
  * [2.2 Registry Explorer and Guide](#22-registry-explorer-and-guide)
      - [Important Registry Locations for NTDS.dat](#important-registry-locations-for-ntdsdat)
      - [LNK files](#lnk-files)
      - [Using Registry viewer](#using-registry-viewer)
        * [👨‍💻System info](#-----system-info)
        * [🛜Network & Identification](#--network---identification)
        * [**User Accounts**](#--user-accounts--)
          + [📂 File & Folder Usage](#---file---folder-usage)
          + [🔌 External Device / USB Forensic](#---external-device---usb-forensic)
        * [🚀 Evidence of Execution](#---evidence-of-execution)
- [3. Event Logs](#3-event-logs)
    + [Event ID Search](#event-id-search)
      - [RDP](#rdp)
      - [Scheduled Tasks](#scheduled-tasks)
      - [Security logs](#security-logs)
      - [Account modifications, creations, deletions, lockouts](#account-modifications--creations--deletions--lockouts)
      - [Account Auth](#account-auth)
- [4. Application](#4-application)
  * [4.1 System Resource Usage Monitor (SRUM)](#41-system-resource-usage-monitor--srum-)
  * [4.2 Browser Forensics](#42-browser-forensics)
  * [4.3 Outlook Hunt](#43-outlook-hunt)
  * [4.4 Teams Hunt](#44-teams-hunt)
  * [4.5 One Drive Hunt](#45-one-drive-hunt)
      - [FAT32 images](#fat32-images)


# 1. Discovery

#### xfreeRDP to Windows host from Kali
```bash
xfreerdp /v:10.49.172.93 /u:THM-4n6 /p:'123' /cert:ignore +clipboard /dynamic-resolution /drive:root,/root/Desktop/Tools
```
`/drive` lets you share files through rdp via a folder on your host

## 1.1 String Search
```shell
cd
dir # ls(equivalent) lists folders andfiles
type # cat(equivalent) prints 
Get-CimInstance Win32_Process | Out-String -Stream | Select-String "<keyword>" # grep(equivalent)
```

## 1.2 Console History
visit `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` in explorer for bash history

## 1.3 Rare File Extensions
Find particular file extensions on user profile that is not app data related
```PowerShell
$targetExt = @(".ps1", ".zip", ".rar", ".txt", ".psm1", ".pdf", ".bat", ".sh",".xlsm",".docm",".py",".js",".exe",".bin")
$results = Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
    $userName = $_.Name
    $userPath = $_.FullName 
    Write-Host "Scanning: $userPath (Skipping AppData)..." -ForegroundColor Gray
    $rootFiles = Get-ChildItem -Path $userPath -File -Force -ErrorAction SilentlyContinue | 
                 Where-Object { $targetExt -contains $_.Extension }
    $subFolderFiles = Get-ChildItem -Path $userPath -Directory -Force -ErrorAction SilentlyContinue | 
                      Where-Object { $_.Name -ne "AppData" } | 
                      ForEach-Object {
                          Get-ChildItem -Path $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                          Where-Object { $targetExt -contains $_.Extension }
                      }
    ($rootFiles + $subFolderFiles) | ForEach-Object {
        [PSCustomObject]@{
            User      = $userName
            FileName  = $_.Name
            Extension = $_.Extension
            FullPath  = $_.FullName
            Created   = $_.CreationTime
        }
    }
}
$results | Format-Table -AutoSize -Wrap
```

## 1.4 PowerShell Location/ Module
```shell
where powershell.exe # finds powershell for you

if exist "C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)
PROFILE DOES NOT EXIST

if exist "C:\Users\Administrator\Documents\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)
PROFILE DOES NOT EXIST

if exist "C:\Users\Administrator\Documents\WindowsPowerShell\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)
PROFILE DOES NOT EXIST

if exist "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)
PROFILE EXISTS
```
#### Enumerate a PowerShell Profile
```shell
type "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" 
```
#### PowerShell Modules
```PowerShell
Get-Module | ft ModuleType, Version, Name
Get-Module -ListAvailable | select ModuleType, Version, Name
```

## 1.5 System Profile
```PowerShell
Get-CimInstance win32_networkadapterconfiguration -Filter IPEnabled=TRUE | ft DNSHostname, IPAddress, MACAddress # system and network
Get-CimInstance -ClassName Win32_OperatingSystem | fl CSName, Version, BuildNumber, InstallDate, LastBootUpTime, OSArchitecture # OS information
Get-Date ; Get-TimeZone # date and timezone
Get-GPResultantSetOfPolicy -ReportType HTML -Path (Join-Path -Path (Get-Location).Path -ChildPath "RSOPReport.html") # Extracting the System Policies
```

## 1.6 User and Sessions
```PowerShell
Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
    $adsiUser = [ADSI]"WinNT://$env:COMPUTERNAME/$($_.Name),user"
    [PSCustomObject]@{
        Name               = $_.Name
        LastLogin          = $adsiUser.LastLogin
        PasswordExpires    = $_.PasswordExpires
        PasswordChangeable = $_.PasswordChangeable
        SID                = $_.SID ## 10xx user accounts
        Description        = $_.Description
    }
} | Format-Table -AutoSize | Tee-Object "user-details.txt" # details of users

Get-LocalGroup | ForEach-Object { $members = Get-LocalGroupMember -Group $_.Name; if ($members) { Write-Output "`nGroup: $($_.Name)"; $members | ForEach-Object { Write-Output "`tMember: $($_.Name)" } } } | tee gp-members.txt  ## groups

$computer = [ADSI]"WinNT://$env:COMPUTERNAME"
$computer.Children | Where-Object {$_.SchemaClassName -eq 'Group'} | ForEach-Object {
    Write-Output "`nGroup: $($_.Name)"
    $members = @($_.Invoke("Members")) | ForEach-Object {
        $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null)
    }
    if ($members) {
        foreach ($member in $members) {
            Write-Output "`tMember: $member"
        }
    }
} | tee gp-members.txt  ## same as above but different way

qwinsta # show the user status, as well as RDP sessons/source of the connection.

.\PsLoggedon64.exe | tee sessions.txt  ## get sessions, requires this exe
```

## 1.7 Network Discovery
```PowerShell
Get-NetTCPConnection | select Local*, Remote*, State, OwningProcess, @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}} | sort State | ft -Auto -Wrap | tee tcp-conn.txt # List theTCPConnections

Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | sort Remoteaddress -Descending | ft -Auto -Wrap | tee tcp-conn.txt  # List theTCPConnections mapped to commandline

Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize ## list udp connections

Get-DnsClientCache | ? Entry -NotMatch "workst|servst|memes|kerb|ws|ocsp" | ft -Auto -Wrap  # Retrieve DNS Cache

Get-Content C:\Apache24\logs\access.log ## webapp access requests or f0r IIS C:\inetpub\logs\LogFiles\<WEBSITE> use this location

gc "C:\Windows\System32\Drivers\etc\hosts" # The hosts file contains "override" domains, attackers will redirect traffic to other infra they control

Get-CimInstance -ClassName Win32_Service | Where-Object {$_.State -eq "Running"} | Select Name, DisplayName, PathName, ProcessId | sort Path | ft -Auto -Wrap | tee net-shares.txt # list network shares

Get-SmbConnection ## get SMB connections
Get-SmbShare   ## get SMB share

tasklist # find active processes and pids
netstat -ano  ## find pid Active Connections add -b to see process

Get-NetFirewallProfile | ft Name, Enabled, DefaultInboundAction, DefaultOutboundAction | tee fw-profiles.txt # Firewall Configuration

Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*LMV*" } | Get-NetFirewallPortFilter ## get the display name from amove firewall config and use here

.\fw-summary.ps1 | tee fw-rules.txt 
```

## 1.8 Services Items
```PowerShell
"Running Services:"; Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId | ft -AutoSize | tee services-active.txt  ## list current services

Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq "YourServiceName" } | ForEach-Object {
    if ($_.PathName -match '^"([^"]+)"') {
        $cleanPath = $matches[1]
    } else {
        $cleanPath = $_.PathName.Split(' ')[0]
    }
    $hash = Get-FileHash -Path $cleanPath -Algorithm SHA256 -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Service = $_.Name
        Path    = $cleanPath
        SHA256  = $hash.Hash
    }
} # Geting path and SHA256 of a running service name from above query

Get-FileHash -Path "C:\Users\Administrator\AppData\SpcTmp\Invoke-SocksProxy.psm1" -Algorithm SHA256 # get hash

(Get-Item "C:\Users\Administrator\AppData\SpcTmp\Invoke-SocksProxy.psm1").VersionInfo.OriginalFilename # get original file name

"Non-Running Services:"; Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -ne "Running" } | Select-Object @{Name='Name'; Expression={if ($_.Name.Length -gt 22) { "$($_.Name.Substring(0,19))..." } else { $_.Name }}}, @{Name='DisplayName'; Expression={if ($_.DisplayName.Length -gt 45) { "$($_.DisplayName.Substring(0,42))..." } else { $_.DisplayName }}}, State, StartMode, PathName, ProcessId | Format-Table -Auto -Wrap | Tee-Object services-idle.txt  ## idle services

"Non-Running Services:"; Get-CimInstance -ClassName Win32_Service | Out-String -Stream | Select-String "ssh" ## finding strings in win32

```

## 1.9 Scheduled Tasks/ Items
```PowerShell
$tasks = Get-CimInstance -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask; if ($tasks.Count -eq 0) { Write-Host "No scheduled tasks found."; exit } else { Write-Host "$($tasks.Count) scheduled tasks found." }; $results = @(); foreach ($task in $tasks) { foreach ($action in $task.Actions) { if ($action.PSObject.TypeNames[0] -eq 'Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_TaskExecAction') { $results += [PSCustomObject]@{ TaskPath = $task.TaskPath.Substring(0, [Math]::Min(50, $task.TaskPath.Length)); TaskName = $task.TaskName.Substring(0, [Math]::Min(50, $task.TaskName.Length)); State = $task.State; Author = $task.Principal.UserId; Execute = $action.Execute } } } }; if ($results.Count -eq 0) { Write-Host "No tasks with 'MSFT_TaskExecAction' actions found." } else { $results | Format-Table  -Auto -Wrap | tee scheduled-tasks.txt }  ## scheduled jobs


Get-ScheduledTask | Where-Object {$_.Date —ne $null —and $_.State —ne "Disabled"} | Sort-Object Date | select Date,TaskName,Author,State,TaskPath | ft # simple scheduled tasks

# List all enabled scheduled tasks 
Get-ScheduledTask | Where-Object {$_.Date -ne $null -and $_.State -ne "Disabled" -and $_.Actions.Execute} | Sort-Object Date | Select-Object @{N='Task Name';E={$_.TaskName}}, @{N='Task Author';E={$_.Author}}, @{N='Creation Date';E={$_.Date}}, @{N='Task Path';E={$_.TaskPath}}, @{N='Command';E={"$($_.Actions.Execute) $($_.Actions.Arguments)"}}, @{N='Run As';E={$_.Principal.UserId}} | Format-Table -AutoSize -Wrap 
```
after scheduled tasks check start up reg below
## 1.10 Start Up and Registry
```PowerShell
.\autorunsc64.exe -a b * -h | tee boot.txt ## List the Boot Startup Programs , u need this exe

Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | fl | tee autorun-cmds.txt ### Startup Programs and Commands

.\autorunsc64.exe -a l * -h | tee logon.txt # List the User Logon Startup Programs

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; "Userinit: $((Get-ItemProperty -Path $winlogonPath -Name 'Userinit').Userinit)"; "Shell: $((Get-ItemProperty -Path $winlogonPath -Name 'Shell').Shell)" # user and shell reg events

Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NetSh" | tee netsh-records.txt # get properties of reg keys


## get start up services (search servicename found in regsitry exploer >SYSTEM )
$services = Get-Service | Where-Object {$_.StartType -eq "Automatic"}
$results = foreach ($service in $services) {
    $serviceName = $service.Name
    $serviceWMI = Get-WmiObject Win32_Service -Filter "Name='$serviceName'"
    $servicePath = $serviceWMI.PathName
    # Filter: REMOVE this filter to see everything
    if ($servicePath -notlike "C:\Windows\system32\svchost.exe -k*") {
        [PSCustomObject]@{
            ServiceName    = $serviceName
            ExecutablePath = $servicePath
        }
    }
}
$results | Format-Table -AutoSize -Wrap
```

## 1.11 Processes and Directories
```PowerShell
Get-WmiObject -Class Win32_Process | ForEach-Object {$owner = $_.GetOwner(); [PSCustomObject]@{Name=$_.Name; PID=$_.ProcessId; P_PID=$_.ParentProcessId; User="$($owner.User)"; CommandLine=if ($_.CommandLine.Length -le 60) { $_.CommandLine } else { $_.CommandLine.Substring(0, 60) + "..." }; Path=$_.Path}} | ft -Auto -Wrap | tee process-summary.txt ## list current running processes

Get-ChildItem -Path "C:\Users" -Force | Where-Object { $_.PSIsContainer } | ForEach-Object { Get-ChildItem -Path "$($_.FullName)\AppData\Local\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object @{Name='User';Expression={$_.FullName.Split('\')[2]}}, FullName, Name, Extension } | ft -AutoSize | tee temp-folders.txt ## details of temp roast

Get-CimInstance -ClassName Win32_Volume | ft -AutoSize DriveLetter, Label, FileSystem, Capacity, FreeSpace | tee disc-volumes.txt ## list disk volumes

```



# 2 Registry Explorer and Tools

## 2.1 Eric Zimmerman Tools 

```bash
### LNK files are like bookmarks that help you pinpoint a specific page. In terms of the Windows OS, these are shortcuts to the original file
.\LECmd.exe -d C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent --csvf Parsed-LNK.csv --csv C:\Users\Administrator\Desktop


### Prefetch files are part of the Windows operating system that keeps track of your file execution activities.
.\PECmd.exe -d "C:\Windows\Prefetch" --csv C:\Users\Administrator\Desktop --csvf Prefetch-Parsed.csv

### Amcache was introduced in the Windows OS to improve program compatibility by maintaining a cache of information about installed applications
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv

### Windows 10 stores recently used applications and files in an SQLite database called the Windows 10 Timeline C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db
.\WxTCmd.exe -f <path-to-timeline-file> --csv <path-to-save-csv> --csvf win10.csv

### Windows Jump Lists Windows introduced jump lists to help users go directly to their recently used files from the taskbar. C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations its important not to wrap the path in string for this one
.\JLECmd.exe -d C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations — csv


#### you need to get the $J and the $MFT file and run it through MFTE
.\MFTECmd.exe -f 'C:\Users\DFIR Analyst\DFIR-Tools\Evidence\$J.copy0' --csv 'C:\Users\DFIR Analyst\DFIR-Tools\Evidence' --csvf USNJrnlJ.csv  
### To find cluster size
.\MFTECmd.exe -f 'C:\Users\THM-4n6\Desktop\triage\C\$Boot' --csv 'C:\Users\THM-4n6\Desktop' --csvf USNJrnlBoot.csv 

```

#### NTDS.dit Export
```PowerShell
ntdsutil.exe "activate instance ntds" "ifm" "create full C:\Exports" quit quit

$bootKey = Get-BootKey -SystemHivePath 'C:\Exports\registry\SYSTEM' # extract the boot key

### To fetch the account details, we then call the `Get-ADDBAccount` cmdlet, passing the path to the NTDS.dit and the boot key:
Get-ADDBAccount -All -DBPath 'C:\Exports\Active Directory\NTDS.dit' -BootKey $bootKey

	Get-ADDBAccount -All -DBPath 'C:\Exports\Active Directory\NTDS.dit' -BootKey $bootKey | Select-Object SamAccountName, DisplayName, Enabled, Sid, NTHash | Format-Table -AutoSize ## same displayed concicesly /nicely

```
## 2.2 Registry Explorer and Guide

#### **IMPORTANT:** USE THE **BOOMARKS** AFTER LOADING IN THE HIVES! SPEEDS THINGS UP!

Load in system events  - usually sees everything. Try use available books marks and go to services and look for psexec to find suss stuff
if looking at an image find this  in `\Windows\System32\config\{SOFTWARE/SYSTEM/SECURITY ETC.}`
NTUSER.DAT will give you some juicy stuff too. look at the user assist folder

#### Important Registry Locations for NTDS.dat
Recent Docs:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
  
Track of the paths to the folders you've most recently visited on your system: (LastVisitedPIdl MRU, OpenSavePidlMRU)
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
  
Identify if any suspicious tools have been executed on the system by the suspect: (look in each folder for count)
1. `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`:
    - This GUID is associated with Windows Explorer and tracks user interactions with files and folders.
2. `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}`:
    - This GUID is associated with shortcut files or extensions like .LNK used to execute the programs.
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

Adversaries tend to use the run dialogue box
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

Here is a clean, organized Markdown cheatsheet for Registry Forensics. The paths have been reconstructed into single lines for easy copying.
#### LNK files
go this locations and explore
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent
```

#### Using Registry viewer
##### 👨‍💻System info
**OS Version**
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion
```
**Time Zone Information**
```
SYSTEM\CurrentControlSet\Control\TimeZoneInformation
```
**Current Control Set**
```
HKLM\SYSTEM\CurrentControlSet
```
**Select (Identify Current & LastKnownGood)**
```
SYSTEM\Select\Current
SYSTEM\Select\LastKnownGood
```
##### 🛜Network & Identification
**Hostname**
```
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
```
**Network Interfaces (IPs, Subnets, etc.)**
```
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
```
 **Persistence (Autoruns)**
**User-Specific Autoruns**
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
**System-Wide Autoruns**
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
```

 ##### **User Accounts**
**SAM Hive (User Information)
 **00000221** (Hex 545) is for **Users**. - **00000222** (Hex 546) is for **Guests**.**
```
SAM\Domains\Account\Users
SAM\Domains\Builtin\Aliases\00000220 # admin group
SAM\Domains\Builtin\Aliases  ## if you click this folder it should load with sid values, but you have to click SAM built in at the top
```
###### 📂 File & Folder Usage
**Recent Documents (Windows)**
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
**Office Recent Files**
```
NTUSER.DAT\Software\Microsoft\Office\VERSION
NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU
```
 **Folder Navigation (ShellBags)**
**User Class Hive (Specific to user)**
```
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```
**NTUSER Hive**
```
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
```
 **Explorer Interaction**
**Open/Save Dialog History**
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```
**Address Bar & Search History**
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```
###### 🔌 External Device / USB Forensic
**USB Storage Devices**
```
SYSTEM\CurrentControlSet\Enum\USBSTOR
```
**All USB Devices**
```
SYSTEM\CurrentControlSet\Enum\USB
```
**Volume Names (Friendly Names)**
```
SOFTWARE\Microsoft\Windows Portable Devices\Devices
```
**Connection Timestamps**
```
SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
```

| **Key ID** | **Description**       |
| ---------- | --------------------- |
| **0064**   | First Connection Time |
| **0066**   | Last Connection Time  |
| **0067**   | Last Removal Time     |
##### 🚀 Evidence of Execution
 **UserAssist**
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```
**ShimCache (AppCompatCache)**
```
SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
 **AmCache**
_Detailed execution artifacts (SHA1, paths)_
```
Amcache.hve\Root\File\{Volume GUID}\
```
**Background Activity Moderator (BAM/DAM)**
last run programs, their full paths, and last execution time.
```
SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}
```


# 3. Event Logs

### Event ID Search
Event Viewer - to search
#### RDP
Event ID 1114 in table `Operational` in folder `TerminalRemoteServices-RemoteConnectionManager`
- Remote Desktop Services: User authentication succeeded
- _“An Event ID 1149 **DOES NOT** indicate successful authentication to a target, simply a successful RDP network connection”_.
Event ID 21 in table `Operational` in folder  `TerminalRemoteServices-LocalConnectionManager`
- remember this is LOCALconnection not remote
- Remote Desktop Services: Session logon succeeded
- Event ID 24 for disconnection.  
#### Scheduled Tasks
Event ID 106 in table `Operational` in folder `TaskScheduler`
- Task registered
Event ID 140 in table `Operational` in folder `TaskScheduler`
- Task registration updated
#### Security logs
- Event ID `4698` - A scheduled task was created.
- Event ID `4702` - A scheduled task was updated.
- Event ID `7045` - New Service was installed (System Channel).
- Event ID `4697` - A service was installed in the system (Security Channel).

```PowerShell
Get-WinEvent -FilterHashTable @{LogName='Security';ID='4697'} | fl
Get-WinEvent -FilterHashTable @{LogName='System';ID='7045'} | fl
```
#### Account modifications, creations, deletions, lockouts
- **Event ID 4720 -** Denotes a user account was created
- **Event ID 4722 -** Denotes a user account was enabled
- **Event ID 4738 -** Denotes a user account was modified
- **Event ID 4740 -** Denotes a user account was locked due to repeated failed login attempts
- **Event ID 4726 -** Denotes an account was deleted, documenting when and by whom an account was removed from the system
#### Account Auth
- **Event ID 4624 -** An account was successfully logged on.
- **Event ID 4625 -** An account failed to log on.
- **Event ID 4768 -** A Kerberos authentication ticket (TGT) was requested.
- **Event ID 4771 -** Kerberos pre-authentication failed.

# 4. Application
## 4.1 System Resource Usage Monitor (SRUM)
The SRUM is a Windows feature that tracks the last 30 to 60 days of resource usage, such as:
- Application and service activity
- Network activity, such as packets sent and received
- User activity (I.e. launching services or processes).
In a database (SRUDB.dat) on the host, this can be found at `C:\Windows\System32\sru\SRUDB.dat`.

```bash
.\kape.exe --tsource C:\Windows\System32\sru --tdest C:\Users\CMNatic\Desktop\SRUM --tflush --mdest C:\Users\CMNatic\Desktop\MODULE --mflush --module SRUMDump --target SRUM
```

Once we have retrieved the SRUDB.dat file, we can use the [srum-dump](https://github.com/MarkBaggett/srum-dump) utility to analyse this database. After downloading the srum-dump executable and SRUM template from the repo, launch the executable and fill out the pop-up with the relevant information:
- Path to the exported SRUMDB.dat on our other analyst machine
- Path to the srum-dump template
- Path to output the srum-dump analysis file
- We can leave the registry boxes blank for now.
## 4.2 Browser Forensics
https://github.com/mac4n6/APOLLO/blob/master/modules/safari_history.txt queries for different browsers
open it in sqllite
```PowerShell
### FIREFOX
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Roaming\Mozilla\Firefox\Profiles" 2>$null} ## profiles (to find places.sqlite and use places table)

### CHROME (use hindsight to get the sqldb from the path)
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Google\Chrome\User Data\Default" 2>$null | findstr Directory} ## Chrome
ls 'C:\Users\{USER}\AppData\Local\Google\Chrome\User Data\Default\Extensions\' ## to view extensions, look for the manifest.jsons to find bad
cat manifest.jsons
cat .\background.js ## to look for background scripts
cat .\script.js

### Edge
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Edge\User Data\Default" 2>$null | findstr Directory}
```

## 4.3 Outlook Hunt
https://github.com/Dijji/XstReader
```PowerShell
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Outlook\" 2>$null | findstr Directory} # find the outlook files

ls -rec C:\Users\jane.adams\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook # if the user has open the client directly this will show
```

## 4.4 Teams Hunt
https://github.com/lxndrblz/forensicsim/
```PowerShell
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Roaming\Microsoft\Teams" 2>$null | findstr Directory}

ls C:\Users\mike.myers\AppData\Roaming\Microsoft\Teams\IndexedDB\ #typical location of teams DB

C:\Tools\ms_teams_parser.exe -f   C:\Users\a.ramirez\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\ -o output.json ## output all teams data


#### run all the below to ready a teams conversation
C:\Tools\ms_teams_parser.exe -f C:\Users\mike.myers\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\ -o output.json
$teams_metadata = cat .\output.json | ConvertFrom-Json
$users = @{}
$messages = @{}
# Initialise user hashtable for correlation
foreach ($data in $teams_metadata) {
   if ($data.record_type -eq "contact") {
     $users.add($data.mri, $data.userPrincipalName)
   }
}
# Combine all conversations/messages with the same ID
foreach ($data in $teams_metadata) {
  if ($data.record_type -eq "message") {
    if ($messages.keys -notcontains $data.conversationId) {
      $messages[$data.conversationId] = [System.Collections.ArrayList]@()
    }
    $messages[$data.conversationId].add($data) > $null
  }
}
# Print the parsed output focused on the significant values
foreach ($conversationID in $messages.keys) {
  Write-Host "Conversation ID: $conversationID`n"
  $conversation = $messages[$conversationID] | Sort createdTime
  foreach ($message in $conversation) {
    $createdTime = $message.createdTime
    $fromme = $message.isFromMe
    $content = $message.content
    $sender = $users[$message.creator]

    Write-Host "Created Time: $createdTime"
    Write-Host "Sent by: $sender"
    Write-Host "Direction: $direction"
    Write-Host "Message content: $content"
    Write-Host "`n"
  }
  Write-host "----------------`n"
}
```

## 4.5 One Drive Hunt
https://github.com/Beercow/OneDriveExplorer






#### FAT32 images
Use autospy
