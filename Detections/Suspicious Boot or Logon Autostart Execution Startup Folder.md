# Suspicious Boot or Logon Autostart Execution: Startup Folder

# Description
This detection rule is designed to identify suspicious instances of programs placed within a Startup Folder in Windows environments. This is a common technique used by cyber adversaries to achieve persistence or privilege escalation.

# References
**MITRE**: https://attack.mitre.org/techniques/T1547/001/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md

# Sentinel / Defender
```kql
//Detecting T1547.001 test - 4,5,6 - Suspicious file run from Startup folder
let processevents = DeviceProcessEvents
| where ProcessCommandLine contains @"Microsoft\Windows\Start Menu\Programs\StartUp" and ProcessCommandLine has_any (".dll",".vba",".vbs",".lnk",".ocx",".exe",".bat",".jse",".cmd");
//Whitelist common files
//Detect Test - 7 - Add files to user startup folder
let deviceevents = DeviceEvents
| where FolderPath contains @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" and FileName has_any (".dll",".vba",".vbs",".lnk",".ocx",".exe",".bat",".jse",".cmd") and ActionType =~ "AntivirusReport";
//Whitelist common files
//Detect Test - 10,11 - Change Startup folder registry key
let registryevents = DeviceRegistryEvents
| where ( RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" and RegistryValueName contains "Startup" and RegistryValueData !contains @"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") or ( RegistryKey contains @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon" and (RegistryValueName =~ "Userinit" or RegistryValueName =~ "Shell")) or ( RegistryValueData contains "autocheck autoche *" and RegistryValueName =~ "BootExecute" and RegistryKey contains @"\Control\Session Manager");
let seceditevents = DeviceProcessEvents
| where FileName =~ "secedit.exe" and ( ProcessCommandLine contains "/import /db" or ProcessCommandLine contains "/configure /db");
union processevents, deviceevents, registryevents, seceditevents
```
