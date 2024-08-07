# Registry Run Keys AutoStart Execution

# Description
Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.

# References
**MITRE**: https://attack.mitre.org/techniques/T1547/001/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md

# Sentinel / Defender
```kql
//This rule looks for files added to or invoked via Registry Run Keys
union DeviceRegistryEvents, DeviceProcessEvents
//Looks for registry key events
| where ( (RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Run" or RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run") and (RegistryValueData contains ".dll" or RegistryValueData contains ".vbs" or RegistryValueData contains ".vba" or RegistryValueData contains ".lnk" or RegistryValueData contains ".ocx" or RegistryValueData contains ".cmd" or RegistryValueData contains ".bat" or RegistryValueData contains ".jse" or RegistryValueData matches regex @"windowstyle\s*hidden\s*-ExecutionPolicy\s*Bypass\s*-File"))
//Looks for registry key creation via process commandline
or ( ( ProcessCommandLine contains @"Software\Microsoft\Windows\CurrentVersion\Run" or ProcessCommandLine contains @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run") and ProcessCommandLine contains "add" and ProcessCommandLine has_any (".dll",".vba",".vbs",".lnk",".ocx",".exe",".bat",".jse",".cmd"))
```
