# File Creation in User's Temp Folder

# Description
This query is crafted to monitor and detect file creation events specifically within the directory path C:\Users\[REDACTED]\AppData\Local\Temp. This directory is frequently targeted by malware and malicious scripts due to its temporary nature and often less stringent security controls.

# References
**MITRE**: https://attack.mitre.org/techniques/T1204/002/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md

# Sentinel / Defender
```kql
DeviceFileEvents
//Look for file creation in the directory using xcopy, rundll32, and copy
| where ( InitiatingProcessFileName =~ "xcopy.exe" or InitiatingProcessCommandLine contains "rundll32" or InitiatingProcessCommandLine contains "/c copy")
and ActionType =~ "FileCreated" and ( FolderPath matches regex @"(?i)C:\\(?i)Users\\\S*\\(?i)AppData\\(?i)Local\\(?i)Temp" and InitiatingProcessCommandLine contains "appData\\local\\temp")
//Exclude common files within your environment
```
