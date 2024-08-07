# Process & File Events Of SystemBC C2

# Description
This query is designed to detect and analyze Command and Control (C2) events associated with the SystemBC malware variant. SystemBC is known for its use in facilitating unauthorized remote access and data exfiltration from compromised systems.

# References
**MITRE**: https://attack.mitre.org/techniques/T1219/

**ATOMIC**: NA

# Sentinel / Defender
```kql
let query1=DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
| where ProcessCommandLine has ".dll, DialogShowOPT";
let query2=DeviceProcessEvents
| where ( FileName contains "reg.exe" and ProcessCommandLine contains "Software" and ProcessCommandLine contains "Microsoft" and ProcessCommandLine contains "CurrentVersion" and ProcessCommandLine contains "Run" and ProcessCommandLine contains "Shell" and ProcessCommandLine contains "explorer" and ProcessCommandLine contains "cmd" and ProcessCommandLine contains "mshta") or ( FileName contains "schtasks.exe" and ( ProcessCommandLine contains "GoogleUpdate" or ProcessCommandLine contains "TaskMachine" or ProcessCommandLine contains "QC" or ProcessCommandLine contains "OneDrive"));
let query3=DeviceFileEvents
| where ActionType == "FileCreated" and FolderPath contains "C:\\Windows\\Tasks";
union query1, query2, query3
```
