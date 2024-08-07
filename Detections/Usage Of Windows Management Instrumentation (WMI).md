# Usage Of Windows Management Instrumentation (WMI)

# Description
WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems. This query detect adversaries abusing Windows Management Instrumentation (WMI) to execute malicious commands and payloads.

# References
**MITRE**: https://attack.mitre.org/techniques/T1047/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md

# Sentinel / Defender
```kql
//This query looks for process reconnaissance via WMIC
let query1=DeviceProcessEvents
| where FileName =~ "wmic.exe" and ProcessCommandLine contains "process get";
//Whitelist common activities
//
//This query looks for process creation on local and remote host via WMIC
let query2=DeviceProcessEvents
| where FileName =~ "wmic.exe" and ProcessCommandLine contains "process call create";
//Whitelist common activities
//
//This query looks for application uninstallation via WMIC
let query3=DeviceProcessEvents
| where FileName =~ "wmic.exe" and ProcessCommandLine contains "call uninstall";
//Whitelist common activities
union query1, query2,query3
```
