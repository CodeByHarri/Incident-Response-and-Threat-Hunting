# File Creation On A Remote Machine via SMB

# Description
By analyzing network traffic and SMB events, the query identifies when files are created on a remote system, which could indicate unauthorized file transfers or malware propagation. Security analysts can use this query to monitor for suspicious activities that may compromise data integrity or violate organizational policies, allowing for timely investigation and response to potential security incidents.

# References
**MITRE**: https://attack.mitre.org/techniques/T1021/002/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md

# Sentinel / Defender
```kql
DeviceFileEvents
| where RequestProtocol contains "smb" and ActionType == "FileCreated" and RequestSourceIP != "" and RequestSourceIP != "127.0.0.1"
//Suspicious File Extensions
| where FileName endswith ".dll" or FileName endswith ".bat" or FileName endswith ".exe" or FileName endswith ".ps1" or FileName endswith ".txt" or FileName endswith ".cmd" or FileName endswith ".lnk" or FileName endswith ".js" or FileName endswith ".zip" or FileName endswith ".iso" or FileName endswith ".img" or FileName endswith ".vmdk" or FileName endswith ".vhd" or FileName endswith ".ocx"
//SMB Shares
| where ShareName contains "C$" or ShareName contains "admin$" or ShareName contains "IPC$" or ShareName contains "sysvol" or ShareName contains "netlogon"
```
