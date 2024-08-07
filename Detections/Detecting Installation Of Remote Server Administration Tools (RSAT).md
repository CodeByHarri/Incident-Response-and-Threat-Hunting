# Detecting Installation Of Remote Server Administration Tools (RSAT)

# Description
This query is designed to track and analyze installation events related to Remote Server Administration Tools (RSAT) on devices within your network.

# References
**MITRE**: https://attack.mitre.org/techniques/T1615/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1615/T1615.md

# Sentinel / Defender
```kql
DeviceEvents
| where ActionType contains "ShellLinkCreateFileEvent" and ( FolderPath contains "Microsoft-Windows-ServerManager-Tools-FoD-Package" or FolderPath contains "Microsoft-Windows-GroupPolicy-Management-Tools-FoD-Package" or FolderPath contains "Microsoft-Windows-ActiveDirectory-DS-LDS-Tools-FoD-Package" or FolderPath contains "Microsoft-Windows-FileServices-Tools-FoD-Package") and InitiatingProcessFileName =~ "tiworker.exe"
| summarize by DeviceName
```
