# Using Runas.exe to spawn Powershell as another user

# Description
An attacker may spawn powershell or other command outlets with a compromised account to laterally move

# Sentinel/ Defender
```kql
union Device*
| where ProcessCommandLine contains "runas.exe"
| summarize count() by bin(TimeGenerated,1h), DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn, ProcessCommandLine
```
