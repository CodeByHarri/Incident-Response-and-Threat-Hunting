# PowerShell version 2 Defense Evasion

# Description
Identifies the use of PowerShell version 2, which lacks AMSI integration, making it a method for executing scripts without AMSI interference.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("powershell","-version 2")
| where AccountName !in ("system")
| join DeviceInfo on DeviceName
| where not (OSPlatform contains "WindowsServer2008") 
| distinct Timestamp, AccountName, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, ReportId, DeviceId
```
