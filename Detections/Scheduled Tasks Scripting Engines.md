# Scheduled Tasks Scripting Engines

# Description
This query helps in identifying potentially malicious scheduled tasks that utilize scripting engines and system utilities known for being leveraged in attacks. By monitoring these events, security teams can detect and mitigate threats that use scheduled tasks as a vector for persistence or payload execution.

# Sentinel Defender
```kql
DeviceProcessEvents
| where trim_start(" ",  ProcessCommandLine) startswith "schtasks"
| where ProcessCommandLine has "regsvr32.exe" or ProcessCommandLine has "cscript.exe" or ProcessCommandLine has "wscript.exe"
```
