# Processes with Network Activity Excluding Trusted Domains

# Description
This query helps in identifying unauthorized or suspicious network connections made by processes on the network, excluding known and trusted domains. By monitoring these events, security teams can detect and investigate network activities that may indicate potential security threats or data exfiltration attempts.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where (ProcessCommandLine contains "https://" or ProcessCommandLine contains "http://" or ProcessCommandLine contains "ftp://")
| where not(ProcessCommandLine has_any ( "microsoft.com", "sharepoint.com","google.com")) // exclusions
| summarize dcount(DeviceName) by FileName, ProcessCommandLine
```
