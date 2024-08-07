# Scheduled Tasks Creation 

# Description
This query helps in identifying unauthorized or suspicious creation of scheduled tasks by users, which can be an indication of attempts to achieve persistence or schedule malicious activities. By monitoring and analyzing these events, security teams can detect and respond to potentially harmful actions taken through the use of scheduled tasks.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where InitiatingProcessCommandLine has "cmd.exe" or InitiatingProcessCommandLine has "powershell.exe"
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/create"
// | where AccountUpn != ""
| summarize
    dcount(ProcessCommandLine),
    ProcessCommandLine = strcat_array(make_set(ProcessCommandLine, 5), ', ')
    by AccountUpn, DeviceName, InitiatingProcessFileName
```

