# Registry Edit Events From Command Line

# Description 
This query helps in identifying unauthorized or suspicious registry modifications made via the command line, which can be an indication of attempts to alter system settings, persist malicious configurations, or evade detection by modifying security-related registry keys.

# Sentinel / Defender 
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where InitiatingProcessFileName =~ "cmd.exe"
| extend TrimmedCmdLine =  translate(" ","", ProcessCommandLine)  
| where TrimmedCmdLine contains "regadd"
```
