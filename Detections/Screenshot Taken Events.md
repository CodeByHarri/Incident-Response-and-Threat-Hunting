# Screenshot Taken Events

# Description
By using this query, security teams can monitor and investigate instances of screenshots being taken on devices, which may indicate unauthorized attempts to capture and exfiltrate sensitive information.

# Sentinel / Defender
```kql
DeviceEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where ActionType == 'ScreenshotTaken'
| project-reorder
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountUpn,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName
```
