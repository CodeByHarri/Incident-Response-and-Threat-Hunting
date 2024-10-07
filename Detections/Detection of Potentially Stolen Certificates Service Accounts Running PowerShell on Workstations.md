# Potentially Stolen Certificates: Service Accounts Running PowerShell on Workstations

# Description
This analytic rule identifies potential misuse of service accounts on workstations by detecting instances where these accounts are used to execute PowerShell commands. 

# Sentinel / Defender
```kql
DeviceEvents
| where TimeGenerated >ago(90d)
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where ActionType contains "PowerShell" and InitiatingProcessAccountName startswith "{SERVICE ACCOUNT PREFIX}" and (DeviceName startswith "{PREFIX FOR WORKSTATIONS}" )
| summarize count(), dcount(DeviceName,4), make_set(DeviceName) by Command, InitiatingProcessAccountName
```
