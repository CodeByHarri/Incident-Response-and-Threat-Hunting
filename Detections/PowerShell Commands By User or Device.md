# PowerShell Commands By User or Device

# Description 
Correlate the PowerShell activity with user logon sessions to identify if the commands were run by legitimate users or malicious actors.

# Sentinel / Defender
```kql
DeviceEvents
| where TimeGenerated > ago (90d)
| where ActionType =~ "PowerShellCommand"
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| extend Command = tostring(parse_json(AdditionalFields)['Command'])
| summarize ['Last Time Generated AEST']=max(TimeGenerated), count() by Command, InitiatingProcessAccountUpn, DeviceName
| sort by ['Last Time Generated AEST'] desc
| extend ['Last Time Generated AEST'] = datetime_utc_to_local(['Last Time Generated AEST'],'Australia/Canberra')
| extend ['Last Time Generated AEST'] = format_datetime(['Last Time Generated AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```

