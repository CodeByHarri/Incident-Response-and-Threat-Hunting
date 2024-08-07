# Device Logins

# Description
This query retrieves logon events for a specific device over the last 30 days, excluding system accounts ("umfd-" and "dwm-"). It extends details about the logon events, including the generated time in Australian Eastern Standard Time (AEST). The results are summarized to show the total events, last generated time, and account names by action type and logon type.

# Sentinel / Defender
```kql
DeviceLogonEvents
| where TimeGenerated > ago(30d)
| where DeviceName contains "@{variables('tid')}"
| where not(AccountName has_any("umfd-", "dwm-"))
| extend ['Generated Time AEST'] = datetime_utc_to_local(TimeGenerated,'Australia/Canberra')
| summarize ['Total Events']= count(), 
['Last Generated Time AEST']=max(TimeGenerated),  
['Account Name']=strcat_array(make_set(AccountName,10),', ') by ActionType, LogonType
| extend ['Last Generated Time AEST'] = format_datetime(['Last Generated Time AEST'] , 'dd-MM-yy [hh:mm:ss tt]')
```
