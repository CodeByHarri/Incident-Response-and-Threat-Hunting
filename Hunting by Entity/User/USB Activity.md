# User USB Activity

# Description
This query retrieves USB drive mount events for a specific user over the last 21 days, then joins with file creation events on these USB drives over the last 90 days. It extends details about the USB drive and files copied to it, including manufacturer, drive letter, product name, file names, and file sizes. The results are summarized to show the total copy size in GB, files copied, folder paths, and file count, ordered by the total copy size.

# Sentinel
```kql
EmailEvents
| where TimeGenerated > ago(90d)
| extend SNOWID = extract("(REQ|INC|CHG)[0-9]{7}", 0, Subject)
| where SNOWID != ""
| where (Subject contains "Your incident INC0") or (Subject contains "Request REQ" and Subject endswith "has been opened on your behalf")or (Subject contains "CHG0" and Subject contains "has been assigned to you" )
| where RecipientEmailAddress =~ "@{body('Get_user')?['userPrincipalName']}"
| summarize ['Min Generated Time AEST']=min(TimeGenerated) by SNOWID
| extend ['Min Generated Time AEST'] = datetime_utc_to_local(['Min Generated Time AEST'],'Australia/Canberra')
| sort by ['Min Generated Time AEST'] desc
| extend ['Min Generated Time AEST'] = format_datetime(['Min Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```
