# Tickets with Service Desk

# Description
This query retrieves ServiceNow (SNOW) ticket-related email events for a specific user over the last 90 days. It filters by specific keywords in the email subjects to identify incident (INC), request (REQ), and change (CHG) tickets. The results are summarized and formatted to show the minimum generated time in AEST.

# Sentinel / Defender
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

