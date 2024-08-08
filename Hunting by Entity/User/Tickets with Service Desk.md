# Tickets with Service Desk

# Description
This query retrieves ServiceNow (SNOW) ticket-related email events for a specific user over the last 90 days. It filters by specific keywords in the email subjects to identify request tickets. The results are summarized and formatted to show the minimum generated time in AEST.

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago(90d)
| extend SNOWID = extract("(REQ|{REQUEST}|{TICKET})[0-9]{7}", 0, Subject)
| where SNOWID != ""
| where (Subject contains "Your incident") or (Subject contains "Request" and Subject endswith "ticket")or (Subject contains "change" and Subject contains "ticket" )
| where RecipientEmailAddress =~ "@{body('Get_user')?['userPrincipalName']}"
| summarize ['Min Generated Time AEST']=min(TimeGenerated) by SNOWID
| extend ['Min Generated Time AEST'] = datetime_utc_to_local(['Min Generated Time AEST'],'Australia/Canberra')
| sort by ['Min Generated Time AEST'] desc
| extend ['Min Generated Time AEST'] = format_datetime(['Min Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```

