# External Domain

# Description 
This query retrieves email events involving a specific user over the last 60 days. It focuses on emails where the sender or recipient is from an external domain, excluding certain internal or automated sender addresses. The results summarize the distinct count of sender domains and list these domains, grouped by the start of the month (SOM) in Australian Eastern Standard Time (AEST).

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago (60d)
| where RecipientEmailAddress =~ "@{variables('upn')}" or SenderFromAddress =~ "@{variables('upn')}" or SenderMailFromAddress =~ "@{variables('upn')}"
| where not(SenderFromAddress in( "noreply@email.teams.microsoft.com" ,"noreply@microsoft.com","noreply@yammer.com","no-reply@sharepointonline.com"))
| where SenderFromAddress !endswith {CLIENT EMAIL} and SenderFromAddress !endswith {CLIENT EMAIL}
| summarize dcount(SenderFromDomain), Domains = strcat_array(make_set(SenderFromDomain,30),', ') by ['SOM AEST']=startofmonth(TimeGenerated)
| sort by ['SOM AEST'] desc 
| extend ['SOM AEST'] = format_datetime(['SOM AEST'], 'dd-MM-yy')
```

