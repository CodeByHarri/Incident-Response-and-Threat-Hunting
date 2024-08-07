# URLs Included In Emails From External Domains

# Description
This query retrieves email events and URL information for emails involving a specific user over the last 60 days. It focuses on emails where the sender or recipient is from an external domain and joins with the URL information table to list URLs in these emails, excluding certain trusted domains. The results summarize the distinct count of URL domains and list these domains, grouped by the start of the month (SOM) in AEST.

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago (60d)
| where RecipientEmailAddress =~ "@{variables('upn')}" or SenderFromAddress =~ "@{variables('upn')}" or SenderMailFromAddress =~ "@{variables('upn')}"
| where not(SenderFromAddress in( "noreply@email.teams.microsoft.com" ,"noreply@microsoft.com","noreply@yammer.com","no-reply@sharepointonline.com"))
| where SenderFromAddress !endswith {CLIENT EMAIL} and SenderFromAddress !endswith {CLIENT EMAIL}
// | join kind=leftouter EmailAttachmentInfo on NetworkMessageId
| join  kind=leftouter EmailUrlInfo on NetworkMessageId
| where not(UrlDomain has_any( "aka.ms","microsoft.com",{CLIENT DOMAIN},"sharepoint.com","windows.net","proofpoint.com","azurewebsites.net","office.com" ))
| summarize dcount(UrlDomain), Domains = strcat_array(make_set(UrlDomain,30),', ') by ['SOM AEST']=startofmonth(TimeGenerated)
| sort by ['SOM AEST'] desc 
| extend ['SOM AEST'] = format_datetime(['SOM AEST'], 'dd-MM-yy')
```
