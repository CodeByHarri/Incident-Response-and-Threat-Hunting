# Personal Email Events

# Description
This query retrieves email events and attachment information for emails involving a specific user over the last 60 days, focusing on personal email accounts. It filters for emails where the sender or recipient domain matches common personal email providers and joins with the attachment information table to list attachments in these emails. The results summarize the distinct count of email subjects and list these subjects and filenames, grouped by the start of the month (SOM) in AEST and sender domain.

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago (60d)
| where RecipientEmailAddress =~ "{UPN}" or SenderFromAddress =~ "{UPN}" or SenderMailFromAddress =~ "{UPN}"
| where SenderFromDomain has_any ("gmail.com",     "yahoo.com",     "hotmail.com",     "outlook.com",     "aol.com",     "live.com",     "msn.com",     "bigpond.com",     "optusnet.com.au",     "comcast.net",     "yahoo.co.uk",     "yahoo.co.in",     "live.co.uk",     "yahoo.co.jp",     "icloud.com") or RecipientEmailAddress has_any ("gmail.com",     "yahoo.com",     "hotmail.com",     "outlook.com",     "aol.com",     "live.com",     "msn.com",     "bigpond.com",     "optusnet.com.au",     "comcast.net",     "yahoo.co.uk",     "yahoo.co.in",     "live.co.uk",     "yahoo.co.jp",     "icloud.com")
| where not(SenderFromAddress in( "noreply@email.teams.microsoft.com" ,"noreply@microsoft.com","noreply@yammer.com","no-reply@sharepointonline.com"))
| extend RecipientDomain=tostring(split(RecipientEmailAddress,'@')[1])
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId
// | join  kind=leftouter EmailUrlInfo on NetworkMessageId
| where FileName !startswith "image0" and FileName !startswith "ATT0000"
| where not(FileName contains "-" and FileName != ".")
| summarize dcount(Subject,4), Subject = strcat_array(make_set(Subject,30),', '), FileNames= strcat_array(make_set(FileName,30),', '), SenderAddresses=strcat_array(make_set(SenderFromAddress,30),', '), RecipientAddreses=strcat_array(make_set(RecipientEmailAddress,30),', ') by ['SOM AEST']=startofmonth(TimeGenerated),SenderFromDomain, RecipientDomain
| sort by ['SOM AEST'] desc 
| extend ['SOM AEST'] = format_datetime(['SOM AEST'], 'dd-MM-yy')
```
