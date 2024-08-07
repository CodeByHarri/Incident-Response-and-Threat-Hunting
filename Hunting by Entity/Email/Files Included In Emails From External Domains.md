# Files Included In Emails From External Domains

# Description
This query retrieves email events and attachment information for emails involving a specific user over the last 60 days. It focuses on emails where the sender or recipient is from an external domain and joins with the attachment information table to list attachments in these emails, excluding certain image and temporary files. The results summarize the distinct count of filenames and list these filenames, grouped by the start of the month (SOM) in AEST.

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago (60d)
| where RecipientEmailAddress =~ "" or SenderFromAddress =~ "" or SenderMailFromAddress =~ ""
| where not(SenderFromAddress in( "noreply@email.teams.microsoft.com" ,"noreply@microsoft.com","noreply@yammer.com","no-reply@sharepointonline.com"))
| where SenderFromAddress !endswith {CLIENT EMAIL} and SenderFromAddress !endswith {CLIENT EMAIL}
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId
// | join  kind=leftouter EmailUrlInfo on NetworkMessageId
| where FileName !startswith "image0" and FileName !startswith "ATT0000"
| where not(FileName contains "-" and FileName != ".")
| summarize dcount(FileName), FileNames = strcat_array(make_set(FileName,30),', ') by ['SOM AEST']=startofmonth(TimeGenerated)
| sort by ['SOM AEST'] desc 
| extend ['SOM AEST'] = format_datetime(['SOM AEST'], 'dd-MM-yy')
```
