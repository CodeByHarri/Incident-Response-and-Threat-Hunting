# Out-of-Office (OOO) Messaging

# Description
This query helps security teams and administrators monitor and investigate the use of out-of-office auto-reply settings in Office 365 mailboxes. By summarizing this information, it provides a clear view of potential OOO periods and their associated settings for each user, which can be useful for detecting unusual or unauthorized configuration changes.

# Sentinel / Defender
```kql
OfficeActivity
| where TimeGenerated > ago(90d)
| where UserId =~ "@{variables('upn')}"
| where Operation =~ "Set-MailboxAutoReplyConfiguration"
| mv-expand parse_json(Parameters)
| evaluate bag_unpack(Parameters, OutputColumnPrefix='Entities_')
| project TimeGenerated, UserId, Entities_Name, tostring(Entities_Value)
| evaluate pivot(Entities_Name,take_any(Entities_Value))
| extend  ['Last Time Generated AEST'] = TimeGenerated
| project-away TimeGenerated
| extend ['Last Time Generated AEST'] = datetime_utc_to_local(['Last Time Generated AEST'],'Australia/Canberra')
| extend ['Last Time Generated AEST'] = format_datetime(['Last Time Generated AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project-rename ['Auto Decline Future Requests When OOF']=AutoDeclineFutureRequestsWhenOOF
| project-reorder ['Last Time Generated AEST'], UserId, ExternalMessage, InternalMessage
```
