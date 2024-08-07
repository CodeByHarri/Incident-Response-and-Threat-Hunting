# Password Activtity 

# Description
This query is useful for security analysts who need to monitor and investigate password-related activities for specific users within their organization. It helps in identifying suspicious activities, such as password changes, resets, or other modifications that could indicate potential security breaches or policy violations.

# Sentinel / Defender
```kql
union AuditLogs,
IntuneAuditLogs,
IdentityDirectoryEvents,
CloudAppEvents,
BehaviorAnalytics,
SecurityEvent
| where TimeGenerated > ago(28d)
| extend Action = coalesce(OperationName, ActionType, ActivityType, Activity)  
| where Action contains "password"
| extend ['Time AEST'] = datetime_utc_to_local(TimeGenerated, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| search "<UPN>" or "<SAM ID/ AccountName>"
```
