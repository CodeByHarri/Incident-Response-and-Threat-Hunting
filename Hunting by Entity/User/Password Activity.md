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

### Hunting by UPN
```kql
// Cloud App Events
let ca = CloudAppEvents
| where TimeGenerated > ago(28d)
| where ActionType contains "password"
| mv-expand parse_json(RawEventData)
| evaluate bag_unpack(RawEventData,  OutputColumnPrefix='Entities_')
| mv-expand parse_json(Entities_Actor)
| evaluate bag_unpack(Entities_Actor,  OutputColumnPrefix='Entities_')
| where Entities_Type == 5;
// Security Events
let se = SecurityEvent
| where TimeGenerated > ago(28d)
| where Activity contains "password"
| join (IdentityInfo | where TimeGenerated > ago(28d) | distinct AccountUPN, SAMAccountName) on $left.TargetUserName==$right.SAMAccountName;
// All other Events
union AuditLogs,
IntuneAuditLogs,
IdentityDirectoryEvents,
ca,
BehaviorAnalytics,
se
| where TimeGenerated > todatetime("2024-09-10")
| extend Action = coalesce(OperationName, ActionType, ActivityType, Activity) // All password action types
| where Action contains "password"
| mv-expand parse_json(TargetResources)
| evaluate bag_unpack(TargetResources,  OutputColumnPrefix='Entities_')
| extend UPN = coalesce(Entities_userPrincipalName,TargetAccountUpn,Entities_ID,AccountUPN)
| extend ['Time AEST'] = datetime_utc_to_local(TimeGenerated, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]') // select which events you care about below
| where Action in ("Account Password changed", "Change user password", "Reset password (self-service)", "Reset user password", "Change password (self-service)", "Change user password.")
| summarize make_list(Action), arg_max(TimeGenerated, ['Time AEST']) by UPN
```
