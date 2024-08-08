# Delete Policy Events

# Description
This analytic rule identifies delete policy events, which can indicate potential attempts to weaken security controls. Monitoring such events is crucial for identifying and mitigating security risks.

# Sentinel / Defender
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName contains "Delete Policy"
| mv-expand TargetResources to typeof(dynamic)
| evaluate bag_unpack(TargetResources, 'TargetResources_')
| extend TargetResources_id = tostring(TargetResources_id)
| extend user = parse_json(InitiatedBy)['user']
| evaluate bag_unpack(user, 'InitiatedBy_')
| extend ['Time AEST'] = datetime_utc_to_local(ActivityDateTime, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project
    ['Time AEST'],
    OperationName,
    Result,
    InitiatedBy_ipAddress,
    InitiatedBy_userPrincipalName,
    TargetResources_displayName,
    TargetResources_id

```
