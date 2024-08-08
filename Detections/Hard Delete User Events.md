# Detection of Hard Delete User Events

# Description
This analytic rule identifies hard delete user events, which can indicate potential malicious activity aiming to remove traces or disrupt operations. Monitoring such events is crucial for identifying and mitigating security risk

# Sentinel / Defender
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName =~ "Hard Delete user"
| extend user = parse_json(InitiatedBy.user)
| evaluate bag_unpack(user, 'InitiatedBy_')
| mv-expand TargetResources to typeof(dynamic)
| evaluate bag_unpack(TargetResources, 'TargetResources_')
| extend TargetResources_id = tostring(TargetResources_id)
| extend ['Time AEST'] = datetime_utc_to_local(ActivityDateTime, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project
    ['Time AEST'],
    SourceSystem,
    OperationName,
    AADOperationType,
    InitiatedBy_ipAddress,
    InitiatedBy_userPrincipalName,
    TargetResources_modifiedProperties,
    TargetResources_type,
    TargetResources_userPrincipalName
```
