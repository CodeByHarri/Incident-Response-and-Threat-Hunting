#Delete Conditional Access Policy Events

# Description
This analytic rule identifies delete conditional access policy events, which can indicate attempts to bypass security measures. Monitoring such events is crucial for maintaining the integrity of access controls.

# Sentinel /Defender
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName contains "Delete conditional access policy"
| mv-expand TargetResources to typeof(dynamic)
| evaluate bag_unpack(TargetResources, 'TargetResources_')
| mv-expand TargetResources_modifiedProperties to typeof(dynamic)
| evaluate bag_unpack(TargetResources_modifiedProperties, 'TargetResources_mP_')
| extend user = parse_json(InitiatedBy)['user']
| evaluate bag_unpack(user, 'InitiatedBy_')
| extend ['Time AEST'] = datetime_utc_to_local(ActivityDateTime, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project
    ['Time AEST'],
    OperationName,
    Result,
    InitiatedBy_id,
    InitiatedBy_userPrincipalName,
    TargetResources_displayName,
    TargetResources_mP_displayName,
    TargetResources_mP_oldValue,
    TargetResources_modifiedProperties,
    AdditionalDetails
```
