# Hard Delete Administrative Unit Events

# Description
This analytic rule identifies hard delete administrative unit events, which can indicate potential malicious intent to disrupt management and remove control structures. Monitoring such events is crucial for maintaining the integrity and continuity of administrative operations.

# Sentinel/ Defender
``kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName contains "Hard Delete administrative unit"
| mv-expand TargetResources to typeof(dynamic)
| evaluate bag_unpack(TargetResources, 'TargetResources_')
| extend user = parse_json(InitiatedBy)['user']
| evaluate bag_unpack(user, 'InitiatedBy_')
| extend ['Time AEST'] = datetime_utc_to_local(ActivityDateTime, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project
    ['Time AEST'],
    OperationName,
    Result,
    Identity,
    InitiatedBy,
    TargetResources_id,
    TargetResources_displayName,
    TargetResources_modifiedProperties,
    TargetResources_type,
    AdditionalDetails
```
