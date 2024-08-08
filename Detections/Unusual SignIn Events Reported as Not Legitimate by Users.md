# Detection of Unusual Sign-In Events Reported as Not Legitimate by Users

# Description
This analytic rule identifies unusual sign-in events that legitimate users have reported as not legitimate. Such reports could indicate potential account compromise, and monitoring these events is crucial for maintaining the security of cloud accounts.

# Sentinel / Defender
```kql

AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName =~ "User reported unusual sign-in event as not legitimate"
// | mv-expand AdditionalDetails to typeof(dynamic)
// | extend KeyValue= pack(tostring(AdditionalDetails.key), AdditionalDetails.value)
// | evaluate bag_unpack(KeyValue, 'AdditionalDetails_')
| extend user = parse_json(InitiatedBy.user)
| evaluate bag_unpack(user, 'user_')
| mv-expand TargetResources to typeof(dynamic)
| evaluate bag_unpack(TargetResources, 'TargetResources_')
| extend TargetResources_id = tostring(TargetResources_id)
| join kind=leftouter SigninLogs on $left.TargetResources_id == $right.Id
| join kind=leftouter (IdentityLogonEvents
    | extend RequestID = tostring(parse_json(AdditionalFields)['Request ID']))
    on $left.TargetResources_id == $right.RequestID
| extend ['Time AEST'] = datetime_utc_to_local(ActivityDateTime, 'Australia/Canberra')
| extend ['Time AEST']= format_datetime(['Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project
    ['Time AEST'],
    SourceSystem,
    OperationName,
    Category,
    user_userPrincipalName,
    TargetResources_displayName,
    AppDisplayName, 
    AuthenticationContextClassReferences,
    AuthenticationDetails,
    AuthenticationProcessingDetails,
    AuthenticationRequirement,
    ClientAppUsed,
    ConditionalAccessStatus,
    IsInteractive,
    DeviceDetail,
    IPAddress,
    LocationDetails,
    NetworkLocationDetails,
    Status,
    DeviceType,
    OSPlatform
```
