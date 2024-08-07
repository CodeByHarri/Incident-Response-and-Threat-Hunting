# Role Assignments Granted to Azure Service Principal

# Description
Service principals are identities used by applications, services, or automation tools to access Azure resources. By tracking permissions granted to these principals, organizations can ensure that access controls are properly managed and audited. This query helps security teams identify any unexpected or unauthorized permissions granted to service principals.

# Sentinel / Defender
```kql
AuditLogs
| where OperationName contains "Add app role assignment to service principal"
| extend
user=InitiatedBy["user"]["userPrincipalName"],
UserIpAddress = InitiatedBy["user"]["ipAddress"],
app=TargetResources[0]["modifiedProperties"][6]["newValue"],
AppRoleAdded = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue))),
AppRoleDescription = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[2].newValue)))
| where AppRoleAdded contains "ReadWrite" or AppRoleAdded contains "Full" or AppRoleAdded contains "KeyVault"
```
