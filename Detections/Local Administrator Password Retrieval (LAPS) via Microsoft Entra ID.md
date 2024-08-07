# Local Administrator Password Retrieval (LAPS) via Microsoft Entra ID

# Description
LAPS is a Microsoft solution that stores and manages unique local administrator passwords for domain-joined computers, enhancing security by preventing lateral movement using compromised credentials. This query is designed to detect instances where the Local Administrator Password (LAPS) for a device has been retrieved using Microsoft Entra ID.

# References
**MITRE**: https://attack.mitre.org/techniques/T1078/003/

**ATOMIC**: NA

# Sentinel / Defender
```kql
AuditLogs
| where Category contains "Device" and OperationName contains "Recover device local administrator password"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy)["user"]["userPrincipalName"])
| extend UserIPAddress = tostring(parse_json(InitiatedBy)["user"]["ipAddress"])
| extend TargetDevice = tostring(parse_json(TargetResources)[0]["displayName"])
```
