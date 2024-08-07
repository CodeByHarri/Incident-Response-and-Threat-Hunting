# Group Memberships

# Description
This query retrieves group membership information for a specific user over the last 7 days. It expands the group membership list, then summarizes the groups and assigned roles, along with the department information, and takes a distinct record.

# Sentinel / Defender
```kql
IdentityInfo
| where TimeGenerated > ago(7d)
| where AccountUPN =~ "@{body('Get_user')?['userPrincipalName']}"
| mv-expand GroupNameList = parse_json(GroupMembership)
| distinct GroupMembership=strcat_array(GroupMembership,', '), AssignedRoles=strcat_array(AssignedRoles,', '), Department
| take 1
```
