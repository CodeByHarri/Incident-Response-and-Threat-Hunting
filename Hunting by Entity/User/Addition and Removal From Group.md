# Addition and Removal from Groups

# Description
This query retrieves group membership change events for a specific user over the last 90 days. It extends details about the change events, including actor account, target user, groups the user was removed from or added to, and the time of the event. The results are formatted to show the minimum generated time in Australian Eastern Standard Time (AEST), sorted by this time.

# Sentinel / Defender
```kql
IdentityDirectoryEvents
| where TimeGenerated > ago(90d)
| where ActionType == "Group Membership changed"
| where TargetAccountUpn contains "@{body('Get_user')?['userPrincipalName']}"
| extend AdditionalFields = parse_json(AdditionalFields)
| extend ['Min Generated Time AEST'] = datetime_utc_to_local(TimeGenerated,'Australia/Canberra')
| sort by ['Min Generated Time AEST'] desc
| extend ['Min Generated Time AEST'] = format_datetime(['Min Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| distinct  ['Min Generated Time AEST'],
ActorAccount = tostring(AdditionalFields['ACTOR.ACCOUNT']),
EntityUser = tostring(AdditionalFields['TARGET_OBJECT.ENTITY_USER']),
Got_Remove_From_Group = tostring(AdditionalFields['FROM.GROUP']),
Got_Added_To_Group = tostring(AdditionalFields['TO.GROUP'])
```
