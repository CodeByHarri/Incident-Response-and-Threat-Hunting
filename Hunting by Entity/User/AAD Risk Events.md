# AAD Risk Events

# Description
This query retrieves Azure Active Directory (AAD) user risk events for a specific user over the last 90 days. It summarizes details about the risk events, including user display name, risk level, risk state, risk event type, and additional information. The results are formatted to show the last time generated in Australian Eastern Standard Time (AEST), sorted by this time

# Sentinel / Defender
```kql
AADUserRiskEvents
| where TimeGenerated >ago(90d)
| where UserPrincipalName contains "@{variables('upn')}"
| summarize ['Last Time Generated AEST']=max(TimeGenerated) by UserDisplayName, RiskLevel, RiskState, RiskEventType, RiskDetail, tostring(AdditionalInfo)
| sort by ['Last Time Generated AEST'] desc
| extend ['Last Time Generated AEST'] = datetime_utc_to_local(['Last Time Generated AEST'],'Australia/Canberra')
| extend ['Last Time Generated AEST'] = format_datetime(['Last Time Generated AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```
