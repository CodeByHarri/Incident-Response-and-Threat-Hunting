# Closing Classification Trend by Day


```kql
SecurityIncident 
| where TimeGenerated > ago (90d) 
| extend temptime = CreatedTime + 12h // converting from UTC to AEST
| extend SOD = startofday(CreatedTime) 
| extend workday = dayofweek(temptime) 
| extend workhour = hourofday(temptime) 
// | where Status == 'Closed' 
| extend Tactics = todynamic(AdditionalData.tactics) 
| extend Owner = todynamic(Owner.assignedTo)  
| extend Product = todynamic((parse_json(tostring(AdditionalData.alertProductNames))[0]))  
| extend feedback =strcat(Classification," ",ClassificationReason) 
| summarize dcount(IncidentNumber) by feedback, bin(SOD, 1d) 
```
