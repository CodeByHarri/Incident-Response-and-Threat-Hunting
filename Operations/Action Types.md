# Get All Action Types
This query will provide a comprehensive view of all action types across different tables over the past 90 days, along with the count of events for each action and table.

# Sentinel/ Defender
``kql
union  *
| where Timestamp > ago(90d)  or TimeGenerated > ago(90d)
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType, ActivityType, Activity)  
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, Table=Type
```
