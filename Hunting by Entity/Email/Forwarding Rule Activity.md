# Forwarding Rule Activity

# Description
This query helps security teams monitor and investigate the creation or update of forwarding rules in Office 365 mailboxes, which can be a sign of account compromise or unauthorized data forwarding. By summarizing this information, it provides a clear view of potential risks associated with mailbox rules for each user.

# Sentinel / Defender 
```kql
OfficeActivity
| where TimeGenerated >= ago(90d)
| where Operation == "UpdateInboxRules"
| extend ActionType_ = tostring(parse_json(tostring(OperationProperties[6].Value))[0].ActionType)
| extend Recipients_ = tostring(parse_json(tostring(parse_json(tostring(OperationProperties[6].Value))[0].Recipients))[0])
| extend RuleCondition_ = tostring(parse_json(tostring(OperationProperties[3].Value)))
| extend RuleName_ = tostring(parse_json(tostring(OperationProperties[4].Value)))
| extend RuleState_ = tostring(parse_json(tostring(OperationProperties[2].Value)))
| where ActionType_ contains "forward"
| summarize Recipients = strcat_array(make_set(Recipients_,10),', '), 
RuleCondition = strcat_array(make_set(RuleCondition_,10),', '), 
RuleName = strcat_array(make_set(RuleName_,10),', '), 
RuleState = strcat_array(make_set(RuleState_,10),', '), dcount(RuleCondition_)
by UserId
```
