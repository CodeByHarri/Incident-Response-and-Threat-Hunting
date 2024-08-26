# Potential Discovery Commands Executed on Devices

# Description
This analytic rule identifies and tracks the execution of potential discovery commands across devices. The commands such as enter-pssession, -Credential, and get-credential are commonly used in remote sessions and credential gathering, which could be leveraged by attackers for lateral movement or privilege escalation. This rule monitors the execution of these commands, providing insights into their usage patterns, including the timeframes and accounts involved.

# Sentinel / Defender
```kql
let discoveryCommands = dynamic(["enter-pssession","-Credential","get-credential"]);
union Device*
| where TimeGenerated >ago(90d)
| extend Command = tostring(parse_json(AdditionalFields).Command)
| extend Commands = parse_command_line(Command,"windows")
| where Commands has_any (discoveryCommands)
| summarize commands=strcat_array(make_set(Command),', '), ActionTypes=strcat_array(make_set(ActionType),', '), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by InitiatingProcessId,InitiatingProcessAccountName,  InitiatingProcessFileName, DeviceName
```
