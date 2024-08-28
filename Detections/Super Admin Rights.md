# super administrator rights - possible ligolo-ng usage (agent.exe)

# Description
This analytic rule is designed to detect potential usage of Ligolo-ng, a tunneling tool often used by attackers for lateral movement and network exploitation. Specifically, it focuses on identifying instances where super administrator rights are invoked, which may indicate unauthorized or malicious activity.

# Sentinel / Defender
```kql
DeviceEvents
| where TimeGenerated >ago(90d)
| extend Description = tostring(parse_json(AdditionalFields).Description)
| where ActionType contains "Other" 
| where Description contains "super administrator rights"
| summarize count() by InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, Description
```
