# Domain Recon Activities

# Description
Looks for strings that perform domain recon in the command line

# Sentinel / Defender
```kql
let powershellCommands = dynamic(['querysession', 'nltest/domain_trusts', 'nltest/dclist:', 'netgroup"Enterpriseadmins"/domain', 'netgroup"Domainadmins"/domain', 'dsquerysubnet', 'netshfirewallsetservicetype=remotedesktop', 'netshfirewallsetrulegroup="remotedesktop"', '-accepteula-d-s\\']); 
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| extend TrimCmd = translate(" ", "", ProcessCommandLine)
| where TrimCmd has_any (powershellCommands)
| summarize commands=strcat_array(make_set(ProcessCommandLine),', '), ActionTypes=strcat_array(make_set(ActionType),', '), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by  InitiatingProcessId,InitiatingProcessAccountName,  InitiatingProcessFileName, DeviceName
```
