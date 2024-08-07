# Process Injection via CreateRemoteThread API Call

# Description
This detection is designed to identify potential process injection techniques leveraging the CreateRemoteThread API call within Windows environments. By analyzing process creation events and API calls, this query helps security analysts detect suspicious behavior indicative of malware or unauthorized code execution.

# References
**MITRE**: https://attack.mitre.org/techniques/T1055/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md

# Sentinel / Defender
```kql
let query1=DeviceEvents
//Identifying when CreateRemoteThread API call is being made to the process by the parent process
| where ActionType contains "CreateRemoteThreadApiCall" and isnotempty( FileName) and isnotempty( InitiatingProcessFileName)
//Whitelist known parent process and related activities
// using join to identify what DLL was loaded into the process on which CreateRemoteThreadAPI call was initiated
| join kind=inner DeviceImageLoadEvents on $left.FileName == $right.InitiatingProcessFileName and $left.DeviceName == $right.DeviceName
| where ActionType1 contains "ImageLoad" and (TimeGenerated1 - TimeGenerated) between (0s..1s)//Timedifference is extremely small between ImageLoad events and API call event
//Whitelisting known DLLs and paths
let uniontables = union DeviceProcessEvents, DeviceNetworkEvents;
//This query then looks for process and network events initiated by the process once the DLL was loaded
let query2=query1
| join kind=inner (uniontables) on $left.FileName == $right.InitiatingProcessFileName and $left.DeviceName == $right.DeviceName
| where (TimeGenerated2 - TimeGenerated1) between (0s..1s);
union query1, query2
```
