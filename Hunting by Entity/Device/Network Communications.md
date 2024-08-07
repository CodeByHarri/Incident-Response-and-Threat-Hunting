# Detection of Suspicious Network Events Triggered by Specific Processes on Device

# Description
The result provides a set of remote URLs contacted, the duration of network activity, and the specific time frames for each change in the parent creation time of the initiating processes. This information can help in detecting suspicious activities and potential security incidents involving common web browsers and file explorers on the specified device.

# Sentinel / Defender
```kql
DeviceNetworkEvents
| where TimeGenerated >ago(1d)
| where DeviceId =~ "{deviceid}"
| extend RemoteUrl = iff(RemoteUrl =="" , RemoteIP, RemoteUrl)
| sort by TimeGenerated asc
| serialize
| extend ChangeGroup = iif(InitiatingProcessParentCreationTime != prev(InitiatingProcessParentCreationTime, 1), 1, 0)
| extend ChangeID = row_cumsum(ChangeGroup)
| summarize make_set(RemoteUrl), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by ChangeID, InitiatingProcessId, InitiatingProcessFileName
| where InitiatingProcessFileName has_any ("msedge","explorer","chrome")
```
