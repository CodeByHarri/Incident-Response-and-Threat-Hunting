# Command Line Activity Initiated by User

# Description
This query looks for user initiated command line activity and summarises the events proceeding by the Parent Process

# Sentinel / Defender
```kql
DeviceProcessEvents
| where TimeGenerated >ago(1d)
| sort by TimeGenerated asc
| serialize
| extend ChangeGroup = iif(InitiatingProcessParentCreationTime != prev(InitiatingProcessParentCreationTime, 1), 1, 0)
| extend ChangeID = row_cumsum(ChangeGroup)
| where InitiatingProcessAccountName =~ "{ACCOUNTNAME}"
| summarize make_set(ProcessCommandLine),  delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by ChangeID, InitiatingProcessId, InitiatingProcessFileName
```
