# Timeline events condensed 

# Sentinel / Defender
```kql
let ac = "{ACCOUNTNAME}"; let dn="{DEVICENAME}" ;
let pe= DeviceProcessEvents
| where TimeGenerated >ago(2d)
| where InitiatingProcessAccountName =~ ac or DeviceName contains dn
| sort by TimeGenerated asc
| serialize
| extend ChangeGroup = iif(InitiatingProcessParentCreationTime != prev(InitiatingProcessParentCreationTime, 1), 1, 0)
| extend ChangeID = row_cumsum(ChangeGroup)
| summarize commands=strcat_array(make_set(ProcessCommandLine),', '), ActionTypes=strcat_array(make_set(ActionType),', '), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by ChangeID, InitiatingProcessId,InitiatingProcessAccountName,  InitiatingProcessFileName, DeviceName;
let de= DeviceEvents
| where TimeGenerated >ago(2d)
| where InitiatingProcessAccountName =~ ac or DeviceName contains dn
| extend ProcessCommandLine = iff(ProcessCommandLine == "" , AdditionalFields, ProcessCommandLine)
| sort by TimeGenerated asc
| serialize
| extend ChangeGroup = iif(InitiatingProcessParentCreationTime != prev(InitiatingProcessParentCreationTime, 1), 1, 0)
| extend ChangeID = row_cumsum(ChangeGroup)
| summarize commands=strcat_array(make_set(ProcessCommandLine),', '),files=strcat_array(make_set(FileName),', '),ActionTypes=strcat_array(make_set(ActionType),', '),  delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by ChangeID, InitiatingProcessId,InitiatingProcessAccountName,  InitiatingProcessFileName, DeviceName;
let ne = DeviceNetworkEvents
| where TimeGenerated >ago(2d)
| where InitiatingProcessAccountName =~ ac or DeviceName contains dn
| extend RemoteUrl = iff(RemoteUrl =="" , RemoteIP, RemoteUrl)
| sort by TimeGenerated asc
| serialize
| extend ChangeGroup = iif(InitiatingProcessParentCreationTime != prev(InitiatingProcessParentCreationTime, 1), 1, 0)
| extend ChangeID = row_cumsum(ChangeGroup)
| summarize URLs_IPs=strcat_array(make_set(RemoteUrl),', '),ActionTypes=strcat_array(make_set(ActionType),', '), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by ChangeID, InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessFileName, DeviceName;
let fe= DeviceFileEvents
| where TimeGenerated > ago(2d)
| where InitiatingProcessAccountName =~ ac or DeviceName contains dn
| where FileName has_any (".txt",".ps1",".zip",".rar",".tar",".exe",".bat",".scr",".vbs", ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".7z", ".tgz", ".tar.gz", ".tar.bz2",  ".tar.xz", ".lz", ".lzma", ".z", ".zipx", ".wim", ".jar", ".iso", ".arj", ".ace", ".cab", ".lzh", ".sfx", ".sz", ".apk", ".dmg", ".img") 
| extend ReferrerHost=tostring(parse_url(FileOriginReferrerUrl).Host)
| extend Referrer_FileURL= strcat(tostring(parse_url(FileOriginReferrerUrl).Host), ', ' ,FileOriginUrl)
| summarize count(), URLs_IPs=strcat_array(make_set(Referrer_FileURL),', '),files=strcat_array(make_set(FileName,200),', ') ,ActionTypes=strcat_array(make_set(ActionType),', '), delta=max(TimeGenerated)-min(TimeGenerated), starttime=min(TimeGenerated), endtime=max(TimeGenerated) by  InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessFileName, DeviceName;
union pe, ne, fe, de
| sort by starttime desc 
| project-reorder InitiatingProcessId,InitiatingProcessFileName, ActionTypes,URLs_IPs, commands, files, starttime, endtime, delta
```
