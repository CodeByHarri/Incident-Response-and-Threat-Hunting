# Similar Incidents

```kql
let ai = SecurityIncident
| where TimeGenerated > ago(90d)
| where IncidentNumber == @{variables('tid')}
| project AlertIds;
let sa = SecurityAlert
| where TimeGenerated > ago(90d)
| where SystemAlertId in (ai)
| extend Entities = iff(isempty(Entities), todynamic('[{"dummy" : ""}]'), todynamic(Entities))
| mvexpand Entities
| evaluate bag_unpack(Entities, "Entity_")
| extend Entity_Type = columnifexists("Entity_Type", "")
| extend Entity_Name = columnifexists("Entity_Name", "")
| extend Entity_ResourceId = columnifexists("Entity_ResourceId", "")
| extend Entity_Directory = columnifexists("Entity_Directory", "")
| extend Entity_Value = columnifexists("Entity_Value", "")
| extend Entity_HostName = columnifexists("Entity_HostName", "")
| extend Entity_HostName= substring(Entity_HostName,0,indexof(Entity_HostName,'.'))
| extend Entity_Address = columnifexists("Entity_Address", "")
| extend Entity_ProcessId = columnifexists("Entity_ProcessId", "")
| extend Entity_Url = columnifexists("Entity_Url", "")
| extend Target = iif(Entity_Type == "account", Entity_Name, iif(Entity_Type == "azure-resource", Entity_ResourceId, iif(Entity_Type == "cloud-application", Entity_Name, iif(Entity_Type == "dns", Entity_Name, iif(Entity_Type == "file", strcat(Entity_Directory, "\\", Entity_Name), iif(Entity_Type == "filehash", Entity_Value, iif(Entity_Type == "host", Entity_HostName, iif(Entity_Type == "ip" , Entity_Address, iif(Entity_Type == "malware", Entity_HostName, iif(Entity_Type == "network-connection", Entity_Name, iif(Entity_Type == "process", Entity_ProcessId, iif(Entity_Type == "registry-key", Entity_Name, iif(Entity_Type == "registry-value", Entity_Name, iif(Entity_Type == "security-group", Entity_Name, iif(Entity_Type == "url", Entity_Url, "NoTarget")))))))))))))))
| where Entity_Type in ("account", "host", "ip", "url", "azure-resource", "cloud-application", "dns", "file", "filehash", "malware", "network-connection", "process", "registry-key", "registry-value", "security-group")
// | extend EntityTarget = strcat(Entity_Type,' | ',Target)
| where Target != ""
| summarize make_set(Target);
let sa2 = SecurityAlert
| where TimeGenerated > ago(90d)
| extend Entities = iff(isempty(Entities), todynamic('[{"dummy" : ""}]'), todynamic(Entities))
| mvexpand Entities
| evaluate bag_unpack(Entities, "Entity_")
| extend Entity_Type = columnifexists("Entity_Type", "")
| extend Entity_Name = columnifexists("Entity_Name", "")
| extend Entity_ResourceId = columnifexists("Entity_ResourceId", "")
| extend Entity_Directory = columnifexists("Entity_Directory", "")
| extend Entity_Value = columnifexists("Entity_Value", "")
| extend Entity_HostName = columnifexists("Entity_HostName", "")
| extend Entity_HostName= substring(Entity_HostName,0,indexof(Entity_HostName,'.'))
| extend Entity_Address = columnifexists("Entity_Address", "")
| extend Entity_ProcessId = columnifexists("Entity_ProcessId", "")
| extend Entity_Url = columnifexists("Entity_Url", "")
| extend Target = iif(Entity_Type == "account", Entity_Name, iif(Entity_Type == "azure-resource", Entity_ResourceId, iif(Entity_Type == "cloud-application", Entity_Name, iif(Entity_Type == "dns", Entity_Name, iif(Entity_Type == "file", strcat(Entity_Directory, "\\", Entity_Name), iif(Entity_Type == "filehash", Entity_Value, iif(Entity_Type == "host", Entity_HostName, iif(Entity_Type == "ip" , Entity_Address, iif(Entity_Type == "malware", Entity_HostName, iif(Entity_Type == "network-connection", Entity_Name, iif(Entity_Type == "process", Entity_ProcessId, iif(Entity_Type == "registry-key", Entity_Name, iif(Entity_Type == "registry-value", Entity_Name, iif(Entity_Type == "security-group", Entity_Name, iif(Entity_Type == "url", Entity_Url, "NoTarget")))))))))))))))
| where Entity_Type in ("account", "host", "ip", "url", "azure-resource", "cloud-application", "dns", "file", "filehash", "malware", "network-connection", "process", "registry-key", "registry-value", "security-group")
| distinct Target, SystemAlertId
| where Target has_any (sa);
// | summarize make_set(SystemAlertId);
SecurityIncident
| where TimeGenerated > ago(90d)
| mv-expand AlertIds
| extend AlertIds = tostring(AlertIds)
| join sa2 on $left.AlertIds == $right.SystemAlertId
| extend Title = replace_string(replace_string(replace_string(replace_string(Title, 'on one endpoint',''),' on multiple endpoints',''),'involving multiple users',''),'involving one user','')
| extend Title = trim(@"\s", Title)
| summarize 
['Max Generated Time AEST']=max(TimeGenerated), 
Entites=strcat_array(make_set(Target),', '),
IncidentNumber=strcat_array(make_set(IncidentNumber),', ')  by  Title
| extend ['Max Generated Time AEST'] = datetime_utc_to_local(['Max Generated Time AEST'],'Australia/Canberra')
| sort by ['Max Generated Time AEST'] desc
| extend ['Max Generated Time AEST'] = format_datetime(['Max Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| take 7
```
