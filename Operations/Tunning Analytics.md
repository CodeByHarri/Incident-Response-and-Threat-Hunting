# Tunning Reconmendations

```kql
let dcount = SecurityAlert
| where TimeGenerated  between ( ago(7d)  .. now() )
| summarize dAlert=dcount(SystemAlertId) by AlertName
| distinct AlertName, dAlert;
let Alerts = SecurityIncident
| where CreatedTime  between ( ago(7d)  .. now() )
| extend Title = replace_string(replace_string(replace_string(replace_string(Title, 'on one endpoint',''),'on multiple endpoints',''),'involving multiple users',''),'involving one user','')
| extend Title = trim(@"\s", Title)
| top-nested of startofweek(CreatedTime,0)+1d by dcount(IncidentNumber), top-nested 20 of Title by dcount(IncidentNumber)
| project-rename  dcount=aggregated_Title
| distinct Title;
SecurityAlert
| where TimeGenerated  between ( ago(7d)  .. now() )
| where AlertName in (Alerts)
| extend Entities = iff(isempty(Entities), todynamic('[{"dummy" : ""}]'), todynamic(Entities))
| mvexpand Entities
| evaluate bag_unpack(Entities, "Entity_")
| extend Entity_Type = columnifexists("Entity_Type", "")
| extend Entity_Name = columnifexists("Entity_Name", "")
| extend Entity_ResourceId = columnifexists("Entity_ResourceId", "")
| extend Entity_Directory = columnifexists("Entity_Directory", "")
| extend Entity_Value = columnifexists("Entity_Value", "")
| extend Entity_HostName = columnifexists("Entity_HostName", "")
| extend Entity_Address = columnifexists("Entity_Address", "")
| extend Entity_ProcessId = columnifexists("Entity_ProcessId", "")
| extend Entity_Url = columnifexists("Entity_Url", "")
| extend Target = iif(Entity_Type == "account", Entity_Name, iif(Entity_Type == "azure-resource", Entity_ResourceId, iif(Entity_Type == "cloud-application", Entity_Name, iif(Entity_Type == "dns", Entity_Name, iif(Entity_Type == "file", strcat(Entity_Directory, "\\", Entity_Name), iif(Entity_Type == "filehash", Entity_Value, iif(Entity_Type == "host", Entity_HostName, iif(Entity_Type == "ip" , Entity_Address, iif(Entity_Type == "malware", Entity_HostName, iif(Entity_Type == "network-connection", Entity_Name, iif(Entity_Type == "process", Entity_ProcessId, iif(Entity_Type == "registry-key", Entity_Name, iif(Entity_Type == "registry-value", Entity_Name, iif(Entity_Type == "security-group", Entity_Name, iif(Entity_Type == "url", Entity_Url, "NoTarget")))))))))))))))
| where Entity_Type in ("account", "host", "ip", "url", "azure-resource", "cloud-application", "dns", "file", "filehash", "malware", "network-connection", "process", "registry-key", "registry-value", "security-group")
| extend EntityTarget = strcat(Entity_Type,' | ',Target)
| summarize count_AlertName=dcount(SystemAlertId)  by  EntityTarget, AlertName
| order by count_AlertName desc
| where count_AlertName > 3
| where EntityTarget != "process | "
| where EntityTarget != "account | "
| extend EntityTarget = replace_string(tostring(strcat(EntityTarget,' | ', count_AlertName))  ,'.','[.]')
| summarize  ['Entity | no. Alerts']=make_set(EntityTarget,10) by  tostring(AlertName)
| join kind=leftouter (dcount) on AlertName
| project-away AlertName1
| sort by dAlert desc
```
