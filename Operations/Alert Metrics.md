# Alert by product name
```kql
SecurityAlert 
| where TimeGenerated > ago(90d) 
| summarize count() by ProductName, bin(TimeGenerated, 1d)
```  

# Alert by Severity. 
```kql
SecurityAlert 
| where TimeGenerated >ago(90d) 
| summarize count() by AlertSeverity, bin(TimeGenerated, 1d)
```

# Incidents by name and time. 
```kql
SecurityIncident 
| where CreatedTime  between ( ago(90d)  .. now() ) 
| extend Title = replace_string(replace_string(replace_string(replace_string(Title, 'on one endpoint',''),'on multiple endpoints',''),'involving multiple users',''),'involving one user','') 
| extend Title = trim(@"\s", Title) 
| summarize count() by Title, bin(CreatedTime, 1d)
```
 

 
