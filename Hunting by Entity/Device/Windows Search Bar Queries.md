# Windows Search Bar Queries

# Description
What Search Queries are made on the device or by a user using the windows search bar

# Sentinel / Defender
```kql
DeviceProcessEvents
| where TimeGenerated > ago(90d) 
| where DeviceName contains "{DEVICENAME}" or AccountUpn =~ "{UPN}"
| where ProcessCommandLine contains  "msedge.exe" 
| extend EncodedUrl = extract(@"url=([^&]+)", 1, ProcessCommandLine)
| extend DecodedUrl = url_decode(EncodedUrl)
| extend QueryString = extract(@"q=([^&]+)", 1, DecodedUrl)
| extend FinalQueryString = replace_string(url_decode(QueryString), "+", " ")
| extend UPN = extract(@"upn=([^&]+)", 1, ProcessCommandLine)
| extend UPN = url_decode(UPN)
| where QueryString != "" or UPN != ""
| summarize SearchBarQueries = strcat_array(make_set(FinalQueryString),', '),
// ProcessCommandLines = strcat_array(make_set(ProcessCommandLine),', '),
// UrlParameter = strcat_array(make_set( DecodedUrl ),', ')
dcount(FinalQueryString,4)
 by bin(TimeGenerated,1d), AccountUpn, UPN
```
