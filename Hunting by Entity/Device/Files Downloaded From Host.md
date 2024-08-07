# Files Downloaded From Host

# Description
This query retrieves file download events from a specific device over the last 30 days. It filters events where the device name matches a given pattern and where the file origin URL is not empty. The query extends details to extract the referrer host from the file origin referrer URL. The results are summarized to show the count of download events and list of filenames, grouped by referrer host, device name, and the account name that initiated the process.

# Sentinel / Defender
```kql
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where DeviceName contains "@{variables('devicename')}"
| where FileOriginUrl contains ""
| extend ReferrerHost=tostring(parse_url(FileOriginReferrerUrl).Host)
| summarize count(), Files=strcat_array(make_set(FileName,20),', ') by ReferrerHost, DeviceName, InitiatingProcessAccountName 
```
