# curl.exe Usage

# Description
This query helps in identifying and analyzing the usage of curl.exe on devices within the network. By monitoring these events, security teams can detect and investigate potential data transfers or suspicious activities involving the curl tool, ensuring network security and data integrity.

# Sentinel / Defender
```kql
union Device*
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where InitiatingProcessFileName =~ "curl.exe" or InitiatingProcessParentFileName =~ "curl.exe"
| summarize FileNames  = strcat_array(make_set(FileName,5),', '),
ProcessCommandLine  = strcat_array(make_set(ProcessCommandLine,5),', '),
InitiatingProcessCommandLine  = strcat_array(make_set(InitiatingProcessCommandLine,5),', ') by InitiatingProcessAccountUpn, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName
```
