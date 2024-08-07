# Execution Of Files From User's Temp Folder via Rundll32

# Description
This KQL (Kusto Query Language) query is designed to detect instances of the rundll32.exe utility executing files located in the directory C:\Users\[REDACTED]\AppData\Local\Temp. By focusing on executions originating from the Temp directory, where malware often resides temporarily, this query helps identify potentially malicious activities within the system.  

# References
**MITRE**: https://attack.mitre.org/techniques/T1218/011/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md

# Sentinel / Defender
```kql
//This query looks for execution of files from C:\Users\[REDACTED]\AppData\Local\Temp via rundll32
let query1=DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| extend CommandLineNoQuotes = replace("\"", "", InitiatingProcessCommandLine)
| where CommandLineNoQuotes startswith "rundll32.exe C:\\Users\\"
| where CommandLineNoQuotes contains "\\AppData\\Local\\Temp\\";
//Exclude common events within your organisation
//This query looks for rundll32 calling CreateRemoteThread API call on LSASS process for either dumping lsass or injection
let query2 =DeviceEvents
| where ActionType contains "CreateRemoteThread"
| where FileName contains "lsass.exe" and InitiatingProcessFileName contains "rundll32";
union query1, query2
```
