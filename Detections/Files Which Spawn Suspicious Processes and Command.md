#  Files Which Spawn Suspicious Processes and Command Lines

# Description
This query helps in identifying potential misuse of scripting engines and command interpreters, which are often exploited by attackers for executing malicious payloads, conducting lateral movements, or performing other nefarious activities on the network.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where InitiatingProcessFileName has_any (@"powershell.exe", @"pwsh.exe", @"wscript.exe", @"cscript.exe", @"mshta.exe", @"cmd.exe")
| summarize dcount(ProcessCommandLine), ProcessCommandLine=strcat_array(make_set(ProcessCommandLine, 5), ', ') by InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256
// | invoke FileProfile(InitiatingProcessSHA256, 100)
```
