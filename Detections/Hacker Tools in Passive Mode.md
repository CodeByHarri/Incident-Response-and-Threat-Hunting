# HackerTools Running in Passive mode

# Description
A actor may try run tools by adding it to defender exclusions. an actor will enumerate the anti virus policies once they have local admin, then spoof hackertools as binaries that are whitelisted in defender policies  

# Sentinel / Defender
```kql
DeviceEvents
| where TimeGenerated >ago(90d)
| extend ReportSource = tostring(parse_json(AdditionalFields).ReportSource)
| where ActionType contains "AntivirusDetectionActionType" 
| where ReportSource contains "passive mode"
| summarize count(), make_set(ReportSource), dcount(ReportSource,4) by InitiatingProcessAccountName, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName
```
