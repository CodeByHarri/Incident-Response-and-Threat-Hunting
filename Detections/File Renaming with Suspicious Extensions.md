# File Renaming with Suspicious Extensions

## Description
File renaming events where benign file types (e.g., `.docx`, `.jpg`) are converted into more suspicious types (e.g., `.exe`, `.dll`) may indicate malicious activities. Attackers often disguise malicious files by renaming them to evade detection or to execute scripts and binaries. This query can help detect such activity by monitoring for these renaming patterns.

## References
**MITRE**: https://attack.mitre.org/techniques/T1560/003/

## Sentinel / Defender
```kql
let Timeframe = 90d;
let SuspiciousExtensions = dynamic([".dll", ".txt", ".ps1", ".zip", ".rar", ".tar", ".exe", ".bat", ".scr", ".vbs", ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".7z", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".lz", ".lzma", ".z", ".zipx", ".wim", ".jar", ".iso", ".arj", ".ace", ".cab", ".lzh", ".sfx", ".sz", ".apk", ".dmg", ".img"]);
let OriginalExtension = dynamic(['.pdf', '.docx', '.jpg', '.xlsx', '.pptx', '.txt', '.wav']);
DeviceFileEvents
| where TimeGenerated > ago(Timeframe)
| where ActionType == "FileRenamed"
| where InitiatingProcessAccountName != "system"
| where PreviousFileName has_any (OriginalExtension)
| extend OldFileName = PreviousFileName
| extend NewFileName = FileName
| extend OldFileNameExtension = tostring(split(PreviousFileName, '.')[-1]) 
| where OldFileNameExtension != "crdownload"
| extend NewFileNameExtension = tostring(split(FileName, '.')[-1]) 
| where NewFileName has_any (SuspiciousExtensions)
| where OldFileNameExtension != NewFileNameExtension
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FolderPath, OldFileName, OldFileNameExtension, NewFileName, NewFileNameExtension, InitiatingProcessCommandLine
```
