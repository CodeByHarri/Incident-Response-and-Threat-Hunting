# Compressed File Activity

# Description
This query helps in identifying potentially unauthorized or suspicious activities involving compressed files on the network. By monitoring these events, security teams can detect and investigate unusual file operations, ensuring the security and integrity of data stored in compressed formats.

# Sentinel / Defender 
```kql
let compressedExtensions = dynamic([
    ".zip", ".tar", ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".7z", ".rar", ".tgz", ".tar.gz", ".tar.bz2", 
    ".tar.xz", ".lz", ".lzma", ".z", ".zipx", ".wim", ".jar", ".iso", ".arj", ".ace", ".cab", ".lzh", 
    ".sfx", ".sz", ".apk", ".dmg", ".img"
]);
DeviceFileEvents
| where ActionType != "FileDeleted"
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where FileName has_any (compressedExtensions)
| where InitiatingProcessAccountUpn != ""
| where FileName !startswith  "policy."
| where InitiatingProcessFileName != "OUTLOOK.EXE" and FileName endswith ".gz"
| summarize FileNames  = strcat_array(make_set(FileName,5),', '), dcount(FileName) by DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessParentFileName
```
