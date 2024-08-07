# Potential Data Exfiltration Strings

# Description
This enhanced query helps in identifying and analyzing process events that may involve data exfiltration attempts using common cloud services, file sharing platforms, and other exfiltration strings. By monitoring these events, security teams can detect and investigate suspicious data transfer activities, ensuring the security and integrity of sensitive data.

# Sentinel / Defender
```kql
let exfilStrings = dynamic([
    "github", "dropbox", "googledrive", "pastebin", "aws s3", "box.com", "mediafire", 
    "mega.nz", "wetransfer", "transfer.sh", "sendspace", "pcloud", "icloud", "yandex.disk"
]);
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where ProcessCommandLine has_any (exfilStrings)
| summarize ProcessCommandLine = strcat_array(make_set(ProcessCommandLine, 2), ', '), dcount(ProcessCommandLine) by DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessParentFileName
```
