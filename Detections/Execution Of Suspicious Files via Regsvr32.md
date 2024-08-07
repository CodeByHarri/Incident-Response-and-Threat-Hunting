# Execution Of Suspicious Files via Regsvr32

# Description
This rule checks for suspicious files spawned from regsvr32.exe with parent process as Office applications, cmd.exe, powershell.exe, etc. This rule is based on Emotet DFIR report.

# References
**MITRE**: https://attack.mitre.org/techniques/T1218/010/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md

# Sentinel / Defender
```kql
DeviceProcessEvents
//Execution of regsvr32
| where FileName contains "regsvr32"
//Suspicious file extension
and (ProcessCommandLine contains ".ocx" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".lnk" or ProcessCommandLine contains ".oof")
//Parent process of regsvr32
and InitiatingProcessFileName has_any ("Excel.exe", "WinWord.exe", "cmd.exe","powershell.exe","powershell_ise.exe","cscript.exe","wscript.exe","POWERPNT.EXE")
//Whitelist common files and command lines observed with regsvr32.exe
```
