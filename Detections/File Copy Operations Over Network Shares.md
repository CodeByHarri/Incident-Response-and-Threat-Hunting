# File Copy Operations Over Network Shares

# Description
This query helps in identifying potentially unauthorized or suspicious file copy operations over network shares, which can be an indication of data exfiltration attempts. By monitoring these events, security teams can detect and investigate unauthorized data transfers, ensuring the security and integrity of sensitive data.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where ((ProcessCommandLine contains "\\\\" and ProcessCommandLine contains "$") or ProcessCommandLine contains "\\Sysvol\\") and (((FolderPath endswith "\\robocopy.exe" or FolderPath endswith "\\xcopy.exe") or (ProcessVersionInfoOriginalFileName in~ ("robocopy.exe", "XCOPY.EXE"))) or (ProcessCommandLine contains "copy" and (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe")) or ((ProcessCommandLine contains "copy-item" or ProcessCommandLine contains "copy " or ProcessCommandLine contains "cpi " or ProcessCommandLine contains " cp " or ProcessCommandLine contains "move " or ProcessCommandLine contains "move-item" or ProcessCommandLine contains " mi " or ProcessCommandLine contains " mv ") and ((FolderPath contains "\\powershell.exe" or FolderPath contains "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))))
| summarize count() by DeviceName, InitiatingProcessAccountUpn, ProcessCommandLine
```
