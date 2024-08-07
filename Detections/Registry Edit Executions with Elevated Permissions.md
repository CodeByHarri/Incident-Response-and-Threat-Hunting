# Registry Edit Executions with Elevated Permissions

# Description
This query helps in identifying potentially unauthorized or suspicious executions of the regedit.exe tool with elevated permissions, which can be an indication of attempts to modify critical system settings or registry keys. By monitoring these events, security teams can detect and investigate unauthorized registry changes that may compromise system security.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where ((ProcessCommandLine contains " /E " or ProcessCommandLine contains " -E ") and (FolderPath endswith "\\regedit.exe" or ProcessVersionInfoOriginalFileName =~ "REGEDIT.EXE")) and (not(((ProcessCommandLine contains "hklm" or ProcessCommandLine contains "hkey_local_machine") and (ProcessCommandLine endswith "\\system" or ProcessCommandLine endswith "\\sam" or ProcessCommandLine endswith "\\security"))))
| summarize count() by FileName, ProcessCommandLine
```
