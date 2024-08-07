# BITS Admin and PowerShell BITS Transfer 

# Description
This query helps in detecting the use of BITS for data transfer operations, which can be an indication of data exfiltration or malicious file downloads. By monitoring these events, security teams can detect and respond to suspicious activities involving BITS, which is often used by attackers to bypass traditional network defenses.

# Sentinel / Defender
```kql
let powershellcommands = dynamic(["BitsTransfer", "Add-BitsFile", "Complete-BitsTransfer", "Get-BitsTransfer", "Remove-BitsTransfer", "Resume-BitsTransfer", "Set-BitsTransfer", "Start-BitsTransfer", "Suspend-BitsTransfer"]);
let commandline = DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has "create" or ProcessCommandLine has "download" or ProcessCommandLine has "transfer";
let powershell = DeviceEvents
| where set_has_element(powershellcommands, tostring(AdditionalFields["Command"]));
union commandline, powershell
| summarize Command  = strcat_array(make_set(tostring(AdditionalFields["Command"])),', '),
ProcessCommandLine  = strcat_array(make_set(ProcessCommandLine),', ')
by  DeviceName, InitiatingProcessAccountUpn
```
