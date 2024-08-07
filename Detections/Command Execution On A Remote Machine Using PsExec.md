# Command Execution On A Remote Machine Using PsExec

# Description
PsExec is often leveraged by administrators for legitimate purposes but can also be exploited by attackers for malicious activities. Security teams can utilize this query to monitor for unauthorized use of PsExec, enabling rapid detection and response to potential security threats or policy violations.

# References
**MITRE**: https://attack.mitre.org/techniques/T1569/002/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md

# Sentinel / Defender
```kql
DeviceNetworkEvents
| where (RemotePort == 135 or RemotePort == 445 or RemotePort == 139 or RemotePort > 49152)
| where InitiatingProcessCommandLine contains "psexec"
| join kind=inner ( DeviceFileEvents
| where InitiatingProcessFolderPath endswith "ntoskrnl.exe" and ShareName =~ "ADMIN$" and FileName contains "PSEXESVC.exe") on $left.LocalIP == $right.RequestSourceIP
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, LocalIP, RemoteIP, RemotePort, RequestSourceIP, InitiatingProcessFileName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName
```
