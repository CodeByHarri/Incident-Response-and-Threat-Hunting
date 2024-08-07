# Usage Of Impacket Tool

# Description
This query identifies potential instances where Impacket tools such as smbclient, wmiexec, or other utilities are being utilized. Monitoring for Impacket activity is crucial for detecting both legitimate administrative actions and unauthorized activities that could indicate malicious intent or compromise of network security. Security analysts can leverage this query to promptly investigate and respond to suspicious Impacket usage, helping to mitigate potential risks and maintain network integrity.

# References
**MITRE**: https://attack.mitre.org/techniques/T1569/002/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md

# Sentinel / Defender
```kql
DeviceProcessEvents
| where (InitiatingProcessFileName in ("svchost.exe","taskeng.exe") and ProcessCommandLine has_all ("cmd.exe","/c", @"windows\temp"," > ","2>&1"))//atexec
or (InitiatingProcessFileName == "wmiprvse.exe" and FileName in ("cmd", "cmd.exe") and ProcessCommandLine has_all (@"127.0.0.1\ADMIN$_") ) //WMIEXEC
or (InitiatingProcessFileName in ("services","services.exe") and FileName in ("cmd","cmd.exe") and ProcessCommandLine has_all ("ping -n","127.0.0.1",@"C$__output","2>&1")) //SMBexec
```
