# Network Drive Mapping Using Net.exe

# Description
This query examines relevant logs to detect instances where users or systems establish connections to network shares via 'net use'. Monitoring these activities is crucial for detecting unauthorized access attempts, ensuring proper access controls, and maintaining the integrity of network resources.

# References
**MITRE**: https://attack.mitre.org/techniques/T1021/002/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md

# Sentinel / Defender
```kql
DeviceProcessEvents | where FileName =~ "net.exe" and ProcessCommandLine has "net use"
//Whitelist common file and network shares used in your organisation
```
