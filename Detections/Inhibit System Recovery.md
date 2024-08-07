Inhibit System Recovery

# Description
Adversaries may delete or disable built-in data and services that are specifically intended to facilitate the recovery of a corrupted system. This tactic is employed to hinder or entirely prevent recovery efforts in the event of a system compromise.

# References
**MITRE**: https://attack.mitre.org/techniques/T1490/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md

# Sentinel / Defender
```kql
//This query looks for deletion of the Windows systemstate backup using wbadmin.exe. This is used by various ransomware families. Atomic test T1490 - Test7
let query1=DeviceProcessEvents
| where ProcessCommandLine contains "delete" and FileName contains "wbadmin.exe"
//Whitelist Azure Recovery Agent if applicable;
//This query looks for resizing of Shadowstorage Volume using vssadmin.exe. Atomic test T1490-Test10
let query2=DeviceProcessEvents
| where ProcessCommandLine contains "resize shadowstorage" and FileName contains "vssadmin.exe";
union query1, query2
```
