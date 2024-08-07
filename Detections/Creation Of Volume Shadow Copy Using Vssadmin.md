# Creation Of Volume Shadow Copy Using Vssadmin

# Description
This query helps security teams detect potentially suspicious activities where **vssadmin.exe** is being used to create shadow copies. Shadow copies can be abused by attackers to recover previous versions of files or to mask unauthorized modifications.

# References
**MITRE**: https://attack.mitre.org/techniques/T1003/003/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md

# Sentinel / Defender
```kql
DeviceProcessEvents
| where FileName =~ "vssadmin.exe" and ProcessCommandLine contains "create shadow"
```
