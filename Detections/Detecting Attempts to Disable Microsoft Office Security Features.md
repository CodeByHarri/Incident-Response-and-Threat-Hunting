# Detecting Attempts to Disable Microsoft Office Security Features

# Description
This query identifies any suspicious activities within Microsoft Office environments where security features have been tampered with or disabled. This detection mechanism helps security teams monitor and respond to potential threats, ensuring robust protection against unauthorized changes that could compromise Office application security.

# References
**MITRE**: https://attack.mitre.org/techniques/T1562/001/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md

# Sentinel / Defender
```kql
DeviceRegistryEvents
| where RegistryKey contains @"\Software\Microsoft\Office" and RegistryValueName in~ ("VBAWarnings","DisableAttachementsInPV","DisableUnsafeLocationsInPV", "DisableInternetFilesinPV") and RegistryValueData == "1"
| where InitiatingProcessFileName !in~ ("excel.exe","winword.exe")
```
