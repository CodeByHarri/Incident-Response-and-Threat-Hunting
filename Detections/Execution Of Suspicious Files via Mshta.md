# Execution Of Suspicious Files via Mshta

# Description
 This query is designed to detect instances of MSHTA.exe execution within your environment. MSHTA.exe is a Microsoft utility used to execute HTML applications (HTA files), and its use can sometimes indicate malicious activities such as script execution or exploitation attempts.

# References
**MITRE**: https://attack.mitre.org/techniques/T1218/005/

**ATOMIC**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md

# Sentinel / Defender
```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe" and (( ProcessCommandLine contains "hta:application" and ProcessCommandLine contains "Wscript.Shell") or ProcessCommandLine contains "shell.application")
//Whitelist common execution within your environment
```
