# Registry Run Keys to Establish Persistence

# Description
This query helps in identifying unauthorized or suspicious modifications to registry run keys, which can be an indication of attempts to establish persistence on the system by configuring programs or scripts to run automatically at startup.

# Sentinel / Defender
```kql
union DeviceRegistryEvents, DeviceProcessEvents
| where TimeGenerated > ago(90d) 
// | where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where ((RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Run" or RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run") and (RegistryValueData contains ".dll" or RegistryValueData contains ".vbs" or RegistryValueData contains ".vba" or RegistryValueData contains ".lnk" or RegistryValueData contains ".ocx" or RegistryValueData contains ".cmd" or RegistryValueData contains ".bat" or RegistryValueData contains ".jse" or RegistryValueData matches regex @"windowstyle\s*hidden\s*-ExecutionPolicy\s*Bypass\s*-File"))
    or ((ProcessCommandLine contains @"Software\Microsoft\Windows\CurrentVersion\Run" or ProcessCommandLine contains @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run") and ProcessCommandLine contains "add" and ProcessCommandLine has_any (".dll", ".vba", ".vbs", ".lnk", ".ocx", ".exe", ".bat", ".jse", ".cmd"))
| summarize
    dcount(RegistryValueData),
    RegistryValues  = strcat_array(make_set(RegistryValueData, 5), ', '), 
    CommandLines  = strcat_array(make_set(ProcessCommandLine, 5), ', ')
    by RegistryKeygistryKey
```
