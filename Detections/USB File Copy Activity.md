# USB File Copy Activity

# Description
This query helps in identifying potentially unauthorized or suspicious file copy activities to USB drives, which can be an indication of data exfiltration attempts. By monitoring these events, security teams can detect and investigate unauthorized data transfers to removable media, ensuring the security and integrity of sensitive data.

# Sentinel / Defender
```kql
DeviceEvents
| where TimeGenerated > ago(90d)
| where DeviceName in~ ("@{variables('tid')}")
| where ActionType =~ "UsbDriveMounted" 
| extend Type = tostring(AdditionalFields.Manufacturer)
| extend DriveLetter = tostring(todynamic(AdditionalFields).DriveLetter)
| extend ProductName = tostring(todynamic(AdditionalFields).ProductName)
| join kind=leftouter (DeviceFileEvents
| where TimeGenerated > ago(90d)
| where DeviceName in~ ("@{variables('tid')}")
| extend FileCopyTime = TimeGenerated
| where ActionType == "FileCreated"
| parse FolderPath with DriveLetter '\\' *
| extend DriveLetter = tostring(DriveLetter)
| where DriveLetter !contains "C"
| distinct DriveLetter, DeviceId, DeviceName, FileName, FileCopyTime, FileSize, FolderPath, ReportId
) on DeviceId, DriveLetter
| distinct DeviceName, DriveLetter, FileName1, FileSize1, Type, FolderPath1, AccountName=InitiatingProcessAccountName, ProductName, FileCopyTime
| summarize CopySizeGB=sum(FileSize1)/1024/1024/1000, FilesCopied=strcat_array(make_set(FileName1,10),', '), FolderPaths=strcat_array(make_set(FolderPath1,10),', '), FileCount=dcount(FileName1) by DeviceName, ProductName, DriveLetter
| order by CopySizeGB
```
