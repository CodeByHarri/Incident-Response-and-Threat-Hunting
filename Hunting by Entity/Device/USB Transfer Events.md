# USB Transfer Events

# Description
This query retrieves USB drive mount events and file creation events on these USB drives for a specific device over the last 90 days. It extends details about the USB drive and files copied to it, including manufacturer, drive letter, product name, file names, and file sizes. The results are summarized to show the total copy size in GB, files copied, folder paths, and file count, ordered by the total copy size.

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
