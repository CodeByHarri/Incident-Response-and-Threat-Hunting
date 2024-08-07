# Plug and Play By  Device

# Description
This query retrieves Plug and Play (PnP) device connection events for a specific device over the last 90 days. It extends details about the connected devices, including class name, device description, vendor IDs, and device IDs. It joins with a datatable to get bus type descriptions and summarizes the device descriptions by class name, excluding print queue devices.

# Sentinel / Defender
```kql
let T = datatable(BusType:string, BusDesc:string)[ '0' , 'The bus type is unknown.',
    '1' , 'SCSI',
    '2' , 'ATAPI',
    '3' , 'ATA',
    '4' , 'IEEE 1394',
    '5' , 'SSA',
    '6' , 'Fibre Channel',
    '7' , 'USB',
    '8' , 'RAID',
    '9' , 'iSCSI',
    '10' , 'Serial Attached SCSI (SAS)',
    '11' , 'Serial ATA (SATA)',
    '12' , 'Secure Digital (SD)',
    '13' , 'Multimedia Card (MMC)',
    '14' , 'This value is reserved for system use (Virtual)',
    '15' , 'File-Backed Virtual',
    '16' , 'Storage spaces',
    '17' , 'NVMe',
];
DeviceEvents
| where TimeGenerated > ago (90d)
| where DeviceName contains "@{variables('tid')}"
| where ActionType == "UsbDriveMounted" or ActionType == "PnpDeviceConnected"
| extend PNPInfo = parse_json(AdditionalFields)
| extend ClassName = tostring(PNPInfo.ClassName), DeviceDescription = tostring(PNPInfo.DeviceDescription), VendorIds = tostring(PNPInfo.VendorIds), DeviceIdx = tostring(PNPInfo.DeviceId)
| extend PnPType = tostring(split(DeviceId, @"\", 0)[0])
| extend ParsedFields=parse_json(AdditionalFields)
| extend BusType = tostring(ParsedFields.BusType)
| join kind=leftouter (T) on BusType
| extend BusType = strcat(BusType , ' | ' , BusDesc)
| extend ClassName = iff(ClassName == "", "USB", ClassName)
| summarize 
DeviceDescription  = strcat_array(make_set(DeviceDescription ),', ')
by ClassName
| where ClassName != "PrintQueue"
```
