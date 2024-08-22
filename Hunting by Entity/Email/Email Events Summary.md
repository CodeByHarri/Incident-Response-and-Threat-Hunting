# Email Events Summary


# Defender / Sentinel
```kql
EmailEvents
| where TimeGenerated > ago (30d)
| where RecipientEmailAddress =~ "USER" or SenderFromAddress =~ "USER" or SenderMailFromAddress =~ "USER"
	| extend LocationDetails = geo_info_from_ip_address(SenderIPv4 )
	| extend location_country = tostring(todynamic(LocationDetails).country)
	| extend location_city = tostring(todynamic(LocationDetails).city)
	| extend location_state = tostring(todynamic(LocationDetails).state)
	| extend Location = strcat(location_country, " ", "/", " ", location_state, " ", "/"," ", location_city)
| join EmailAttachmentInfo on NetworkMessageId
| join EmailUrlInfo on NetworkMessageId
| extend URLs = replace_string(Url, '.','[.]')
| summarize DeliveryLocation = strcat_array(make_set(DeliveryLocation,10),', '), 
DeliveryAction = strcat_array(make_set(DeliveryAction,10),', '), 
Location = strcat_array(make_set(Location,10),', '), 
SenderIPv4 = strcat_array(make_set(SenderIPv4,10),', '), 
FileName = strcat_array(make_set(FileName,10),', '), 
URLs= strcat_array(make_set(URLs,10),', ')
by bin(TimeGenerated,1d), Subject, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, RecipientEmailAddress
```
