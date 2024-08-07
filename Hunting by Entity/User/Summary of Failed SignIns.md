# Summary of Failed SignIns

# Description
Similar to the successful sign-ins query, this one retrieves sign-in logs for a specific user over the last 7 days but focuses on failed sign-in attempts (Login_Status != 0). It includes details about the failure reason, location, device used, and authentication methods. The results are summarized and formatted to show the maximum generated time in AEST.

# Sentinel
```kql
SigninLogs
| where TimeGenerated > ago (7d)
| where UserPrincipalName =~ "@{body('Get_user')?['userPrincipalName']}"
| where OperationName == "Sign-in activity"
// | where isnotempty(Status)
| extend Login_Status = tostring(todynamic(Status).errorCode) // Check the error code here: https://login.microsoftonline.com/error
| extend Login_Status_Info = tostring(todynamic(Status).failureReason)
| extend Device_Join_Status = tostring(todynamic(DeviceDetail).trustType),
     Browser = tostring(parse_json(DeviceDetail).browser),
     OS = tostring(parse_json(DeviceDetail).operatingSystem),
     DeviceDisplayName = tostring(parse_json(DeviceDetail).displayName)
// | extend DeviceDetail = strcat('(',DeviceDisplayName, " ", "/", " ", OS, " ", "/"," ", Browser,')')
| extend location_country = tostring(todynamic(LocationDetails).countryOrRegion)
| extend location_city = tostring(todynamic(LocationDetails).city)
| extend location_state = tostring(todynamic(LocationDetails).state)
| extend Location = strcat(location_country, " ", "/", " ", location_state, " ", "/"," ", location_city)
| extend Authentication_Method = tostring(todynamic(AuthenticationDetails).[0].authenticationMethod)
| extend Authentication_Detail = tostring(todynamic(AuthenticationDetails).[0].authenticationStepResultDetail)
| extend Authentication_Success = tostring(todynamic(AuthenticationDetails).[0].succeeded)
| extend Authentication_Details =  strcat(Authentication_Method, " ", "/", " ", Authentication_Detail, " ", "/", " ", Authentication_Success)
| summarize 
Login_Status_Info = strcat_array(make_set(Login_Status_Info,10),', '),
Location = strcat_array(make_set(Location,10),', '),
AppDisplayName = strcat_array(make_set(AppDisplayName,10),', '),
IP_Count = count(),
Device_Join_Status = strcat_array(make_set(Device_Join_Status,10),', '),
DeviceDisplayName = strcat_array(make_set(DeviceDisplayName,10),', '),
Authentication_Method = strcat_array(make_set(Authentication_Method,10),', '),
Auth_Method_Detail_Success = strcat_array(make_set( Authentication_Details,10),', '),
Authentication_Success = strcat_array(make_set(Authentication_Success,10),', '),
['Max Generated Time AEST']=max(TimeGenerated)
by  Login_Status
| where Login_Status != 0
| sort by ['Max Generated Time AEST'] desc
| extend ['Max Generated Time AEST'] = datetime_utc_to_local(['Max Generated Time AEST'],'Australia/Canberra')
| extend ['Max Generated Time AEST'] = format_datetime(['Max Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project AppDisplayName, Login_Status_Info, Login_Status, Location, IP_Count, ['Max Generated Time AEST'], DeviceDisplayName, Auth_Method_Detail_Success
```
