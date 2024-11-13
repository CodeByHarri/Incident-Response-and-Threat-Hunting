# Device Logins

# Description
This query retrieves logon events for a specific device over the last 30 days, excluding system accounts ("umfd-" and "dwm-"). It extends details about the logon events, including the generated time in Australian Eastern Standard Time (AEST). The results are summarized to show the total events, last generated time, and account names by action type and logon type.

# Sentinel / Defender
```kql
let DEVICE = tolower("{DEVICENAME}");
let PERIOD = 7d;
let dle = DeviceLogonEvents
| where TimeGenerated > ago(PERIOD)
| extend DeviceName = tostring(split(DeviceName,'.')[0])
| where tolower(DeviceName) contains DEVICE
| where not(AccountName has_any("umfd-", "dwm-"))
| summarize ['Total Events']= count(), 
['Last Generated Time AEST']=max(TimeGenerated),
LogonType =  strcat_array(make_set(LogonType,10),', '),
['Account Name']=strcat_array(make_set(AccountName,10),', ') by ActionType
| extend Table = "DeviceLogonEvents";
let sil =SigninLogs
| where TimeGenerated > ago (PERIOD)
| where OperationName == "Sign-in activity"
// | where isnotempty(Status)
| extend Login_Status = tostring(todynamic(Status).errorCode),
Login_Status_Info = tostring(todynamic(Status).failureReason),
Device_Join_Status = tostring(todynamic(DeviceDetail).trustType),
Browser = tostring(parse_json(DeviceDetail).browser),
OS = tostring(parse_json(DeviceDetail).operatingSystem),
DeviceDisplayName = tostring(parse_json(DeviceDetail).displayName),
Authentication_Method = tostring(todynamic(AuthenticationDetails).[0].authenticationMethod),
Authentication_Detail = tostring(todynamic(AuthenticationDetails).[0].authenticationStepResultDetail),
Authentication_Success = tostring(todynamic(AuthenticationDetails).[0].succeeded)
| where tolower(DeviceDisplayName) contains DEVICE
| summarize 
Login_Status_Info = strcat_array(make_set(Login_Status_Info,10),', '),
Location = strcat_array(make_set(Location,10),', '),
AppDisplayName = strcat_array(make_set(AppDisplayName,10),', '),
IP_Count = count(),
Device_Join_Status = strcat_array(make_set(Device_Join_Status,10),', '),
DeviceDisplayName = strcat_array(make_set(DeviceDisplayName,10),', '),
Authentication_Method = strcat_array(make_set(Authentication_Method,10),', '),
Authentication_Success = strcat_array(make_set(Authentication_Success,10),', '),
['Last Generated Time AEST']=max(TimeGenerated),
UserPrincipalName = strcat_array(make_set(UserPrincipalName,10),', ')
by  Login_Status
| extend Table = "SigninLogs"
| project Table, ActionType=Login_Status_Info, ['Total Events']=IP_Count, ['Last Generated Time AEST'],LogonType =Authentication_Method, ['Account Name']=UserPrincipalName
| extend ActionType=iff(ActionType == "", "LogonSuccess",ActionType);
union dle, sil
| extend ['Last Generated Time AEST'] = datetime_utc_to_local(['Last Generated Time AEST'],'Australia/Canberra')
| sort by ['Last Generated Time AEST'] desc
| extend ['Last Generated Time AEST']= format_datetime(['Last Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```
