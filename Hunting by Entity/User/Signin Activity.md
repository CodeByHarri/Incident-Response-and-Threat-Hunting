
```kql
let ACTOR = "{UPN}";
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string) ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip'] with (ignoreFirstRecord=true));
union isfuzzy=false  SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago (7d)
| where UserPrincipalName contains ACTOR
| where OperationName == "Sign-in activity"
// | extend iff(DeviceDetail_string )
| extend Login_Status = iff(isempty(Status_dynamic),tostring(todynamic(Status_string).errorCode), tostring(todynamic(Status_dynamic).errorCode))
| extend Login_Status_Info = iff(isempty(Status_dynamic),tostring(todynamic(Status_string).failureReason), tostring(todynamic(Status_dynamic).failureReason))
| extend Device_Join_Status = tostring(todynamic(Status_string).trustType),
     Browser = tostring(parse_json(DeviceDetail_string).browser),
     OS = tostring(parse_json(DeviceDetail_string).operatingSystem),
     DeviceDisplayName = tostring(parse_json(DeviceDetail_string).displayName)
| extend DeviceDetail = strcat('(',DeviceDisplayName, " ", "/", " ", OS, " ", "/"," ", Browser,')')
| extend location_country = iff(tostring(todynamic(LocationDetails_string).countryOrRegion) == "", Location,tostring(todynamic(LocationDetails_string).countryOrRegion))
| extend location_city = tostring(todynamic(LocationDetails_string).city)
| extend location_state = tostring(todynamic(LocationDetails_string).state)
| extend Location = strcat(location_country, " ", "/", " ", location_state, " ", "/"," ", location_city)
| extend Authentication_Method0 = tostring(todynamic(AuthenticationDetails).[0].authenticationMethod)
| extend Authentication_Detail0 = tostring(todynamic(AuthenticationDetails).[0].authenticationStepResultDetail)
| extend Authentication_Success0 = tostring(todynamic(AuthenticationDetails).[0].succeeded)
| extend Authentication_Method1 = tostring(todynamic(AuthenticationDetails).[1].authenticationMethod)
| extend Authentication_Detail1 = tostring(todynamic(AuthenticationDetails).[1].authenticationStepResultDetail)
| extend Authentication_Success1 = tostring(todynamic(AuthenticationDetails).[1].succeeded)
| extend Authentication_Method2 = tostring(todynamic(AuthenticationDetails).[2].authenticationMethod)
| extend Authentication_Detail2 = tostring(todynamic(AuthenticationDetails).[2].authenticationStepResultDetail)
| extend Authentication_Success2 = tostring(todynamic(AuthenticationDetails).[2].succeeded)
| extend Authentication_Details0 =  strcat(Authentication_Method0, " ", "/", " ", Authentication_Detail0, " ", "/", " ", Authentication_Success0),
Authentication_Details1 =  strcat(Authentication_Method1, " ", "/", " ", Authentication_Detail1, " ", "/", " ", Authentication_Success1),
Authentication_Details2 =  strcat(Authentication_Method2, " ", "/", " ", Authentication_Detail2, " ", "/", " ", Authentication_Success2)
| summarize 
Login_Status_Info = strcat_array(make_set(Login_Status_Info,10),', '),
Location = strcat_array(make_set(Location,10),', '),
AppDisplayName = strcat_array(make_set(AppDisplayName,10),', '),
ResourceDisplayName = strcat_array(make_set(ResourceDisplayName,10),', '),
IPAddress = strcat_array(make_set(IPAddress,10),', '),
Device_Join_Status = strcat_array(make_set(Device_Join_Status,10),', '),
DeviceDisplayName = strcat_array(make_set(DeviceDetail,10),', '),
UserAgent = strcat_array(make_set(UserAgent,10),', '),
Auth_Method_Detail_Success0 = strcat_array(make_set( Authentication_Details0,10),', '),
Auth_Method_Detail_Success1 = strcat_array(make_set( Authentication_Details1,10),', '),
Auth_Method_Detail_Success2 = strcat_array(make_set( Authentication_Details2,10),', '),
['CreatedDateTime AEST']=max(CreatedDateTime)
by Type, Login_Status, UserPrincipalName, TimeGenerated
| extend ['CreatedDateTime AEST'] = datetime_utc_to_local(['CreatedDateTime AEST'],'Australia/Canberra')
| evaluate ipv4_lookup(CIDRASN, IPAddress, CIDR, return_unmatched=true)
| sort by ['CreatedDateTime AEST']desc
| extend ['CreatedDateTime AEST'] = format_datetime(['CreatedDateTime AEST'], 'dd-MM-yy [hh:mm:ss tt]')
| project Type,Login_Status,UserPrincipalName, Login_Status_Info, AppDisplayName, ResourceDisplayName, Location, IPAddress, CIDRASNName,TimeGenerated, ['CreatedDateTime AEST'], DeviceDisplayName, UserAgent, Auth_Method_Detail_Success0, Auth_Method_Detail_Success1,Auth_Method_Detail_Success2
<img width="1597" height="860" alt="image" src="https://github.com/user-attachments/assets/bed8ec44-d9ae-4ecb-b8ab-ebe75521b9c1" />

```
