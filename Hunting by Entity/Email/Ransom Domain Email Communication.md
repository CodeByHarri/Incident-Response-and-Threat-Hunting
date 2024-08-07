# Victim Data from Ransomware.Live Communications in Email Events

# Description
This query retrieves data about ransomware attack victims from ransomware.live and cross-references this information with email events to identify any communications from these domains. This helps in understanding the potential impact and communications involving known ransomware-affected domains.
Inspiration credit: [Bert JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/Ransomware%20-%20LeaksiteMontitoring.md)

# Sentinel / Defender
```kql
let all_victims = externaldata(["date"]:datetime,
        victim:string,
        domain:string,
        country:string,
        summary:string,
        title:string,
        url:string,
        added:datetime)
[h@"https://api.ransomware.live/allcyberattacks"]
with(format="multijson",ignoreFirstRecord=false);
let domains = all_victims
| project domain;
EmailEvents
| where TimeGenerated >ago(90d)
| where SenderFromDomain in(domains)
| summarize dcount(NetworkMessageId), make_set(DeliveryAction), make_set(Subject) by domain=SenderMailFromDomain
| join all_victims on domain
| where domain != ""
```
