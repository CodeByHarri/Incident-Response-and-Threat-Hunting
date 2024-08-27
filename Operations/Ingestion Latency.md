# Observing the Ingestion Latency of Logs

# Description
Capture which hosts have a delayed ingestion
Source: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time

# Sentinel / Defender
```kql
let p=1d ;
union Device*
| where TimeGenerated >ago(p)
| where not(InitiatingProcessAccountName in ("system","network service","local service") or  
InitiatingProcessAccountName contains "$" or 
InitiatingProcessAccountName == "")
| extend E2EIngestionLatency = ingestion_time() - TimeGenerated 
| extend Ingestion=ingestion_time()
| extend AgentLatency = _TimeReceived - TimeGenerated 
| summarize avg(E2EIngestionLatency), avg(AgentLatency), min(E2EIngestionLatency),max(E2EIngestionLatency), min(AgentLatency),max(AgentLatency) by DeviceName, Log=Type, InitiatingProcessAccountName
```
