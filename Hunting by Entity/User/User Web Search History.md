# User Web Search History

# Description
This query retrieves the web search history for a specific user over the last 30 days. It extracts the domain and query parameters from the URL, then summarizes the URLs searched and counts distinct queries per domain.

# Sentinel
```kql
url_CL
| where TimeGenerated > ago(30d)
// | where URLCategory_s == "search-engines"
| where SourceUser_s contains "@{body('Get_user')?['userPrincipalName']}"
| extend domain = tostring(parse_url(Referer_s).Host)
| extend g = parse_url(Referer_s)
| where (g.["Query Parameters"] != "{}" or g.Path != "")
| where (g.["Query Parameters"].q != "" or g.["Query Parameters"].oq != "")
| extend q = url_decode(tostring(g.["Query Parameters"].q))
| project q, SourceUser_s, domain
| summarize URLs= strcat_array(make_set(replace_string(q,'+',' ')),',\n '), dcount(q) by domain
| sort by dcount_q
```
