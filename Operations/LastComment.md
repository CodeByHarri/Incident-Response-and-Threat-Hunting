# Sentinel Incident Closing Comments

# Sentinel / Defender
```kql
SecurityIncident
| where TimeGenerated > ago(1d)
| mv-expand AlertIds
| extend Title = replace_string(replace_string(replace_string(replace_string(Title, 'on one endpoint', ''), ' on multiple endpoints', ''), 'involving multiple users', ''), 'involving one user', '')
| extend Title = trim(@"\s", Title)
| extend LastComment = Comments[-1].message
| summarize
    ['Max Generated Time AEST'] = max(TimeGenerated),
    IncidentNumber = strcat_array(make_set(IncidentNumber), ', '),
    lastMessage = strcat_array(make_set(LastComment), ', '),
    lastClassification = strcat_array(make_set(ClassificationComment), ', '),
    Comments = strcat_array(make_set(Comments), ', ')
    by Title
| extend ['Max Generated Time AEST'] = datetime_utc_to_local(['Max Generated Time AEST'], 'Australia/Canberra')
| sort by ['Max Generated Time AEST'] desc
| extend ['Max Generated Time AEST'] = format_datetime(['Max Generated Time AEST'], 'dd-MM-yy [hh:mm:ss tt]')
```
