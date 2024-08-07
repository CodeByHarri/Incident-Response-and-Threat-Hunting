# Detecting Emails with Non-Standard UTF-8 Characters

# Description
This query helps identify emails with potentially suspicious or obfuscated subjects, which can be a sign of phishing or other malicious activities. Security teams can use this information to prioritize investigations and enhance email security measures.

# Sentinel / Defender
```kql
EmailEvents
| where TimeGenerated > ago (60d)
| where RecipientEmailAddress =~ "@{variables('upn')}" or SenderFromAddress =~ "@{variables('upn')}" or SenderMailFromAddress =~ "@{variables('upn')}"
| extend utc8=to_utf8(Subject)
| extend out = 0
| mv-apply element = utc8 to typeof(int) on
    (
    extend out = iff(
            element !between (0 .. 128)
            and element !in (8203,8211, 8212)// – exclusions
        ,
                 out + 1,
                 out
             )
    | top 1 by out
    )
| where out !=0
| summarize count() by SenderFromAddress,Subject,tostring(utc8)
```
