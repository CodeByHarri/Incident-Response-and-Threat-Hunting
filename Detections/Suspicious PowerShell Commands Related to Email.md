# Suspicious PowerShell Commands Related to Email

# Description
This query helps in identifying potentially unauthorized or suspicious PowerShell commands that relate to email operations and the addition of snap-ins. By monitoring these events, security teams can detect and investigate attempts to access or manipulate email data, ensuring the security and integrity of email systems and data.

# Sentinel / Defender
```kql
DeviceProcessEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where (ProcessCommandLine contains "Add-PSSnapin" or ProcessCommandLine contains "Get-Recipient" or ProcessCommandLine contains "EmailAddresses" or ProcessCommandLine contains "SmtpAddress" or ProcessCommandLine contains "-hidetableheaders") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")
| summarize count() by ProcessCommandLine, InitiatingProcessAccountName
```
