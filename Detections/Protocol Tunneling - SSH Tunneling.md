# Protocol Tunneling - SSH Tunneling

# Description
SSH tunneling is a technique often used by attackers to bypass network restrictions or exfiltrate data covertly. By analyzing relevant logs, such as SSH session logs or network traffic data, this query identifies patterns indicative of SSH tunneling attempts.

# References
**MITRE**: https://attack.mitre.org/techniques/T1572/

**ATOMIC**: NA

**Articles**: https://www.blackhillsinfosec.com/ssh-dont-tell-them-i-am-not-https/, https://www.mandiant.com/resources/blog/bypassing-network-restrictions-through-rdp-tunneling

# Sentinel / Defender
```kql
//Looking for SSH connection that is not over port 22, plink.exe is a command-line utility of Putty
let query1=DeviceNetworkEvents
| where ( InitiatingProcessFileName contains "ssh.exe" or InitiatingProcessFileName contains "plink.exe") and RemotePort != "22" and ActionType !contains "Failed" and not (ipv4_is_private( RemoteIP)) and RemoteIPType !contains "Loopback";
//Look for dynamic port forwarding (SOCKS proxy) via SSH connection
let query2=DeviceNetworkEvents
| where ( InitiatingProcessFileName contains "ssh.exe" or InitiatingProcessFileName contains "plink.exe") and InitiatingProcessCommandLine contains_cs "-D" and ActionType =~ "ListeningConnectionCreated";
//Look for remote and local port forwarding via SSH connection
let query3=DeviceNetworkEvents
| where ( InitiatingProcessFileName contains "ssh.exe" or InitiatingProcessFileName contains "plink.exe") and ( InitiatingProcessCommandLine contains_cs "-R" or InitiatingProcessCommandLine contains_cs "-L");
union query1, query2, query3
```
