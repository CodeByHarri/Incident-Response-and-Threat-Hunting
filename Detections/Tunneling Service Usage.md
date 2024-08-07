# Tunneling Service Usage

# Description
This query helps in identifying network events that may involve tunneling activities using known tunneling services and domains. By monitoring these events, security teams can detect and investigate suspicious tunneling activities, ensuring the security and integrity of network communications.

# Sentinel / Defender
```kql
let tunnelingDomains = dynamic([
    ".v2.argotunnel.com", "protocol-v2.argotunnel.com", "trycloudflare.com", "update.argotunnel.com",
    ".devtunnels.ms", "mega.co.nz", "mega.nz", ".tunnels.api.visualstudio.com", 
    "tunnel.us.ngrok.com", "tunnel.eu.ngrok.com", "tunnel.ap.ngrok.com", "tunnel.au.ngrok.com", 
    "tunnel.sa.ngrok.com", "tunnel.jp.ngrok.com", "tunnel.in.ngrok.com",
    "localtunnel.me", "serveo.net", "pagekite.net", "cloudflared.com", 
    "*.ngrok.io", "*.ngrok.com", "*.localtunnel.me", "*.serveo.net", "*.pagekite.net",
    "*.trycloudflare.com", "*.devtunnels.ms", "*.argotunnel.com", "*.update.argotunnel.com",
    "*.protocol-v2.argotunnel.com", "*.tunnels.api.visualstudio.com", "*.mega.co.nz", "*.mega.nz",
    "*.tailscale.com", "*.zerotier.com", "*.gravitational.com", "*.duckdns.org", "*.noip.com",
    "*.dyndns.org", "*.netlify.com", "*.dataplicity.com", "*.twingate.com", "*.remote.it"
]);
DeviceNetworkEvents
| where DeviceName =~ "@{variables('DeviceName')}" or InitiatingProcessAccountUpn =~ "@{variables('upn')}"
| where RemoteUrl has_any (tunnelingDomains)
| summarize RemoteUrls = strcat_array(make_set(RemoteUrl, 5), ', '), dcount(RemoteUrl) by DeviceName, InitiatingProcessAccountUpn, RemoteIP, InitiatingProcessFileName
```
