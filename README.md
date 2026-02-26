# soc-tool
A collection of tools and utilities to help with SOC ticket work

## Tool tabs
**CSV to Ticket** - Parse a linkedAlerts CSV and fills in ticket template with relevant information <br>
**Enrich IOC** - Open multiple browser tabs for different threat intelligence and enrichment tools based on IOC input (ip, domain, url, hash) <br>
**Redact** - Replace/remove sensitive organization information from text

## Setup
1. Add bookmark for `file:///<wherever you saved the file>/soc-tool.html`
2. In browser settings, add a 'pop-ups and redirects' exception for the `soc-tool.html` file

    - Chrome:
       1. Settings > Privacy and Security > Pop-ups and redirects
       2. Add `file:///<wherever you saved the file>/soc-tool.html` to allowed list
    
    - Edge:
       1. Settings > Privacy, search, and services > Site permissions > All permissions > Pop-ups and redirects
       2. Add `file:///<wherever you saved the file>/soc-tool.html` to allowed list
    
    - Firefox:
       1. Settings > Privacy & Security > Manage pop-up and third-party redirect exceptions
       2. Add `file:///<wherever you saved the file>/soc-tool.html`