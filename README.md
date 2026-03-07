# SOCAP Console
A collection of tools and utilities to help with SOC ticket work.

## Tools
- **<u>CSV to Ticket:<u>** Upload linkedAlerts CSV files to auto-generate investigation tickets. Supports multiple file merge.
- **<u>KQL Queries:<u>** Pre-built KQL hunting queries auto-filled from the CSV data. All queries are expanded by default — click a title to collapse. Fill in additional fields below to refine.
- **<u>Enrich IOC:<u>** Enter an IOC to query across multiple threat intelligence sources. Select sources and open them all at once.
- **<u>Redact:<u>** Paste raw text/logs below. Auto-substitutes sensitive org information (IPs, emails, org names) with masked values. Add custom patterns below.
- **<u>Header to Curl:<u>** Paste a raw HTTP request (from browser DevTools, Burp, etc.) to convert it into a curl command.
- **<u>HTML Analyzer:<u>** Paste raw HTML source code or enter a URL to auto-fetch its source. Supports Wannabrowser links and direct URLs.
- **<u>IOC Extractor:<u>** Paste raw text (emails, logs, reports) to extract IPs, domains, URLs, and hashes. Supports IPv4, IPv6, SHA-256, SHA-1, and MD5.
- **<u>Defang:<u>** Safely defang IOCs for sharing in reports and tickets, or refang them for active investigation. Supports multi-line input.
- **<u>Encode/Decode:<u>** Encode and decode payloads across common formats. Useful for analyzing obfuscated payloads, crafting queries, and sharing IOCs safely.
- **<u>Timestamp Converter:<u>** Convert between epoch timestamps and human-readable formats. Auto-detects input format. All conversions shown simultaneously.

## Setup
1. Add a bookmark for `file:///<path to socap-console folder>/index.html`
2. In browser settings, add a 'pop-ups and redirects' exception for `file:///<path to socap-console folder>/index.html`

    - Chrome:
       1. Settings > Privacy and Security > Pop-ups and redirects
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list
    
    - Edge:
       1. Settings > Privacy, search, and services > Site permissions > All permissions > Pop-ups and redirects
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list
    
    - Firefox:
       1. Settings > Privacy & Security > Manage pop-up and third-party redirect exceptions
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list
