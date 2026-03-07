# SOCAP Console
A collection of tools and utilities to help with SOC ticket work.

## Tools
- **CSV to Ticket:** Upload linkedAlerts CSV files to auto-generate investigation tickets. Supports multiple file merge.
- **KQL Queries:** Pre-built KQL hunting queries auto-filled from the CSV data. All queries are expanded by default — click a title to collapse. Fill in additional fields below to refine.
- **Enrich IOC:** Enter an IOC to query across multiple threat intelligence sources. Select sources and open them all at once.
- **Redact:** Paste raw text/logs below. Auto-substitutes sensitive org information (IPs, emails, org names) with masked values. Add custom patterns below.
- **Header to Curl:** Paste a raw HTTP request (from browser DevTools, Burp, etc.) to convert it into a curl command.
- **HTML Analyzer:** Paste raw HTML source code or enter a URL to auto-fetch its source. Supports Wannabrowser links and direct URLs.
- **IOC Extractor:** Paste raw text (emails, logs, reports) to extract IPs, domains, URLs, and hashes. Supports IPv4, IPv6, SHA-256, SHA-1, and MD5.
- **Defang:** Safely defang IOCs for sharing in reports and tickets, or refang them for active investigation. Supports multi-line input.
- **Encode/Decode:** Encode and decode payloads across common formats. Useful for analyzing obfuscated payloads, crafting queries, and sharing IOCs safely.
- **Timestamp Converter:** Convert between epoch timestamps and human-readable formats. Auto-detects input format. All conversions shown simultaneously.

## Setup
1. Add a bookmark for `file:///<path to socap-console folder>/index.html`.
2. In browser settings, add a 'pop-ups and redirects' exception for `file:///<path to socap-console folder>/index.html`.

    - Chrome:
       1. Settings > Privacy and Security > Pop-ups and redirects.
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list.
    
    - Edge:
       1. Settings > Privacy, search, and services > Site permissions > All permissions > Pop-ups and redirects.
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list.
    
    - Firefox:
       1. Settings > Privacy & Security > Manage pop-up and third-party redirect exceptions.
       2. Add `file:///<path to socap-console folder>/index.html` to allowed list.
