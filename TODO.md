# CSV2Ticket Tab (csv2ticket.js)
- [ ] Add ticket template selection (socap event alert, defender ticket, etc.) 
- [ ] some \n is not interpreted as newline in the payload_printable from stamus; must take from 'payload_printable' column not event_json
- [ ] fix "Observed Domains/URLs" regex to not pull from payload or filter out IPS
- [ ] simplify regex extraction logic to process less columns

# KQL Queries Tab (kql.js)
- [ ] AND/OR toggle for these input boxes (usf_ip, device name, netid)
- [ ] add slider on top of each query text box to change the time window (+/-) for each query
- [ ] fix copy button animation

# DHCP Lookup Tab (html-analyzer.js)
- [ ] After adding Source IP to the KQL tab, pull it from there and pre-fill the Start IP.
- [ ] try via url parameters: https://box.net.usf.edu/cgi-bin/dhcp/lease-query.pl?start_ip=x.x.x.x&start_time=20260406000000&end_time=20260407000000

# HTML Analyzer Tab (html-analyzer.js)
- [ ] make the categorization more intelligent (whitelisted/safe things in green, suspicious things in yellow, definitely malicious things in red)
- [ ] add to list of malicious things to search for
- [ ] provide the full line / function context of malicious items
- [ ] maybe follow external JS if found

# Accesibility 
- [ ] remove the automatic input -> output and read buttons on all tools
- [ ] keyboard shortcut feature for tabs
- [ ] Add tooltips that display tab names when you hover over the tab (useful when the tab is short on width)

# Integrations
- [ ] Zendesk (pull and search similar solved tickets by ticket Description, remote IP, payload, or domain)
- [ ] Local model to understand zendesk past ticket context (summarize findings of similar tickets: threat assessment/osint, affected users/devices)