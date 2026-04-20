# CSV2Ticket Tab
- [ ] simplify regex extraction logic to process less columns and search mostly event_json

# KQL Queries Tab
- [ ] fix queries (no dynamic vaiables only AND/OR change; all variable lines show by default commented out if not used)
- [ ] Add Source IP input field
- [ ] Add start time and end time field 
- [ ] add slider on top of each query text box to change the time window (+/-) for each query

# DHCP Lookup Tab
- [ ] After adding Source IP to the KQL tab, pull it from there and pre-fill the Start IP.
- try via url parameters: 
    - https://box.net.usf.edu/cgi-bin/dhcp/lease-query.pl?start_ip=x.x.x.x&start_time=20260406000000&end_time=20260407000000

# HTML Analyzer Tab
- [ ] make the categorization more intelligent (whitelisted/safe things in green, suspicious things in yellow, definitely malicious things in red)
- [ ] add to list of malicious things to search for
- [ ] provide the full line / function context of malicious items
- [ ] maybe follow external JS if found

# Accesibility 
- [ ] remove the automatic input -> output and readd buttons on all tools
- [ ] keyboard shortcut feature for tabs
- [ ] Add tooltips that display tab names when you hover over the tab (useful when the tab is short on width)

# Integrations
- [ ] Zendesk (pull and search similar solved tickets by ticket Description, remote IP, payload, or domain)
- [ ] Local model to understand zendesk past ticket context (summarize findings of similar tickets: threat assessment/osint, affected users/devices)

# Time Convert
- [x] assume the input time is in UTC by default unless specified
