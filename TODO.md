# repo hierachy
- [ ] put all .js into "modules" folder and change references


# reorder tools on sidebar
1. csv to ticket
2. kql queries
3. enrich ioc
4. redact
5. header to curl
6. html analyzer
7. ioc extractor
8. defang
9. encode/decode
10. time convert


# CSV To Ticket
- [ ] remove 'Splunk' from ticket template


# KQL queries tab
- [ ] separate tab for KQL queries, using the same data extracted from the linkedAlerts in the CSV to Ticket tab
- [ ] no buttons; have all queries show in a vertical pane, but add the ability to collapse them
- [ ] copy query button should be closer to query title text 
- [ ] domain should already be taken from the linkedAlerts so no need for entry box
- [ ] IP Search: split the IP Search query into multiple, but one for each IP. Title should be IP-Hunt (<IP>)
- [ ] bug where only the input Device name/Net ID/MAC/Domain/Hash only applies in the query if it is currently selected.
- [ ] add domain-hunt query


# Enrich IOC tab
- [ ] select all button is crazy haha; browser will explode
- [ ] "Deselect All" and "Clear" are redudant
- [ ] add a small "(?)" button next to "\<h2>Enrich IOC\</h2>" that displays a little text box telling the user how to allow pop-ups/redirects for the tab. should say something like what's on the readme
- [ ] fix categorization: put threatYeti under reputation & intel


# Timestamp
- [ ] add YYYYMMDDhhmmss format in time convert, Labeled 'ITC portal'
