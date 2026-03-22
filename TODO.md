# CSV2Ticket Tab
- [ ] simplify regex extraction logic to process less columns and search mostly event_json
- [ ] add logic for stamus alert tickets (separate regex patterns and extraction based on named of .csv input)

# KQL Queries Tab
- [ ] fix query textbox issue where edited text is not copied after selecting copy
- [ ] fix queries 
- [ ] domain taken from the csv2ticket template should be in undefanged form
- [ ] input MAC address should be automatically converted to colon and dash format (no need to enter comma list)

# Enrich IOC Tab
- [ ] fix the info dialog

# HTML Analyzer Tab
- [ ] fix fetch error "CORS blocked the request (running from file://)."

# Time Convert Tab
- [ ] Start time should be taken from csv and used as default input
- [ ] give a date for the start date YYYYMMDDhhmmss where hhmmss is 000000 and end date in the same format. Label them ITC Portal (Start) and ITC Portal (End) respectively