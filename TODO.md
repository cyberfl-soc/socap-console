# CSV2Ticket Tab
- [-] simplify regex extraction logic to process less columns and search mostly event_json
- [x] add logic for stamus alert tickets (separate regex patterns and extraction based on named of .csv input)

# KQL Queries Tab
- [x] fix query textbox issue where edited text is not copied after selecting copy
- [ ] fix queries 
- [x] domain taken from the csv2ticket template should be in undefanged form
- [x] input MAC address should be automatically converted to colon and dash format (no need to enter comma list)

# Enrich IOC Tab
- [x] fix the info dialog

# HTML Analyzer Tab
- [-] fix fetch error "CORS blocked the request (running from file://)."

# Time Convert Tab
- [x] Start time should be taken from csv and used as default input
- [x] give a date for the start date where hhmmss is 000000 and end date in the same format. Label them ITC Portal (Start) and ITC Portal (End) respectively

# Accesibility 
- [ ] keyboard shortcut feature

# Integrations
- [ ] Zendesk
- [ ] Local model to understand zendesk past ticket context (possible collaboration with Fayeed/Kritan?)
