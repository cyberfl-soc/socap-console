// ---------- UI Generation ---------- //
const csvTab = document.getElementById("csvTab");

// Tab Header
const csvHeader = document.createElement('h2');
csvHeader.textContent = 'CSV to Ticket';
csvTab.appendChild(csvHeader);

const csvDesc = document.createElement('p');
csvDesc.className = 'tab-desc';
csvDesc.textContent = 'Upload linkedAlerts CSV files to auto-generate investigation tickets with KQL queries. Supports multiple file merge.';
csvTab.appendChild(csvDesc);

// File input
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.id = 'csvInput';
fileInput.accept = '.csv';
fileInput.multiple = true;
csvTab.appendChild(fileInput);

// Ticket Label
const ticketLabel = document.createElement('label');
ticketLabel.textContent = 'Generated Ticket';
ticketLabel.style.marginTop = 'var(--sp-4)';
ticketLabel.style.display = 'block';
csvTab.appendChild(ticketLabel);

// Output Textarea
const outputArea = document.createElement('textarea');
outputArea.id = 'output';
outputArea.placeholder = 'Upload a linkedAlerts CSV...';
csvTab.appendChild(outputArea);

// Copy Button
const copyBtn = document.createElement('button');
copyBtn.className = 'action-button';
copyBtn.textContent = 'Copy Ticket';
copyBtn.onclick = () => copyToClipboard(outputArea.value, copyBtn);
csvTab.appendChild(copyBtn);

// Divider
const divider = document.createElement('hr');
divider.className = 'ops-divider';
csvTab.appendChild(divider);

// Signature ID Lookup Section
const sigLabel = document.createElement('h3');
sigLabel.textContent = 'Signature ID Lookup';
csvTab.appendChild(sigLabel);

const sigDesc = document.createElement('p');
sigDesc.style.fontSize = '12px';
sigDesc.style.color = 'var(--ops-text-dim)';
sigDesc.style.marginBottom = 'var(--sp-3)';
sigDesc.textContent = 'Click a signature ID to look up its rule on EveBox.';
csvTab.appendChild(sigDesc);

const sigButtonContainer = document.createElement('div');
sigButtonContainer.id = 'sigButtonContainer';
sigButtonContainer.style.display = 'flex';
sigButtonContainer.style.flexWrap = 'wrap';
sigButtonContainer.style.gap = 'var(--sp-2)';
sigButtonContainer.style.marginBottom = 'var(--sp-4)';
csvTab.appendChild(sigButtonContainer);

// Divider 2
const divider2 = document.createElement('hr');
divider2.className = 'ops-divider';
csvTab.appendChild(divider2);

// KQL Label
const kqlLabel = document.createElement('h3');
kqlLabel.textContent = 'Generated KQL Queries for Extracted IPs';
csvTab.appendChild(kqlLabel);

// KQL Inputs Container
const kqlInputsContainer = document.createElement('div');
kqlInputsContainer.className = 'ops-inset-panel';
kqlInputsContainer.style.display = 'flex';
kqlInputsContainer.style.flexWrap = 'wrap';
kqlInputsContainer.style.gap = 'var(--sp-4)';
kqlInputsContainer.style.marginBottom = 'var(--sp-5)';

const kqlInputFields = [
  { id: 'kql_device_name', label: 'Device Name', placeholder: 'e.g. DESKTOP-123' },
  { id: 'kql_netid', label: 'NetID', placeholder: 'e.g. user@usf.edu' },
  { id: 'kql_mac', label: 'MAC Address(es)', placeholder: 'Comma separated' },
  { id: 'kql_domain', label: 'Domain', placeholder: 'e.g. example.com' },
  { id: 'kql_sha256', label: 'SHA256 Hash(es)', placeholder: 'Comma separated' }
];

kqlInputFields.forEach(f => {
  const wrapper = document.createElement('div');
  wrapper.style.flex = '1';
  wrapper.style.minWidth = '180px';
  const lbl = document.createElement('label');
  lbl.textContent = f.label;
  lbl.style.display = 'block';
  lbl.style.marginBottom = 'var(--sp-1)';
  const inp = document.createElement('input');
  inp.type = 'text';
  inp.id = f.id;
  inp.placeholder = f.placeholder;
  inp.style.width = '100%';
  inp.style.margin = '0';
  inp.addEventListener('input', refreshActiveKQL);
  wrapper.appendChild(lbl);
  wrapper.appendChild(inp);
  kqlInputsContainer.appendChild(wrapper);
});

csvTab.appendChild(kqlInputsContainer);

// KQL Button Grid
const kqlButtonGrid = document.createElement('div');
kqlButtonGrid.id = 'kqlButtonGrid';
kqlButtonGrid.style.display = 'flex';
kqlButtonGrid.style.flexWrap = 'wrap';
kqlButtonGrid.style.gap = 'var(--sp-2)';
kqlButtonGrid.style.marginBottom = 'var(--sp-4)';
csvTab.appendChild(kqlButtonGrid);

// Single KQL Output Card (hidden until a query is selected)
const kqlOutputCard = document.createElement('div');
kqlOutputCard.id = 'kqlOutputCard';
kqlOutputCard.className = 'ops-card';
kqlOutputCard.style.display = 'none';

const kqlOutputHeader = document.createElement('div');
kqlOutputHeader.style.display = 'flex';
kqlOutputHeader.style.justifyContent = 'space-between';
kqlOutputHeader.style.alignItems = 'center';
kqlOutputHeader.style.marginBottom = 'var(--sp-2)';

const kqlOutputTitle = document.createElement('h4');
kqlOutputTitle.id = 'kqlOutputTitle';
kqlOutputTitle.style.margin = '0';

const kqlCopyBtn = document.createElement('button');
kqlCopyBtn.className = 'action-button secondary';
kqlCopyBtn.textContent = 'Copy';
kqlCopyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
kqlCopyBtn.style.fontSize = '11px';
kqlCopyBtn.onclick = () => copyToClipboard(kqlOutputTA.value, kqlCopyBtn);

kqlOutputHeader.appendChild(kqlOutputTitle);
kqlOutputHeader.appendChild(kqlCopyBtn);
kqlOutputCard.appendChild(kqlOutputHeader);

const kqlOutputTA = document.createElement('textarea');
kqlOutputTA.id = 'kqlOutputTA';
kqlOutputTA.readOnly = true;
kqlOutputTA.style.marginBottom = '0';
kqlOutputTA.style.background = 'var(--ops-inset)';
kqlOutputCard.appendChild(kqlOutputTA);

csvTab.appendChild(kqlOutputCard);

// Track active query
let activeQueryKey = null;

// Global State for KQL Generator
let csvParsedState = {
  allIPs: [],
  times: [],
  domains: []
};

// ---------- regex patterns ----------
const patterns = {
  timestamp: /"timestamp": "(.+?)\./,
  src_ip: /"src_ip": "(.+?)"/,
  src_port: /"src_port": (.+?),/,
  dest_ip: /"dest_ip": "(.+?)"/,
  dest_port: /"dest_port": (.+?),/,
  signature_id: /"signature_id": (.+?),/,
  host_header: /^Host: (.+)$/m,
  request_uri: /^(?:GET|POST|HEAD|CONNECT|PUT)\ (.+)\ .+$/m,
  tls_subject: /"tls": {"subject": "(.+?)"/,
  tls_issuer: /"issuerdn": "(.+?)"/,
  app_proto: /"app_proto": "(.+?)"/,
  direction: /"direction": "(.+?)"/
};

// ---------- No non-printable chars ----------
function noBreakingText(str) {
  return str.split('').map(c => {
    const code = c.charCodeAt(0);
    return (code >= 32 && code <= 126 || [9, 10, 13].includes(code)) ? c : '.';
  }).join('');
}

// ---------- CSV Parser func ----------
function parseCSV(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (c === '"' && inQuotes && n === '"') { field += '"'; i++; }
    else if (c === '"') { inQuotes = !inQuotes; }
    else if (c === ',' && !inQuotes) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !inQuotes) {
      if (c === '\r' && n === '\n') i++;
      row.push(field);
      rows.push(row);
      row = []; field = '';
    } else { field += c; }
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

// ---------- read input ----------
fileInput.addEventListener("change", e => {
  const files = e.target.files;
  if (files.length === 0) return;

  let combinedText = "";
  let filesProcessed = 0;
  let isFirstFile = true;

  Array.from(files).forEach(file => {
    const reader = new FileReader();
    reader.onload = () => {
      const fileContent = reader.result;

      if (isFirstFile) {
        combinedText += fileContent;
        isFirstFile = false;
      } else {
        const rows = fileContent.split("\n");
        combinedText += rows.slice(1).join("\n");
      }

      filesProcessed++;

      if (filesProcessed === files.length) {
        processCSV(combinedText);
        showToast(`Processed ${files.length} CSV file(s)`, 'success');
      }
    };
    reader.readAsText(file);
  });
});



// ---------- process CSV ----------
function processCSV(text) {
  const rawRows = parseCSV(text);
  const headers = rawRows.shift();
  const idx = name => headers.indexOf(name);

  const sets = {
    timestamps: new Set(), descriptions: new Set(), src_ips: new Set(), src_ports: new Set(),
    dest_ips: new Set(), dest_ports: new Set(), tls_subjects: new Set(), tls_issuers: new Set(),
    directions: new Set(), app_protos: new Set(), domains: new Set(), urls: new Set(),
    sigs: new Set(), payloads: new Set()
  };

  rawRows.forEach(r => {
    const row = {};
    headers.forEach((h, i) => row[h] = r[i] || '');

    const event_json = row["event_json"] || "";

    // regex extraction
    for (const [k, rx] of Object.entries(patterns)) {
      const m = event_json.match(rx);
      if (!m) continue;
      switch (k) {
        case 'timestamp': sets.timestamps.add(m[1].replace("T", " ")); break;
        case 'signature_id': sets.sigs.add(m[1]); break;
        case 'tls_subject': sets.tls_subjects.add(m[1]); break;
        case 'tls_issuer': sets.tls_issuers.add(m[1]); break;
        case 'app_proto':
          const proto = (m[1] && (m[1].toLowerCase() === "failed" || m[1].toLowerCase() === "null")) ? "N/A" : m[1]?.toUpperCase();
          sets.app_protos.add(proto);
          break;
        case 'direction': sets.directions.add(m[1]); break;
        default: sets[k + 's']?.add(m[1]);
      }
    }

    sets.descriptions.add(row["event_alertSignature"] || "");

    // payload handling
    let payload = (row["event_alertPayload"] || row["event_decoded_alertPayload"] || "").replace(/\s/g, '');
    try {
      const padLen = payload.length - (payload.length % 4);
      payload = atob(payload.slice(0, padLen)).trim();
    } catch (e) {
      payload = (row["event_decoded_alertPayload"] || "").trim();
    }
    sets.payloads.add(payload);

    // domains, urls
    const proto = row["event_app_Proto"] === "tls" ? "hxxps://" : "hxxp://";
    const httpHostname = row["event_httpHostname"]?.replace(/\./g, '[.]');
    const httpUrl = row["event_httpUrl"] || "";
    const tlsSni = row["event_tlsSni"]?.replace(/\./g, '[.]');
    const decodedPayload = row["event_decoded_alertPayload"] || "";
    const hostname = decodedPayload.match(patterns.host_header);
    const uri = decodedPayload.match(patterns.request_uri);

    if (row["event_rrname_domain"]) sets.domains.add(row["event_rrname_domain"].replace(/\./g, '[.]'));
    if (row["event_rrname_url"]) sets.urls.add(row["event_rrname_url"].replace(/\./g, '[.]'));
    if (httpHostname !== "null") {
      sets.domains.add(`${httpHostname}`);
      if (httpUrl) { sets.urls.add(`${proto}${httpHostname}${httpUrl}`); }
    }
    if (tlsSni) { sets.domains.add(tlsSni); }
    if (hostname) { sets.domains.add(hostname[1]?.replace(/\./g, '[.]')); }
    if (uri) { sets.urls.add(`${proto}${hostname[1]?.replace(/\./g, '[.]')}${uri[1] || ''}`); }

  });

  const times = [...sets.timestamps].sort();
  const timerange = times.length <= 1 ? times[0] || "" : `${times[0]} - ${times[times.length - 1]}`;
  const domainsInfo = sets.domains.size ? `\n\nObserved Domains/URLs:\n${[...sets.domains].join("\n")}` : "";
  const urlsInfo = sets.urls.size ? `\n${[...sets.urls].join("\n")}` : "";
  const tlsInfo = sets.tls_subjects.size || sets.tls_issuers.size ? `\n\nTLS Subject:\n${[...sets.tls_subjects].join("\n")}\nTLS Issuer:\n${[...sets.tls_issuers].join("\n")}` : "";
  const appProtoInfo = sets.app_protos.size ? `\nApplication Protocol: ${[...sets.app_protos].join(", ")}` : "";
  const dirInfo = sets.directions.size ? `\nDirection: ${[...sets.directions].join(", ")}` : "";

  // start of ticket template
  const output = `
**Description:**
${[...sets.descriptions].join("\n")}

**Summary:**
Defender
* -

Splunk
* -

ITC Portal
* -

Azure
* -

Threat Assessment
* -

----------------------------------------------------------------\u200B
**Recommendations:**



----------------------------------------------------------------\u200B
**Supporting Details:**

Time (UTC): ${timerange}

Source IP: ${[...sets.src_ips].join(", ")}
Source Port: ${[...sets.src_ports].join(", ")}
Destination IP: ${[...sets.dest_ips].join(", ")}
Destination Port: ${[...sets.dest_ports].join(", ")}${dirInfo}${appProtoInfo}${tlsInfo}${domainsInfo}${urlsInfo}

----------------------------------------------------------------\u200B
**Users / Devices:**

**IP:** -
**MAC:** -
**Hostname:** -
**NetID:** -

----------------------------------------------------------------\u200B
Defender


Splunk


ITC Portal


Azure


----------------------------------------------------------------\u200B
**Threat Assessment:**

VT


CentralOps.net


Recorded Future


OTX AlienVault


IOC Radar


ThreatBook CTI


ThreatFox


ANY.RUN


urlscan.io


curl Online


Sandbox


----------------------------------------------------------------\u200B
**Signatures:** ${[...sets.sigs].join(", ")}

**Payload(s):**

${noBreakingText([...sets.payloads].join("\n\n"))}
`.trim(); // end of ticket template

  outputArea.value = output;

  // save state
  csvParsedState.allIPs = [...sets.src_ips, ...sets.dest_ips];
  csvParsedState.times = times;
  csvParsedState.domains = [...sets.domains];

  // Render Signature ID buttons
  sigButtonContainer.innerHTML = '';
  const sigIds = [...sets.sigs].filter(s => s && s.trim());
  if (sigIds.length > 0) {
    sigIds.forEach(sigId => {
      const btn = document.createElement('button');
      btn.className = 'action-button secondary';
      btn.style.fontSize = '12px';
      btn.textContent = `SID: ${sigId}`;
      btn.title = `Look up signature ${sigId} on EveBox`;
      btn.onclick = () => window.open(`https://rules.evebox.org/search?q=${sigId.trim()}`, '_blank');
      sigButtonContainer.appendChild(btn);
    });
  } else {
    const noSigs = document.createElement('span');
    noSigs.style.fontSize = '12px';
    noSigs.style.color = 'var(--ops-text-dim)';
    noSigs.textContent = 'No signature IDs found in CSV.';
    sigButtonContainer.appendChild(noSigs);
  }

  // Update Intel Strip with first IP found
  if (csvParsedState.allIPs.length > 0) {
    updateIntelStrip(csvParsedState.allIPs[0], 'IP');
  }

  renderKQL();
}

// ---------- KQL Query Definitions ----------
function getKQLQueries() {
  const allIPs = csvParsedState.allIPs;
  const times = csvParsedState.times;
  const extractedDomains = csvParsedState.domains;

  // Track which inputs the user actually provided
  const device_name_raw = document.getElementById('kql_device_name').value.trim();
  const netid_raw = document.getElementById('kql_netid').value.trim();
  const macRaw = document.getElementById('kql_mac').value.trim();
  const domain_raw = document.getElementById('kql_domain').value.trim();
  const shaRaw = document.getElementById('kql_sha256').value.trim();

  const hasDevice = !!device_name_raw;
  const hasNetid = !!netid_raw;
  const hasMacs = !!macRaw;
  const hasDomain = !!domain_raw || extractedDomains.length > 0;
  const hasSha = !!shaRaw;
  const hasIPs = allIPs.some(ip => ip && ip.trim() && ip.toLowerCase() !== "null");

  const device_name = device_name_raw || "{device name}";
  const netid = netid_raw || "xxx@usf.edu";
  const macs = macRaw ? macRaw.split(',').map(m => m.trim()).filter(x => x) : ["XX:XX:XX:XX:XX:XX", "XX-XX-XX-XX-XX-XX"];
  const domain = domain_raw || (extractedDomains.length ? extractedDomains[0] : "exampledomain1234x.com");
  const sha256s = shaRaw ? shaRaw.split(',').map(m => m.trim()).filter(x => x) : ["a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9"];

  const validIPs = allIPs.filter(ip => ip && ip.trim() && ip.toLowerCase() !== "null");
  const usfIPs = validIPs.filter(ip => ip.startsWith('131.247.'));
  const remoteIPs = validIPs.filter(ip => !ip.startsWith('131.247.'));

  const anyIpStr = validIPs.length ? validIPs.map(ip => `"${ip}"`).join(", ") : '"x.x.x.x"';
  const remoteIpStr = remoteIPs.length ? remoteIPs.map(ip => `"${ip}"`).join(", ") : '"x.x.x.x"';
  const usfIpStr = usfIPs.length ? usfIPs.map(ip => `"${ip}"`).join(", ") : '"131.247.x.x"';
  const firstAnyIp = validIPs.length ? validIPs[0] : "x.x.x.x";

  const macStr = macs.map(m => `"${m}"`).join(", ");
  const shaStr = sha256s.map(s => `"${s}"`).join(", ");

  const startTime = times.length > 0 ? times[0] : "2026-01-31 00:00:00";
  const endTime = times.length > 0 ? times[times.length - 1] : "2026-01-31 00:00:00";

  // Helper: build OR'd where conditions, skip unfilled fields
  function buildOrWhere(conditions) {
    const active = conditions.filter(c => c.active);
    if (active.length === 0) return '// ⚠️ No search variables provided — fill in at least one field above';
    return '| where ' + active.map(c => c.clause).join('\nor ');
  }

  return [
    {
      key: 'general_ip',
      title: "General IP Search",
      short: "IP Search",
      query: `let ips = dynamic([${anyIpStr}]); // any IP (remote/internal/USF)
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (AlertEvidence,BehaviorEntities,DeviceEvents,DeviceNetworkEvents,AADSignInEventsBeta,EntraIdSignInEvents,
IdentityDirectoryEvents,IdentityLogonEvents,IdentityQueryEvents,DeviceNetworkInfo,Anomalies,BehaviorAnalytics,
OfficeActivity,DeviceFileEvents,DeviceLogonEvents,CommonSecurityLog)
LocalIP in (ips)
or IPAddress in (ips)
or FileOriginIP in (ips)
or RequestSourceIP in (ips)
or RemoteIP in (ips)
or DestinationIPAddress in (ips)
or SourceIP in (ips)
or DestinationIP in (ips)
| where TimeGenerated between (start_time..end_time)`
    },
    {
      key: 'remote_usf',
      title: "Remote IP + USF IP → Internal IP",
      short: "Remote → Internal",
      query: `// remote IP + USF IP --> Internal IP
let ip = dynamic([${remoteIpStr}]); // remote IP(s)
let usf_ip = dynamic([${usfIpStr}]); // USF IP(s), 131.247.x.x
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
CommonSecurityLog
| extend USF_IP = extract(@"131.247.[0-9]{1,3}.[0-9]{1,3}", 0, AdditionalExtensions)
| where SourceIP in (ip) or DestinationIP in (ip)
| where USF_IP in (usf_ip) or SourceIP in (usf_ip) or DestinationIP in (usf_ip)
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort, USF_IP, SourceUserName, DeviceEventClassID, Reason, DeviceCustomString1, Computer, DeviceName
| sort by TimeGenerated desc
| take 100`
    },
    {
      key: 'device_netid',
      title: "Device Name / USF IP → NetID",
      short: "Device → NetID",
      query: `// Device Name and/or USF IP --> NetID
let netid  = "${netid}";
let device_name = "${device_name}";
let ip = "${firstAnyIp}"; // USF IP (131.247.x.x) or remote IP
let start_time = datetime(${startTime}) - 1m;
let end_time  = datetime(${endTime}) + 1m;
AADSignInEventsBeta
${buildOrWhere([
        { active: hasNetid, clause: `AccountUpn == netid` },
        { active: hasDevice, clause: `DeviceName contains device_name` },
        { active: hasIPs, clause: `IPAddress == ip` }
      ])}
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, IPAddress, DeviceName, AccountDisplayName, AccountUpn, OSPlatform, UserAgent, Application, * 
| sort by TimeGenerated desc 
| take 100`
    },
    {
      key: 'device_tables',
      title: "Device Name → Tables",
      short: "Device → Tables",
      query: `// Device Name --> Tables
let device_name = "${device_name}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (AlertEvidence,AADSignInEventsBeta,EntraIdSignInEvents,IdentityDirectoryEvents,IdentityLogonEvents,
IdentityQueryEvents,DeviceEvents,DeviceFileEvents,DeviceImageLoadEvents,DeviceInfo,DeviceLogonEvents,
DeviceNetworkEvents,DeviceNetworkInfo,DeviceProcessEvents,DeviceRegistryEvents)
DeviceName contains device_name
or DeviceId contains device_name
or RemoteDeviceName contains device_name
or TargetDeviceName contains device_name
or DestinationDeviceName contains device_name
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc`
    },
    {
      key: 'device_info',
      title: "Device Name → Info (DeviceInfo)",
      short: "DeviceInfo",
      query: `// Device Name --> Info
let device_name = "${device_name}";
let time_ago = 90d;
DeviceInfo
| where DeviceName =~ device_name
| project-reorder TimeGenerated, DeviceName, DeviceId, PublicIP, LoggedOnUsers, DeviceType, OSPlatform, Vendor, Model, OSDistribution, *
| where TimeGenerated >= ago(time_ago)
| sort by TimeGenerated desc
| take 100`
    },
    {
      key: 'device_logon',
      title: "Device Name → Info (DeviceLogonEvents)",
      short: "Logon Events",
      query: `let device_name = "${device_name}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
DeviceLogonEvents
| where DeviceName contains device_name or RemoteDeviceName contains device_name or AccountName contains device_name
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP, RemotePort, RemoteDeviceName, LogonType, AccountSid, AdditionalFields, Protocol, * 
| sort by TimeGenerated desc
| take 100`
    },
    {
      key: 'mac_device',
      title: "MAC / IP / Device → Device Info",
      short: "MAC → Device",
      query: `// MAC or Internal/USF IP or Device Name --> Device Info
let mac = dynamic([${macStr}]); // MAC Address, Both - and : forms
let ip = "${firstAnyIp}"; // Internal/USF IP (10.x.x.x or 131.247.x.x)
let device_name = "${device_name}";
let time_ago = 90d;
DeviceNetworkInfo
${buildOrWhere([
        { active: hasMacs, clause: `MacAddress in~ (mac)` },
        { active: hasIPs, clause: `IPAddresses == ip` },
        { active: hasDevice, clause: `DeviceName contains device_name` }
      ])}
| where TimeGenerated >= ago(time_ago)
| extend IPAddress = tostring(parse_json(IPAddresses)[0].IPAddress) 
| project-reorder TimeGenerated, DeviceName, DeviceId, MacAddress, IPAddress, NetworkAdapterVendor, * 
| sort by TimeGenerated desc
| take 10`
    },
    {
      key: 'identity_logon',
      title: "Identity Logon Events",
      short: "Identity Logon",
      query: `let ip = "${firstAnyIp}";
let device_name = "${device_name}";
let netid = "${netid}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
IdentityLogonEvents 
${buildOrWhere([
        { active: hasNetid, clause: `AccountUpn == netid` },
        { active: hasDevice, clause: `DeviceName contains device_name` },
        { active: hasIPs, clause: `(IPAddress == ip or DestinationIPAddress == ip)` }
      ])}
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, AccountDisplayName, AccountUpn, DeviceName, IPAddress, DestinationDeviceName, 
DestinationIPAddress, DestinationPort, ActionType, LogonType, FailureReason, TargetDeviceName, Application, Protocol, *
| order by TimeGenerated asc
| take 500`
    },
    {
      key: 'dns_ldap',
      title: "Domain / Remote IP → DNS/LDAP Logs",
      short: "DNS/LDAP",
      query: `// domain or remote IP --> query (DNS/LDAP) logs
let domain = "${domain}"; // queried domain
let ip = dynamic([${remoteIpStr}]); // remote IP(s)
let device_name = "${device_name}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
IdentityQueryEvents
${buildOrWhere([
        { active: hasDomain, clause: `QueryTarget contains domain` },
        { active: hasIPs, clause: `(IPAddress in (ip) or DestinationIPAddress in (ip))` },
        { active: hasDevice, clause: `DeviceName =~ device_name` }
      ])}
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, DeviceName, IPAddress, Port, DestinationDeviceName, DestinationIPAddress, DestinationPort, QueryTarget, QueryType, Application, Location, AdditionalFields
| order by TimeGenerated desc
| take 100`
    },
    {
      key: 'netid_tables',
      title: "NetID → Tables",
      short: "NetID → Tables",
      query: `// returns tables with instances of a NetID
let net_id = "${netid}";
let start_time = datetime(${startTime}) - 15m;
let end_time = datetime(${endTime}) + 15m;
let username = extract("^(.*)@", 1, net_id); // leave this alone
search
AccountUpn == net_id
or AccountName == username
or SourceUserName contains username
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table`
    },
    {
      key: 'sha256_hunt',
      title: "SHA256 Hunt",
      short: "SHA256 Hunt",
      query: `// SHA256-Hunt
let sha256_hash = dynamic([${shaStr}]); // hashes
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,
DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,BehaviorEntities)
SHA256 in (sha256_hash)
| where TimeGenerated between (start_time..end_time)
| sort by Timestamp asc
| project-reorder TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType,
InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
FileName, ProcessCommandLine, SHA256, InitiatingProcessSHA256, InitiatingProcessParentId, InitiatingProcessId
| take 500`
    },
    {
      key: 'mac_netid',
      title: "MAC → NetID",
      short: "MAC → NetID",
      query: `// MAC --> NetID
let mac = dynamic([${macStr}]); // MAC Address, Both - and : forms
let time_ago = 90d;
Syslog
| extend MAC_Address = extract(@"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", 0, SyslogMessage), NetID = extract(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", 0, SyslogMessage)
| where MAC_Address in~ (mac)
| where TimeGenerated >= ago(time_ago)
| where notempty(NetID)
| project EventTime, MAC_Address, NetID, Computer, HostIP, SyslogMessage 
| sort by EventTime desc
| take 10`
    }
  ];

  return queries;
}

// ---------- Build KQL Button Grid ----------
function renderKQL() {
  kqlButtonGrid.innerHTML = '';
  const queries = getKQLQueries();

  queries.forEach(q => {
    const btn = document.createElement('button');
    btn.className = 'action-button secondary';
    btn.textContent = q.short;
    btn.style.fontSize = '12px';
    btn.dataset.key = q.key;

    if (activeQueryKey === q.key) {
      btn.className = 'action-button';
    }

    btn.onclick = () => {
      if (activeQueryKey === q.key) {
        // Toggle off
        activeQueryKey = null;
        kqlOutputCard.style.display = 'none';
        btn.className = 'action-button secondary';
      } else {
        // Show this query
        activeQueryKey = q.key;
        showSingleQuery(q);
        // Update button states
        kqlButtonGrid.querySelectorAll('button').forEach(b => {
          b.className = b.dataset.key === q.key ? 'action-button' : 'action-button secondary';
          b.style.fontSize = '12px';
        });
      }
    };

    kqlButtonGrid.appendChild(btn);
  });

  // If there's an active query, refresh it with updated values
  if (activeQueryKey) {
    const active = queries.find(q => q.key === activeQueryKey);
    if (active) showSingleQuery(active);
  }
}

function showSingleQuery(q) {
  kqlOutputTitle.textContent = q.title;
  kqlOutputTA.value = q.query;
  kqlOutputCard.style.display = 'block';
  // Calculate height based on line count (more reliable than scrollHeight during initial render)
  const lineCount = q.query.split('\n').length;
  const lineHeight = 20; // ~13px font * 1.5 line-height
  const padding = 24; // top + bottom padding
  kqlOutputTA.style.height = Math.max(Math.min(lineCount * lineHeight + padding, 500), 120) + 'px';
}

// Refresh active query when inputs change
function refreshActiveKQL() {
  if (activeQueryKey) {
    const queries = getKQLQueries();
    const active = queries.find(q => q.key === activeQueryKey);
    if (active) showSingleQuery(active);
  }
}

// Initial render of button grid
renderKQL();

// ---------- Copy text ----------
function copyOutput() {
  copyToClipboard(outputArea.value, copyBtn);
}