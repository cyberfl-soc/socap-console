// ---------- KQL Queries Tab ---------- //

const kqlTab = document.getElementById("kqlTab");

// Header
const kqlHeader = document.createElement('h2');
kqlHeader.textContent = 'KQL Queries';
kqlTab.appendChild(kqlHeader);

const kqlDesc = document.createElement('p');
kqlDesc.className = 'tab-desc';
kqlDesc.textContent = 'Pre-built KQL hunting queries auto-filled from the CSV data. Click a title to expand. Fill in additional fields below to refine.';
kqlTab.appendChild(kqlDesc);

// Info banner (shown when no CSV data)
const kqlInfoBanner = document.createElement('div');
kqlInfoBanner.className = 'ops-card';
kqlInfoBanner.style.borderLeft = '3px solid var(--intel-blue)';
kqlInfoBanner.style.marginBottom = 'var(--sp-4)';
kqlInfoBanner.innerHTML = '<span style="font-size: 13px; color: var(--ops-text-muted);">ℹ Upload a CSV in the <strong>CSV to Ticket</strong> tab to auto-fill IPs, domains, and time ranges into these queries.</span>';
kqlTab.appendChild(kqlInfoBanner);

// Input fields
const kqlInputsContainer = document.createElement('div');
kqlInputsContainer.className = 'ops-inset-panel';
kqlInputsContainer.style.display = 'flex';
kqlInputsContainer.style.flexWrap = 'wrap';
kqlInputsContainer.style.gap = 'var(--sp-4)';
kqlInputsContainer.style.marginBottom = 'var(--sp-5)';

const kqlInputFields = [
  { id: 'kql_remote_ip', label: 'Remote IP', placeholder: 'e.g. 8.8.8.8' },
  { id: 'kql_usf_ip', label: 'USF IP', placeholder: 'e.g. 131.247.226.180' },
  { id: 'kql_domain', label: 'Domain', placeholder: 'e.g. google.com' },
  { id: 'kql_device_name', label: 'Device Name', placeholder: 'e.g. DESKTOP-123' },
  { id: 'kql_netid', label: 'NetID', placeholder: 'e.g. user@usf.edu' },
  { id: 'kql_mac', label: 'MAC Address', placeholder: 'e.g. ab:f4:0a:a6:8f:f9' },
  { id: 'kql_sha256', label: 'SHA256 Hash(es)', placeholder: 'Comma separated' },
  { id: 'kql_start_time', label: 'Start Time', placeholder: '2026-04-06 00:00:00', type: 'text' },
  { id: 'kql_end_time', label: 'End Time', placeholder: '2026-04-07 23:59:59', type: 'text' }
];

const topRow = document.createElement('div');
topRow.style.display = 'flex';
topRow.style.gap = 'var(--sp-4)';
topRow.style.width = '100%';

const bottomRow = document.createElement('div');
bottomRow.style.display = 'flex';
bottomRow.style.gap = 'var(--sp-4)';
bottomRow.style.width = '100%';

kqlInputFields.forEach((f, index) => {
  const wrapper = document.createElement('div');
  wrapper.style.flex = '1 1 20%';
  wrapper.style.minWidth = '120px';
  const lbl = document.createElement('label');
  lbl.textContent = f.label;
  lbl.style.display = 'block';
  lbl.style.marginBottom = 'var(--sp-1)';
  const inp = document.createElement('input');
  inp.type = f.type || 'text';
  inp.id = f.id;
  inp.placeholder = f.placeholder;
  inp.style.width = '100%';
  inp.style.margin = '0';
  inp.addEventListener('input', () => renderAllQueries(false, true));
  wrapper.appendChild(lbl);
  wrapper.appendChild(inp);

  if (index < 5) {
    topRow.appendChild(wrapper);
  } else {
    bottomRow.appendChild(wrapper);
  }
});

kqlInputsContainer.appendChild(topRow);
kqlInputsContainer.appendChild(bottomRow);

// Add spacer to make bottom row 5 columns (same width as top row)
const spacer = document.createElement('div');
spacer.style.flex = '1 1 20%';
spacer.style.minWidth = '120px';
bottomRow.appendChild(spacer);

kqlTab.appendChild(kqlInputsContainer);

// Queries container
const queriesContainer = document.createElement('div');
queriesContainer.id = 'kqlQueriesContainer';
queriesContainer.style.display = 'flex';
queriesContainer.style.flexDirection = 'column';
queriesContainer.style.gap = 'var(--sp-3)';
kqlTab.appendChild(queriesContainer);

// ---------- Query Generation Logic ---------- //
function getKQLQueriesForTab() {
  const state = window.csvParsedState || { allIPs: [], times: [], domains: [] };
  const allIPs = state.allIPs;
  const times = state.times;
  const extractedDomains = state.domains;

  // Read user inputs
  const device_name_raw = document.getElementById('kql_device_name')?.value.trim() || '';
  const netid_raw = document.getElementById('kql_netid')?.value.trim() || '';
  const macRaw = document.getElementById('kql_mac')?.value.trim() || '';
  const shaRaw = document.getElementById('kql_sha256')?.value.trim() || '';
  const remoteIpRaw = document.getElementById('kql_remote_ip')?.value.trim() || '';
  const usfIpRaw = document.getElementById('kql_usf_ip')?.value.trim() || '';
  const domainRaw = document.getElementById('kql_domain')?.value.trim() || '';
  const startTimeRaw = document.getElementById('kql_start_time')?.value.trim() || '';
  const endTimeRaw = document.getElementById('kql_end_time')?.value.trim() || '';

  const hasDevice = !!device_name_raw;
  const hasNetid = !!netid_raw;
  const hasMacs = !!macRaw;
  const hasDomain = extractedDomains.length > 0;
  const hasSha = !!shaRaw;
  const hasIPs = allIPs.some(ip => ip && ip.trim() && ip.toLowerCase() !== "null");
  const hasRemoteIp = !!remoteIpRaw;
  const hasUserTime = !!startTimeRaw || !!endTimeRaw;

  const device_name = device_name_raw || "DeviceName";
  const netid = netid_raw || "xxx@usf.edu";
  function macToAllFormats(mac) {
    const raw = mac.replace(/[:\-\s.]/g, '').toUpperCase();
    if (raw.length !== 12 || !/^[0-9A-F]+$/.test(raw)) return [mac];
    const p = raw.match(/.{2}/g);
    return [p.join(':'), p.join('-'), raw];
  }
  const macs = macRaw
    ? macRaw.split(',').map(m => m.trim()).filter(x => x).flatMap(macToAllFormats)
    : ["XX:XX:XX:XX:XX:XX", "XX-XX-XX-XX-XX-XX", "XXXXXXXXXXXX"];
  const domain = domainRaw || (extractedDomains.length ? extractedDomains[0] : "domain.tld");
  const sha256s = shaRaw ? shaRaw.split(',').map(m => m.trim()).filter(x => x) : ["{sha256 hash(es)}"];

  const validIPs = [...new Set(allIPs.filter(ip => ip && ip.trim() && ip.toLowerCase() !== "null"))];
  const usfIPs = validIPs.filter(ip => ip.startsWith('131.247.'));
  const csvRemoteIPs = validIPs.filter(ip => !ip.startsWith('131.247.'));

  const userRemoteIpList = remoteIpRaw
    ? remoteIpRaw.split(',').map(ip => ip.trim()).filter(ip => ip)
    : [];
  const remoteIPs = [...new Set([...userRemoteIpList, ...csvRemoteIPs])].filter(ip => ip).map(ip => `"${ip}"`).join(", ") || '"x.x.x.x"';
  const remoteIP = remoteIPs.split(', ')[0] || '"x.x.x.x"';

  const usfIPsStr = (usfIPs.length ? usfIPs : ["131.247.x.x"]).map(ip => `"${ip}"`).join(", ");
  const usfIP = usfIPsStr.split(', ')[0] || '"131.247.x.x"';

  const macStr = macs.map(m => `"${m}"`).join(", ");
  const shaStr = sha256s.map(s => `"${s}"`).join(", ");

  function parseUserTime(raw) {
    if (!raw) return null;
    const trimmed = raw.trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
      return `${trimmed} 00:00:00`;
    }
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)) {
      return trimmed;
    }
    return trimmed;
  }
  const userStartTime = parseUserTime(startTimeRaw);
  const userEndTime = parseUserTime(endTimeRaw);

  const startTime = userStartTime || (times.length > 0 ? times[0] : "2026-01-31 00:00:00");
  const endTime = userEndTime || (times.length > 0 ? times[times.length - 1] : "2026-01-31 00:00:00");

  const queries = [];

// ---------- KQL Queries ---------- //
// --- CommonSecurityLog ---
  queries.push({
    title: `CommonSecurityLog`,
    query: `// Remote IP + USF IP --> Internal IP
let ip = dynamic([${remoteIPs}]); // remote IP(s)
let usf_ip = dynamic([${usfIPsStr}]); // USF IP(s), 131.247.x.x
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
CommonSecurityLog
| extend USF_IP = extract(@"131.247.[0-9]{1,3}.[0-9]{1,3}", 0, AdditionalExtensions)
| where SourceIP in (ip) or DestinationIP in (ip)
| where USF_IP in (usf_ip) or SourceIP in (usf_ip) or DestinationIP in (usf_ip)
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort, USF_IP, ReceivedBytes, SentBytes, 
Protocol, DeviceEventClassID, Reason, SourceUserName, DestinationUserName, Computer, 
DeviceName, DeviceVendor, DeviceProduct, AdditionalExtensions
| sort by TimeGenerated desc
| take 100`
  });

// --- IP-Hunt (Per-IP) ---
  if (validIPs.length > 0) {
    validIPs.forEach(ip => {
      queries.push({
        title: `IP-Hunt (${ip})`,
        query: `let ip = "${ip}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (AlertEvidence,BehaviorEntities,DeviceEvents,DeviceNetworkEvents,AADSignInEventsBeta,EntraIdSignInEvents,
IdentityDirectoryEvents,IdentityLogonEvents,IdentityQueryEvents,DeviceNetworkInfo,Anomalies,BehaviorAnalytics,
OfficeActivity,DeviceFileEvents,DeviceLogonEvents,CommonSecurityLog)
LocalIP == ip
or IPAddress == ip
or FileOriginIP == ip
or RequestSourceIP == ip
or RemoteIP == ip
or DestinationIPAddress == ip
or SourceIP == ip
or DestinationIP == ip
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc`
      });
    });
  } else {
    // Show placeholder when no IPs
    queries.push({
      title: `IP-Hunt (x.x.x.x)`,
      query: `let ip = ${remoteIP};
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (AlertEvidence,BehaviorEntities,DeviceEvents,DeviceNetworkEvents,AADSignInEventsBeta,EntraIdSignInEvents,
IdentityDirectoryEvents,IdentityLogonEvents,IdentityQueryEvents,DeviceNetworkInfo,Anomalies,BehaviorAnalytics,
OfficeActivity,DeviceFileEvents,DeviceLogonEvents,CommonSecurityLog)
LocalIP == ip
or IPAddress == ip
or FileOriginIP == ip
or RequestSourceIP == ip
or RemoteIP == ip
or DestinationIPAddress == ip
or SourceIP == ip
or DestinationIP == ip
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc`
    });
  }

// --- AADSignInEventsBeta ---
  queries.push({
    title: `AADSignInEventsBeta`,
    query: `// Device Name and/or USF IP --> NetID
let netid  = "${netid}";
let device_name = "${device_name}";
let usf_ip = ${usfIP};
let start_time = datetime(${startTime}) - 1m;
let end_time  = datetime(${endTime}) + 1m;
AADSignInEventsBeta
| where IPAddress == usf_ip 
or DeviceName contains device_name
or AccountUpn == netid
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, IPAddress, DeviceName, AccountDisplayName, AccountUpn, OSPlatform, UserAgent, Application, * 
| sort by TimeGenerated desc 
| take 100`
  });

// --- DeviceNetworkInfo ---
  queries.push({
    title: `DeviceNetworkInfo`,
    query: `// MAC or Internal/USF IP or Device Name --> Device Info
let mac = dynamic([${macStr}]); // MAC Address, Both - and : forms
let usf_ip = ${usfIP}; // Internal/USF IP (10.x.x.x or 131.247.x.x)
let device_name = "${device_name}";
let time_ago = 90d;
DeviceNetworkInfo
| where MacAddress in~ (mac) or IPAddresses == usf_ip or DeviceName contains device_name
| where TimeGenerated >= ago(time_ago)
| extend IPAddress = tostring(parse_json(IPAddresses)[0].IPAddress) 
| project-reorder TimeGenerated, DeviceName, DeviceId, MacAddress, IPAddress, NetworkAdapterVendor, * 
| sort by TimeGenerated desc
| take 10`
  });

// --- Domain-Hunt ---
  queries.push({
    title: `Domain-Hunt`,
    query: `// Domain --> Tables
let domain = "${domain}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (DeviceNetworkEvents, DeviceProcessEvents, DeviceEvents, DeviceFileEvents, 
DeviceImageLoadEvents, DeviceRegistryEvents, EmailUrlInfo, CloudAppEvents, 
ThreatIntelIndicators, UrlClickEvents, IdentityQueryEvents)
RemoteUrl contains domain
or Url contains domain
or UrlDomain contains domain
or AdditionalFields contains domain
or QueryTarget contains domain
or DeviceName contains domain
or ProcessCommandLine contains domain
or InitiatingProcessCommandLine contains domain
or RawEventData contains domain
or Data contains domain
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc`
  });

// --- DeviceNetworkEvents ---
  queries.push({
    title: `DeviceNetworkEvents`,
    query: `let domain = "${domain}"; // flagged domain
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
DeviceNetworkEvents
| where RemoteUrl contains domain
| extend Direction = extract(@'"direction":"([^"]+)"', 1, tostring(AdditionalFields))
| where ActionType !contains "Dns"
| where TimeGenerated between (start_time..end_time)
| project-reorder DeviceName, InitiatingProcessAccountUpn, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ActionType, Direction, InitiatingProcessAccountName, * 
| sort by TimeGenerated desc
| take 100`
  });

// --- IdentityLogonEvents ---
  queries.push({
    title: `IdentityLogonEvents`,
    query: `let ip = ${remoteIP};
let device_name = "${device_name}";
let netid = "${netid}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
IdentityLogonEvents 
| where AccountUpn == netid
or DeviceName contains device_name
or (IPAddress == ip or DestinationIPAddress == ip)
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, AccountDisplayName, AccountUpn, DeviceName, IPAddress, DestinationDeviceName, 
DestinationIPAddress, DestinationPort, ActionType, LogonType, FailureReason, TargetDeviceName, Application, Protocol, *
| order by TimeGenerated asc
| take 500`
  });

// --- DeviceLogonEvents ---
  queries.push({
    title: `DeviceLogonEvents`,
    query: `let device_name = "${device_name}";
let netid = "${netid}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
DeviceLogonEvents
| where DeviceName contains device_name 
or RemoteDeviceName contains device_name 
or AccountName in (device_name, netid)
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP, RemotePort, RemoteDeviceName, LogonType, AccountSid, AdditionalFields, Protocol, * 
| sort by TimeGenerated desc
| take 100`
  });

// --- Device-Hunt ---
  queries.push({
    title: `Device-Hunt`,
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
  });

// --- DeviceInfo ---
  queries.push({
    title: `DeviceInfo`,
    query: `// Device Name --> Info
let device_name = "${device_name}";
let time_ago = 90d;
DeviceInfo
| where DeviceName =~ device_name
| project-reorder TimeGenerated, DeviceName, DeviceId, PublicIP, LoggedOnUsers, DeviceType, OSPlatform, Vendor, Model, OSDistribution, *
| where TimeGenerated >= ago(time_ago)
| sort by TimeGenerated desc
| take 5`
  });

// --- IdentityQueryEvents ---
  queries.push({
    title: `IdentityQueryEvents`,
    query: `// domain or IP --> query (DNS/LDAP) logs
let domain = "${domain}"; // queried domain
let ip = dynamic([${remoteIPs}]); // IP(s)
let device_name = "${device_name}";
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
IdentityQueryEvents
| where QueryTarget contains domain 
or (IPAddress in (ip) or DestinationIPAddress in (ip))
or DeviceName =~ device_name
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, DeviceName, IPAddress, Port, DestinationDeviceName, DestinationIPAddress, DestinationPort, QueryTarget, QueryType, Application, Location, AdditionalFields
| order by TimeGenerated desc
| take 100`
  });

// --- NetID-Hunt ---
  queries.push({
    title: `NetID-Hunt`,
    query: `// NetID --> tables
let net_id = "${netid}";
let start_time = datetime(${startTime}) - 15m;
let end_time = datetime(${endTime}) + 15m;
let username = extract("^(.*)@", 1, net_id); // leave this alone
search AccountUpn == net_id
or AccountName == username
or SourceUserName contains username
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc`
  });

// --- SHA256-Hunt ---
  queries.push({
    title: `SHA256-Hunt`,
    query: `// SHA256-Hunt
let sha256_hash = dynamic([${shaStr}]); // hashes
let start_time = datetime(${startTime}) - 15m;
let end_time  = datetime(${endTime}) + 15m;
search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,
DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,BehaviorEntities)
SHA256 in (sha256_hash)
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType,
InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
FileName, ProcessCommandLine, SHA256, InitiatingProcessSHA256, InitiatingProcessParentId, InitiatingProcessId
| take 500
| sort by Timestamp asc`
  });

// --- Syslog ---
  queries.push({
    title: `Syslog`,
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
  });

  return queries;
}

// ---------- Render All Queries ---------- //
function renderAllQueries(collapseAll = false, isUserInput = false) {
  const state = window.csvParsedState || { allIPs: [], times: [], domains: [] };
  const hasCSVData = state.allIPs.length > 0 || state.times.length > 0 || state.domains.length > 0;

  // Populate input boxes from CSV data only on fresh load (not on user input)
  if (hasCSVData && !isUserInput) {
    const remoteIpInput = document.getElementById('kql_remote_ip');
    const usfIpInput = document.getElementById('kql_usf_ip');
    const domainInput = document.getElementById('kql_domain');
    const startTimeInput = document.getElementById('kql_start_time');
    const endTimeInput = document.getElementById('kql_end_time');

    // Clear fields first when fresh CSV loaded (collapseAll = new CSV)
    if (collapseAll) {
      remoteIpInput.value = '';
      usfIpInput.value = '';
      domainInput.value = '';
      startTimeInput.value = '';
      endTimeInput.value = '';
    }

    const validIPs = [...new Set(state.allIPs.filter(ip => ip && ip.trim() && ip.toLowerCase() !== "null"))];
    const usfIPsFromCSV = validIPs.filter(ip => ip.startsWith('131.247.'));
    const remoteIPsFromCSV = validIPs.filter(ip => !ip.startsWith('131.247.'));

    if (!remoteIpInput?.value && remoteIPsFromCSV.length > 0) {
      remoteIpInput.value = remoteIPsFromCSV[0];
    }
    if (!usfIpInput?.value && usfIPsFromCSV.length > 0) {
      usfIpInput.value = usfIPsFromCSV[0];
    }
    if (!domainInput?.value && state.domains.length > 0) {
      domainInput.value = state.domains[0];
    }
    if (!startTimeInput?.value && state.times.length > 0) {
      startTimeInput.value = state.times[0];
    }
    if (!endTimeInput?.value && state.times.length > 0) {
      endTimeInput.value = state.times[state.times.length - 1];
    }
  }

  // Show/hide info banner
  kqlInfoBanner.style.display = hasCSVData ? 'none' : 'block';

  // Track which details are currently open to preserve state (unless a new CSV was loaded)
  const openStates = {};
  if (!collapseAll) {
    queriesContainer.querySelectorAll('details').forEach(d => {
      openStates[d.dataset.title] = d.open;
    });
  }

  const queries = getKQLQueriesForTab();
  queriesContainer.innerHTML = '';

  queries.forEach(q => {
    const details = document.createElement('details');
    details.dataset.title = q.title;
    // If we've seen this query before, preserve its open/closed state. Otherwise default to closed.
    details.open = openStates.hasOwnProperty(q.title) ? openStates[q.title] : false;
    details.style.marginBottom = 'var(--sp-2)';

    const summary = document.createElement('summary');
    summary.style.display = 'flex';
    summary.style.alignItems = 'center';
    summary.style.justifyContent = 'space-between';
    summary.style.gap = 'var(--sp-3)';

    const titleSpan = document.createElement('span');
    titleSpan.textContent = q.title;
    titleSpan.style.flex = '1';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'action-button secondary';
    copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy';
    copyBtn.style.padding = '4px 14px';
    copyBtn.style.fontSize = '12px';
    copyBtn.style.marginLeft = 'var(--sp-2)';
    copyBtn.style.flexShrink = '0';
    copyBtn.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const ta = details.querySelector('textarea');
      copyToClipboard(ta ? ta.value : q.query, copyBtn);
    };

    summary.appendChild(titleSpan);
    summary.appendChild(copyBtn);
    details.appendChild(summary);

    const queryBlock = document.createElement('textarea');
    queryBlock.value = q.query;
    queryBlock.style.fontFamily = "'Fira Code', monospace";
    queryBlock.style.fontSize = '12px';
    queryBlock.style.lineHeight = '1.6';
    queryBlock.style.color = 'var(--ops-text)';
    queryBlock.style.background = 'var(--ops-inset)';
    queryBlock.style.border = '1px solid var(--ops-border)';
    queryBlock.style.borderRadius = 'var(--radius-md)';
    queryBlock.style.padding = 'var(--sp-3)';
    queryBlock.style.marginTop = 'var(--sp-3)';
    queryBlock.style.marginBottom = 'var(--sp-3)';
    queryBlock.style.overflowX = 'auto';
    queryBlock.style.overflowY = 'hidden';
    queryBlock.style.whiteSpace = 'pre-wrap';
    queryBlock.style.wordBreak = 'break-word';
    queryBlock.style.cursor = 'text';
    queryBlock.style.transition = 'border-color 0.15s ease, box-shadow 0.15s ease';
    queryBlock.style.width = '100%';
    queryBlock.style.resize = 'none';
    queryBlock.style.boxSizing = 'border-box';
    queryBlock.readOnly = false;
    queryBlock.title = 'Edit query as needed';
    queryBlock.onfocus = function() {
      this.style.borderColor = 'var(--ops-accent)';
      this.style.boxShadow = '0 0 0 2px var(--ops-accent-dim)';
    };
    queryBlock.onblur = function() {
      this.style.borderColor = 'var(--ops-border)';
      this.style.boxShadow = 'none';
    };

    // Auto-resize textarea to fit content exactly
    const autoResize = () => {
      queryBlock.style.height = 'auto';
      queryBlock.style.height = queryBlock.scrollHeight + 'px';
    };
    queryBlock.addEventListener('input', autoResize);

    // Resize when details is opened to ensure accurate height
    details.addEventListener('toggle', () => {
      if (details.open) {
        setTimeout(autoResize, 0);
      }
    });

    details.appendChild(queryBlock);
    // Call autoResize after appending to DOM to get accurate height
    setTimeout(autoResize, 0);
    queriesContainer.appendChild(details);
  });
}

// Register global refresh function so csv2ticket.js can trigger re-render (collapse all on new CSV)
window.refreshKQLTab = () => renderAllQueries(true);

// Initial render
renderAllQueries();