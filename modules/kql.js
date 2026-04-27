// ═══════════════════════════════════════════
//   KQL Queries — Built-in queries only
//   + Internal IP field (syncs to DHCP Lookup + Ticket)
//   + NetID / MAC / Device Name feed the Generated Ticket
// ═══════════════════════════════════════════

window.kqlFilterLogic = window.kqlFilterLogic || 'OR';
window.kqlTimeBefore  = window.kqlTimeBefore  ?? 15;
window.kqlTimeAfter   = window.kqlTimeAfter   ?? 15;

const kqlTab = document.getElementById('kqlTab');

// ─── Header ──────────────────────────────────────────────
const kqlHeader = document.createElement('h2');
kqlHeader.textContent = 'KQL Queries';
kqlTab.appendChild(kqlHeader);

const kqlDesc = document.createElement('p');
kqlDesc.className = 'tab-desc';
kqlDesc.style.marginBottom = 'var(--sp-4)';
kqlDesc.textContent = 'Pre-built hunting queries auto-filled from CSV data. NetID, MAC, Device Name, and Internal IP also populate the Generated Ticket.';
kqlTab.appendChild(kqlDesc);

// ─── Info banner ─────────────────────────────────────────
const kqlInfoBanner = document.createElement('div');
kqlInfoBanner.className = 'ops-card';
kqlInfoBanner.style.cssText = 'border-left:3px solid var(--intel-blue);margin-bottom:var(--sp-4);';
kqlInfoBanner.innerHTML = '<span style="font-size:13px;color:var(--ops-text-muted);">ℹ Upload a CSV in the <strong>Console</strong> section above to auto-fill IPs, domains, and timestamps.</span>';
kqlTab.appendChild(kqlInfoBanner);

// ─── Input fields panel ──────────────────────────────────
const kqlInputsContainer = document.createElement('div');
kqlInputsContainer.className = 'ops-inset-panel';
kqlInputsContainer.style.cssText = 'display:flex;flex-wrap:wrap;gap:var(--sp-4);margin-bottom:var(--sp-4);';

// Note: these feed BOTH the queries AND the ticket
const kqlInputFields = [
  { id:'kql_device_name', label:'Device Name',    placeholder:'e.g. DESKTOP-123',       ticketKey:'deviceName' },
  { id:'kql_netid',       label:'NetID',           placeholder:'e.g. user@usf.edu',       ticketKey:'netid' },
  { id:'kql_mac',         label:'MAC Address',     placeholder:'e.g. ab:f4:0a:a6:8f:f9',  ticketKey:'mac' },
  { id:'kql_internal_ip', label:'Internal IP',     placeholder:'e.g. 131.247.x.x or 10.x.x.x', ticketKey:'internalIp' },
  { id:'kql_sha256',      label:'SHA256 Hash(es)', placeholder:'Comma separated',          ticketKey:null },
];

function pushToTicket() {
  if (typeof window.updateTicketFromKQL !== 'function') return;
  const payload = {};
  kqlInputFields.forEach(f => {
    if (!f.ticketKey) return;
    const el = document.getElementById(f.id);
    payload[f.ticketKey] = el ? el.value : '';
  });
  window.updateTicketFromKQL(payload);
}

kqlInputFields.forEach(f => {
  const w = document.createElement('div');
  w.style.cssText = 'flex:1;min-width:180px;';
  const lbl = document.createElement('label');
  lbl.textContent = f.label;
  lbl.style.cssText = 'display:block;margin-bottom:var(--sp-1);';
  const inp = document.createElement('input');
  inp.type = 'text'; inp.id = f.id; inp.placeholder = f.placeholder;
  inp.style.cssText = 'width:100%;margin:0;';

  inp.addEventListener('input', () => {
    renderBuiltinQueries();
    if (f.ticketKey) pushToTicket();
    if (f.id === 'kql_internal_ip') {
      // Sync to DHCP Start IP
      if (typeof window.setDhcpStartIp === 'function') {
        window.setDhcpStartIp(inp.value, { silent: true });
      }
    }
  });
  w.appendChild(lbl); w.appendChild(inp);
  kqlInputsContainer.appendChild(w);
});

// AND/OR toggle
const kqlLogicRow = document.createElement('div');
kqlLogicRow.style.cssText = 'display:flex;align-items:center;gap:var(--sp-2);width:100%;margin-top:var(--sp-3);padding-top:var(--sp-3);border-top:1px solid var(--ops-border);';
const kqlLogicLabel = document.createElement('span');
kqlLogicLabel.textContent = 'Filter logic:';
kqlLogicLabel.style.cssText = 'font-size:12px;color:var(--ops-text-muted);';
kqlLogicRow.appendChild(kqlLogicLabel);
['OR','AND'].forEach(op => {
  const btn = document.createElement('button');
  btn.textContent = op; btn.dataset.op = op;
  btn.className = 'action-button ' + (op === 'OR' ? 'primary' : 'secondary');
  btn.style.cssText = 'padding:3px 14px;font-size:12px;font-family:"Fira Code",monospace;font-weight:600;';
  btn.addEventListener('click', () => {
    window.kqlFilterLogic = op;
    document.querySelectorAll('[data-op]').forEach(b => {
      b.className = 'action-button ' + (b.dataset.op === op ? 'primary' : 'secondary');
    });
    renderBuiltinQueries();
  });
  kqlLogicRow.appendChild(btn);
});
const kqlLogicHint = document.createElement('span');
kqlLogicHint.style.cssText = 'font-size:11px;color:var(--ops-text-dim);';
kqlLogicHint.textContent = 'OR = match any · AND = match all';
kqlLogicRow.appendChild(kqlLogicHint);
kqlInputsContainer.appendChild(kqlLogicRow);
kqlTab.appendChild(kqlInputsContainer);

// Expose an API for dhcp-lookup.js to push Internal IP back into the KQL field
window.setKqlInternalIp = function(ip, opts = {}) {
  const el = document.getElementById('kql_internal_ip');
  if (!el) return;
  if (el.value === ip) return;
  el.value = ip;
  if (!opts.silent) {
    renderBuiltinQueries();
    pushToTicket();
  }
};

// ─── Time window control (single stepper: sets BOTH before and after) ──
const kqlTimeCtrl = document.createElement('div');
kqlTimeCtrl.className = 'kql-time-ctrl';
kqlTimeCtrl.innerHTML = `
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--ops-text-dim)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
  <span style="font-size:12px;color:var(--ops-text-muted);font-weight:500;">Time Window</span>
  <span style="font-size:11px;color:var(--ops-text-dim);">± minutes around event</span>
`;

const stepper = document.createElement('div');
stepper.className = 'time-stepper';

const minusBtn = document.createElement('button');
minusBtn.type = 'button';
minusBtn.className = 'stepper-btn';
minusBtn.setAttribute('aria-label', 'Decrease by 1 minute');
minusBtn.textContent = '−';

const windowInput = document.createElement('input');
windowInput.type = 'text';
windowInput.className = 'stepper-input';
windowInput.value = '15';
windowInput.setAttribute('aria-label', 'Time window in minutes');
windowInput.inputMode = 'numeric';

const plusBtn = document.createElement('button');
plusBtn.type = 'button';
plusBtn.className = 'stepper-btn';
plusBtn.setAttribute('aria-label', 'Increase by 1 minute');
plusBtn.textContent = '+';

const minSuffix = document.createElement('span');
minSuffix.textContent = 'min';
minSuffix.style.cssText = 'font-size:12px;color:var(--ops-text-muted);margin-left:var(--sp-1);';

function setTimeWindow(v, { rerender = true } = {}) {
  const n = Math.max(0, Math.min(1440, Math.floor(v)));  // clamp 0–1440 minutes
  window.kqlTimeBefore = n;
  window.kqlTimeAfter  = n;
  windowInput.value    = String(n);
  if (rerender) renderBuiltinQueries();
}

minusBtn.addEventListener('click', () => setTimeWindow((parseInt(windowInput.value, 10) || 0) - 1));
plusBtn.addEventListener('click',  () => setTimeWindow((parseInt(windowInput.value, 10) || 0) + 1));

windowInput.addEventListener('input', () => {
  const v = parseInt(windowInput.value, 10);
  if (isNaN(v)) return;          // let user keep typing
  setTimeWindow(v, { rerender: true });
});
windowInput.addEventListener('blur', () => {
  const v = parseInt(windowInput.value, 10);
  if (isNaN(v) || v < 0) setTimeWindow(0);
});
windowInput.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowUp')   { e.preventDefault(); setTimeWindow((parseInt(windowInput.value, 10) || 0) + 1); }
  if (e.key === 'ArrowDown') { e.preventDefault(); setTimeWindow((parseInt(windowInput.value, 10) || 0) - 1); }
});

stepper.appendChild(minusBtn);
stepper.appendChild(windowInput);
stepper.appendChild(plusBtn);
kqlTimeCtrl.appendChild(stepper);
kqlTimeCtrl.appendChild(minSuffix);
kqlTab.appendChild(kqlTimeCtrl);

// ─── Built-in queries container ──────────────────────────
const builtinHeader = document.createElement('div');
builtinHeader.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--sp-3);';
builtinHeader.innerHTML = `<h3 style="margin:0;font-size:14px;font-weight:600;color:var(--ops-text-muted);text-transform:uppercase;letter-spacing:0.06em;">Built-in Queries</h3>`;
const collapseAllBtn = document.createElement('button');
collapseAllBtn.className = 'action-button secondary';
collapseAllBtn.style.cssText = 'padding:3px 10px;font-size:11px;';
collapseAllBtn.textContent = 'Collapse All';
collapseAllBtn.onclick = () => queriesContainer.querySelectorAll('details').forEach(d => d.open = false);
builtinHeader.appendChild(collapseAllBtn);
kqlTab.appendChild(builtinHeader);

const queriesContainer = document.createElement('div');
queriesContainer.id = 'kqlQueriesContainer';
queriesContainer.style.cssText = 'display:flex;flex-direction:column;gap:var(--sp-2);';
kqlTab.appendChild(queriesContainer);

// ─────────────────────────────────────────────────
//   BUILT-IN QUERY GENERATION
// ─────────────────────────────────────────────────
function getKQLQueriesForTab() {
  const state = window.csvParsedState || { allIPs:[], times:[], domains:[] };
  const allIPs = state.allIPs;
  const times  = state.times;
  const extractedDomains = state.domains;

  const device_name_raw = document.getElementById('kql_device_name')?.value.trim() || '';
  const netid_raw  = document.getElementById('kql_netid')?.value.trim() || '';
  const macRaw     = document.getElementById('kql_mac')?.value.trim() || '';
  const shaRaw     = document.getElementById('kql_sha256')?.value.trim() || '';
  const internalIp = document.getElementById('kql_internal_ip')?.value.trim() || '';

  const hasDevice = !!device_name_raw;
  const hasNetid  = !!netid_raw;
  const hasMacs   = !!macRaw;
  const hasDomain = extractedDomains.length > 0;
  const hasIPs    = allIPs.some(ip => ip && ip.trim() && ip.toLowerCase() !== 'null');

  const device_name = device_name_raw || '{device name}';
  const netid  = netid_raw  || 'xxx@usf.edu';
  const domain = extractedDomains.length ? extractedDomains[0] : 'exampledomain1234x.com';

  function macToAllFormats(mac) {
    const raw = mac.replace(/[:\-\s.]/g,'').toUpperCase();
    if (raw.length !== 12 || !/^[0-9A-F]+$/.test(raw)) return [mac];
    const p = raw.match(/.{2}/g);
    return [p.join(':'), p.join('-'), raw];
  }
  const macs = macRaw
    ? macRaw.split(',').map(m=>m.trim()).filter(Boolean).flatMap(macToAllFormats)
    : ['XX:XX:XX:XX:XX:XX','XX-XX-XX-XX-XX-XX','XXXXXXXXXXXX'];
  const sha256s = shaRaw ? shaRaw.split(',').map(s=>s.trim()).filter(Boolean) : ['{sha256 hash(es)}'];

  const validIPs  = allIPs.filter(ip => ip && ip.trim() && ip.toLowerCase() !== 'null');
  const usfIPs    = validIPs.filter(ip => ip.startsWith('131.247.'));
  const remoteIPs = validIPs.filter(ip => !ip.startsWith('131.247.'));

  // If Internal IP was provided manually, include it in USF IPs
  const usfIPsCombined = internalIp && !usfIPs.includes(internalIp)
    ? [...usfIPs, internalIp] : usfIPs;

  const remoteIpStr = remoteIPs.length ? remoteIPs.map(ip=>`"${ip}"`).join(', ') : '"x.x.x.x"';
  const usfIpStr    = usfIPsCombined.length ? usfIPsCombined.map(ip=>`"${ip}"`).join(', ') : (internalIp ? `"${internalIp}"` : '"131.247.x.x"');
  const firstAnyIp  = internalIp || (validIPs.length ? validIPs[0] : 'x.x.x.x');
  const macStr  = macs.map(m=>`"${m}"`).join(', ');
  const shaStr  = sha256s.map(s=>`"${s}"`).join(', ');

  const startTime = times.length > 0 ? times[0] : '2026-01-31 00:00:00';
  const endTime   = times.length > 0 ? times[times.length-1] : '2026-01-31 00:00:00';

  const tb = window.kqlTimeBefore ?? 15;
  const ta = window.kqlTimeAfter  ?? 15;

  function buildOrWhere(conditions) {
    const active = conditions.filter(c => c.active);
    if (active.length === 0) return '// ⚠️ No search variables provided — fill in at least one field above';
    const op = window.kqlFilterLogic === 'AND' ? '\nand ' : '\nor ';
    return '| where ' + active.map(c => c.clause).join(op);
  }

  const queries = [];

  queries.push({ title:'CommonSecurityLog', query:
`// Remote IP + USF IP --> Internal IP
let ip = dynamic([${remoteIpStr}]); // remote IP(s)
let usf_ip = dynamic([${usfIpStr}]); // USF IP(s), 131.247.x.x or internal
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
CommonSecurityLog
| extend USF_IP = extract(@"131.247.[0-9]{1,3}.[0-9]{1,3}", 0, AdditionalExtensions)
| where SourceIP in (ip) or DestinationIP in (ip)
| where USF_IP in (usf_ip) or SourceIP in (usf_ip) or DestinationIP in (usf_ip)
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort, USF_IP, ReceivedBytes, SentBytes,
Protocol, DeviceEventClassID, Reason, SourceUserName, DestinationUserName, Computer,
DeviceName, DeviceVendor, DeviceProduct, AdditionalExtensions
| sort by TimeGenerated desc
| take 100` });

  if (validIPs.length > 0) {
    validIPs.forEach(ip => {
      queries.push({ title:`IP-Hunt (${ip})`, query:
`let ip = "${ip}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
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
| sort by count_ desc` });
    });
  } else if (internalIp) {
    queries.push({ title:`IP-Hunt (${internalIp})`, query:
`let ip = "${internalIp}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
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
| sort by count_ desc` });
  } else {
    queries.push({ title:'IP-Hunt (x.x.x.x)', query:
`let ip = "x.x.x.x";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
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
| sort by count_ desc` });
  }

  queries.push({ title:'AADSignInEventsBeta', query:
`let netid  = "${netid}";
let device_name = "${device_name}";
let ip = "${firstAnyIp}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
AADSignInEventsBeta
${buildOrWhere([
  { active:hasNetid,  clause:`AccountUpn == netid` },
  { active:hasDevice, clause:`DeviceName contains device_name` },
  { active:hasIPs||!!internalIp, clause:`IPAddress == ip` },
])}
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, IPAddress, DeviceName, AccountDisplayName, AccountUpn, OSPlatform, UserAgent, Application, *
| sort by TimeGenerated desc
| take 100` });

  queries.push({ title:'DeviceNetworkInfo', query:
`let mac = dynamic([${macStr}]);
let ip = "${firstAnyIp}";
let device_name = "${device_name}";
let time_ago = 90d;
DeviceNetworkInfo
${buildOrWhere([
  { active:hasMacs,   clause:`MacAddress in~ (mac)` },
  { active:hasIPs||!!internalIp, clause:`IPAddresses == ip` },
  { active:hasDevice, clause:`DeviceName contains device_name` },
])}
| where TimeGenerated >= ago(time_ago)
| extend IPAddress = tostring(parse_json(IPAddresses)[0].IPAddress)
| project-reorder TimeGenerated, DeviceName, DeviceId, MacAddress, IPAddress, NetworkAdapterVendor, *
| sort by TimeGenerated desc
| take 10` });

  queries.push({ title:'Domain-Hunt', query:
`let domain = "${domain}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
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
| sort by count_ desc` });

  queries.push({ title:'DeviceNetworkEvents', query:
`let domain = "${domain}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
DeviceNetworkEvents
| where RemoteUrl contains domain
| extend Direction = extract(@'"direction":"([^"]+)"', 1, tostring(AdditionalFields))
| where ActionType !contains "Dns"
| where TimeGenerated between (start_time..end_time)
| project-reorder DeviceName, InitiatingProcessAccountUpn, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ActionType, Direction, InitiatingProcessAccountName, *
| sort by TimeGenerated desc
| take 100` });

  queries.push({ title:'IdentityLogonEvents', query:
`let ip = "${firstAnyIp}";
let device_name = "${device_name}";
let netid = "${netid}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
IdentityLogonEvents
${buildOrWhere([
  { active:hasNetid,  clause:`AccountUpn == netid` },
  { active:hasDevice, clause:`DeviceName contains device_name` },
  { active:hasIPs||!!internalIp, clause:`(IPAddress == ip or DestinationIPAddress == ip)` },
])}
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, AccountDisplayName, AccountUpn, DeviceName, IPAddress, DestinationDeviceName,
DestinationIPAddress, DestinationPort, ActionType, LogonType, FailureReason, TargetDeviceName, Application, Protocol, *
| order by TimeGenerated asc
| take 500` });

  queries.push({ title:'DeviceLogonEvents', query:
`let device_name = "${device_name}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
DeviceLogonEvents
| where DeviceName contains device_name or RemoteDeviceName contains device_name or AccountName contains device_name
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP, RemotePort, RemoteDeviceName, LogonType, AccountSid, AdditionalFields, Protocol, *
| sort by TimeGenerated desc
| take 100` });

  queries.push({ title:'Device-Hunt', query:
`let device_name = "${device_name}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
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
| sort by count_ desc` });

  queries.push({ title:'DeviceInfo', query:
`let device_name = "${device_name}";
let time_ago = 90d;
DeviceInfo
| where DeviceName =~ device_name
| project-reorder TimeGenerated, DeviceName, DeviceId, PublicIP, LoggedOnUsers, DeviceType, OSPlatform, Vendor, Model, OSDistribution, *
| where TimeGenerated >= ago(time_ago)
| sort by TimeGenerated desc
| take 5` });

  queries.push({ title:'IdentityQueryEvents', query:
`let domain = "${domain}";
let ip = dynamic([${remoteIpStr}]);
let device_name = "${device_name}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
IdentityQueryEvents
${buildOrWhere([
  { active:hasDomain, clause:`QueryTarget contains domain` },
  { active:hasIPs,    clause:`(IPAddress in (ip) or DestinationIPAddress in (ip))` },
  { active:hasDevice, clause:`DeviceName =~ device_name` },
])}
| where TimeGenerated between (start_time..end_time)
| project TimeGenerated, DeviceName, IPAddress, Port, DestinationDeviceName, DestinationIPAddress, DestinationPort, QueryTarget, QueryType, Application, Location, AdditionalFields
| order by TimeGenerated desc
| take 100` });

  queries.push({ title:'NetID-Hunt', query:
`let net_id = "${netid}";
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
let username = extract("^(.*)@", 1, net_id);
search
AccountUpn == net_id
or AccountName == username
or SourceUserName contains username
| where TimeGenerated between (start_time..end_time)
| summarize count() by $table
| sort by count_ desc` });

  queries.push({ title:'SHA256-Hunt', query:
`let sha256_hash = dynamic([${shaStr}]);
let start_time = datetime(${startTime}) - ${tb}m;
let end_time   = datetime(${endTime})   + ${ta}m;
search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,
DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,BehaviorEntities)
SHA256 in (sha256_hash)
| where TimeGenerated between (start_time..end_time)
| project-reorder TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType,
InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
FileName, ProcessCommandLine, SHA256, InitiatingProcessSHA256, InitiatingProcessParentId, InitiatingProcessId
| take 500
| sort by Timestamp asc` });

  queries.push({ title:'Syslog', query:
`let mac = dynamic([${macStr}]);
let time_ago = 90d;
Syslog
| extend MAC_Address = extract(@"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", 0, SyslogMessage), NetID = extract(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", 0, SyslogMessage)
| where MAC_Address in~ (mac)
| where TimeGenerated >= ago(time_ago)
| where notempty(NetID)
| project EventTime, MAC_Address, NetID, Computer, HostIP, SyslogMessage
| sort by EventTime desc
| take 10` });

  return queries;
}

// ─────────────────────────────────────────────────
//   RENDER
// ─────────────────────────────────────────────────
function renderBuiltinQueries(collapseAll = false) {
  const state = window.csvParsedState || { allIPs:[], times:[], domains:[] };
  const hasCSVData = state.allIPs.length > 0 || state.times.length > 0 || state.domains.length > 0;
  kqlInfoBanner.style.display = hasCSVData ? 'none' : 'block';

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
    details.open = openStates.hasOwnProperty(q.title) ? openStates[q.title] : false;

    const summary = document.createElement('summary');
    summary.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:var(--sp-3);';

    const titleSpan = document.createElement('span');
    titleSpan.textContent = q.title;
    titleSpan.style.flex = '1';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'action-button secondary';
    copyBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy`;
    copyBtn.style.cssText = 'padding:4px 12px;font-size:12px;margin-left:var(--sp-2);flex-shrink:0;';
    copyBtn.onclick = (e) => {
      e.preventDefault(); e.stopPropagation();
      const ta = details.querySelector('textarea');
      copyToClipboard(ta ? ta.value : q.query, copyBtn);
    };

    summary.appendChild(titleSpan);
    summary.appendChild(copyBtn);
    details.appendChild(summary);

    const queryBlock = document.createElement('textarea');
    queryBlock.value = q.query;
    queryBlock.style.cssText = `font-family:'Fira Code',monospace;font-size:12px;line-height:1.6;
      color:var(--ops-text);background:var(--ops-inset);border:1px solid var(--ops-border);
      border-radius:var(--radius-md);padding:var(--sp-3);margin-top:var(--sp-3);margin-bottom:var(--sp-3);
      overflow-x:auto;overflow-y:hidden;white-space:pre-wrap;word-break:break-word;
      width:100%;resize:none;box-sizing:border-box;`;
    queryBlock.readOnly = false;
    queryBlock.onfocus = function() { this.style.borderColor='var(--ops-accent)'; this.style.boxShadow='0 0 0 2px var(--ops-accent-dim)'; };
    queryBlock.onblur  = function() { this.style.borderColor='var(--ops-border)'; this.style.boxShadow='none'; };

    const autoResize = () => {
      queryBlock.style.height = 'auto';
      queryBlock.style.height = queryBlock.scrollHeight + 'px';
    };
    queryBlock.addEventListener('input', autoResize);
    details.addEventListener('toggle', () => { if (details.open) setTimeout(autoResize, 0); });
    details.appendChild(queryBlock);
    setTimeout(autoResize, 0);
    queriesContainer.appendChild(details);
  });
}

window.refreshKQLTab = () => renderBuiltinQueries(true);
renderBuiltinQueries();
