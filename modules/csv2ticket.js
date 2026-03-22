// ---------- UI Generation ---------- //
const csvTab = document.getElementById("csvTab");

// Tab Header
const csvHeader = document.createElement('h2');
csvHeader.textContent = 'CSV to Ticket';
csvTab.appendChild(csvHeader);

const csvDesc = document.createElement('p');
csvDesc.className = 'tab-desc';
csvDesc.textContent = 'Upload linkedAlerts CSV files to auto-generate investigation tickets. Supports multiple file merge.';
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

// Global State for KQL Generator (shared with kql.js)
window.csvParsedState = {
  allIPs: [],
  times: [],
  domains: []
};

// ---------- regex patterns ----------
const patterns = {
  timestamp: /"timestamp": "(.+?)\./, // event_json
  src_ip: /"src_ip": "(.+?)"/, // event_json
  src_port: /"src_port": (.+?),/, // event_json
  dest_ip: /"dest_ip": "(.+?)"/, // event_json
  dest_port: /"dest_port": (.+?),/, // event_json
  signature_id: /"signature_id": (.+?),/, // event_json
  host_header: /^Host: (.+)$/m, // event_decoded_alertPayload
  request_uri: /^(?:GET|POST|HEAD|CONNECT|PUT)\ (.+)\ .+$/m, // event_decoded_alertPayload
  tls_subject: /"tls": {"subject": "(.+?)"/, // event_json
  tls_issuer: /"issuerdn": "(.+?)"/, // event_json
  app_proto: /"app_proto": "(.+?)"/, // event_json
  direction: /"direction": "(.+?)"/, // event_json
  signature: /"signature":" (.+?)"/ // event_json
};

// const stamus_regex = {
//   timestamp: /"timestamp":"(.+?)\./,
//   src_ip: /"src_ip":"(.+?)"/,
//   src_port: /"src_port":(.+?),/,
//   dest_ip: /"dest_ip":"(.+?)"/,
//   dest_port: /"dest_port":(.+?),/,
//   signature_id: /"signature_id":(.+?),/,
//   host_header: /^Host:(.+)$/m,
//   request_uri: /^(?:GET|POST|HEAD|CONNECT|PUT)\ (.+)\ .+$/m,
//   tls_subject: /"tls": {"subject":"(.+?)"/,
//   tls_issuer: /"issuerdn":"(.+?)"/,
//   app_proto: /"app_proto":"(.+?)"/,
//   direction: /"direction":"(.+?)"/,
//   signature: /"signature":"(.+?)"/ // not yet
// };

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
    signature_ids: new Set(), payloads: new Set()
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
**Signatures:** ${[...sets.signature_ids].join(", ")}

**Payload(s):**

${noBreakingText([...sets.payloads].join("\n\n"))}
`.trim(); // end of ticket template

  outputArea.value = output;

  // save state (shared with kql.js)
  window.csvParsedState.allIPs = [...sets.src_ips, ...sets.dest_ips];
  window.csvParsedState.times = times;
  window.csvParsedState.domains = [...sets.domains];

  // Render Signature ID buttons
  sigButtonContainer.innerHTML = '';
  const sigIds = [...sets.signature_ids].filter(s => s && s.trim());
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
  if (window.csvParsedState.allIPs.length > 0) {
    updateIntelStrip(window.csvParsedState.allIPs[0], 'IP');
  }

  // Notify KQL tab if it has a refresh function
  if (typeof window.refreshKQLTab === 'function') {
    window.refreshKQLTab();
  }
}

// ---------- Copy text ----------
function copyOutput() {
  const output = document.getElementById('output');
  output.select();
  document.execCommand('copy');
}