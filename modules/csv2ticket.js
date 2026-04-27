// ═══════════════════════════════════════════════════════════
//   CSV → Ticket   +   MS-ISAC Paste   +   Generated Ticket
//
//   Two-column layout:
//     LEFT  = Inputs (MS-ISAC email paste + CSV upload)
//     RIGHT = Generated Ticket (reactive to all inputs)
//
//   Ticket regenerates whenever:
//     • CSV is uploaded
//     • MS-ISAC email is pasted
//     • KQL input fields change (NetID, MAC, Device Name, Internal IP)
//     • Enrich IOC sources are toggled
// ═══════════════════════════════════════════════════════════

const csvTab = document.getElementById("csvTab");

// ─── Shared state ────────────────────────────────────────────
window.ticketState = {
  csv: {
    loaded: false,
    rows: [],
    descriptions: new Set(),
    timestamps: [],
    srcIps: new Set(),
    srcPorts: new Set(),
    dstIps: new Set(),
    dstPorts: new Set(),
    tlsSubjects: new Set(),
    tlsIssuers: new Set(),
    directions: new Set(),
    appProtos: new Set(),
    domains: new Set(),
    urls: new Set(),
    signatureIds: new Set(),
    rawPayloads: new Set(),     // base64/raw payload → Streamdata "Input"
    payloads: new Set(),        // decoded printable → Streamdata "Output"
  },
  msIsac: {
    loaded: false,
    description: '',
    analysis: '',
    srcIp: '',
    srcPort: '',
    dstIp: '',
    dstPort: '',
  },
  kql: { netid: '', mac: '', deviceName: '', internalIp: '' },
  osintSources: [],
  pixelAnalysis: '',
  pixelRecommendations: '',
};

const SEP = '\n\n----------------------------------------------------------------\u200B\n';

// ─── UI: Header ──────────────────────────────────────────────
const csvHeader = document.createElement('h2');
csvHeader.textContent = 'CSV → Ticket';
csvTab.appendChild(csvHeader);

const csvDesc = document.createElement('p');
csvDesc.className = 'tab-desc';
csvDesc.textContent = 'Paste MS-ISAC email context on the left, upload CSV evidence, and the ticket renders live on the right.';
csvTab.appendChild(csvDesc);

// ─── UI: Two-column layout ───────────────────────────────────
const twoCol = document.createElement('div');
twoCol.className = 'console-twocol';
twoCol.style.cssText = 'display:flex;gap:var(--sp-5);align-items:flex-start;';
csvTab.appendChild(twoCol);

const mqStyle = document.createElement('style');
mqStyle.textContent = `
  @media (max-width: 1000px) {
    .console-twocol { flex-direction: column; }
    .console-twocol > div { width: 100%; }
  }
`;
document.head.appendChild(mqStyle);

// ═════ LEFT COLUMN ═════
const leftCol = document.createElement('div');
leftCol.style.cssText = 'flex:1;min-width:0;';
twoCol.appendChild(leftCol);

// --- MS-ISAC paste card ---
const misacCard = document.createElement('div');
misacCard.className = 'ops-card';

// Header row: title on the left, "Clear All" button on the right
const misacHeaderRow = document.createElement('div');
misacHeaderRow.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:var(--sp-2);margin-bottom:var(--sp-2);';
const misacTitle = document.createElement('h4');
misacTitle.style.cssText = 'margin:0;';
misacTitle.textContent = 'Email Context (MS-ISAC / Stamus)';
const misacClearAllBtn = document.createElement('button');
misacClearAllBtn.type = 'button';
misacClearAllBtn.className = 'action-button secondary';
misacClearAllBtn.style.cssText = 'padding:3px 10px;font-size:11px;';
misacClearAllBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:3px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>Clear All`;
misacClearAllBtn.title = 'Clear the email context + generated ticket';
misacHeaderRow.appendChild(misacTitle);
misacHeaderRow.appendChild(misacClearAllBtn);
misacCard.appendChild(misacHeaderRow);

const misacHint = document.createElement('p');
misacHint.style.cssText = 'font-size:11px;color:var(--ops-text-dim);margin-bottom:var(--sp-2);';
misacHint.textContent = 'Paste the raw email. Description, Analysis, Source/Destination IP + Port are auto-extracted and cross-matched against the CSV for timestamp and payload.';
misacCard.appendChild(misacHint);

const misacInput = document.createElement('textarea');
misacInput.id = 'misacInput';
misacInput.placeholder = 'Paste MS-ISAC or Stamus Networks email here…\n\nMS-ISAC:\n  Description: …\n  Analysis: Source IP is 1.2.3.4 connecting to destination IP 5.6.7.8 on port 443 …\n\nStamus:\n  [ Stamus Networks Event ] # Description: … # Analysis: Source IP X (Port: Y) was observed communicating with Destination IP …';
misacInput.style.cssText = 'height:260px;margin-top:0;margin-bottom:var(--sp-2);';
misacCard.appendChild(misacInput);

const misacStatus = document.createElement('div');
misacStatus.style.cssText = 'font-size:11px;color:var(--ops-text-dim);font-family:"Fira Code",monospace;min-height:16px;';
misacCard.appendChild(misacStatus);

leftCol.appendChild(misacCard);

// --- CSV upload card ---
const csvCard = document.createElement('div');
csvCard.className = 'ops-card';
csvCard.innerHTML = `<h4>CSV Evidence</h4>`;
const csvHint = document.createElement('p');
csvHint.style.cssText = 'font-size:11px;color:var(--ops-text-dim);margin-bottom:var(--sp-2);';
csvHint.textContent = 'Upload linkedAlerts or Stamus CSV. Multiple files merge. Used to aggregate IPs/domains/payloads and to find the specific event matching the MS-ISAC context.';
csvCard.appendChild(csvHint);

const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.id = 'csvInput';
fileInput.accept = '.csv';
fileInput.multiple = true;
csvCard.appendChild(fileInput);

const csvStatus = document.createElement('div');
csvStatus.style.cssText = 'font-size:11px;color:var(--ops-text-dim);font-family:"Fira Code",monospace;min-height:16px;margin-top:var(--sp-2);';
csvCard.appendChild(csvStatus);

leftCol.appendChild(csvCard);

// --- Signature IDs card ---
const sigCard = document.createElement('div');
sigCard.className = 'ops-card';
sigCard.style.display = 'none';
sigCard.innerHTML = `<h4>Signature IDs</h4>`;
const sigHint = document.createElement('p');
sigHint.style.cssText = 'font-size:11px;color:var(--ops-text-dim);margin-bottom:var(--sp-3);';
sigHint.textContent = 'Click a signature to look it up on EveBox.';
sigCard.appendChild(sigHint);

const sigButtonContainer = document.createElement('div');
sigButtonContainer.id = 'sigButtonContainer';
sigButtonContainer.style.cssText = 'display:flex;flex-wrap:wrap;gap:var(--sp-2);';
sigCard.appendChild(sigButtonContainer);
leftCol.appendChild(sigCard);

// ═════ RIGHT COLUMN ═════
const rightCol = document.createElement('div');
rightCol.style.cssText = 'flex:1;min-width:0;position:sticky;top:var(--sp-4);';
twoCol.appendChild(rightCol);

const ticketCard = document.createElement('div');
ticketCard.className = 'ops-card';
ticketCard.style.marginBottom = 0;

const ticketHeader = document.createElement('div');
ticketHeader.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--sp-2);';
const ticketTitle = document.createElement('h4');
ticketTitle.textContent = 'Generated Ticket';
ticketTitle.style.margin = 0;
const copyBtn = document.createElement('button');
copyBtn.className = 'action-button';
copyBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:4px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy Ticket`;
copyBtn.style.cssText = 'padding:4px 12px;font-size:12px;';
copyBtn.onclick = () => copyToClipboard(outputArea.value, copyBtn);

ticketHeader.appendChild(ticketTitle);
ticketHeader.appendChild(copyBtn);
ticketCard.appendChild(ticketHeader);

const outputArea = document.createElement('textarea');
outputArea.id = 'output';
outputArea.placeholder = 'Paste an MS-ISAC email or upload a CSV to generate a ticket…';
outputArea.style.cssText = 'height:700px;margin-top:var(--sp-2);margin-bottom:0;font-size:12px;line-height:1.55;';
ticketCard.appendChild(outputArea);

rightCol.appendChild(ticketCard);

// Pixel chatbot has moved to modules/pixel.js — it's now a floating widget
// attached to document.body so it persists across tab switches.

// ─────────────────────────────────────────────────────────────
//   PARSING
// ─────────────────────────────────────────────────────────────

function noBreakingText(str) {
  return str.split('').map(c => {
    const code = c.charCodeAt(0);
    return (code >= 32 && code <= 126 || [9, 10, 13].includes(code)) ? c : '.';
  }).join('');
}

// ─── Defang helper ───────────────────────────────────────────
// Converts live IOCs to neutered form for safe pasting in tickets.
//   https://evil.com  →  hxxps://evil[.]com
//   1.2.3.4          →  1[.]2[.]3[.]4
// Preserves the reference URLs in the template (whois.com, cyberchef, etc.)
// via a placeholder swap — they're whitelisted so analysts can still click.
const DEFANG_WHITELIST = [
  'https://www.whois.com/whois/',
  'https://gchq.github.io/CyberChef',
  'https://rules.evebox.org',
];

function defangText(str) {
  if (!str) return str;

  // 1. Swap whitelisted URLs for placeholders so they aren't touched
  const placeholders = [];
  DEFANG_WHITELIST.forEach(url => {
    const re = new RegExp(url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    str = str.replace(re, () => {
      const token = `\u0000WL${placeholders.length}\u0000`;
      placeholders.push(url);
      return token;
    });
  });

  // 2. Defang URL schemes
  str = str.replace(/\bhttps:\/\//gi,  'hxxps://');
  str = str.replace(/\bhttp:\/\//gi,   'hxxp://');
  str = str.replace(/\bftp:\/\//gi,    'fxp://');

  // 3. Defang IPv4 addresses (x.x.x.x → x[.]x[.]x[.]x)
  str = str.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    (m, a, b, c, d) => `${a}[.]${b}[.]${c}[.]${d}`);

  // 4. Defang domains — any FQDN-looking token not already defanged.
  //    Skip anything that already has [.] or \x00 (our placeholders).
  //    Only neuter labels between 2-63 chars with a TLD of 2+ letters.
  str = str.replace(
    /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})\b/g,
    (m) => {
      if (m.includes('[.]') || m.includes('\u0000')) return m;
      return m.replace(/\./g, '[.]');
    }
  );

  // 5. Restore whitelisted URLs
  str = str.replace(/\u0000WL(\d+)\u0000/g, (_, i) => placeholders[+i]);

  return str;
}

// ─── Light defang for Pixel chat ────────────────────────────
// Only defangs clearly-malicious-looking IOCs, leaving normal prose URLs alone.
// Rules:
//   • Public IPv4 addresses (skip private/reserved/localhost ranges)
//   • Domains that appear next to malicious context keywords
//     (malware, c2, phishing, attacker, threat, iocs listed, etc.)
//   • Never touches well-known benign domains (microsoft, google, github, etc.)
const BENIGN_DOMAINS = new Set([
  'microsoft.com','google.com','github.com','stackoverflow.com','wikipedia.org',
  'cloudflare.com','mozilla.org','apple.com','amazon.com','linkedin.com',
  'virustotal.com','abuseipdb.com','urlscan.io','shodan.io','censys.io',
  'whois.com','gchq.github.io','rules.evebox.org','recordedfuture.com',
  'anyrun.com','hybrid-analysis.com','joesandbox.com','otx.alienvault.com',
]);

function isPrivateIp(a, b /*, c, d */) {
  a = +a; b = +b;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0)   return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 224) return true;  // multicast
  if (a === 255) return true;
  // USF public IPv4 space — university endpoints, never IOCs
  if (a === 131 && b === 247) return true;
  return false;
}

function softDefang(str) {
  if (!str) return str;

  // Tokenize word-ish spans so we can inspect each atom
  return str.replace(
    // IPv4 OR  domain OR URL
    /(?:\b(?:https?|ftp):\/\/[^\s<>"']+)|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b)/g,
    (m) => {
      // Skip if already defanged
      if (m.includes('[.]') || /hxxps?:\/\//i.test(m)) return m;

      // URL form — only defang if host isn't benign
      const urlMatch = m.match(/^(https?|ftp):\/\/([^\/?#:]+)(.*)$/i);
      if (urlMatch) {
        const scheme = urlMatch[1].toLowerCase();
        const host = urlMatch[2].toLowerCase();
        const rest = urlMatch[3] || '';
        // benign → leave
        if (BENIGN_DOMAINS.has(host) || [...BENIGN_DOMAINS].some(d => host.endsWith('.' + d))) {
          return m;
        }
        // skip loopback
        if (/^(localhost|127\.|0\.|10\.|192\.168\.)/.test(host)) return m;
        const defangedScheme = scheme === 'https' ? 'hxxps' : scheme === 'http' ? 'hxxp' : 'fxp';
        const defangedHost = /^\d+\.\d+\.\d+\.\d+$/.test(host)
          ? host.replace(/\./g, '[.]')
          : host.replace(/\./g, '[.]');
        return `${defangedScheme}://${defangedHost}${rest}`;
      }

      // IPv4 — only public
      const ipMatch = m.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      if (ipMatch) {
        if (isPrivateIp(ipMatch[1], ipMatch[2])) return m;
        return ipMatch.slice(1).join('[.]');
      }

      // Bare domain — only defang if NOT in benign list
      const dom = m.toLowerCase();
      if (BENIGN_DOMAINS.has(dom)) return m;
      if ([...BENIGN_DOMAINS].some(d => dom.endsWith('.' + d))) return m;
      // Require at least one ".xx" TLD-ish segment that isn't a common English word ending
      // Avoid defanging things like "e.g." or "i.e." — ensure 2+ labels, last label is letters only
      const parts = m.split('.');
      if (parts.length < 2) return m;
      if (parts.some(p => p.length === 0)) return m;
      return m.replace(/\./g, '[.]');
    }
  );
}

function parseCSVText(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (c === '"' && inQuotes && n === '"') { field += '"'; i++; }
    else if (c === '"') inQuotes = !inQuotes;
    else if (c === ',' && !inQuotes) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !inQuotes) {
      if (c === '\r' && n === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

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
  direction: /"direction": "(.+?)"/,
  signature: /"signature":" (.+?)"/,
};

function processCSV(text) {
  const rawRows = parseCSVText(text);
  const headers = rawRows.shift();

  const st = window.ticketState.csv;
  st.rows = [];
  st.descriptions = new Set();
  st.timestamps = [];
  st.srcIps = new Set(); st.srcPorts = new Set();
  st.dstIps = new Set(); st.dstPorts = new Set();
  st.tlsSubjects = new Set(); st.tlsIssuers = new Set();
  st.directions = new Set(); st.appProtos = new Set();
  st.domains = new Set(); st.urls = new Set();
  st.signatureIds = new Set(); st.rawPayloads = new Set(); st.payloads = new Set();

  const timestamps = new Set();
  const isStamus = headers.includes('timestamp_utc') && headers.includes('alert.signature');

  rawRows.forEach(r => {
    const row = {};
    headers.forEach((h, i) => row[h] = r[i] || '');
    const structured = { timestamp:'', src_ip:'', src_port:'', dest_ip:'', dest_port:'', payload:'', rawPayload:'' };

    if (isStamus) {
      const ts = (row['timestamp_utc'] || '').replace(/\.\d+\s*UTC$/, '').replace(' UTC', '');
      if (ts) timestamps.add(ts);
      structured.timestamp = ts;
      if (row['src_ip']) { st.srcIps.add(row['src_ip']); structured.src_ip = row['src_ip']; }
      if (row['src_port']) { st.srcPorts.add(row['src_port']); structured.src_port = row['src_port']; }
      if (row['dest_ip']) { st.dstIps.add(row['dest_ip']); structured.dest_ip = row['dest_ip']; }
      if (row['dest_port']) { st.dstPorts.add(row['dest_port']); structured.dest_port = row['dest_port']; }
      if (row['direction']) st.directions.add(row['direction']);
      if (row['alert.signature']) st.descriptions.add(row['alert.signature']);
      if (row['alert.signature_id']) st.signatureIds.add(row['alert.signature_id']);
      // Stamus: payload_printable = decoded output, payload = raw base64 input
      if (row['payload']) {
        const raw = row['payload'].trim();
        st.rawPayloads.add(raw); structured.rawPayload = raw;
      }
      if (row['payload_printable']) {
        const p = row['payload_printable'].trim();
        st.payloads.add(p); structured.payload = p;
      }
      const ap = row['app_proto'] || '';
      if (ap && ap.toLowerCase() !== 'unknown' && ap.toLowerCase() !== 'failed') st.appProtos.add(ap.toUpperCase());
      const sni = row['tls.sni']; if (sni) st.domains.add(sni.replace(/\./g, '[.]'));
      const host = row['hostname_info.host']; if (host) st.domains.add(host.replace(/\./g, '[.]'));
      const url = row['hostname_info.url']; if (url) st.urls.add(url);
      const ej = row['event_json'] || '';
      const tls_s = ej.match(patterns.tls_subject); if (tls_s) st.tlsSubjects.add(tls_s[1]);
      const tls_i = ej.match(patterns.tls_issuer);  if (tls_i) st.tlsIssuers.add(tls_i[1]);
    } else {
      const event_json = row['event_json'] || '';
      for (const [k, rx] of Object.entries(patterns)) {
        const m = event_json.match(rx);
        if (!m) continue;
        switch (k) {
          case 'timestamp': {
            const t = m[1].replace('T', ' ');
            timestamps.add(t); structured.timestamp = t; break;
          }
          case 'tls_subject': st.tlsSubjects.add(m[1]); break;
          case 'tls_issuer':  st.tlsIssuers.add(m[1]); break;
          case 'app_proto': {
            const proto = (m[1] && (m[1].toLowerCase() === 'failed' || m[1].toLowerCase() === 'null')) ? 'N/A' : m[1]?.toUpperCase();
            st.appProtos.add(proto); break;
          }
          case 'direction': st.directions.add(m[1]); break;
          case 'src_ip':    st.srcIps.add(m[1]);   structured.src_ip = m[1]; break;
          case 'src_port':  st.srcPorts.add(m[1]); structured.src_port = m[1]; break;
          case 'dest_ip':   st.dstIps.add(m[1]);   structured.dest_ip = m[1]; break;
          case 'dest_port': st.dstPorts.add(m[1]); structured.dest_port = m[1]; break;
          case 'signature_id': st.signatureIds.add(m[1]); break;
        }
      }
      st.descriptions.add(row['event_alertSignature'] || '');

      // linkedAlerts: event_alertPayload is base64 raw → decode for printable output
      const rawPayloadStr = (row['event_alertPayload'] || '').replace(/\s/g, '');
      if (rawPayloadStr) { st.rawPayloads.add(rawPayloadStr); structured.rawPayload = rawPayloadStr; }

      let payload = rawPayloadStr || (row['event_decoded_alertPayload'] || '').replace(/\s/g, '');
      try {
        const padLen = payload.length - (payload.length % 4);
        payload = atob(payload.slice(0, padLen)).trim();
      } catch {
        payload = (row['event_decoded_alertPayload'] || '').trim();
      }
      st.payloads.add(payload); structured.payload = payload;

      const proto = row['event_app_Proto'] === 'tls' ? 'hxxps://' : 'hxxp://';
      const httpHostname = row['event_httpHostname']?.replace(/\./g, '[.]');
      const httpUrl = row['event_httpUrl'] || '';
      const tlsSni = row['event_tlsSni']?.replace(/\./g, '[.]');
      const decodedPayload = row['event_decoded_alertPayload'] || '';
      const hostname = decodedPayload.match(patterns.host_header);
      const uri = decodedPayload.match(patterns.request_uri);

      if (row['event_rrname_domain']) st.domains.add(row['event_rrname_domain'].replace(/\./g, '[.]'));
      if (row['event_rrname_url'])    st.urls.add(row['event_rrname_url'].replace(/\./g, '[.]'));
      if (httpHostname && httpHostname !== 'null') {
        st.domains.add(httpHostname);
        if (httpUrl) st.urls.add(`${proto}${httpHostname}${httpUrl}`);
      }
      if (tlsSni) st.domains.add(tlsSni);
      if (hostname) st.domains.add(hostname[1]?.replace(/\./g, '[.]'));
      if (uri) st.urls.add(`${proto}${hostname?.[1]?.replace(/\./g, '[.]') || ''}${uri[1] || ''}`);
    }

    st.rows.push(structured);
  });

  st.timestamps = [...timestamps].sort();
  st.loaded = true;

  window.csvParsedState = {
    allIPs: [...st.srcIps, ...st.dstIps],
    times: st.timestamps,
    domains: [...st.domains].map(d => d.replace(/\[\.\]/g, '.')),
  };

  renderSignatureButtons();

  if (window.csvParsedState.allIPs.length > 0) {
    updateIntelStrip(window.csvParsedState.allIPs[0], 'IP');
  }

  csvStatus.textContent = `✓ ${st.rows.length} rows · ${st.srcIps.size + st.dstIps.size} IPs · ${st.timestamps.length} timestamps`;
  csvStatus.style.color = 'var(--threat-green)';

  if (typeof window.refreshKQLTab === 'function') window.refreshKQLTab();
  if (typeof window.refreshTimestampTab === 'function') window.refreshTimestampTab();

  regenerateTicket();
}

function renderSignatureButtons() {
  const st = window.ticketState.csv;
  sigButtonContainer.innerHTML = '';
  const sigIds = [...st.signatureIds].filter(s => s && s.trim());
  if (sigIds.length > 0) {
    sigCard.style.display = '';
    sigIds.forEach(sigId => {
      const btn = document.createElement('button');
      btn.className = 'action-button secondary';
      btn.style.cssText = 'font-size:12px;padding:4px 10px;';
      btn.textContent = `SID: ${sigId}`;
      btn.title = `Look up signature ${sigId} on EveBox`;
      btn.onclick = () => window.open(`https://rules.evebox.org/search?q=${sigId.trim()}`, '_blank');
      sigButtonContainer.appendChild(btn);
    });
  } else {
    sigCard.style.display = 'none';
  }
}

// ─── MS-ISAC parser (port of the Python logic) ──────────────
// Parses email context — supports MS-ISAC and Stamus Networks formats.
// Detects format heuristically and extracts:
//   - description
//   - analysis  (with or without leading "#" prefix)
//   - source IP/port, destination IP/port
function parseMSISAC(text) {
  const out = { description:'', analysis:'', srcIp:'', srcPort:'', dstIp:'', dstPort:'', loaded:false, format:'' };
  if (!text || !text.trim()) return out;

  out.loaded = true;
  out.format = /\[\s*Stamus Networks Event\s*\]/i.test(text) ? 'stamus' : 'msisac';

  // Section markers: Stamus prefixes "# ", MS-ISAC has them on their own lines.
  // Regex covers both: optional "#" prefix, then label, then ":" or "-".
  const descM = text.match(/(?:#\s*)?Description\s*[:\-]?\s*([\s\S]*?)(?=(?:\n|^|\s)#?\s*Analysis\b|$)/i);
  if (descM) out.description = descM[1].trim().replace(/^[:\-\s]+/, '');

  const anaM = text.match(/(?:#\s*)?Analysis\s*[:\-]?\s*([\s\S]*?)(?=(?:\n|^|\s)#?\s*(?:Recommendations|Supporting Details)\b|$)/i);
  if (anaM) out.analysis = anaM[1].trim().replace(/^[:\-\s]+/, '');

  const searchIn = out.analysis || text;

  // Pattern A — Stamus inline: "Source IP 1.2.3.4 (Port: 49182)"
  //                            "Destination IP 5.6.7.8 (Port: 80/TCP)"
  const stamusSrc = searchIn.match(/(?:Source|Src)\s*IP\s+([0-9]+(?:\.[0-9]+){3})\s*\(?\s*Port\s*[:\s]+(\d{1,5})/i);
  const stamusDst = searchIn.match(/(?:Destination|Dest|Dst)\s*IP\s+([0-9]+(?:\.[0-9]+){3})\s*\(?\s*Port\s*[:\s]+(\d{1,5})/i);
  if (stamusSrc) { out.srcIp = stamusSrc[1]; out.srcPort = stamusSrc[2]; }
  if (stamusDst) { out.dstIp = stamusDst[1]; out.dstPort = stamusDst[2]; }

  // Pattern B — MS-ISAC prose: "Source IP is 1.2.3.4 ... port 443"
  if (!out.srcIp) {
    const m = searchIn.match(/(?:Source|Src)\s*IP(?:\s+address)?\s*(?:is|was|:)?\s*([0-9]+(?:\.[0-9]+){3})/i);
    if (m) out.srcIp = m[1];
  }
  if (!out.dstIp) {
    const m = searchIn.match(/(?:Destination|Dest|Dst)\s*IP(?:\s+address)?\s*(?:is|was|:)?\s*([0-9]+(?:\.[0-9]+){3})/i);
    if (m) out.dstIp = m[1];
  }
  if (!out.srcPort) {
    const m = searchIn.match(/(?:Source|Src)\s*port\s*(?:is|was|:)?\s*(\d{1,5})/i);
    if (m) out.srcPort = m[1];
  }
  if (!out.dstPort) {
    const m = searchIn.match(/(?:Destination|Dest|Dst)\s*port\s*(?:is|was|:)?\s*(\d{1,5})/i);
    if (m) out.dstPort = m[1];
  }
  if (!out.dstPort) {
    const m = searchIn.match(/\bport\s+(\d{1,5})\b/i);
    if (m) out.dstPort = m[1];
  }

  return out;
}

// ─── MS-ISAC ↔ CSV matcher ─────────────────────────────────
function findBestCsvMatch(rows, ms) {
  if (!rows.length) return null;
  let best = null, bestScore = 0;
  for (const r of rows) {
    let score = 0;
    if (ms.srcIp   && r.src_ip   === ms.srcIp)   score++;
    if (ms.srcPort && r.src_port === ms.srcPort) score++;
    if (ms.dstIp   && r.dest_ip  === ms.dstIp)   score++;
    if (ms.dstPort && r.dest_port === ms.dstPort) score++;
    if (score > bestScore) { bestScore = score; best = r; }
  }
  return bestScore > 0 ? best : null;
}

// ─────────────────────────────────────────────────────────────
//   TICKET TEMPLATE
// ─────────────────────────────────────────────────────────────
function buildTicket() {
  const s = window.ticketState;

  const description = s.msIsac.description || [...s.csv.descriptions].filter(Boolean).join('\n') || '';
  // Pixel's analysis overrides MS-ISAC when applied; MS-ISAC still wins over blank
  const analysis = (s.pixelAnalysis || s.msIsac.analysis || '');

  const srcIp  = s.msIsac.srcIp  || [...s.csv.srcIps].join(', ')   || '';
  const srcPort = s.msIsac.srcPort || [...s.csv.srcPorts].join(', ') || '';
  const dstIp  = s.msIsac.dstIp  || [...s.csv.dstIps].join(', ')   || '';
  const dstPort = s.msIsac.dstPort || [...s.csv.dstPorts].join(', ') || '';

  let timestamp = '';
  if (s.msIsac.loaded && s.csv.loaded) {
    const match = findBestCsvMatch(s.csv.rows, s.msIsac);
    if (match?.timestamp) timestamp = match.timestamp;
  }
  if (!timestamp && s.csv.timestamps.length) {
    const ts = s.csv.timestamps;
    timestamp = ts.length === 1 ? ts[0] : `${ts[0]} - ${ts[ts.length-1]}`;
  }

  const macVal = s.kql.mac.trim();
  const devVal = s.kql.deviceName.trim();
  let macLine = '';
  if (macVal && devVal) macLine = `${macVal} (${devVal})`;
  else if (macVal) macLine = macVal;
  else if (devVal) macLine = `(${devVal})`;

  // Each source: header + 2 newlines (= one blank line) for screenshot paste
  const osintBlock = (s.osintSources && s.osintSources.length)
    ? s.osintSources.map(n => `${n}\n\n`).join('')
    : '';

  // ─── Streamdata block ───
  // Layout per user spec:
  //   Streamdata:
  //    Signatures: 1012230
  //
  //   From: https://gchq.github.io/CyberChef
  //
  //   Input: <raw base64 payload, inline>
  //
  //   Output: <decoded printable payload, inline>

  // Streamdata per user spec — exact layout:
  //   **Streamdata:**
  //    Signatures: 1012230
  //   [blank line]
  //   From: https://gchq.github.io/CyberChef
  //   [blank line]
  //   Input: <raw base64>
  //   [blank line]
  //   Output: <decoded, defanged printable>

  const sigLine = s.csv.signatureIds.size
    ? `\n Signatures: ${[...s.csv.signatureIds].join(', ')}\n`
    : '';

  // Choose the matched row's payloads if MS-ISAC matched, else join all unique
  let rawIn = '';
  let decodedOut = '';
  if (s.msIsac.loaded && s.csv.loaded) {
    const match = findBestCsvMatch(s.csv.rows, s.msIsac);
    if (match) {
      rawIn = match.rawPayload || '';
      decodedOut = match.payload || '';
    }
  }
  if (!rawIn && s.csv.rawPayloads.size)   rawIn = [...s.csv.rawPayloads].join('\n\n');
  if (!decodedOut && s.csv.payloads.size) decodedOut = [...s.csv.payloads].join('\n\n');
  // Only the DECODED payload output gets defanged — nothing else in the ticket.
  decodedOut = decodedOut ? defangText(noBreakingText(decodedOut)) : '';

  const streamdataBlock =
    `**Streamdata:**\n` +
    sigLine +
    `\nFrom: https://gchq.github.io/CyberChef\n` +
    `\nInput: ${rawIn}\n` +
    `\nOutput / Payload:\n${decodedOut}\n`;

  // Direction / App Protocol appear under Destination IP only if a destination is set
  const directions = [...s.csv.directions].filter(Boolean);
  const appProtos  = [...s.csv.appProtos].filter(Boolean);
  let destTail = '';
  if (dstIp && dstIp.trim()) {
    if (directions.length) destTail += `Direction: ${directions.join(', ')}\n`;
    if (appProtos.length)  destTail += `Application Protocol: ${appProtos.join(', ')}\n`;
  }

  return (
    `**Description:**\n\n${description}` + SEP +
    `**Analysis:**\n\n${analysis}` + SEP +
    `**Recommendations:**\n\n${s.pixelRecommendations || ''}` + SEP +
    `**Supporting Details:**\n\nTimestamp: ${timestamp}\n\n` +
    `Source IP: ${srcIp}\nPort: ${srcPort}\nFrom: https://www.whois.com/whois/\n\n` +
    (`Destination IP: ${dstIp}\nPort: ${dstPort}\nFrom: https://www.whois.com/whois/\n${destTail}`).replace(/\n+$/, '') + SEP +
    `**Defender:**\n\nTimeframe:\n\nInternal IP: ${s.kql.internalIp}\n\n` +
    `MAC: ${macLine}\n\nNetID: ${s.kql.netid}` + SEP +
    `**OSINT:**\n\n${osintBlock}`.replace(/\n+$/, '') + SEP +
    streamdataBlock
  );
}

function regenerateTicket() {
  const s = window.ticketState;
  if (!s.csv.loaded && !s.msIsac.loaded) {
    outputArea.value = '';
    return;
  }
  // buildTicket() already defangs the decoded payload output; the rest stays live
  outputArea.value = buildTicket();
}
window.regenerateTicket = regenerateTicket;

// ─────────────────────────────────────────────────────────────
//   EVENT WIRING
// ─────────────────────────────────────────────────────────────

// Clear Pixel-applied ticket fields + button state whenever a fresh
// ticket input arrives. Without this, pixelAnalysis / pixelRecommendations
// from the previous incident carry over into the new one.
function resetPixelAppliedToTicket() {
  window.ticketState.pixelAnalysis        = '';
  window.ticketState.pixelRecommendations = '';
  if (typeof window.pixelResetAppliedState === 'function') {
    window.pixelResetAppliedState();
  }
}

// Tracks the last parsed MS-ISAC content so we can detect when the user
// replaces it with fresh content (vs. just extending the existing text).
let lastMsisacContent = '';

// Clear All — wipes email context, CSV state, generated ticket, and Pixel
// applied fields. No confirmation prompt; action is instant.
misacClearAllBtn.addEventListener('click', () => {
  // Wipe the email input + status line
  misacInput.value = '';
  misacStatus.textContent = '';
  lastMsisacContent = '';

  // Reset MS-ISAC parsed state
  window.ticketState.msIsac = {
    loaded:false, description:'', analysis:'',
    srcIp:'', srcPort:'', dstIp:'', dstPort:'',
  };

  // Reset Pixel-applied ticket fields
  resetPixelAppliedToTicket();

  // Clear the generated ticket textarea
  if (typeof outputArea !== 'undefined') outputArea.value = '';

  showToast('Email context and ticket cleared', 'success');
});

fileInput.addEventListener('change', e => {
  const files = e.target.files;
  if (files.length === 0) return;
  resetPixelAppliedToTicket();
  let combined = '', done = 0, isFirst = true;
  csvStatus.textContent = 'Reading…';
  csvStatus.style.color = 'var(--ops-text-muted)';
  Array.from(files).forEach(file => {
    const reader = new FileReader();
    reader.onload = () => {
      if (isFirst) { combined += reader.result; isFirst = false; }
      else { combined += reader.result.split('\n').slice(1).join('\n'); }
      if (++done === files.length) {
        processCSV(combined);
        showToast(`Processed ${files.length} CSV file(s)`, 'success');
      }
    };
    reader.readAsText(file);
  });
});

let misacDebounce;
misacInput.addEventListener('input', () => {
  clearTimeout(misacDebounce);
  misacDebounce = setTimeout(() => {
    const current = misacInput.value;
    // If the user replaced the content (not just extended), consider it a new ticket
    if (current && lastMsisacContent && current.slice(0, 30) !== lastMsisacContent.slice(0, 30)) {
      resetPixelAppliedToTicket();
    }
    lastMsisacContent = current;

    const parsed = parseMSISAC(current);
    window.ticketState.msIsac = parsed;
    if (parsed.loaded) {
      const bits = [];
      if (parsed.srcIp) bits.push(`src=${parsed.srcIp}${parsed.srcPort ? ':' + parsed.srcPort : ''}`);
      if (parsed.dstIp) bits.push(`dst=${parsed.dstIp}${parsed.dstPort ? ':' + parsed.dstPort : ''}`);
      const fmt = parsed.format === 'stamus' ? 'Stamus' : 'MS-ISAC';
      misacStatus.textContent = bits.length ? `✓ Parsed (${fmt})  ·  ${bits.join('  ·  ')}` : `✓ Parsed (${fmt}, no IPs found)`;
      misacStatus.style.color = bits.length ? 'var(--threat-green)' : 'var(--threat-amber)';
    } else {
      misacStatus.textContent = '';
    }
    regenerateTicket();
  }, 200);
});

// ─── Public hooks for other modules ─────────────────────────
window.updateTicketFromKQL = function(kql) {
  Object.assign(window.ticketState.kql, kql);
  regenerateTicket();
};

window.updateTicketFromEnrich = function(sourceNames) {
  window.ticketState.osintSources = Array.isArray(sourceNames) ? sourceNames : [];
  regenerateTicket();
};
