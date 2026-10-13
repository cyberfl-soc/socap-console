(() => {
'use strict';

// ---------- Investigation Workspace (local/private test build v3) ---------- //
const investigationTab = document.getElementById('investigationTab');
const STORAGE_KEY = 'socapInvestigationWorkspaceV3';

const DEFAULT_STATE = {
  caseId: '', alertTitle: '', signatureId: '', severity: '', confidence: '', eventTimestamp: '',
  source: '', destination: '', domain: '', url: '', relatedActivity: '',
  netid: '', displayName: '', remoteIp: '', usfIp: '', deviceName: '', userAgent: '',
  startTime: '', endTime: '',
  executiveSummary: '', verdict: '', actionTaken: '',
  conclusion: '', recommendations: '',
  analysisContext: '',
  findings: [],
  timelineEvents: [],
  iocs: [],
  devices: [],
  timelineMode: 'chronological',
  autoDefang: true,
  sanitizePreserveExternalIocs: true,
  sanitizeDefangIocs: true,
  checklist: {}
};

function loadWorkspaceState() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    return {
      ...DEFAULT_STATE,
      ...saved,
      findings: Array.isArray(saved.findings) ? saved.findings : [],
      timelineEvents: Array.isArray(saved.timelineEvents) ? saved.timelineEvents : [],
      iocs: Array.isArray(saved.iocs) ? saved.iocs : [],
      devices: Array.isArray(saved.devices) ? saved.devices : [],
      checklist: saved.checklist || {}
    };
  } catch {
    return { ...DEFAULT_STATE, findings: [], checklist: {} };
  }
}
window.investigationState = loadWorkspaceState();
window.ticketHtmlSource = '';

function saveWorkspaceState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(window.investigationState));
    const status = document.getElementById('iw_autosave_status');
    if (status) {
      const now = new Date();
      status.textContent = `Autosaved locally at ${now.toLocaleTimeString()}`;
    }
  } catch (e) {
    if (typeof showToast === 'function') {
      showToast('Local browser storage is full. Save a draft file or remove large screenshots.', 'error');
    }
  }
}

function mk(tag, opts = {}) {
  const el = document.createElement(tag);
  if (opts.className) el.className = opts.className;
  if (opts.text != null) el.textContent = opts.text;
  if (opts.html != null) el.innerHTML = opts.html;
  if (opts.id) el.id = opts.id;
  return el;
}
function actionButton(text, fn, variant = 'primary') {
  const b = mk('button', { text });
  b.type = 'button';
  b.addEventListener('click', fn);
  b.style.minHeight = '36px';
  b.style.padding = '8px 13px';
  b.style.borderRadius = 'var(--radius-md)';
  b.style.fontWeight = '600';
  b.style.cursor = 'pointer';

  if (variant === true || variant === 'secondary') {
    b.style.background = 'transparent';
    b.style.border = '1px solid var(--ops-border-med)';
    b.style.color = 'var(--ops-text)';
  } else if (variant === 'danger') {
    b.style.background = 'var(--threat-red-bg)';
    b.style.border = '1px solid var(--threat-red)';
    b.style.color = 'var(--threat-red)';
  } else if (variant === 'success') {
    b.style.background = 'var(--threat-green-bg)';
    b.style.border = '1px solid var(--threat-green)';
    b.style.color = 'var(--threat-green)';
  } else if (variant === 'accent') {
    b.style.background = 'var(--ops-accent-dim)';
    b.style.border = '1px solid var(--ops-accent)';
    b.style.color = 'var(--ops-accent)';
  } else {
    b.style.background = 'var(--btn-primary)';
    b.style.border = '1px solid var(--btn-primary)';
    b.style.color = '#fff';
  }
  return b;
}

function splitValues(value) {
  return [...new Set(String(value || '')
    .split(/[,\n;]+/)
    .map(v => v.trim())
    .filter(Boolean))];
}

function defangValue(value) {
  const v = String(value || '');
  if (!v) return '';
  if (/^https?:\/\//i.test(v)) {
    return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(v)) {
    return v.replace(/\./g, '[.]');
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) {
    return v.replace(/\./g, '[.]');
  }
  return v;
}

function isInternalIp(ip) {
  if (/^131\.247\./.test(ip)) return true;
  if (/^10\./.test(ip) || /^192\.168\./.test(ip)) return true;
  const m = ip.match(/^172\.(\d+)\./);
  return !!m && Number(m[1]) >= 16 && Number(m[1]) <= 31;
}

function parseCsvText(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else {
      if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n') {
        row.push(field); field = '';
        if (row.some(v => String(v).trim() !== '')) rows.push(row);
        row = [];
      } else if (c !== '\r') field += c;
    }
  }
  row.push(field);
  if (row.some(v => String(v).trim() !== '')) rows.push(row);
  if (!rows.length) return [];
  const headers = rows[0].map(h => h.trim());
  return rows.slice(1).map(cols => {
    const obj = {};
    headers.forEach((h, i) => obj[h] = (cols[i] ?? '').trim());
    return obj;
  });
}

function pickCsvValue(row, patterns) {
  const entries = Object.entries(row);
  for (const re of patterns) {
    const hit = entries.find(([k, v]) => re.test(k) && String(v || '').trim());
    if (hit) return String(hit[1]).trim();
  }
  return '';
}

function allCsvValues(row, patterns) {
  const values = [];
  Object.entries(row).forEach(([k, v]) => {
    if (patterns.some(re => re.test(k)) && String(v || '').trim()) values.push(String(v).trim());
  });
  return values;
}

function sanitizeInvestigationForLlm() {
  const s = window.investigationState;
  const preserveExternal = !!s.sanitizePreserveExternalIocs;
  const defangIocs = !!s.sanitizeDefangIocs;

  const userMap = new Map();
  const deviceMap = new Map();
  const internalIpMap = new Map();
  const macMap = new Map();
  let userN = 0, deviceN = 0, ipN = 0, macN = 0;

  const aliasEmail = email => {
    if (!userMap.has(email)) {
      userN++;
      const domain = email.includes('@') ? email.split('@').pop() : 'example.invalid';
      userMap.set(email, `user${String(userN).padStart(2,'0')}@${domain}`);
    }
    return userMap.get(email);
  };
  const aliasDevice = d => {
    if (!deviceMap.has(d)) {
      deviceN++;
      deviceMap.set(d, `DEVICE-${String(deviceN).padStart(2,'0')}`);
    }
    return deviceMap.get(d);
  };
  const aliasIp = ip => {
    if (!internalIpMap.has(ip)) {
      ipN++;
      internalIpMap.set(ip, `[INTERNAL_IP_${String(ipN).padStart(2,'0')}]`);
    }
    return internalIpMap.get(ip);
  };
  const aliasMac = mac => {
    if (!macMap.has(mac)) {
      macN++;
      macMap.set(mac, `[MAC_${String(macN).padStart(2,'0')}]`);
    }
    return macMap.get(mac);
  };

  function sanitizeText(input) {
    let out = String(input || '');
    out = out.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, m => aliasEmail(m));
    out = out.replace(/\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, m => aliasMac(m));
    out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ip => {
      if (isInternalIp(ip)) return aliasIp(ip);
      if (!preserveExternal) return `[EXTERNAL_IP]`;
      return defangIocs ? defangValue(ip) : ip;
    });
    [...deviceMap.keys()].forEach(d => { out = out.split(d).join(deviceMap.get(d)); });
    return out;
  }

  // Seed device aliases from structured device data.
  (s.devices || []).forEach(d => {
    if (d.hostname) aliasDevice(d.hostname);
  });

  const lines = [];
  lines.push(`Case: ${sanitizeText(s.caseId)}`);
  lines.push(`Alert: ${sanitizeText(s.alertTitle)}`);
  if (s.severity) lines.push(`Severity: ${sanitizeText(s.severity)}`);
  if (s.eventTimestamp) lines.push(`Timestamp: ${sanitizeText(s.eventTimestamp)}`);

  if ((s.iocs || []).length) {
    lines.push('\nIOCs:');
    s.iocs.forEach(i => {
      let value = i.value || '';
      const type = (i.type || '').toLowerCase();
      if (['ip','ip address'].includes(type)) {
        if (isInternalIp(value)) value = aliasIp(value);
        else if (!preserveExternal) value = '[EXTERNAL_IP]';
        else if (defangIocs) value = defangValue(value);
      } else if (['domain','url'].includes(type)) {
        if (!preserveExternal) value = `[${type.toUpperCase()}]`;
        else if (defangIocs) value = defangValue(value);
      } else {
        value = sanitizeText(value);
      }
      lines.push(`- ${i.type || 'IOC'}: ${value}${i.source ? ` | Source: ${sanitizeText(i.source)}` : ''}`);
    });
  }

  if ((s.devices || []).length) {
    lines.push('\nDevices / Users:');
    s.devices.forEach(d => {
      const parts = [];
      if (d.internalIp) parts.push(`IP=${sanitizeText(d.internalIp)}`);
      if (d.mac) parts.push(`MAC=${sanitizeText(d.mac)}`);
      if (d.hostname) parts.push(`Host=${aliasDevice(d.hostname)}`);
      if (d.netid) parts.push(`User=${sanitizeText(d.netid)}`);
      if (d.os) parts.push(`OS=${sanitizeText(d.os)}`);
      lines.push(`- ${parts.join(' | ')}`);
    });
  }

  if (s.analysisContext) lines.push(`\nInvestigation Context:\n${sanitizeText(s.analysisContext)}`);
  if ((s.findings || []).length) {
    lines.push('\nInvestigation Findings:');
    s.findings.forEach(f => {
      lines.push(`- ${sanitizeText([f.timestamp, f.source, f.text].filter(Boolean).join(' | '))}`);
    });
  }
  if (s.conclusion) lines.push(`\nConclusion:\n${sanitizeText(s.conclusion)}`);

  const mapping = [
    ...[...userMap.entries()].map(([a,b]) => `${a} -> ${b}`),
    ...[...deviceMap.entries()].map(([a,b]) => `${a} -> ${b}`),
    ...[...internalIpMap.entries()].map(([a,b]) => `${a} -> ${b}`),
    ...[...macMap.entries()].map(([a,b]) => `${a} -> ${b}`)
  ];

  return {
    text: lines.join('\n'),
    mapping
  };
}
function showLocalToast(msg, type='success') {
  if (typeof showToast === 'function') showToast(msg, type);
}
function escaped(v) {
  return String(v || '').replace(/\\/g,'\\\\').replace(/"/g,'\\"');
}
function firstIp(text) {
  const m = String(text || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return m ? m[0] : '';
}
function uid() {
  return `f_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
function normalizeTimestampForSort(value) {
  if (!value) return Number.MAX_SAFE_INTEGER;
  const parsed = Date.parse(value);
  if (!Number.isNaN(parsed)) return parsed;
  const isoish = value.replace(' UTC', 'Z').replace(' ', 'T');
  const parsed2 = Date.parse(isoish);
  return Number.isNaN(parsed2) ? Number.MAX_SAFE_INTEGER : parsed2;
}
function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

const header = mk('h2', { text: 'Investigation Workspace' });
const desc = mk('p', {
  className: 'tab-desc',
  text: 'Import the ticket once, investigate normally, add findings once, and let SOCAP build the inline analysis, visual timeline, and evidence log from the same findings.'
});
investigationTab.append(header, desc);

const privacy = mk('div', { className: 'ops-card' });
privacy.style.borderLeft = '3px solid var(--threat-green)';
privacy.style.marginBottom = 'var(--sp-4)';
privacy.innerHTML = '<span style="font-size:13px;color:var(--ops-text-muted)">Workspace data is stored locally in this browser. Drafts can be exported for portable recovery.</span>';
investigationTab.appendChild(privacy);

const commandBar = mk('div', { className:'ops-card' });
commandBar.style.cssText = 'display:flex;gap:var(--sp-2);flex-wrap:wrap;align-items:center;margin-bottom:var(--sp-4);border-left:3px solid var(--ops-accent)';
const commandLabel = mk('strong', { text:'Case Actions' });
commandLabel.style.marginRight = '4px';
const topSaveBtn = actionButton('Save Draft', () => saveDraftFile(), 'accent');
const topLoadBtn = actionButton('Load Draft', () => draftInput.click(), 'secondary');
const topExportBtn = actionButton('Export Updated HTML', () => downloadUpdatedHtml(), 'success');
const topClearBtn = actionButton('Clear Workspace', () => clearWorkspace(), 'danger');
commandBar.append(commandLabel, topSaveBtn, topLoadBtn, topExportBtn, topClearBtn);
investigationTab.appendChild(commandBar);

// ---------- Ticket HTML integration ----------
const ticketCard = mk('div', { className: 'ops-card' });
const ticketTitle = mk('h3', { text: 'Ticket HTML Integration' });
ticketTitle.style.marginTop = '0';
const ticketHelp = mk('p', {
  text: 'Paste exported investigation-report HTML or choose an HTML file. Parse fills known context. Export preserves the original document and replaces only mapped fields, Investigation & Analysis, and Evidence Log.'
});
ticketHelp.style.fontSize = '12px';
ticketHelp.style.color = 'var(--ops-text-muted)';
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = '.html,.htm,text/html';
const htmlInput = mk('textarea', { id: 'iw_ticket_html' });
htmlInput.style.height = '130px';
htmlInput.placeholder = 'Paste exported ticket HTML here…';
fileInput.addEventListener('change', async () => {
  const f = fileInput.files?.[0];
  if (!f) return;
  htmlInput.value = await f.text();
  parseTicketHtml();
});
const ticketActions = mk('div');
ticketActions.style.cssText = 'display:flex;gap:var(--sp-2);flex-wrap:wrap';

const draftInput = document.createElement('input');
draftInput.type = 'file';
draftInput.accept = '.socapdraft,.json,application/json';
draftInput.style.display = 'none';
draftInput.addEventListener('change', async () => {
  const f = draftInput.files?.[0];
  if (!f) return;
  try {
    const text = await f.text();
    loadDraftFromText(text);
  } catch (e) {
    showLocalToast('Could not load draft file', 'error');
  } finally {
    draftInput.value = '';
  }
});

ticketActions.append(
  actionButton('Import Ticket HTML', parseTicketHtml, 'accent'),
  actionButton('Copy Updated HTML', copyUpdatedHtml, 'secondary')
);
ticketCard.append(ticketTitle, ticketHelp, fileInput, htmlInput, draftInput, ticketActions);

const autosaveStatus = mk('div', { id:'iw_autosave_status' });
autosaveStatus.style.cssText = 'margin-top:8px;font-size:11px;color:var(--ops-text-dim)';
autosaveStatus.textContent = 'Autosave: local browser draft enabled';
ticketCard.appendChild(autosaveStatus);

investigationTab.appendChild(ticketCard);

// ---------- Context ----------
const contextCard = mk('div', { className: 'ops-card' });
contextCard.style.marginTop = 'var(--sp-4)';
const contextTitle = mk('h3', { text: 'Investigation Context' });
contextTitle.style.marginTop = '0';
contextCard.appendChild(contextTitle);

const grid = mk('div');
grid.style.display = 'grid';
grid.style.gridTemplateColumns = 'repeat(3,minmax(180px,1fr))';
grid.style.gap = 'var(--sp-3)';

const fields = [
  ['caseId','Case / Incident ID','SOC-2026-0000'],
  ['alertTitle','Alert Signature','Suspected password spray attack'],
  ['signatureId','Signature ID','Defender Incident 000000'],
  ['severity','Severity','Medium'],
  ['confidence','Confidence','High / Moderate / Low'],
  ['eventTimestamp','Alert Timestamp','2026-09-02 22:13 UTC'],
  ['source','Source','source IP(s) / port(s)'],
  ['destination','Destination','destination IP(s) / port(s)'],
  ['domain','Domain(s)','example.com, second.example'],
  ['url','URL','https://example.com/path'],
  ['relatedActivity','Related Activity','prior cases / event count'],
  ['netid','NetID / Account','user@usf.edu'],
  ['displayName','Display Name','User Name'],
  ['remoteIp','Remote / Suspicious IP(s)','185.98.168.11, 203.0.113.8'],
  ['usfIp','USF IP(s)','131.247.x.x, 131.247.y.y'],
  ['deviceName','Device Name','DEVICE-NAME'],
  ['userAgent','User Agent','python-requests/...'],
  ['startTime','Start Time','2026-09-01 18:45:00'],
  ['endTime','End Time','2026-09-02 02:00:00']
];

const inputRefs = {};
fields.forEach(([key,label,placeholder]) => {
  const wrap = mk('div');
  const lbl = mk('label', { text: label });
  lbl.style.cssText = 'display:block;font-size:12px;color:var(--ops-text-muted)';
  const inp = mk('input', { id:`iw_${key}` });
  inp.type = 'text';
  inp.placeholder = placeholder;
  inp.value = window.investigationState[key] || '';
  inp.style.margin = 'var(--sp-1) 0 0';
  inp.addEventListener('input', () => {
    window.investigationState[key] = inp.value.trim();
    saveWorkspaceState();
  });
  inputRefs[key] = inp;
  wrap.append(lbl, inp);
  grid.appendChild(wrap);
});
contextCard.appendChild(grid);

const csvFileInput = document.createElement('input');
csvFileInput.type = 'file';
csvFileInput.accept = '.csv,text/csv';
csvFileInput.style.display = 'none';
let csvImportMode = 'context';
csvFileInput.addEventListener('change', async () => {
  const file = csvFileInput.files?.[0];
  if (!file) return;
  try {
    await importCsvFile(file, csvImportMode);
  } finally {
    csvFileInput.value = '';
  }
});

const ctxActions = mk('div');
ctxActions.style.cssText = 'display:flex;gap:var(--sp-2);flex-wrap:wrap;align-items:end;margin-top:var(--sp-4)';

const importSourceWrap = mk('div');
importSourceWrap.style.minWidth = '260px';

const importSourceLabel = mk('label', { text:'Import Source' });
importSourceLabel.style.cssText = 'display:block;font-size:11px;color:var(--ops-text-muted);margin-bottom:4px';

const importSourceSelect = document.createElement('select');
importSourceSelect.style.margin = '0';
[
  ['context','CSV Context File'],
  ['linked','Linked Alerts CSV'],
  ['csvtab','Existing CSV-to-Ticket Data']
].forEach(([value,label]) => {
  const opt = document.createElement('option');
  opt.value = value;
  opt.textContent = label;
  importSourceSelect.appendChild(opt);
});
importSourceWrap.append(importSourceLabel, importSourceSelect);

const importDataBtn = actionButton('Import Data', () => {
  const source = importSourceSelect.value;
  if (source === 'csvtab') {
    importCsvContext();
  } else {
    csvImportMode = source;
    csvFileInput.click();
  }
}, 'secondary');

const sendKqlBtn = actionButton('Send Context to KQL', sendContextToKql, 'accent');

ctxActions.append(importSourceWrap, importDataBtn, sendKqlBtn);
contextCard.append(csvFileInput, ctxActions);
investigationTab.appendChild(contextCard);

// ---------- Structured IOCs ----------
const intelCard = mk('div', { className:'ops-card' });
intelCard.style.marginTop = 'var(--sp-4)';
const intelHeader = mk('div');
intelHeader.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:var(--sp-3);flex-wrap:wrap';
const intelTitle = mk('h3', { text:'IOCs' });
intelTitle.style.margin = '0';
const addIocBtn = actionButton('Add IOC', () => addIoc(), 'accent');
intelHeader.append(intelTitle, addIocBtn);

const iocOptions = mk('div');
iocOptions.style.cssText = 'display:flex;align-items:center;gap:8px;margin:8px 0 12px;font-size:12px;color:var(--ops-text-muted)';
const defangCb = document.createElement('input');
defangCb.type = 'checkbox';
defangCb.checked = window.investigationState.autoDefang !== false;
defangCb.style.width = 'auto';
defangCb.addEventListener('change', () => {
  window.investigationState.autoDefang = defangCb.checked;
  saveWorkspaceState();
  renderIocs();
});
iocOptions.append(defangCb, mk('span', { text:'Auto-defang IOCs in the final report (raw values remain available for KQL).' }));

const iocContainer = mk('div');
iocContainer.style.cssText = 'display:flex;flex-direction:column;gap:8px';
intelCard.append(intelHeader, iocOptions, iocContainer);
investigationTab.appendChild(intelCard);

// ---------- Structured Devices / Users ----------
const deviceCard = mk('div', { className:'ops-card' });
deviceCard.style.marginTop = 'var(--sp-4)';
const deviceHeader = mk('div');
deviceHeader.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:var(--sp-3);flex-wrap:wrap';
const deviceTitle = mk('h3', { text:'Devices / Users' });
deviceTitle.style.margin = '0';
const addDeviceBtn = actionButton('Add Device', () => addDevice(), 'accent');
deviceHeader.append(deviceTitle, addDeviceBtn);
const deviceHelp = mk('p', { text:'Track asset identity once here. These values can feed KQL and Section 4 of the final ticket.' });
deviceHelp.style.cssText = 'font-size:12px;color:var(--ops-text-muted);margin:6px 0 12px';
const deviceContainer = mk('div');
deviceContainer.style.cssText = 'display:flex;flex-direction:column;gap:8px';
deviceCard.append(deviceHeader, deviceHelp, deviceContainer);
investigationTab.appendChild(deviceCard);

// ---------- LLM Sanitizer ----------
const sanitizerCard = mk('div', { className:'ops-card' });
sanitizerCard.style.marginTop = 'var(--sp-4)';
const sanitizerTitle = mk('h3', { text:'Sanitize for LLM' });
sanitizerTitle.style.marginTop = '0';
const sanitizerHelp = mk('p', { text:'Creates a local text-only copy with users, device names, MACs, and internal IPs pseudonymized. Screenshots are intentionally excluded.' });
sanitizerHelp.style.cssText = 'font-size:12px;color:var(--ops-text-muted)';

const sanitizerOpts = mk('div');
sanitizerOpts.style.cssText = 'display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--ops-text-muted);margin:8px 0';
const preserveExt = document.createElement('input');
preserveExt.type = 'checkbox';
preserveExt.checked = window.investigationState.sanitizePreserveExternalIocs !== false;
preserveExt.style.width = 'auto';
preserveExt.addEventListener('change', () => {
  window.investigationState.sanitizePreserveExternalIocs = preserveExt.checked;
  saveWorkspaceState();
});
const defangExt = document.createElement('input');
defangExt.type = 'checkbox';
defangExt.checked = window.investigationState.sanitizeDefangIocs !== false;
defangExt.style.width = 'auto';
defangExt.addEventListener('change', () => {
  window.investigationState.sanitizeDefangIocs = defangExt.checked;
  saveWorkspaceState();
});
const l1 = mk('label'); l1.style.cssText='display:flex;gap:6px;align-items:center'; l1.append(preserveExt, mk('span',{text:'Preserve external IOCs for threat evaluation'}));
const l2 = mk('label'); l2.style.cssText='display:flex;gap:6px;align-items:center'; l2.append(defangExt, mk('span',{text:'Defang preserved external IOCs'}));
sanitizerOpts.append(l1,l2);

const sanitizerOutput = mk('textarea', { id:'iw_sanitized_output' });
sanitizerOutput.style.height = '180px';
sanitizerOutput.placeholder = 'Generate a sanitized copy when you need to paste case context into an LLM.';
const sanitizerMapping = mk('pre');
sanitizerMapping.style.cssText = 'display:none;white-space:pre-wrap;font-family:"Fira Code",monospace;font-size:11px;color:var(--ops-text-muted);margin-top:8px';
const sanitizerActions = mk('div');
sanitizerActions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
sanitizerActions.append(
  actionButton('Generate Sanitized Copy', () => {
    const out = sanitizeInvestigationForLlm();
    sanitizerOutput.value = out.text;
    sanitizerMapping.textContent = out.mapping.length ? `Local mapping (do not paste externally unless needed):\n${out.mapping.join('\n')}` : 'No identifiers required replacement.';
    sanitizerMapping.style.display = 'block';
  }, 'accent'),
  actionButton('Copy Sanitized Text', () => copyToClipboard(sanitizerOutput.value), 'secondary')
);
sanitizerCard.append(sanitizerTitle, sanitizerHelp, sanitizerOpts, sanitizerOutput, sanitizerActions, sanitizerMapping);
investigationTab.appendChild(sanitizerCard);

// ---------- Ticket summary / determination ----------
const reportCard = mk('div', { className: 'ops-card' });
reportCard.style.marginTop = 'var(--sp-4)';
const reportTitle = mk('h3', { text: 'Ticket Summary & Determination' });
reportTitle.style.marginTop = '0';
reportCard.appendChild(reportTitle);

function addGuide(text) {
  const p = mk('p', { text });
  p.style.cssText = 'font-size:12px;color:var(--ops-text-muted);font-style:italic;margin:4px 0 8px;line-height:1.45';
  reportCard.appendChild(p);
  return p;
}

function addReportTextarea(key, label, height, placeholder, guideText='') {
  const lbl = mk('label', { text: label });
  lbl.style.cssText = 'display:block;font-size:12px;color:var(--ops-text-muted);margin-top:var(--sp-3);font-weight:600';
  reportCard.appendChild(lbl);

  if (guideText) addGuide(guideText);

  const ta = mk('textarea', { id:`iw_${key}` });
  ta.style.height = `${height}px`;
  ta.value = window.investigationState[key] || '';
  ta.placeholder = placeholder || '';
  ta.addEventListener('input', () => {
    window.investigationState[key] = ta.value;
    saveWorkspaceState();
  });
  reportRefs[key] = ta;
  reportCard.appendChild(ta);
  return ta;
}

const reportRefs = {};

addReportTextarea(
  'executiveSummary',
  'Executive Summary / BLUF',
  150,
  '<BLUF; brief summary>',
  'BLUF — the answer first, in one or two sentences, for a reader who stops here.'
);

addReportTextarea(
  'verdict',
  'Verdict',
  62,
  '<Malicious / Suspicious / Benign - False Positive / Inconclusive>'
);

addReportTextarea(
  'actionTaken',
  'Action Taken',
  62,
  '<Escalated / Closed as false positive / Inconclusive / Other>'
);

addReportTextarea(
  'conclusion',
  'Conclusion',
  160,
  '<conclusory statement>'
);

addReportTextarea(
  'recommendations',
  'Recommendations — one per line',
  170,
  '<action for USF IT Security to take> <why>\n<action for USF IT Security to take> <why>\n<any other recommendations>'
);

const reportFormatHint = mk('div');
reportFormatHint.className = 'ops-inset-panel';
reportFormatHint.style.marginTop = 'var(--sp-3)';
reportFormatHint.innerHTML = `
  <div style="font-size:12px;color:var(--ops-text-muted);line-height:1.5">
    <strong style="color:var(--ops-text)">Ticket format reminder</strong><br>
    <em>Executive Summary:</em> answer first, one or two sentences.<br>
    <strong>Verdict:</strong> &lt;Malicious / Suspicious / Benign - False Positive / Inconclusive&gt;<br>
    <strong>Action taken:</strong> &lt;Escalated / Closed as false positive / Inconclusive / Other&gt;
  </div>`;
reportCard.appendChild(reportFormatHint);

investigationTab.appendChild(reportCard);

// ---------- Findings + inline screenshots ----------
const findingsCard = mk('div', { className: 'ops-card' });
findingsCard.style.marginTop = 'var(--sp-4)';
const findingsTitleRow = mk('div');
findingsTitleRow.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:var(--sp-3);flex-wrap:wrap';
const findingsTitle = mk('h3', { text: 'Investigation & Analysis' });
findingsTitle.style.margin = '0';
const addFindingBtn = actionButton('Add Evidence / Finding', () => addFinding(), 'accent');
findingsTitleRow.append(findingsTitle, addFindingBtn);

const findingsHelp = mk('p', {
  text: 'All investigation findings: environment threat hunting, OSINT source URLs, screenshots, alert signature behaviour, payload analysis, threat context and reference links. Add broad narrative context once below, then use findings only for evidence/events worth tracking individually.'
});
findingsHelp.style.cssText = 'font-size:12px;color:var(--ops-text-muted);margin-top:var(--sp-2)';

const analysisContextLabel = mk('label', { text:'General Investigation Context' });
analysisContextLabel.style.cssText = 'display:block;font-size:12px;font-weight:600;color:var(--ops-text-muted);margin-top:var(--sp-3)';
const analysisContext = mk('textarea', { id:'iw_analysis_context' });
analysisContext.style.height = '170px';
analysisContext.placeholder = 'Write the narrative/context that does not need its own timestamped artifact. This exports into Investigation & Analysis before the individual findings.';
analysisContext.value = window.investigationState.analysisContext || '';
analysisContext.addEventListener('input', () => {
  window.investigationState.analysisContext = analysisContext.value;
  saveWorkspaceState();
});

const findingsContainer = mk('div');
findingsContainer.style.cssText = 'display:flex;flex-direction:column;gap:var(--sp-3);margin-top:var(--sp-3)';
findingsCard.append(findingsTitleRow, findingsHelp, analysisContextLabel, analysisContext, findingsContainer);
investigationTab.appendChild(findingsCard);

// ---------- Visual timeline ----------
const timelineCard = mk('div', { className: 'ops-card' });
timelineCard.style.marginTop = 'var(--sp-4)';
const timelineHeader = mk('div');
timelineHeader.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:var(--sp-3);flex-wrap:wrap';
const timelineTitle = mk('h3', { text: 'Investigation Timeline' });
timelineTitle.style.margin = '0';
const timelineControls = mk('div');
timelineControls.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap';
const chronologicalBtn = actionButton('Chronological', () => { window.investigationState.timelineMode='chronological'; saveWorkspaceState(); renderTimeline(); }, 'accent');
const entryOrderBtn = actionButton('Entry Order', () => { window.investigationState.timelineMode='entry'; saveWorkspaceState(); renderTimeline(); }, 'secondary');
timelineControls.append(chronologicalBtn, entryOrderBtn);
timelineHeader.append(timelineTitle, timelineControls);
const timelineHelp = mk('p', { text: 'The display can be sorted chronologically without changing the order of Investigation & Analysis artifacts. Linked-alert CSV events can appear here without being added to the report.' });
timelineHelp.style.cssText = 'font-size:12px;color:var(--ops-text-muted)';
const timelineContainer = mk('div');
timelineContainer.style.marginTop = 'var(--sp-3)';
timelineCard.append(timelineHeader, timelineHelp, timelineContainer);
investigationTab.appendChild(timelineCard);

// ---------- Checklist ----------
const checklistCard = mk('div', { className: 'ops-card' });
checklistCard.style.marginTop = 'var(--sp-4)';
const checklistTitle = mk('h3', { text: 'Investigation Checklist' });
checklistTitle.style.marginTop = '0';
checklistCard.appendChild(checklistTitle);

const checklistItems = [
  ['incident_ip','Check whether the suspicious IP is tied to another Defender incident'],
  ['ip_hunt','Run a general Defender / Advanced Hunting pivot on the IP'],
  ['signin','Review interactive and non-interactive sign-ins'],
  ['cloud','Review CloudAppEvents for post-authentication activity'],
  ['mail_rules','Check inbox / mailbox rule changes'],
  ['url_clicks','Review UrlClickEvents near the incident'],
  ['sent_mail','Check outbound mail after suspicious activity'],
  ['blast_radius','Check whether the suspicious email/domain reached other users'],
  ['user_agent','Pivot on suspicious User-Agent across other accounts'],
  ['device','Review managed-device process activity when applicable'],
  ['network','Review CommonSecurityLog / network telemetry when applicable'],
  ['baseline','Compare activity with the user/device normal baseline']
];

const checklistContainer = mk('div');
checklistContainer.style.cssText = 'display:grid;grid-template-columns:repeat(2,minmax(260px,1fr));gap:8px 20px';
checklistItems.forEach(([id,text]) => {
  const row = mk('label');
  row.style.cssText = 'display:flex;align-items:flex-start;gap:8px;font-size:13px;color:var(--ops-text-muted)';
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.checked = !!window.investigationState.checklist[id];
  cb.style.cssText = 'width:auto;margin:3px 0 0';
  cb.addEventListener('change', () => {
    window.investigationState.checklist[id] = cb.checked;
    saveWorkspaceState();
  });
  row.append(cb, mk('span', { text }));
  checklistContainer.appendChild(row);
});
checklistCard.appendChild(checklistContainer);
investigationTab.appendChild(checklistCard);

function syncUiFromState() {
  fields.forEach(([key]) => {
    if (inputRefs[key]) inputRefs[key].value = window.investigationState[key] || '';
  });
  Object.keys(reportRefs).forEach(key => {
    if (reportRefs[key]) reportRefs[key].value = window.investigationState[key] || '';
  });
  if (analysisContext) analysisContext.value = window.investigationState.analysisContext || '';
  defangCb.checked = window.investigationState.autoDefang !== false;
  preserveExt.checked = window.investigationState.sanitizePreserveExternalIocs !== false;
  defangExt.checked = window.investigationState.sanitizeDefangIocs !== false;
  renderIocs();
  renderDevices();
  renderFindings();
  renderTimeline();
}

function addIoc(seed = {}) {
  window.investigationState.iocs.push({
    id: uid(),
    type: seed.type || 'IP Address',
    value: seed.value || '',
    source: seed.source || '',
    intel: seed.intel || ''
  });
  saveWorkspaceState();
  renderIocs();
}

function removeIoc(id) {
  window.investigationState.iocs = window.investigationState.iocs.filter(i => i.id !== id);
  saveWorkspaceState();
  renderIocs();
}

function renderIocs() {
  iocContainer.innerHTML = '';
  const list = window.investigationState.iocs || [];
  if (!list.length) {
    const empty = mk('div', { text:'No structured IOCs yet. CSV/ticket import can add them automatically, or add one manually.' });
    empty.style.cssText = 'font-size:12px;color:var(--ops-text-muted);padding:10px;border:1px dashed var(--ops-border-med)';
    iocContainer.appendChild(empty);
    return;
  }

  list.forEach(ioc => {
    const row = mk('div', { className:'ops-inset-panel' });
    row.style.cssText += ';display:grid;grid-template-columns:150px minmax(220px,1fr) minmax(160px,.8fr) minmax(160px,.8fr) auto;gap:8px;align-items:end';

    const type = document.createElement('select');
    ['IP Address','Domain','URL','File Hash','Email','Other'].forEach(v => {
      const opt = document.createElement('option'); opt.value=v; opt.textContent=v; type.appendChild(opt);
    });
    type.value = ioc.type || 'IP Address';
    type.addEventListener('change', () => { ioc.type=type.value; saveWorkspaceState(); });

    const value = document.createElement('input');
    value.type='text'; value.value=ioc.value || ''; value.placeholder='IOC value';
    value.style.margin='0';
    value.addEventListener('input', () => { ioc.value=value.value.trim(); saveWorkspaceState(); });

    const source = document.createElement('input');
    source.type='text'; source.value=ioc.source || ''; source.placeholder='Where seen';
    source.style.margin='0';
    source.addEventListener('input', () => { ioc.source=source.value.trim(); saveWorkspaceState(); });

    const intel = document.createElement('input');
    intel.type='text'; intel.value=ioc.intel || ''; intel.placeholder='Threat intel / reputation';
    intel.style.margin='0';
    intel.addEventListener('input', () => { ioc.intel=intel.value.trim(); saveWorkspaceState(); });

    const remove = actionButton('Remove', () => removeIoc(ioc.id), 'danger');
    row.append(type,value,source,intel,remove);
    iocContainer.appendChild(row);
  });
}

function addDevice(seed = {}) {
  window.investigationState.devices.push({
    id: uid(),
    internalIp: seed.internalIp || '',
    mac: seed.mac || '',
    hostname: seed.hostname || '',
    netid: seed.netid || '',
    os: seed.os || '',
    management: seed.management || '',
    deviceId: seed.deviceId || ''
  });
  saveWorkspaceState();
  renderDevices();
}

function removeDevice(id) {
  window.investigationState.devices = window.investigationState.devices.filter(d => d.id !== id);
  saveWorkspaceState();
  renderDevices();
}

function renderDevices() {
  deviceContainer.innerHTML = '';
  const list = window.investigationState.devices || [];
  if (!list.length) {
    const empty = mk('div', { text:'No devices/users identified yet.' });
    empty.style.cssText = 'font-size:12px;color:var(--ops-text-muted);padding:10px;border:1px dashed var(--ops-border-med)';
    deviceContainer.appendChild(empty);
    return;
  }

  list.forEach(d => {
    const row = mk('div', { className:'ops-inset-panel' });
    row.style.cssText += ';display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:8px';
    const defs = [
      ['internalIp','Internal IP'],['mac','MAC'],['hostname','Hostname'],['netid','NetID / User'],
      ['os','OS / Version'],['management','Management Status'],['deviceId','Device ID']
    ];
    defs.forEach(([key,label]) => {
      const wrap=mk('div');
      const lbl=mk('label',{text:label}); lbl.style.cssText='font-size:10px;color:var(--ops-text-muted)';
      const inp=document.createElement('input'); inp.type='text'; inp.value=d[key] || ''; inp.style.margin='3px 0 0';
      inp.addEventListener('input', () => { d[key]=inp.value.trim(); saveWorkspaceState(); });
      wrap.append(lbl,inp); row.appendChild(wrap);
    });
    const removeWrap=mk('div'); removeWrap.style.cssText='display:flex;align-items:end';
    removeWrap.appendChild(actionButton('Remove Device', () => removeDevice(d.id), 'danger'));
    row.appendChild(removeWrap);
    deviceContainer.appendChild(row);
  });
}

function addFinding(seed = {}) {
  window.investigationState.findings.push({
    id: uid(),
    type: seed.type || 'finding',
    timestamp: seed.timestamp || '',
    source: seed.source || '',
    text: seed.text || '',
    imageData: seed.imageData || '',
    imageName: seed.imageName || '',
    reference: seed.reference || ''
  });
  saveWorkspaceState();
  renderFindings();
  renderTimeline();
  const newest = findingsContainer.lastElementChild;
  newest?.scrollIntoView?.({ behavior:'smooth', block:'center' });
}

function removeFinding(id) {
  window.investigationState.findings = window.investigationState.findings.filter(f => f.id !== id);
  saveWorkspaceState();
  renderFindings();
  renderTimeline();
}

function moveFinding(id, direction) {
  const arr = window.investigationState.findings;
  const i = arr.findIndex(f => f.id === id);
  const j = i + direction;
  if (i < 0 || j < 0 || j >= arr.length) return;
  [arr[i], arr[j]] = [arr[j], arr[i]];
  saveWorkspaceState();
  renderFindings();
  renderTimeline();
}

function updateFinding(id, key, value) {
  const f = window.investigationState.findings.find(x => x.id === id);
  if (!f) return;
  f[key] = value;
  saveWorkspaceState();
  if (key === 'timestamp' || key === 'source' || key === 'text') renderTimeline();
}

async function fileToCompressedDataUrl(file) {
  const raw = await new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = reject;
    r.readAsDataURL(file);
  });

  if (!file.type.startsWith('image/')) return raw;
  const img = await new Promise((resolve, reject) => {
    const i = new Image();
    i.onload = () => resolve(i);
    i.onerror = reject;
    i.src = raw;
  });

  const maxWidth = 1600;
  const scale = Math.min(1, maxWidth / img.width);
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(img.width * scale));
  canvas.height = Math.max(1, Math.round(img.height * scale));
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  const type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
  return canvas.toDataURL(type, type === 'image/jpeg' ? 0.84 : undefined);
}

async function attachImageToFinding(id, file) {
  if (!file || !file.type.startsWith('image/')) {
    showLocalToast('Choose or paste an image file', 'error');
    return;
  }
  try {
    const data = await fileToCompressedDataUrl(file);
    const f = window.investigationState.findings.find(x => x.id === id);
    if (!f) return;
    f.imageData = data;
    f.imageName = file.name || 'screenshot';
    saveWorkspaceState();
    renderFindings();
    renderTimeline();
  } catch {
    showLocalToast('Could not process screenshot', 'error');
  }
}

function renderFindings() {
  findingsContainer.innerHTML = '';
  const findings = window.investigationState.findings;

  if (!findings.length) {
    const empty = mk('div', { text: 'No findings yet. Add the first meaningful event or observation when you begin investigating.' });
    empty.style.cssText = 'padding:var(--sp-4);border:1px dashed var(--ops-border-med);color:var(--ops-text-muted);font-size:13px';
    findingsContainer.appendChild(empty);
    return;
  }

  findings.forEach((f, idx) => {
    const card = mk('div', { className:'ops-inset-panel', id:`finding_${f.id}` });
    card.style.borderLeft = '3px solid var(--intel-blue)';

    const top = mk('div');
    top.style.cssText = 'display:grid;grid-template-columns:minmax(170px,0.8fr) minmax(160px,0.8fr) auto;gap:var(--sp-2);align-items:end';

    const timeWrap = mk('div');
    const timeLbl = mk('label', { text:'Timestamp' });
    timeLbl.style.cssText = 'font-size:11px;color:var(--ops-text-muted)';
    const timeInp = mk('input');
    timeInp.type = 'text';
    timeInp.placeholder = '2026-09-01 23:14:07 UTC';
    timeInp.value = f.timestamp || '';
    timeInp.style.margin = '3px 0 0';
    timeInp.addEventListener('input', () => updateFinding(f.id, 'timestamp', timeInp.value.trim()));
    timeWrap.append(timeLbl, timeInp);

    const sourceWrap = mk('div');
    const sourceLbl = mk('label', { text:'Source' });
    sourceLbl.style.cssText = 'font-size:11px;color:var(--ops-text-muted)';
    const sourceInp = mk('input');
    sourceInp.type = 'text';
    sourceInp.placeholder = 'Entra / CloudAppEvents / Stamus';
    sourceInp.value = f.source || '';
    sourceInp.style.margin = '3px 0 0';
    sourceInp.addEventListener('input', () => updateFinding(f.id, 'source', sourceInp.value.trim()));
    sourceWrap.append(sourceLbl, sourceInp);

    const controls = mk('div');
    controls.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end';
    const up = actionButton('↑', () => moveFinding(f.id, -1), true);
    const down = actionButton('↓', () => moveFinding(f.id, 1), true);
    const del = actionButton('Remove', () => removeFinding(f.id), true);
    up.disabled = idx === 0;
    down.disabled = idx === findings.length - 1;
    controls.append(up, down, del);
    top.append(timeWrap, sourceWrap, controls);

    const textLbl = mk('label', { text:'Finding' });
    textLbl.style.cssText = 'display:block;font-size:11px;color:var(--ops-text-muted);margin-top:var(--sp-2)';
    const ta = mk('textarea');
    ta.style.height = '92px';
    ta.placeholder = '<what you did, what you found, and what the traffic actually is>';
    ta.value = f.text || '';
    ta.addEventListener('input', () => updateFinding(f.id, 'text', ta.value));

    const refLbl = mk('label', { text:'Query / Reference (optional)' });
    refLbl.style.cssText = 'display:block;font-size:11px;color:var(--ops-text-muted);margin-top:var(--sp-2)';
    const ref = mk('input');
    ref.type = 'text';
    ref.placeholder = 'e.g. EntraIdSignInEvents query / Defender Incident 503071';
    ref.value = f.reference || '';
    ref.style.margin = '3px 0 0';
    ref.addEventListener('input', () => updateFinding(f.id, 'reference', ref.value.trim()));

    const imageRow = mk('div');
    imageRow.style.cssText = 'margin-top:var(--sp-2);display:flex;gap:var(--sp-2);align-items:flex-start;flex-wrap:wrap';

    const imgInput = document.createElement('input');
    imgInput.type = 'file';
    imgInput.accept = 'image/*';
    imgInput.style.maxWidth = '340px';
    imgInput.addEventListener('change', () => attachImageToFinding(f.id, imgInput.files?.[0]));

    const pasteTarget = mk('div', { text:'Paste screenshot here (Ctrl+V)' });
    pasteTarget.tabIndex = 0;
    pasteTarget.style.cssText = 'min-height:44px;padding:10px;border:1px dashed var(--ops-border-med);border-radius:var(--radius-md);font-size:12px;color:var(--ops-text-muted);display:flex;align-items:center';
    pasteTarget.addEventListener('paste', e => {
      const image = [...(e.clipboardData?.items || [])].find(item => item.type.startsWith('image/'));
      if (!image) return;
      e.preventDefault();
      attachImageToFinding(f.id, image.getAsFile());
    });

    imageRow.append(imgInput, pasteTarget);

    if (f.imageData) {
      const previewWrap = mk('div');
      previewWrap.style.cssText = 'margin-top:var(--sp-2)';
      const img = document.createElement('img');
      img.src = f.imageData;
      img.alt = f.imageName || 'Investigation screenshot';
      img.style.cssText = 'max-width:100%;max-height:460px;border:1px solid var(--ops-border-med);border-radius:var(--radius-md)';
      const removeImage = actionButton('Remove Screenshot', () => {
        updateFinding(f.id, 'imageData', '');
        updateFinding(f.id, 'imageName', '');
        renderFindings();
      }, true);
      removeImage.style.marginTop = '6px';
      previewWrap.append(img, document.createElement('br'), removeImage);
      imageRow.appendChild(previewWrap);
    }

    card.append(top, textLbl, ta, refLbl, ref, imageRow);
    findingsContainer.appendChild(card);
  });
}

function renderTimeline() {
  timelineContainer.innerHTML = '';

  const findingEvents = (window.investigationState.findings || [])
    .filter(f => f.timestamp || f.text || f.source)
    .map((f, idx) => ({ ...f, eventKind:'finding', entryIndex:idx }));

  const importedEvents = (window.investigationState.timelineEvents || [])
    .map((f, idx) => ({ ...f, eventKind:'imported', entryIndex:f.entryIndex ?? (100000 + idx) }));

  let findings = [...findingEvents, ...importedEvents];
  if ((window.investigationState.timelineMode || 'chronological') === 'chronological') {
    findings.sort((a,b) => normalizeTimestampForSort(a.timestamp) - normalizeTimestampForSort(b.timestamp));
  } else {
    findings.sort((a,b) => (a.entryIndex ?? 0) - (b.entryIndex ?? 0));
  }

  chronologicalBtn.style.opacity = window.investigationState.timelineMode === 'entry' ? '.65' : '1';
  entryOrderBtn.style.opacity = window.investigationState.timelineMode === 'entry' ? '1' : '.65';

  if (!findings.length) {
    const empty = mk('div', { text:'Timeline will appear automatically as findings are added.' });
    empty.style.cssText = 'color:var(--ops-text-muted);font-size:13px';
    timelineContainer.appendChild(empty);
    return;
  }

  const line = mk('div');
  line.style.cssText = 'display:flex;flex-direction:column;gap:0';

  findings.forEach((f, idx) => {
    const row = mk('button');
    row.type = 'button';
    row.style.cssText = 'display:grid;grid-template-columns:150px 22px minmax(0,1fr);gap:10px;width:100%;padding:0;background:transparent;border:0;color:inherit;text-align:left;cursor:pointer';

    const when = mk('div', { text:f.timestamp || 'No timestamp' });
    when.style.cssText = 'font-family:"Fira Code",monospace;font-size:11px;color:var(--ops-text-muted);padding:11px 0';

    const spine = mk('div');
    spine.style.cssText = 'position:relative;min-height:58px';
    const dot = mk('div');
    dot.style.cssText = 'position:absolute;top:15px;left:6px;width:10px;height:10px;border-radius:50%;background:var(--intel-blue);border:2px solid var(--ops-surface)';
    spine.appendChild(dot);
    if (idx < findings.length - 1) {
      const vline = mk('div');
      vline.style.cssText = 'position:absolute;top:25px;bottom:-15px;left:10px;width:1px;background:var(--ops-border-bold)';
      spine.appendChild(vline);
    }

    const detail = mk('div');
    detail.style.cssText = 'padding:8px 10px 10px;border-bottom:1px solid var(--ops-border)';
    const src = mk('div', { text:f.source || (f.eventKind === 'imported' ? 'Imported CSV Event' : 'Analyst Finding') });
    src.style.cssText = 'font-size:11px;font-weight:600;color:var(--ops-accent);text-transform:uppercase;letter-spacing:.04em';
    const txt = mk('div', { text:(f.text || 'Screenshot / evidence').slice(0, 220) });
    txt.style.cssText = 'font-size:13px;color:var(--ops-text);margin-top:2px;line-height:1.4';
    const tags = mk('div');
    tags.style.cssText = 'font-size:11px;color:var(--ops-text-dim);margin-top:4px';
    tags.textContent = [
      f.eventKind === 'imported' ? 'Linked Alerts CSV' : '',
      f.imageData ? 'Screenshot' : '',
      f.reference ? 'Reference' : ''
    ].filter(Boolean).join(' · ');
    detail.append(src, txt, tags);

    row.append(when, spine, detail);
    row.addEventListener('click', () => {
      if (f.eventKind === 'finding') {
        document.getElementById(`finding_${f.id}`)?.scrollIntoView?.({ behavior:'smooth', block:'center' });
      }
    });
    line.appendChild(row);
  });

  timelineContainer.appendChild(line);
}

function getMetaValue(doc,label) {
  const rows = [...doc.querySelectorAll('table.meta tr')];
  const row = rows.find(r => r.querySelector('th')?.textContent.trim().toLowerCase() === label.toLowerCase());
  if (!row) return '';
  const td = row.querySelector('td');
  if (!td || td.querySelector('.ph')) return '';
  return td.textContent.trim();
}
function setMetaValue(doc,label,value) {
  if (!value) return;
  const rows = [...doc.querySelectorAll('table.meta tr')];
  const row = rows.find(r => r.querySelector('th')?.textContent.trim().toLowerCase() === label.toLowerCase());
  if (row?.querySelector('td')) row.querySelector('td').textContent = value;
}
function findHeading(doc,starts) {
  return [...doc.querySelectorAll('.triage-report h2')].find(h => h.textContent.trim().toLowerCase().startsWith(starts.toLowerCase()));
}
function contentParagraphAfter(heading) {
  if (!heading) return null;
  let el = heading.nextElementSibling;
  while (el && (el.matches('p.guide') || el.tagName === 'HR')) el = el.nextElementSibling;
  return el?.tagName === 'P' ? el : null;
}
function labeledParagraphValue(doc,label) {
  const ps = [...doc.querySelectorAll('.triage-report p')];
  const p = ps.find(x => x.querySelector('strong')?.textContent.trim().toLowerCase() === `${label.toLowerCase()}:`);
  if (!p || p.querySelector('.ph')) return '';
  return p.textContent.replace(new RegExp(`^${label}:\\s*`,'i'),'').trim();
}
function setLabeledParagraph(doc,label,value) {
  if (!value) return;
  const ps = [...doc.querySelectorAll('.triage-report p')];
  const p = ps.find(x => x.querySelector('strong')?.textContent.trim().toLowerCase() === `${label.toLowerCase()}:`);
  if (p) p.innerHTML = `<strong>${label}:</strong> ${escapeHtml(value)}`;
}

function parseExistingAnalysis(doc) {
  const h = findHeading(doc, '2. investigation');
  if (!h) return [];
  let el = h.nextElementSibling;
  const findings = [];
  while (el && !(el.tagName === 'HR')) {
    if (!el.matches?.('.guide')) {
      if (el.tagName === 'P' && !el.querySelector('.ph') && el.textContent.trim()) {
        findings.push({ id:uid(), timestamp:'', source:'Imported Analysis', text:el.textContent.trim(), imageData:'', imageName:'', reference:'' });
      } else if (el.tagName === 'IMG' && el.src) {
        const target = findings[findings.length - 1] || { id:uid(), timestamp:'', source:'Imported Analysis', text:'', imageData:'', imageName:'', reference:'' };
        target.imageData = el.src;
        target.imageName = el.alt || 'Imported screenshot';
        if (!findings.includes(target)) findings.push(target);
      } else if (el.tagName === 'FIGURE') {
        const img = el.querySelector('img');
        const caption = el.querySelector('figcaption')?.textContent.trim() || '';
        const target = { id:uid(), timestamp:'', source:'Imported Analysis', text:caption, imageData:img?.src || '', imageName:img?.alt || 'Imported screenshot', reference:'' };
        findings.push(target);
      }
    }
    el = el.nextElementSibling;
  }
  return findings;
}

function parseTicketHtml() {
  const html = htmlInput.value.trim();
  if (!html) {
    showLocalToast('Paste or select ticket HTML first','error');
    return;
  }
  const doc = new DOMParser().parseFromString(html,'text/html');
  if (!doc.querySelector('.triage-report')) {
    showLocalToast('Could not find .triage-report in the HTML','error');
    return;
  }

  window.ticketHtmlSource = html;
  const s = window.investigationState;
  const h1 = doc.querySelector('.triage-report h1')?.textContent.trim() || '';

  s.caseId = (h1.match(/SOC-\d{4}-\d+/i) || [])[0] || s.caseId;
  s.alertTitle = getMetaValue(doc,'Alert Signature') || s.alertTitle;
  s.signatureId = getMetaValue(doc,'Signature ID') || s.signatureId;
  s.severity = getMetaValue(doc,'Severity') || s.severity;
  s.confidence = getMetaValue(doc,'Confidence') || s.confidence;
  s.eventTimestamp = getMetaValue(doc,'Timestamp') || s.eventTimestamp;
  s.source = getMetaValue(doc,'Source') || s.source;
  s.destination = getMetaValue(doc,'Destination') || s.destination;
  s.domain = getMetaValue(doc,'Domain') || s.domain;
  s.url = getMetaValue(doc,'URLs') || s.url;
  s.relatedActivity = getMetaValue(doc,'Related Activity') || s.relatedActivity;

  const srcIp = firstIp(s.source);
  const dstIp = firstIp(s.destination);
  if (srcIp) {
    if (srcIp.startsWith('131.247.')) s.usfIp = srcIp;
    else s.remoteIp = srcIp;
  }
  if (dstIp) {
    if (dstIp.startsWith('131.247.')) s.usfIp = dstIp;
    else if (!s.remoteIp) s.remoteIp = dstIp;
  }

  const execP = contentParagraphAfter(findHeading(doc,'1. executive summary'));
  if (execP && !execP.querySelector('.ph')) s.executiveSummary = execP.textContent.trim();
  s.verdict = labeledParagraphValue(doc,'Verdict') || s.verdict;
  s.actionTaken = labeledParagraphValue(doc,'Action taken') || s.actionTaken;

  const importedFindings = parseExistingAnalysis(doc);
  if (importedFindings.length && !s.findings.length) s.findings = importedFindings;

  // Parse non-placeholder Asset/User Identification rows.
  const assetH = findHeading(doc,'4. asset/user identification');
  if (assetH && !s.devices.length) {
    let table = assetH.nextElementSibling;
    while (table && table.tagName !== 'TABLE' && table.tagName !== 'HR') table = table.nextElementSibling;
    if (table?.tagName === 'TABLE') {
      [...table.querySelectorAll('tr')].slice(1).forEach(tr => {
        const cells = [...tr.querySelectorAll('td')];
        if (cells.length >= 7 && !cells.some(td => td.querySelector('.ph'))) {
          const vals = cells.map(td => td.textContent.trim());
          if (vals.some(Boolean)) s.devices.push({
            id:uid(), internalIp:vals[0], mac:vals[1], hostname:vals[2],
            netid:vals[3], os:vals[4], management:vals[5], deviceId:vals[6]
          });
        }
      });
    }
  }

  // Parse non-placeholder IOC rows.
  const iocH = findHeading(doc,'5. indicators of compromise');
  if (iocH && !s.iocs.length) {
    let table = iocH.nextElementSibling;
    while (table && table.tagName !== 'TABLE' && table.tagName !== 'HR') table = table.nextElementSibling;
    if (table?.tagName === 'TABLE') {
      [...table.querySelectorAll('tr')].slice(1).forEach(tr => {
        const cells = [...tr.querySelectorAll('td')];
        if (cells.length >= 4 && !cells.some(td => td.querySelector('.ph'))) {
          const vals = cells.map(td => td.textContent.trim());
          if (vals.some(Boolean)) s.iocs.push({ id:uid(), type:vals[0], value:vals[1], source:vals[2], intel:vals[3] });
        }
      });
    }
  }

  const concH = findHeading(doc,'3. conclusion');
  const concP = contentParagraphAfter(concH);
  if (concP && !concP.querySelector('.ph')) s.conclusion = concP.textContent.trim();

  if (concH) {
    let ul = concH.nextElementSibling;
    while (ul && ul.tagName !== 'UL' && ul.tagName !== 'HR') ul = ul.nextElementSibling;
    const lis = ul?.querySelectorAll?.('li');
    if (lis?.length && ![...lis].some(li => li.querySelector('.ph'))) {
      s.recommendations = [...lis].map(li => li.textContent.trim().replace(/^We recommend\s+/i,'')).join('\n');
    }
  }

  saveWorkspaceState();
  syncUiFromState();
  sendContextToKql(false);
  showLocalToast('Ticket HTML parsed into workspace');
}

function replaceInvestigationAnalysis(doc, findings, analysisContextText='') {
  const h = findHeading(doc,'2. investigation');
  if (!h) return;

  let el = h.nextElementSibling;
  const toRemove = [];
  while (el && el.tagName !== 'HR') {
    const next = el.nextElementSibling;
    if (!el.matches?.('.guide')) toRemove.push(el);
    el = next;
  }
  toRemove.forEach(node => node.remove());

  let insertBefore = h.nextElementSibling;
  while (insertBefore && insertBefore.matches?.('.guide')) insertBefore = insertBefore.nextElementSibling;

  const frag = doc.createDocumentFragment();
  const usable = findings.filter(f => f.text.trim() || f.imageData);

  if (analysisContextText.trim()) {
    analysisContextText.split(/\n\s*\n/).map(x => x.trim()).filter(Boolean).forEach(block => {
      const p = doc.createElement('p');
      p.textContent = block;
      frag.appendChild(p);
    });
  }

  if (!usable.length && !analysisContextText.trim()) {
    const p = doc.createElement('p');
    p.innerHTML = '<span class="ph">&lt;what you did, what you found, and what the traffic actually is&gt;</span>';
    frag.appendChild(p);
  } else {
    usable.forEach(f => {
      if (f.text.trim()) {
        const p = doc.createElement('p');
        if (f.timestamp || f.source) {
          const lead = doc.createElement('strong');
          const prefix = [f.timestamp, f.source].filter(Boolean).join(' — ');
          lead.textContent = `${prefix}: `;
          p.appendChild(lead);
        }
        p.appendChild(doc.createTextNode(f.text.trim()));
        frag.appendChild(p);
      }

      if (f.imageData) {
        const figure = doc.createElement('figure');
        figure.setAttribute('data-socap-evidence', f.id);
        figure.style.margin = '10px 0 16px';
        const img = doc.createElement('img');
        img.src = f.imageData;
        img.alt = f.imageName || 'Investigation screenshot';
        figure.appendChild(img);

        const captionText = [f.timestamp, f.source, f.reference].filter(Boolean).join(' · ');
        if (captionText) {
          const cap = doc.createElement('figcaption');
          cap.textContent = captionText;
          cap.style.fontSize = '11px';
          cap.style.color = 'var(--rpt-muted)';
          cap.style.marginTop = '3px';
          figure.appendChild(cap);
        }
        frag.appendChild(figure);
      }
    });
  }

  h.parentNode.insertBefore(frag, insertBefore);
}

function replaceEvidenceLog(doc, findings) {
  const h = findHeading(doc,'7. evidence log');
  if (!h) return;
  let table = h.nextElementSibling;
  while (table && table.tagName !== 'TABLE' && table.tagName !== 'HR') table = table.nextElementSibling;
  if (!table || table.tagName !== 'TABLE') return;

  const tbody = table.querySelector('tbody') || table;
  const header = tbody.querySelector('tr');
  [...tbody.querySelectorAll('tr')].slice(1).forEach(r => r.remove());

  const evidence = findings.filter(f => f.text.trim() || f.imageData || f.reference);
  if (!evidence.length) {
    const tr = doc.createElement('tr');
    ['<query results / flows>','<Defender CommonSecurityLog>','<attachment / query>'].forEach(v => {
      const td = doc.createElement('td');
      const span = doc.createElement('span');
      span.className = 'ph';
      span.textContent = v;
      td.appendChild(span);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
    return;
  }

  evidence.forEach((f, idx) => {
    const tr = doc.createElement('tr');
    const ev = doc.createElement('td');
    const src = doc.createElement('td');
    const ref = doc.createElement('td');

    const summary = f.text.trim().split(/\s+/).slice(0, 18).join(' ');
    ev.textContent = summary || (f.imageData ? `Screenshot ${idx + 1}` : `Evidence ${idx + 1}`);
    src.textContent = f.source || 'Analyst Finding';
    ref.textContent = f.reference || (f.imageData ? 'Inline screenshot in Investigation & Analysis' : (f.timestamp || 'Investigation finding'));

    tr.append(ev, src, ref);
    tbody.appendChild(tr);
  });
}

function replaceAssetSection(doc, devices) {
  if (!devices?.length) return;
  const h = findHeading(doc,'4. asset/user identification');
  if (!h) return;
  let table = h.nextElementSibling;
  while (table && table.tagName !== 'TABLE' && table.tagName !== 'HR') table = table.nextElementSibling;
  if (!table || table.tagName !== 'TABLE') return;
  const tbody = table.querySelector('tbody') || table;
  [...tbody.querySelectorAll('tr')].slice(1).forEach(r => r.remove());
  devices.forEach(d => {
    const tr = doc.createElement('tr');
    [d.internalIp,d.mac,d.hostname,d.netid,d.os,d.management,d.deviceId].forEach(v => {
      const td = doc.createElement('td'); td.textContent = v || ''; tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function replaceIocSection(doc, iocs) {
  if (!iocs?.length) return;
  const h = findHeading(doc,'5. indicators of compromise');
  if (!h) return;
  let table = h.nextElementSibling;
  while (table && table.tagName !== 'TABLE' && table.tagName !== 'HR') table = table.nextElementSibling;
  if (!table || table.tagName !== 'TABLE') return;
  const tbody = table.querySelector('tbody') || table;
  [...tbody.querySelectorAll('tr')].slice(1).forEach(r => r.remove());
  iocs.forEach(i => {
    const tr = doc.createElement('tr');
    const value = window.investigationState.autoDefang ? defangValue(i.value) : i.value;
    [i.type,value,i.source,i.intel].forEach(v => {
      const td = doc.createElement('td'); td.textContent = v || ''; tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function buildUpdatedTicketHtml() {
  if (!window.ticketHtmlSource) {
    const pasted = htmlInput.value.trim();
    if (!pasted) throw new Error('No ticket HTML loaded');
    window.ticketHtmlSource = pasted;
  }

  const doc = new DOMParser().parseFromString(window.ticketHtmlSource,'text/html');
  const s = window.investigationState;

  setMetaValue(doc,'Alert Signature',s.alertTitle);
  setMetaValue(doc,'Signature ID',s.signatureId);
  setMetaValue(doc,'Severity',s.severity);
  setMetaValue(doc,'Confidence',s.confidence);
  setMetaValue(doc,'Timestamp',s.eventTimestamp);
  setMetaValue(doc,'Source',s.source);
  setMetaValue(doc,'Destination',s.destination);
  setMetaValue(doc,'Domain',s.domain);
  setMetaValue(doc,'URLs',s.url);
  setMetaValue(doc,'Related Activity',s.relatedActivity);

  const h1 = doc.querySelector('.triage-report h1');
  if (h1 && s.caseId) h1.textContent = `${s.caseId} — Investigation Report`;

  const execP = contentParagraphAfter(findHeading(doc,'1. executive summary'));
  if (execP && s.executiveSummary) execP.innerHTML = `<strong>${escapeHtml(s.executiveSummary)}</strong>`;
  setLabeledParagraph(doc,'Verdict',s.verdict);
  setLabeledParagraph(doc,'Action taken',s.actionTaken);

  replaceInvestigationAnalysis(doc, s.findings, s.analysisContext || '');

  const concH = findHeading(doc,'3. conclusion');
  const concP = contentParagraphAfter(concH);
  if (concP && s.conclusion) concP.textContent = s.conclusion;

  if (concH && s.recommendations.trim()) {
    let ul = concH.nextElementSibling;
    while (ul && ul.tagName !== 'UL' && ul.tagName !== 'HR') ul = ul.nextElementSibling;
    if (ul?.tagName === 'UL') {
      ul.innerHTML = '';
      s.recommendations.split(/\r?\n/).map(x => x.trim()).filter(Boolean).forEach(r => {
        const li = doc.createElement('li');
        li.textContent = r;
        ul.appendChild(li);
      });
    }
  }

  replaceAssetSection(doc, s.devices);
  replaceIocSection(doc, s.iocs);
  replaceEvidenceLog(doc, s.findings);
  return '<!doctype html>\n' + doc.documentElement.outerHTML;
}

function downloadUpdatedHtml() {
  try {
    const out = buildUpdatedTicketHtml();
    const blob = new Blob([out], { type:'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${window.investigationState.caseId || 'SOC-investigation'}-updated.html`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 0);
    showLocalToast('Updated ticket HTML downloaded');
  } catch (e) {
    showLocalToast(e.message, 'error');
  }
}
function copyUpdatedHtml() {
  try {
    const out = buildUpdatedTicketHtml();
    copyToClipboard(out);
  } catch (e) {
    showLocalToast(e.message, 'error');
  }
}


function buildDraftPayload() {
  return {
    format: 'SOCAP_INVESTIGATION_DRAFT',
    version: 1,
    savedAt: new Date().toISOString(),
    state: window.investigationState,
    ticketHtmlSource: window.ticketHtmlSource || htmlInput.value || ''
  };
}

function saveDraftFile() {
  try {
    const payload = buildDraftPayload();
    const json = JSON.stringify(payload, null, 2);
    const blob = new Blob([json], { type:'application/json' });
    const a = document.createElement('a');
    const safeCase = (window.investigationState.caseId || 'SOC-investigation').replace(/[^a-zA-Z0-9._-]+/g,'_');
    const stamp = new Date().toISOString().replace(/[:]/g,'-').replace(/\.\d{3}Z$/,'Z');
    a.href = URL.createObjectURL(blob);
    a.download = `${safeCase}_${stamp}.socapdraft`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 0);
    showLocalToast('Draft saved locally');
  } catch (e) {
    showLocalToast('Could not save draft', 'error');
  }
}

function loadDraftFromText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Draft is not valid JSON');
  }

  if (!parsed || parsed.format !== 'SOCAP_INVESTIGATION_DRAFT') {
    throw new Error('Not a SOCAP investigation draft');
  }

  if (!parsed.state || typeof parsed.state !== 'object') {
    throw new Error('Draft state is missing');
  }

  const incoming = {
    ...DEFAULT_STATE,
    ...parsed.state,
    findings: Array.isArray(parsed.state.findings) ? parsed.state.findings : [],
    timelineEvents: Array.isArray(parsed.state.timelineEvents) ? parsed.state.timelineEvents : [],
    iocs: Array.isArray(parsed.state.iocs) ? parsed.state.iocs : [],
    devices: Array.isArray(parsed.state.devices) ? parsed.state.devices : [],
    checklist: parsed.state.checklist || {}
  };

  window.investigationState = incoming;
  window.ticketHtmlSource = parsed.ticketHtmlSource || '';
  htmlInput.value = window.ticketHtmlSource;

  localStorage.setItem(STORAGE_KEY, JSON.stringify(window.investigationState));
  syncUiFromState();

  checklistContainer.querySelectorAll('input[type="checkbox"]').forEach((cb, idx) => {
    const item = checklistItems[idx];
    if (item) cb.checked = !!window.investigationState.checklist[item[0]];
  });

  sendContextToKql(false);

  const status = document.getElementById('iw_autosave_status');
  if (status) {
    const when = parsed.savedAt ? new Date(parsed.savedAt).toLocaleString() : 'unknown time';
    status.textContent = `Draft loaded · saved ${when}`;
  }

  showLocalToast('Draft loaded');
}

async function importCsvFile(file, mode='context') {
  let rows;
  try {
    rows = parseCsvText(await file.text());
  } catch {
    showLocalToast('Could not parse CSV', 'error');
    return;
  }
  if (!rows.length) {
    showLocalToast('CSV contains no data rows', 'error');
    return;
  }

  const ips = new Set();
  const domains = new Set();
  const users = new Set();
  const devices = new Set();
  const times = [];
  const hashes = new Set();
  const newTimeline = [];

  rows.forEach((row, idx) => {
    allCsvValues(row, [/ipaddress/i,/sourceip/i,/destinationip/i,/remoteip/i,/localip/i,/clientip/i,/senderipv4/i,/senderipv6/i]).forEach(v => {
      (v.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach(ip => ips.add(ip));
    });
    allCsvValues(row, [/domain/i,/urldomain/i,/fqdn/i,/hostname/i]).forEach(v => {
      splitValues(v).forEach(d => {
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) domains.add(d);
      });
    });
    allCsvValues(row, [/accountupn/i,/accountid/i,/recipientemail/i,/senderfrom/i,/netid/i,/userprincipal/i]).forEach(v => {
      if (/@/.test(v)) users.add(v);
    });
    allCsvValues(row, [/devicename/i,/computer/i,/hostname/i]).forEach(v => {
      if (v && !/\./.test(v)) devices.add(v);
    });
    allCsvValues(row, [/sha256/i,/hash/i]).forEach(v => {
      if (/^[a-f0-9]{64}$/i.test(v)) hashes.add(v);
    });

    const ts = pickCsvValue(row, [/^timestamp$/i,/timegenerated/i,/emailtime/i,/^time$/i,/received/i,/date/i]);
    if (ts) times.push(ts);

    if (mode === 'linked') {
      const action = pickCsvValue(row, [/actiontype/i,/activity/i,/alert/i,/incident/i,/title/i,/subject/i,/event/i,/name/i]);
      const account = pickCsvValue(row, [/accountupn/i,/accountid/i,/user/i,/recipientemail/i,/senderfrom/i]);
      const ip = pickCsvValue(row, [/ipaddress/i,/sourceip/i,/destinationip/i,/remoteip/i,/clientip/i]);
      const source = pickCsvValue(row, [/sourcetable/i,/application/i,/service/i,/table/i]) || file.name;
      const text = [action, account, ip].filter(Boolean).join(' | ') || `Imported CSV row ${idx + 1}`;
      newTimeline.push({
        id:uid(),
        timestamp:ts,
        source,
        text,
        reference:file.name,
        entryIndex:100000 + (window.investigationState.timelineEvents?.length || 0) + idx
      });
    }
  });

  const extIps = [...ips].filter(ip => !isInternalIp(ip));
  const intIps = [...ips].filter(isInternalIp);
  if (extIps.length) window.investigationState.remoteIp = [...new Set([...splitValues(window.investigationState.remoteIp), ...extIps])].join(', ');
  if (intIps.length) window.investigationState.usfIp = [...new Set([...splitValues(window.investigationState.usfIp), ...intIps])].join(', ');
  if (domains.size) window.investigationState.domain = [...new Set([...splitValues(window.investigationState.domain), ...domains])].join(', ');
  if (users.size && !window.investigationState.netid) window.investigationState.netid = [...users][0];
  if (devices.size && !window.investigationState.deviceName) window.investigationState.deviceName = [...devices][0];
  if (times.length) {
    window.investigationState.startTime = window.investigationState.startTime || times[0];
    window.investigationState.endTime = window.investigationState.endTime || times[times.length - 1];
  }

  // Add extracted IOCs without duplicates.
  const existing = new Set((window.investigationState.iocs || []).map(i => `${i.type}|${i.value}`.toLowerCase()));
  [...ips].forEach(ip => {
    const k = `IP Address|${ip}`.toLowerCase();
    if (!existing.has(k)) { window.investigationState.iocs.push({id:uid(),type:'IP Address',value:ip,source:file.name,intel:''}); existing.add(k); }
  });
  [...domains].forEach(d => {
    const k = `Domain|${d}`.toLowerCase();
    if (!existing.has(k)) { window.investigationState.iocs.push({id:uid(),type:'Domain',value:d,source:file.name,intel:''}); existing.add(k); }
  });
  [...hashes].forEach(h => {
    const k = `File Hash|${h}`.toLowerCase();
    if (!existing.has(k)) { window.investigationState.iocs.push({id:uid(),type:'File Hash',value:h,source:file.name,intel:''}); existing.add(k); }
  });

  // Add basic device stubs without duplicates.
  [...devices].forEach(host => {
    if (!(window.investigationState.devices || []).some(d => d.hostname === host)) {
      window.investigationState.devices.push({id:uid(),internalIp:'',mac:'',hostname:host,netid:'',os:'',management:'',deviceId:''});
    }
  });

  if (mode === 'linked') {
    window.investigationState.timelineEvents = [...(window.investigationState.timelineEvents || []), ...newTimeline];
  }


  saveWorkspaceState();
  syncUiFromState();
  sendContextToKql(false);
  showLocalToast(mode === 'linked'
    ? `Imported ${rows.length} linked-alert rows into the timeline`
    : `Imported CSV context from ${rows.length} rows`);
}

function importCsvContext() {
  const csv = window.csvParsedState || {};
  const ips = Array.isArray(csv.allIPs) ? csv.allIPs.filter(Boolean) : [];
  const times = Array.isArray(csv.times) ? csv.times.filter(Boolean) : [];
  const domains = Array.isArray(csv.domains) ? csv.domains.filter(Boolean) : [];
  const urls = Array.isArray(csv.urls) ? csv.urls.filter(Boolean) : [];
  const signatureIds = Array.isArray(csv.signatureIds) ? csv.signatureIds.filter(Boolean) : [];

  const remote = ips.filter(x => !isInternalIp(String(x)));
  const internal = ips.filter(x => isInternalIp(String(x)));

  if (remote.length) window.investigationState.remoteIp = [...new Set([...splitValues(window.investigationState.remoteIp), ...remote])].join(', ');
  if (internal.length) window.investigationState.usfIp = [...new Set([...splitValues(window.investigationState.usfIp), ...internal])].join(', ');
  if (domains.length) window.investigationState.domain = [...new Set([...splitValues(window.investigationState.domain), ...domains])].join(', ');
  if (urls.length && !window.investigationState.url) window.investigationState.url = urls[0];
  if (signatureIds.length && !window.investigationState.signatureId) {
    window.investigationState.signatureId = signatureIds.join(', ');
  }
  if (times[0]) window.investigationState.startTime = times[0];
  if (times.length) window.investigationState.endTime = times[times.length - 1];

  saveWorkspaceState();
  syncUiFromState();
  sendContextToKql(false);
  showLocalToast('CSV-to-Ticket data imported into the investigation workspace');
}

function setKqlInput(id,value) {
  const el = document.getElementById(id);
  if (!el || !value) return;
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles:true }));
}
function sendContextToKql(show=true) {
  const s = window.investigationState;
  const structuredIps = (s.iocs || []).filter(i => /ip/i.test(i.type)).map(i => i.value).filter(Boolean);
  const structuredDomains = (s.iocs || []).filter(i => /domain/i.test(i.type)).map(i => i.value).filter(Boolean);
  const structuredDevices = (s.devices || []).map(d => d.hostname).filter(Boolean);
  const structuredUsers = (s.devices || []).map(d => d.netid).filter(Boolean);

  const remoteIps = [...new Set([...splitValues(s.remoteIp), ...structuredIps.filter(ip => !isInternalIp(ip))])];
  const internalIps = [...new Set([...splitValues(s.usfIp), ...structuredIps.filter(isInternalIp)])];
  const domains = [...new Set([...splitValues(s.domain), ...structuredDomains])];

  setKqlInput('kql_remote_ip',remoteIps.join(', '));
  setKqlInput('kql_usf_ip',internalIps.join(', '));
  setKqlInput('kql_domain',domains.join(', '));
  setKqlInput('kql_device_name',s.deviceName || structuredDevices[0] || '');
  setKqlInput('kql_netid',s.netid || structuredUsers[0] || '');
  setKqlInput('kql_start_time',s.startTime);
  setKqlInput('kql_end_time',s.endTime);
  if (show) showLocalToast('Investigation context sent to KQL');
}

function clearWorkspace() {
  if (!confirm('Clear this Investigation Workspace case? CSV-to-Ticket data will remain unchanged.')) return;

  window.investigationState = {
    ...DEFAULT_STATE,
    findings:[],
    timelineEvents:[],
    iocs:[],
    devices:[],
    checklist:{}
  };

  localStorage.removeItem(STORAGE_KEY);
  window.ticketHtmlSource = '';

  htmlInput.value = '';
  fileInput.value = '';
  draftInput.value = '';
  csvFileInput.value = '';
  sanitizerOutput.value = '';
  sanitizerMapping.textContent = '';
  sanitizerMapping.style.display = 'none';

  checklistContainer.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
  syncUiFromState();

  // Clear KQL fields immediately as part of the same action.
  ['kql_remote_ip','kql_usf_ip','kql_domain','kql_device_name','kql_netid','kql_start_time','kql_end_time']
    .forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.value = '';
        el.dispatchEvent(new Event('input',{bubbles:true}));
      }
    });

  const status = document.getElementById('iw_autosave_status');
  if (status) status.textContent = 'Autosave: local browser draft enabled';
  showLocalToast('Investigation Workspace and KQL context cleared. CSV-to-Ticket was left unchanged.','info');
}
window.refreshInvestigationWorkspace = importCsvContext;

// ---------- Extend the existing KQL tab instead of duplicating queries here ----------
function investigationExtraQueries() {
  const s = window.investigationState;
  const val = id => document.getElementById(id)?.value.trim() || '';
  const netid = escaped(val('kql_netid') || s.netid || 'user@usf.edu');
  const ipList = splitValues(val('kql_remote_ip') || s.remoteIp || 'x.x.x.x');
  const domainList = splitValues(val('kql_domain') || s.domain || 'example.com');
  const ipsDynamic = ipList.map(x => `"${escaped(x)}"`).join(', ');
  const domainsDynamic = domainList.map(x => `"${escaped(x)}"`).join(', ');
  const device = escaped(val('kql_device_name') || s.deviceName || 'DEVICE-NAME-HERE');
  const ua = escaped(s.userAgent || 'python-requests/2.34.2');
  const start = val('kql_start_time') || s.startTime || '2026-09-01 00:00:00';
  const end = val('kql_end_time') || s.endTime || '2026-09-02 00:00:00';

  return [
    {title:'Investigation — URL Clicks',query:`let netid = "${netid}";
let start_time = datetime(${start});
let end_time = datetime(${end});
UrlClickEvents
| where Timestamp between (start_time .. end_time)
| where AccountUpn =~ netid
| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, IsClickedThrough, Workload, NetworkMessageId
| sort by Timestamp desc`},

    {title:'Investigation — Mail Sent',query:`let netid = "${netid}";
let start_time = datetime(${start});
let end_time = datetime(${end});
EmailEvents
| where Timestamp between (start_time .. end_time)
| where SenderFromAddress =~ netid
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, NetworkMessageId
| sort by Timestamp desc`},

    {title:'Investigation — Inbox / Mailbox Rule Changes',query:`let netid = "${netid}";
let start_time = datetime(${start});
let end_time = datetime(${end});
CloudAppEvents
| where Timestamp between (start_time .. end_time)
| where AccountId =~ netid
| where ActionType in ("New-InboxRule","Set-InboxRule","Remove-InboxRule","UpdateInboxRules")
| project-reorder Timestamp, AccountId, ActionType, IPAddress, UserAgent, RawEventData, *
| sort by Timestamp desc`},

    {title:'Investigation — CloudAppEvents User Activity',query:`let netid = "${netid}";
let start_time = datetime(${start});
let end_time = datetime(${end});
CloudAppEvents
| where Timestamp between (start_time .. end_time)
| where AccountId =~ netid
| project-reorder Timestamp, Application, ActionType, IPAddress, UserAgent, ObjectName, AccountId, AccountDisplayName, *
| sort by Timestamp asc`},

    {title:'Investigation — Phishing Blast Radius',query:`let target_domains = dynamic([${domainsDynamic}]);
let start_time = datetime(${start});
let end_time = datetime(${end});
EmailUrlInfo
| where Timestamp between (start_time .. end_time)
| where set_has_element(target_domains, UrlDomain)
    or target_domains has tostring(UrlDomain)
    or Url has_any (target_domains)
| join kind=inner (
    EmailEvents
    | where Timestamp between (start_time .. end_time)
    | project NetworkMessageId, EmailTime=Timestamp, SenderFromAddress, SenderMailFromAddress,
              RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods
) on NetworkMessageId
| project-reorder EmailTime, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
                  Subject, Url, UrlDomain, DeliveryAction, DeliveryLocation, ThreatTypes,
                  DetectionMethods, NetworkMessageId
| sort by EmailTime asc`},

    {title:'Investigation — User-Agent Hunt',query:`let user_agent = "${ua}";
EntraIdSignInEvents
| where UserAgent =~ user_agent
| project-reorder Timestamp, AccountUpn, IPAddress, Application, ResourceDisplayName,
                  UserAgent, ErrorCode, ConditionalAccessStatus, Country, State, City, *
| sort by Timestamp desc`},

    {title:'Investigation — Suspicious Device Processes',query:`let device = "${device}";
let start_time = datetime(${start});
let end_time = datetime(${end});
DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName =~ device
| where FileName in~ (
    "powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe"
)
| project-reorder Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
                  InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc`},

    {title:'Investigation — IP-wide Defender Activity',query:`let ips = dynamic([${ipsDynamic}]);
let start_time = datetime(${start});
let end_time = datetime(${end});
union isfuzzy=true
(
    CloudAppEvents
    | where Timestamp between (start_time .. end_time)
    | where set_has_element(ips, IPAddress)
    | project Timestamp, SourceTable="CloudAppEvents", Account=AccountId,
              Action=ActionType, Application, IPAddress, UserAgent, ObjectName, RawEventData
),
(
    EntraIdSignInEvents
    | where Timestamp between (start_time .. end_time)
    | where set_has_element(ips, IPAddress)
    | project Timestamp, SourceTable="EntraIdSignInEvents", Account=AccountUpn,
              Action=Application, Application, IPAddress, UserAgent,
              ObjectName=ResourceDisplayName, RawEventData=tostring(pack_all())
)
| sort by Timestamp asc`}
  ];
}

function installKqlExtension() {
  if (window.__iwKqlExtended) return true;
  if (typeof window.getKQLQueriesForTab !== 'function') return false;
  const original = window.getKQLQueriesForTab;
  window.getKQLQueriesForTab = function() {
    const existing = original();
    return [...existing, ...investigationExtraQueries()];
  };
  window.__iwKqlExtended = true;

  const remote = document.getElementById('kql_remote_ip');
  const domain = document.getElementById('kql_domain');
  if (remote) remote.placeholder = 'Comma-separated IPs';
  if (domain) domain.placeholder = 'Comma-separated domains';

  document.querySelectorAll('label').forEach(lbl => {
    if (lbl.htmlFor === 'kql_remote_ip' || lbl.textContent.trim() === 'Remote IP') lbl.textContent = 'Remote IP(s)';
    if (lbl.htmlFor === 'kql_domain' || lbl.textContent.trim() === 'Domain') lbl.textContent = 'Domain(s)';
  });

  if (typeof window.renderAllQueries === 'function') window.renderAllQueries(false,true);
  return true;
}

if (!installKqlExtension()) {
  let attempts = 0;
  const timer = setInterval(() => {
    attempts++;
    if (installKqlExtension() || attempts > 80) clearInterval(timer);
  }, 100);
}

renderIocs();
renderDevices();
renderFindings();
renderTimeline();

})();
