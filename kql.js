// ---------- KQL Templates ---------- //
const kqlTab = document.getElementById("kqlTab");

// Header
const kqlHeader = document.createElement('h2');
kqlHeader.textContent = 'KQL Query Templates';
kqlTab.appendChild(kqlHeader);

const kqlDesc = document.createElement('p');
kqlDesc.className = 'tab-desc';
kqlDesc.textContent = 'Select a query template, fill in parameters, and generate ready-to-paste KQL. Useful for common hunting patterns in Microsoft Sentinel / Defender.';
kqlTab.appendChild(kqlDesc);

// Template Definitions
const templates = {
  'Network Traffic (IP)': {
    query: 'DeviceNetworkEvents \n| where RemoteIP == "{IP}" \n| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol',
    params: ['IP']
  },
  'Process Execution (Name)': {
    query: 'DeviceProcessEvents \n| where FileName =~ "{FileName}" \n| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine',
    params: ['FileName']
  },
  'File Creation (Hash)': {
    query: 'DeviceFileEvents \n| where SHA256 == "{SHA256}" \n| project Timestamp, DeviceName, FileName, FolderPath, SHA256',
    params: ['SHA256']
  },
  'Email Events (Sender)': {
    query: 'EmailEvents \n| where SenderFromAddress =~ "{SenderEmail}" \n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, AttachmentCount',
    params: ['SenderEmail']
  },
  'Logon Events (User)': {
    query: 'DeviceLogonEvents \n| where AccountName =~ "{User}" \n| project Timestamp, DeviceName, ActionType, AccountName, LogonType',
    params: ['User']
  },
  'Registry Modifications': {
    query: 'DeviceRegistryEvents \n| where RegistryKey contains "{RegistryKey}" \n| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName',
    params: ['RegistryKey']
  },
  'PowerShell Execution': {
    query: 'DeviceProcessEvents \n| where FileName in~ ("powershell.exe", "pwsh.exe") \n| where ProcessCommandLine contains "{SearchTerm}" \n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
    params: ['SearchTerm']
  },
  'Lateral Movement (Remote Logons)': {
    query: 'DeviceLogonEvents \n| where LogonType in ("RemoteInteractive", "Network", "CachedRemoteInteractive") \n| where RemoteIP != "" \n| where DeviceName contains "{DeviceName}" or AccountName contains "{AccountName}" \n| project Timestamp, DeviceName, ActionType, AccountName, RemoteIP, RemoteDeviceName, LogonType \n| sort by Timestamp desc \n| take 200',
    params: ['DeviceName', 'AccountName']
  },
  'Alert Correlation (Device)': {
    query: 'AlertEvidence \n| where DeviceName contains "{DeviceName}" \n| join kind=leftanti AlertInfo on AlertId \n| project Timestamp, AlertId, DeviceName, EntityType, EvidenceDirection, EvidenceRole \n| sort by Timestamp desc \n| take 100',
    params: ['DeviceName']
  },
  'Suspicious Command Line': {
    query: 'DeviceProcessEvents \n| where ProcessCommandLine has_any ("whoami", "net user", "net localgroup", "nltest", "ipconfig", "systeminfo", "tasklist", "nslookup", "ping", "arp", "route") \n| where DeviceName contains "{DeviceName}" \n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine \n| sort by Timestamp desc \n| take 200',
    params: ['DeviceName']
  }
};

// Dropdown
const selectLabel = document.createElement('label');
selectLabel.textContent = 'Query Template';
kqlTab.appendChild(selectLabel);

const select = document.createElement('select');

const defOpt = document.createElement('option');
defOpt.text = '— Select a template —';
defOpt.value = '';
select.appendChild(defOpt);

Object.keys(templates).forEach(key => {
  const opt = document.createElement('option');
  opt.value = key;
  opt.text = key;
  select.appendChild(opt);
});
kqlTab.appendChild(select);

// Inputs Container
const paramsDiv = document.createElement('div');
paramsDiv.style.marginTop = 'var(--sp-3)';
kqlTab.appendChild(paramsDiv);

// Generate Button
const genBtn = document.createElement('button');
genBtn.className = 'action-button';
genBtn.textContent = 'Generate Query';
genBtn.style.display = 'none';
genBtn.style.marginTop = 'var(--sp-2)';
genBtn.onclick = generateKQL;
kqlTab.appendChild(genBtn);

// Output Card
const kqlOutputCard = document.createElement('div');
kqlOutputCard.className = 'ops-card';
kqlOutputCard.style.marginTop = 'var(--sp-4)';
kqlOutputCard.style.display = 'none';

const kqlOutputHeader = document.createElement('div');
kqlOutputHeader.style.display = 'flex';
kqlOutputHeader.style.justifyContent = 'space-between';
kqlOutputHeader.style.alignItems = 'center';
kqlOutputHeader.style.marginBottom = 'var(--sp-2)';

const kqlOutputTitle = document.createElement('h4');
kqlOutputTitle.textContent = 'Generated Query';
kqlOutputTitle.style.margin = '0';

const kqlCopyBtn = document.createElement('button');
kqlCopyBtn.className = 'action-button secondary';
kqlCopyBtn.textContent = 'Copy';
kqlCopyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
kqlCopyBtn.style.fontSize = '11px';
kqlCopyBtn.onclick = () => copyToClipboard(kqlOutput.value, kqlCopyBtn);

kqlOutputHeader.appendChild(kqlOutputTitle);
kqlOutputHeader.appendChild(kqlCopyBtn);
kqlOutputCard.appendChild(kqlOutputHeader);

const kqlOutput = document.createElement('textarea');
kqlOutput.id = 'kqlOutput';
kqlOutput.placeholder = 'Generated KQL Query...';
kqlOutput.style.marginBottom = '0';
kqlOutputCard.appendChild(kqlOutput);

kqlTab.appendChild(kqlOutputCard);

// Events
select.addEventListener('change', () => {
  const key = select.value;
  paramsDiv.innerHTML = '';

  if (!templates[key]) {
    genBtn.style.display = 'none';
    kqlOutputCard.style.display = 'none';
    return;
  }

  const tmpl = templates[key];
  tmpl.params.forEach(param => {
    const wrapper = document.createElement('div');
    wrapper.style.marginBottom = 'var(--sp-2)';

    const label = document.createElement('label');
    label.textContent = param;
    label.style.display = 'block';

    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'param_' + param;
    input.placeholder = `Enter ${param}...`;
    input.style.maxWidth = '400px';

    wrapper.appendChild(label);
    wrapper.appendChild(input);
    paramsDiv.appendChild(wrapper);
  });

  genBtn.style.display = 'inline-flex';
});

function generateKQL() {
  const key = select.value;
  if (!templates[key]) return;

  let query = templates[key].query;

  templates[key].params.forEach(param => {
    const val = document.getElementById('param_' + param).value;
    query = query.replace('{' + param + '}', val);
  });

  kqlOutput.value = query;
  kqlOutputCard.style.display = 'block';
  // Calculate height based on line count
  const lineCount = query.split('\n').length;
  const lineHeight = 20;
  const padding = 24;
  kqlOutput.style.height = Math.max(Math.min(lineCount * lineHeight + padding, 500), 120) + 'px';
  showToast('Query generated', 'success');
}