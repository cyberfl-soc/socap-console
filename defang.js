// ---------- Defang / un-Defang ---------- //
const defangTab = document.getElementById("defangTab");

// Header
const dfHeader = document.createElement('h2');
dfHeader.textContent = 'Defang / Refang';
defangTab.appendChild(dfHeader);

const dfDesc = document.createElement('p');
dfDesc.className = 'tab-desc';
dfDesc.textContent = 'Safely defang IOCs for sharing in reports and tickets, or refang them for active investigation. Supports multi-line input.';
defangTab.appendChild(dfDesc);

// Input Label
const dfInputLabel = document.createElement('label');
dfInputLabel.textContent = 'Input IOC(s)';
defangTab.appendChild(dfInputLabel);

// Input — multi-line textarea instead of single input
const defangInput = document.createElement('textarea');
defangInput.id = 'defangInput';
defangInput.placeholder = 'Paste IOCs here (one per line or comma-separated)...\ne.g. https://malware.com/payload\n192.168.1.1\nmalicious[.]domain[.]com';
defangInput.style.height = '150px';
defangTab.appendChild(defangInput);

// Button row
const dfBtnRow = document.createElement('div');
dfBtnRow.style.display = 'flex';
dfBtnRow.style.gap = 'var(--sp-2)';
dfBtnRow.style.marginTop = 'var(--sp-2)';

const defangBtn = document.createElement('button');
defangBtn.textContent = 'Defang';
defangBtn.className = 'action-button';

const undefangBtn = document.createElement('button');
undefangBtn.textContent = 'Refang';
undefangBtn.className = 'action-button secondary';

dfBtnRow.appendChild(defangBtn);
dfBtnRow.appendChild(undefangBtn);
defangTab.appendChild(dfBtnRow);

// Output Card
const dfOutputCard = document.createElement('div');
dfOutputCard.className = 'ops-card';
dfOutputCard.style.marginTop = 'var(--sp-4)';

const dfOutputHeader = document.createElement('div');
dfOutputHeader.style.display = 'flex';
dfOutputHeader.style.justifyContent = 'space-between';
dfOutputHeader.style.alignItems = 'center';
dfOutputHeader.style.marginBottom = 'var(--sp-2)';

const dfOutputTitle = document.createElement('h4');
dfOutputTitle.textContent = 'Output';
dfOutputTitle.style.margin = '0';

const copyDefangBtn = document.createElement('button');
copyDefangBtn.textContent = 'Copy';
copyDefangBtn.className = 'action-button secondary';
copyDefangBtn.style.padding = 'var(--sp-1) var(--sp-3)';
copyDefangBtn.style.fontSize = '11px';
copyDefangBtn.onclick = () => copyToClipboard(defangOutput.value, copyDefangBtn);

dfOutputHeader.appendChild(dfOutputTitle);
dfOutputHeader.appendChild(copyDefangBtn);
dfOutputCard.appendChild(dfOutputHeader);

const defangOutput = document.createElement('textarea');
defangOutput.id = 'defangOutput';
defangOutput.readOnly = true;
defangOutput.placeholder = 'Result will appear here...';
defangOutput.style.height = '150px';
defangOutput.style.background = 'var(--ops-inset)';
defangOutput.style.marginBottom = '0';
dfOutputCard.appendChild(defangOutput);

defangTab.appendChild(dfOutputCard);

// ---------- Maps ---------- //
const undefang_map = {
  '\\[\\.\\]': '.',
  ' \\.': '.',
  '\\[:\\]': ':',
  'hxxp': 'http',
  'hxxps': 'https'
};

// ---------- Logic ---------- //
function runDefang() {
  let text = defangInput.value;
  if (!text) return;

  // First undefang to prevent double defanging
  for (let key in undefang_map) {
    const regex = new RegExp(key, "gi");
    text = text.replace(regex, undefang_map[key]);
  }

  // Then defang
  text = text.replace(/https/gi, 'hxxps');
  text = text.replace(/http/gi, 'hxxp');
  text = text.replace(/\./g, '[.]');
  text = text.replace(/:/g, '[:]');

  defangOutput.value = text;
  showToast('Defanged', 'success');
}

function runUndefang() {
  let text = defangInput.value;
  if (!text) return;

  for (let key in undefang_map) {
    const regex = new RegExp(key, "gi");
    text = text.replace(regex, undefang_map[key]);
  }

  defangOutput.value = text;
  showToast('Refanged', 'success');
}

// ---------- Events ---------- //
defangBtn.addEventListener("click", runDefang);
undefangBtn.addEventListener("click", runUndefang);