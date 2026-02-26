// ---------- Redact Tab ---------- //
const redactTab = document.getElementById("redactTab");

// Header
const rdHeader = document.createElement('h2');
rdHeader.textContent = 'Redact';
redactTab.appendChild(rdHeader);

const rdDesc = document.createElement('p');
rdDesc.className = 'tab-desc';
rdDesc.textContent = 'Paste raw text/logs below. Auto-substitutes sensitive org information (IPs, emails, org names) with masked values. Add custom patterns below.';
redactTab.appendChild(rdDesc);

// Two-column layout container
const rdContainer = document.createElement('div');
rdContainer.style.display = 'flex';
rdContainer.style.gap = 'var(--sp-4)';
rdContainer.style.alignItems = 'flex-start';

// Left Column: Input
const rdLeftCol = document.createElement('div');
rdLeftCol.style.flex = '1';

const rdInputLabel = document.createElement('label');
rdInputLabel.textContent = 'Raw Text Input';
rdLeftCol.appendChild(rdInputLabel);

const redactInput = document.createElement('textarea');
redactInput.id = 'redactInput';
redactInput.placeholder = 'Paste sensitive text here...';
redactInput.style.height = '350px';
rdLeftCol.appendChild(redactInput);

const rdBtnRow = document.createElement('div');
rdBtnRow.style.display = 'flex';
rdBtnRow.style.gap = 'var(--sp-2)';
rdBtnRow.style.marginTop = 'var(--sp-2)';

const redactBtn = document.createElement('button');
redactBtn.className = 'action-button';
redactBtn.textContent = 'Redact';
redactBtn.onclick = runRedact;
rdBtnRow.appendChild(redactBtn);

rdLeftCol.appendChild(rdBtnRow);
rdContainer.appendChild(rdLeftCol);

// Right Column: Output
const rdRightCol = document.createElement('div');
rdRightCol.style.flex = '1';

const rdOutputLabel = document.createElement('label');
rdOutputLabel.textContent = 'Redacted Output';
rdRightCol.appendChild(rdOutputLabel);

const redactOutput = document.createElement('textarea');
redactOutput.id = 'redactOutput';
redactOutput.readOnly = true;
redactOutput.placeholder = 'Redacted text will appear here...';
redactOutput.style.height = '350px';
redactOutput.style.background = 'var(--ops-elevated)';
rdRightCol.appendChild(redactOutput);

const rdCopyBtn = document.createElement('button');
rdCopyBtn.className = 'action-button secondary';
rdCopyBtn.textContent = 'Copy Redacted';
rdCopyBtn.style.marginTop = 'var(--sp-2)';
rdCopyBtn.onclick = () => copyToClipboard(redactOutput.value, rdCopyBtn);
rdRightCol.appendChild(rdCopyBtn);

rdContainer.appendChild(rdRightCol);
redactTab.appendChild(rdContainer);

// Custom Replacements Section
const customSection = document.createElement('div');
customSection.style.marginTop = 'var(--sp-6)';

const customLabel = document.createElement('h3');
customLabel.textContent = 'Custom Patterns';
customSection.appendChild(customLabel);

const customDesc = document.createElement('p');
customDesc.style.fontSize = '12px';
customDesc.style.color = 'var(--ops-text-dim)';
customDesc.style.marginBottom = 'var(--sp-3)';
customDesc.textContent = 'Add custom find/replace pairs (one per line). Format: find → replace. Applied after built-in patterns.';
customSection.appendChild(customDesc);

const customInput = document.createElement('textarea');
customInput.id = 'customRedactPatterns';
customInput.placeholder = 'CompanyName → REDACTED\n192.168.1.0 → 10.0.0.0\nsecret-project → project-x';
customInput.style.height = '100px';
customInput.style.fontSize = '12px';
customSection.appendChild(customInput);

redactTab.appendChild(customSection);

// ---------- text replacement ---------- //
const replacements = [
  { regex: /131\.247\./g, replace: "89.101." },
  { regex: /\b[\w.]+@usf\.edu/gi, replace: "user1@xxx.xxx" },
  { regex: /forest\\(.+)/gi, replace: "forest\\user1" },
  { regex: /\.edu/gi, replace: "\.org" },
  { regex: /USF/gi, replace: "xxx" },
  { regex: /Florida/gi, replace: "xxx" },
  { regex: /University/gi, replace: "Institute" },
  { regex: /fl-/gi, replace: "xx-" },
  { regex: /("cisOrgId"\s*:\s*")[^"]*(")/g, replace: '$1xxx$2' },
  { regex: /("cisOrgName"\s*:\s*")[^"]*(")/g, replace: '$1xxx$2' },
  { regex: /("cisOrgInfo"\s*:\s*")[^"]*(")/g, replace: '$1xxx$2' },
];

function runRedact() {
  let text = redactInput.value;
  if (!text) return;

  // Built-in replacements
  replacements.forEach(r => {
    text = text.replace(r.regex, r.replace);
  });

  // Custom replacements
  const customRaw = customInput.value.trim();
  if (customRaw) {
    customRaw.split('\n').forEach(line => {
      const parts = line.split('→').map(s => s.trim());
      if (parts.length === 2 && parts[0] && parts[1]) {
        try {
          const regex = new RegExp(escapeRegex(parts[0]), 'gi');
          text = text.replace(regex, parts[1]);
        } catch (e) { /* skip invalid */ }
      }
    });
  }

  redactOutput.value = text;
  showToast('Text redacted', 'success');
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}