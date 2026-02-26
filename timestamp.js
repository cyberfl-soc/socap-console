// ---------- Timestamp Converter ---------- //
const tsTab = document.getElementById("timestampTab");

// Header
const tsHeader = document.createElement('h2');
tsHeader.textContent = 'Timestamp Converter';
tsTab.appendChild(tsHeader);

const tsDesc = document.createElement('p');
tsDesc.className = 'tab-desc';
tsDesc.textContent = 'Convert between epoch timestamps and human-readable formats. Auto-detects input format. All conversions shown simultaneously.';
tsTab.appendChild(tsDesc);

// Layout: input column + results column
const tsLayout = document.createElement('div');
tsLayout.style.display = 'flex';
tsLayout.style.gap = 'var(--sp-6)';
tsLayout.style.alignItems = 'flex-start';

// Left: Input
const tsLeft = document.createElement('div');
tsLeft.style.flex = '1';

const tsInputLabel = document.createElement('label');
tsInputLabel.textContent = 'Input Timestamp';
tsLeft.appendChild(tsInputLabel);

const tsInput = document.createElement('input');
tsInput.type = 'text';
tsInput.id = 'tsInput';
tsInput.placeholder = 'e.g. 1708300800, 2025-02-19T12:00:00Z, Feb 19 2025 12:00:00';
tsLeft.appendChild(tsInput);

// Button row
const tsBtnRow = document.createElement('div');
tsBtnRow.style.display = 'flex';
tsBtnRow.style.gap = 'var(--sp-2)';
tsBtnRow.style.marginTop = 'var(--sp-2)';

const tsConvertBtn = document.createElement('button');
tsConvertBtn.className = 'action-button';
tsConvertBtn.textContent = 'Convert';
tsConvertBtn.onclick = convertTimestamp;

const tsNowBtn = document.createElement('button');
tsNowBtn.className = 'action-button secondary';
tsNowBtn.textContent = '⏱ Now';
tsNowBtn.onclick = () => {
    tsInput.value = Math.floor(Date.now() / 1000).toString();
    convertTimestamp();
};

const tsClearBtn = document.createElement('button');
tsClearBtn.className = 'action-button secondary';
tsClearBtn.textContent = 'Clear';
tsClearBtn.onclick = () => {
    tsInput.value = '';
    tsResults.innerHTML = '<p style="color: var(--ops-text-dim); font-size: 13px;">Enter a timestamp above and click Convert.</p>';
};

tsBtnRow.appendChild(tsConvertBtn);
tsBtnRow.appendChild(tsNowBtn);
tsBtnRow.appendChild(tsClearBtn);
tsLeft.appendChild(tsBtnRow);

// Quick reference
const tsRef = document.createElement('div');
tsRef.className = 'ops-card';
tsRef.style.marginTop = 'var(--sp-4)';
tsRef.innerHTML = `
  <h4>Supported Formats</h4>
  <ul style="font-size: 12px; color: var(--ops-text-muted); padding-left: 16px; line-height: 2;">
    <li>Unix Epoch (seconds): <code style="color: var(--ops-accent); font-family: 'Fira Code', monospace;">1708300800</code></li>
    <li>Unix Epoch (ms): <code style="color: var(--ops-accent); font-family: 'Fira Code', monospace;">1708300800000</code></li>
    <li>ISO 8601: <code style="color: var(--ops-accent); font-family: 'Fira Code', monospace;">2025-02-19T12:00:00Z</code></li>
    <li>Common Log: <code style="color: var(--ops-accent); font-family: 'Fira Code', monospace;">19/Feb/2025:12:00:00</code></li>
    <li>Most date strings parseable by JS Date()</li>
  </ul>
`;
tsLeft.appendChild(tsRef);

tsLayout.appendChild(tsLeft);

// Right: Results
const tsRight = document.createElement('div');
tsRight.style.flex = '1';

const tsResultsLabel = document.createElement('label');
tsResultsLabel.textContent = 'Conversions';
tsRight.appendChild(tsResultsLabel);

const tsResults = document.createElement('div');
tsResults.id = 'tsResults';
tsResults.style.marginTop = 'var(--sp-2)';
tsResults.innerHTML = '<p style="color: var(--ops-text-dim); font-size: 13px;">Enter a timestamp above and click Convert.</p>';
tsRight.appendChild(tsResults);

tsLayout.appendChild(tsRight);
tsTab.appendChild(tsLayout);

// ---------- Logic ---------- //
function parseTimestampInput(input) {
    input = input.trim();

    // Unix epoch seconds (10 digits)
    if (/^\d{10}$/.test(input)) {
        return new Date(parseInt(input) * 1000);
    }

    // Unix epoch milliseconds (13 digits)
    if (/^\d{13}$/.test(input)) {
        return new Date(parseInt(input));
    }

    // Common log format: 19/Feb/2025:12:00:00
    const clfMatch = input.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
    if (clfMatch) {
        const dateStr = `${clfMatch[3]}-${clfMatch[2]}-${clfMatch[1]}T${clfMatch[4]}:${clfMatch[5]}:${clfMatch[6]}Z`;
        const d = new Date(dateStr);
        if (!isNaN(d)) return d;
    }

    // Try native Date parsing
    const d = new Date(input);
    if (!isNaN(d)) return d;

    return null;
}

function convertTimestamp() {
    const input = tsInput.value;
    if (!input.trim()) {
        tsResults.innerHTML = '<p style="color: var(--threat-amber); font-size: 13px;">Please enter a timestamp.</p>';
        return;
    }

    const date = parseTimestampInput(input);
    if (!date) {
        tsResults.innerHTML = '<p style="color: var(--threat-red); font-size: 13px;">Could not parse timestamp. Try a different format.</p>';
        return;
    }

    const etTzLabel = date.toLocaleTimeString('en-US', { timeZone: 'America/New_York', timeZoneName: 'short' }).split(' ').pop();

    const formats = [
        { label: 'Unix Epoch (seconds)', value: Math.floor(date.getTime() / 1000).toString() },
        { label: 'Unix Epoch (milliseconds)', value: date.getTime().toString() },
        { label: 'ISO 8601 (UTC)', value: date.toISOString() },
        { label: 'UTC String', value: date.toUTCString() },
        { label: `Eastern Time (${etTzLabel})`, value: date.toLocaleString('en-US', { timeZone: 'America/New_York', hour12: true, year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ` ${etTzLabel}` },
        { label: 'Local Time', value: date.toLocaleString() },
        { label: 'Date Only (UTC)', value: date.toISOString().split('T')[0] },
        { label: 'Time Only (UTC)', value: date.toISOString().split('T')[1].replace('Z', '') + ' UTC' },
        { label: 'Relative', value: getRelativeTime(date) }
    ];

    tsResults.innerHTML = '';

    formats.forEach(f => {
        const row = document.createElement('div');
        row.className = 'ops-card';
        row.style.display = 'flex';
        row.style.justifyContent = 'space-between';
        row.style.alignItems = 'center';
        row.style.padding = 'var(--sp-3) var(--sp-4)';
        row.style.marginBottom = 'var(--sp-2)';

        const info = document.createElement('div');
        const lbl = document.createElement('div');
        lbl.style.fontSize = '11px';
        lbl.style.color = 'var(--ops-text-dim)';
        lbl.style.textTransform = 'uppercase';
        lbl.style.letterSpacing = '0.04em';
        lbl.style.marginBottom = '2px';
        lbl.textContent = f.label;

        const val = document.createElement('div');
        val.style.fontFamily = "'Fira Code', monospace";
        val.style.fontSize = '13px';
        val.style.color = 'var(--ops-text)';
        val.textContent = f.value;

        info.appendChild(lbl);
        info.appendChild(val);

        const copyBtn = document.createElement('button');
        copyBtn.className = 'action-button secondary';
        copyBtn.textContent = 'Copy';
        copyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
        copyBtn.style.fontSize = '11px';
        copyBtn.onclick = () => copyToClipboard(f.value, copyBtn);

        row.appendChild(info);
        row.appendChild(copyBtn);
        tsResults.appendChild(row);
    });
}

function getRelativeTime(date) {
    const now = new Date();
    const diff = now - date;
    const absDiff = Math.abs(diff);
    const sign = diff > 0 ? 'ago' : 'from now';

    if (absDiff < 60000) return `${Math.floor(absDiff / 1000)} seconds ${sign}`;
    if (absDiff < 3600000) return `${Math.floor(absDiff / 60000)} minutes ${sign}`;
    if (absDiff < 86400000) return `${Math.floor(absDiff / 3600000)} hours ${sign}`;
    if (absDiff < 2592000000) return `${Math.floor(absDiff / 86400000)} days ${sign}`;
    return `${Math.floor(absDiff / 2592000000)} months ${sign}`;
}

// Auto-convert on Enter
tsInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') convertTimestamp();
});

