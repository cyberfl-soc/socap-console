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

// ---------- Quick TZ Converter ---------- //
const tzDivider = document.createElement('hr');
tzDivider.className = 'ops-divider';
tsTab.appendChild(tzDivider);

const tzHeader = document.createElement('h3');
tzHeader.textContent = 'Quick Time Zone Converter';
tsTab.appendChild(tzHeader);

// Auto-detect current ET status
function getETStatus() {
    const now = new Date();
    const etLabel = now.toLocaleTimeString('en-US', { timeZone: 'America/New_York', timeZoneName: 'short' }).split(' ').pop();
    const isDST = etLabel === 'EDT';
    return { label: etLabel, offset: isDST ? -4 : -5, isDST };
}

const etStatus = getETStatus();
const tzNote = document.createElement('p');
tzNote.style.fontSize = '12px';
tzNote.style.color = 'var(--ops-text-dim)';
tzNote.style.marginBottom = 'var(--sp-3)';
tzNote.innerHTML = `Currently in <strong style="color: var(--ops-accent)">${etStatus.label}</strong> (UTC${etStatus.offset}). Enter a time below to convert between Eastern Time and UTC.`;
tsTab.appendChild(tzNote);

// Input row
const tzInputRow = document.createElement('div');
tzInputRow.style.display = 'flex';
tzInputRow.style.gap = 'var(--sp-3)';
tzInputRow.style.alignItems = 'flex-end';
tzInputRow.style.flexWrap = 'wrap';

// Time input
const tzTimeGroup = document.createElement('div');
const tzTimeLabel = document.createElement('label');
tzTimeLabel.textContent = 'Time';
tzTimeLabel.style.fontSize = '12px';
tzTimeGroup.appendChild(tzTimeLabel);

const tzTimeInput = document.createElement('input');
tzTimeInput.type = 'text';
tzTimeInput.id = 'tzTimeInput';
tzTimeInput.placeholder = 'e.g. 5:00 PM, 17:00, 14:30';
tzTimeInput.style.width = '180px';
tzTimeGroup.appendChild(tzTimeInput);
tzInputRow.appendChild(tzTimeGroup);

// Date input (optional)
const tzDateGroup = document.createElement('div');
const tzDateLabel = document.createElement('label');
tzDateLabel.textContent = 'Date (optional)';
tzDateLabel.style.fontSize = '12px';
tzDateGroup.appendChild(tzDateLabel);

const tzDateInput = document.createElement('input');
tzDateInput.type = 'date';
tzDateInput.id = 'tzDateInput';
tzDateInput.valueAsDate = new Date();
tzDateInput.style.width = '160px';
tzDateGroup.appendChild(tzDateInput);
tzInputRow.appendChild(tzDateGroup);

// Source timezone
const tzFromGroup = document.createElement('div');
const tzFromLabel = document.createElement('label');
tzFromLabel.textContent = 'From';
tzFromLabel.style.fontSize = '12px';
tzFromGroup.appendChild(tzFromLabel);

const tzFromSelect = document.createElement('select');
tzFromSelect.id = 'tzFromSelect';
tzFromSelect.style.width = '120px';
const optUTC = document.createElement('option');
optUTC.value = 'UTC';
optUTC.textContent = 'UTC';
const optET = document.createElement('option');
optET.value = 'ET';
optET.textContent = `ET (${etStatus.label})`;
optET.selected = true;
tzFromSelect.appendChild(optET);
tzFromSelect.appendChild(optUTC);
tzFromGroup.appendChild(tzFromSelect);
tzInputRow.appendChild(tzFromGroup);

// Convert button
const tzConvertBtn = document.createElement('button');
tzConvertBtn.className = 'action-button';
tzConvertBtn.textContent = 'Convert';
tzConvertBtn.onclick = convertTZ;
tzInputRow.appendChild(tzConvertBtn);

tsTab.appendChild(tzInputRow);

// TZ Results
const tzResultsDiv = document.createElement('div');
tzResultsDiv.id = 'tzResults';
tzResultsDiv.style.marginTop = 'var(--sp-3)';
tsTab.appendChild(tzResultsDiv);

function parseTimeString(timeStr) {
    timeStr = timeStr.trim().toUpperCase();

    // Handle "5 PM", "5:00 PM", "5:30PM", "17:00", "14:30"
    let hours, minutes;

    // 12-hour format
    const match12 = timeStr.match(/^(\d{1,2})(?::(\d{2}))?\s*(AM|PM)$/);
    if (match12) {
        hours = parseInt(match12[1]);
        minutes = parseInt(match12[2] || '0');
        const isPM = match12[3] === 'PM';
        if (isPM && hours !== 12) hours += 12;
        if (!isPM && hours === 12) hours = 0;
        return { hours, minutes };
    }

    // 24-hour format
    const match24 = timeStr.match(/^(\d{1,2}):(\d{2})$/);
    if (match24) {
        hours = parseInt(match24[1]);
        minutes = parseInt(match24[2]);
        if (hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59) {
            return { hours, minutes };
        }
    }

    return null;
}

function convertTZ() {
    const timeStr = tzTimeInput.value;
    if (!timeStr.trim()) {
        tzResultsDiv.innerHTML = '<p style="color: var(--threat-amber); font-size: 13px;">Enter a time to convert.</p>';
        return;
    }

    const parsed = parseTimeString(timeStr);
    if (!parsed) {
        tzResultsDiv.innerHTML = '<p style="color: var(--threat-red); font-size: 13px;">Could not parse time. Try formats like "5:00 PM", "17:00", or "2:30 PM".</p>';
        return;
    }

    const from = tzFromSelect.value;
    const dateVal = tzDateInput.value || new Date().toISOString().split('T')[0];

    // Build a Date object in the source timezone
    let sourceDate, targetDate;

    if (from === 'UTC') {
        // Input is UTC → convert to ET
        sourceDate = new Date(`${dateVal}T${String(parsed.hours).padStart(2, '0')}:${String(parsed.minutes).padStart(2, '0')}:00Z`);
        targetDate = sourceDate;
    } else {
        // Input is ET → we need to figure out the UTC equivalent
        // Use Intl to determine the offset for the given date
        const tempDate = new Date(`${dateVal}T${String(parsed.hours).padStart(2, '0')}:${String(parsed.minutes).padStart(2, '0')}:00`);
        // Get ET offset for this specific date (handles DST correctly)
        const etFormatter = new Intl.DateTimeFormat('en-US', {
            timeZone: 'America/New_York',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
        // Use the inverse: create UTC date by adding offset
        const etParts = etFormatter.formatToParts(tempDate);
        const etOffset = tempDate.getTimezoneOffset(); // local offset in minutes

        // More reliable: create in ET using a known approach
        // Build ISO string assuming UTC, then adjust
        const utcGuess = new Date(`${dateVal}T${String(parsed.hours).padStart(2, '0')}:${String(parsed.minutes).padStart(2, '0')}:00Z`);

        // Get what ET shows for this UTC time
        const etTime = new Date(utcGuess.toLocaleString('en-US', { timeZone: 'America/New_York' }));
        const diffMs = utcGuess - etTime;

        // The actual UTC time when it's the given time in ET
        sourceDate = new Date(utcGuess.getTime() + diffMs);
        targetDate = sourceDate;
    }

    if (isNaN(sourceDate)) {
        tzResultsDiv.innerHTML = '<p style="color: var(--threat-red); font-size: 13px;">Invalid date/time combination.</p>';
        return;
    }

    // Format results
    const utcStr = sourceDate.toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: true });
    const utcStr24 = sourceDate.toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false });
    const etStr = sourceDate.toLocaleTimeString('en-US', { timeZone: 'America/New_York', hour: '2-digit', minute: '2-digit', hour12: true });
    const etStr24 = sourceDate.toLocaleTimeString('en-US', { timeZone: 'America/New_York', hour: '2-digit', minute: '2-digit', hour12: false });
    const etTzName = sourceDate.toLocaleTimeString('en-US', { timeZone: 'America/New_York', timeZoneName: 'short' }).split(' ').pop();
    const etDateStr = sourceDate.toLocaleDateString('en-US', { timeZone: 'America/New_York', weekday: 'short', month: 'short', day: 'numeric' });
    const utcDateStr = sourceDate.toLocaleDateString('en-US', { timeZone: 'UTC', weekday: 'short', month: 'short', day: 'numeric' });

    // Check if date changes across timezone
    const dateNote = etDateStr !== utcDateStr ? ' <span style="color: var(--threat-amber);">(next day)</span>' : '';

    tzResultsDiv.innerHTML = '';

    const results = [
        { label: `Eastern Time (${etTzName})`, value: `${etStr} / ${etStr24}`, sub: etDateStr },
        { label: 'UTC', value: `${utcStr} / ${utcStr24}`, sub: `${utcDateStr}${dateNote}` },
        { label: 'Epoch (seconds)', value: Math.floor(sourceDate.getTime() / 1000).toString(), sub: '' },
    ];

    results.forEach(r => {
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
        lbl.textContent = r.label;

        const val = document.createElement('div');
        val.style.fontFamily = "'Fira Code', monospace";
        val.style.fontSize = '14px';
        val.style.color = 'var(--ops-text)';
        val.innerHTML = r.value;

        info.appendChild(lbl);
        info.appendChild(val);
        if (r.sub) {
            const sub = document.createElement('div');
            sub.style.fontSize = '11px';
            sub.style.color = 'var(--ops-text-muted)';
            sub.style.marginTop = '2px';
            sub.innerHTML = r.sub;
            info.appendChild(sub);
        }

        const copyBtn = document.createElement('button');
        copyBtn.className = 'action-button secondary';
        copyBtn.textContent = 'Copy';
        copyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
        copyBtn.style.fontSize = '11px';
        copyBtn.onclick = () => copyToClipboard(r.value.replace(/<[^>]*>/g, ''), copyBtn);

        row.appendChild(info);
        row.appendChild(copyBtn);
        tzResultsDiv.appendChild(row);
    });
}

// Auto-convert on Enter
tzTimeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') convertTZ();
});

// ---------- Main converter: add ET to output ---------- //
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

