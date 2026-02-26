// ---------- Encode/Decode Tab ---------- //
const encTab = document.getElementById("encodeTab");

// Header
const encHeader = document.createElement('h2');
encHeader.textContent = 'Encode / Decode';
encTab.appendChild(encHeader);

const encDesc = document.createElement('p');
encDesc.className = 'tab-desc';
encDesc.textContent = 'Encode and decode payloads across common formats. Useful for analyzing obfuscated payloads, crafting queries, and sharing IOCs safely.';
encTab.appendChild(encDesc);

// Mode selector
const modeRow = document.createElement('div');
modeRow.style.display = 'flex';
modeRow.style.gap = 'var(--sp-2)';
modeRow.style.marginBottom = 'var(--sp-4)';
modeRow.style.flexWrap = 'wrap';

const modes = [
    { id: 'base64', label: 'Base64' },
    { id: 'url', label: 'URL' },
    { id: 'html', label: 'HTML Entity' },
    { id: 'hex', label: 'Hex' }
];

let activeMode = 'base64';

modes.forEach(m => {
    const btn = document.createElement('button');
    btn.className = 'action-button' + (m.id === activeMode ? '' : ' secondary');
    btn.textContent = m.label;
    btn.id = 'encMode_' + m.id;
    btn.onclick = () => {
        activeMode = m.id;
        modes.forEach(mm => {
            const b = document.getElementById('encMode_' + mm.id);
            b.className = mm.id === activeMode ? 'action-button' : 'action-button secondary';
        });
    };
    modeRow.appendChild(btn);
});

encTab.appendChild(modeRow);

// Two-pane layout
const encLayout = document.createElement('div');
encLayout.style.display = 'flex';
encLayout.style.gap = 'var(--sp-4)';
encLayout.style.alignItems = 'flex-start';

// Left: Input
const encLeft = document.createElement('div');
encLeft.style.flex = '1';

const encInputLabel = document.createElement('label');
encInputLabel.textContent = 'Input';
encLeft.appendChild(encInputLabel);

const encInput = document.createElement('textarea');
encInput.id = 'encInput';
encInput.placeholder = 'Paste text to encode or decode...';
encInput.style.height = '300px';
encLeft.appendChild(encInput);

const encBtnRow = document.createElement('div');
encBtnRow.style.display = 'flex';
encBtnRow.style.gap = 'var(--sp-2)';
encBtnRow.style.marginTop = 'var(--sp-2)';

const encodeBtn = document.createElement('button');
encodeBtn.className = 'action-button';
encodeBtn.textContent = 'Encode →';
encodeBtn.onclick = () => runEncode('encode');

const decodeBtn = document.createElement('button');
decodeBtn.className = 'action-button';
decodeBtn.textContent = '← Decode';
decodeBtn.onclick = () => runEncode('decode');

const chainBtn = document.createElement('button');
chainBtn.className = 'action-button secondary';
chainBtn.textContent = 'Auto-Decode';
chainBtn.title = 'Attempts Base64 → URL → HTML decode in sequence';
chainBtn.onclick = runChainDecode;

encBtnRow.appendChild(encodeBtn);
encBtnRow.appendChild(decodeBtn);
encBtnRow.appendChild(chainBtn);
encLeft.appendChild(encBtnRow);

encLayout.appendChild(encLeft);

// Right: Output
const encRight = document.createElement('div');
encRight.style.flex = '1';

const encOutputLabel = document.createElement('label');
encOutputLabel.textContent = 'Output';
encRight.appendChild(encOutputLabel);

const encOutput = document.createElement('textarea');
encOutput.id = 'encOutput';
encOutput.placeholder = 'Result will appear here...';
encOutput.style.height = '300px';
encOutput.readOnly = true;
encOutput.style.background = 'var(--ops-elevated)';
encRight.appendChild(encOutput);

const encCopyRow = document.createElement('div');
encCopyRow.style.display = 'flex';
encCopyRow.style.gap = 'var(--sp-2)';
encCopyRow.style.marginTop = 'var(--sp-2)';

const encCopyBtn = document.createElement('button');
encCopyBtn.className = 'action-button secondary';
encCopyBtn.textContent = 'Copy Output';
encCopyBtn.onclick = () => copyToClipboard(encOutput.value, encCopyBtn);

const encSwapBtn = document.createElement('button');
encSwapBtn.className = 'action-button secondary';
encSwapBtn.textContent = '↕ Swap';
encSwapBtn.onclick = () => {
    const tmp = encInput.value;
    encInput.value = encOutput.value;
    encOutput.value = tmp;
};

encCopyRow.appendChild(encCopyBtn);
encCopyRow.appendChild(encSwapBtn);
encRight.appendChild(encCopyRow);

encLayout.appendChild(encRight);
encTab.appendChild(encLayout);

// ---------- Encoding Logic ---------- //

function runEncode(direction) {
    const input = encInput.value;
    if (!input) {
        encOutput.value = '';
        return;
    }

    try {
        if (direction === 'encode') {
            encOutput.value = encodeText(input, activeMode);
        } else {
            encOutput.value = decodeText(input, activeMode);
        }
    } catch (e) {
        encOutput.value = `Error: ${e.message}`;
        showToast('Decode/Encode failed', 'error');
    }
}

function encodeText(text, mode) {
    switch (mode) {
        case 'base64': return btoa(unescape(encodeURIComponent(text)));
        case 'url': return encodeURIComponent(text);
        case 'html': return text.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        case 'hex': return Array.from(new TextEncoder().encode(text)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        default: return text;
    }
}

function decodeText(text, mode) {
    switch (mode) {
        case 'base64': return decodeURIComponent(escape(atob(text.trim())));
        case 'url': return decodeURIComponent(text);
        case 'html': {
            const el = document.createElement('textarea');
            el.innerHTML = text;
            return el.value;
        }
        case 'hex': {
            const hexStr = text.replace(/\s+/g, '');
            const bytes = [];
            for (let i = 0; i < hexStr.length; i += 2) {
                bytes.push(parseInt(hexStr.substr(i, 2), 16));
            }
            return new TextDecoder().decode(new Uint8Array(bytes));
        }
        default: return text;
    }
}

function runChainDecode() {
    let text = encInput.value;
    if (!text) return;

    const steps = [];

    // Step 1: Try Base64
    try {
        const decoded = decodeURIComponent(escape(atob(text.trim())));
        if (decoded !== text) {
            steps.push('Base64 decoded');
            text = decoded;
        }
    } catch (e) { /* not base64 */ }

    // Step 2: Try URL decode
    try {
        const decoded = decodeURIComponent(text);
        if (decoded !== text) {
            steps.push('URL decoded');
            text = decoded;
        }
    } catch (e) { /* not url encoded */ }

    // Step 3: Try HTML entity decode
    try {
        const el = document.createElement('textarea');
        el.innerHTML = text;
        if (el.value !== text) {
            steps.push('HTML entity decoded');
            text = el.value;
        }
    } catch (e) { /* not html encoded */ }

    if (steps.length > 0) {
        encOutput.value = text;
        showToast(`Chain: ${steps.join(' → ')}`, 'info');
    } else {
        encOutput.value = text;
        showToast('No encoding detected', 'info');
    }
}
