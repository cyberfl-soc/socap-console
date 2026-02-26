// ---------- IOC Extractor ---------- //
const iocTab = document.getElementById("iocExtTab");

// Header
const iocHeader = document.createElement('h2');
iocHeader.textContent = 'IOC Extractor';
iocTab.appendChild(iocHeader);

const iocDesc = document.createElement('p');
iocDesc.className = 'tab-desc';
iocDesc.textContent = 'Paste raw text (emails, logs, reports) to extract IPs, domains, URLs, and hashes. Supports IPv4, IPv6, SHA-256, SHA-1, and MD5.';
iocTab.appendChild(iocDesc);

// Input Textarea
const iocInputLabel = document.createElement('label');
iocInputLabel.textContent = 'Raw Text Input';
iocTab.appendChild(iocInputLabel);

const iocTextSource = document.createElement('textarea');
iocTextSource.id = 'iocTextSource';
iocTextSource.placeholder = 'Paste raw text here (emails, logs, reports) to extract IOCs...';
iocTextSource.style.height = '180px';
iocTab.appendChild(iocTextSource);

// Action Button
const extractBtn = document.createElement('button');
extractBtn.className = 'action-button';
extractBtn.textContent = 'Extract IOCs';
extractBtn.onclick = extractIOCs;
iocTab.appendChild(extractBtn);

// Output Container (card-based)
const iocOutputContainer = document.createElement('div');
iocOutputContainer.id = 'iocOutputContainer';
iocOutputContainer.style.marginTop = 'var(--sp-4)';
iocOutputContainer.style.display = 'flex';
iocOutputContainer.style.flexDirection = 'column';
iocOutputContainer.style.gap = 'var(--sp-3)';
iocTab.appendChild(iocOutputContainer);

// Regex Patterns
const extractionPatterns = {
    ipv4: /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    ipv6: /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[fF]{4}:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/g,
    domain: /\b([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+)\b/gi,
    url: /(?:https?|ftp):\/\/[^\s/$.?#].[^\s]*/gi,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    md5: /\b[a-fA-F0-9]{32}\b/g
};

// Filter out false positives
const commonFalsePositives = new Set([
    'example.com', 'test.com'
]);

// Helper to remove defang chars like [.]
function cleanIOC(raw) {
    return raw.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':').replace(/hxxp/ig, 'http');
}

function extractIOCs() {
    const rawText = cleanIOC(iocTextSource.value);
    const results = {
        IPs: new Set(),
        IPv6: new Set(),
        Domains: new Set(),
        URLs: new Set(),
        SHA256: new Set(),
        SHA1: new Set(),
        MD5: new Set()
    };

    // Extract
    for (let [type, regex] of Object.entries(extractionPatterns)) {
        const matches = rawText.match(regex) || [];
        matches.forEach(m => {
            let finalMatch = m.toLowerCase();

            // Exclude IP matches from domains
            if (type === 'domain') {
                if (extractionPatterns.ipv4.test(finalMatch)) return;
            }
            if (commonFalsePositives.has(finalMatch)) return;

            // Avoid SHA1 false positives (substrings of SHA256)
            if (type === 'sha1') {
                for (const sha of results.SHA256) {
                    if (sha.includes(finalMatch)) return;
                }
            }

            if (type === 'ipv4') results.IPs.add(finalMatch);
            else if (type === 'ipv6') results.IPv6.add(finalMatch);
            else if (type === 'domain') results.Domains.add(finalMatch);
            else if (type === 'url') results.URLs.add(m);
            else if (type === 'sha256') results.SHA256.add(finalMatch);
            else if (type === 'sha1') results.SHA1.add(finalMatch);
            else if (type === 'md5') results.MD5.add(finalMatch);
        });
    }

    // Build card-based output
    iocOutputContainer.innerHTML = '';

    const sections = [
        { key: 'IPs', label: 'IPv4 Addresses', icon: '🌐' },
        { key: 'IPv6', label: 'IPv6 Addresses', icon: '🌐' },
        { key: 'Domains', label: 'Domains', icon: '🔗' },
        { key: 'URLs', label: 'URLs', icon: '🔗' },
        { key: 'SHA256', label: 'SHA-256 Hashes', icon: '🔑' },
        { key: 'SHA1', label: 'SHA-1 Hashes', icon: '🔑' },
        { key: 'MD5', label: 'MD5 Hashes', icon: '🔑' }
    ];

    let totalFound = 0;

    sections.forEach(sec => {
        const items = results[sec.key];
        if (items.size === 0) return;
        totalFound += items.size;

        const card = document.createElement('div');
        card.className = 'ops-card';

        const headerRow = document.createElement('div');
        headerRow.style.display = 'flex';
        headerRow.style.justifyContent = 'space-between';
        headerRow.style.alignItems = 'center';
        headerRow.style.marginBottom = 'var(--sp-2)';

        const title = document.createElement('h4');
        title.style.margin = '0';
        title.innerHTML = `${sec.icon} ${sec.label} <span style="color: var(--ops-text-dim); font-weight: 400;">(${items.size})</span>`;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'action-button secondary';
        copyBtn.textContent = 'Copy';
        copyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
        copyBtn.style.fontSize = '11px';
        copyBtn.onclick = () => copyToClipboard(Array.from(items).join('\n'), copyBtn);

        headerRow.appendChild(title);
        headerRow.appendChild(copyBtn);
        card.appendChild(headerRow);

        const list = document.createElement('div');
        list.style.fontFamily = "'Fira Code', monospace";
        list.style.fontSize = '12px';
        list.style.lineHeight = '1.8';
        list.style.color = 'var(--ops-text)';
        list.style.wordBreak = 'break-all';
        items.forEach(item => {
            const line = document.createElement('div');
            line.textContent = item;
            list.appendChild(line);
        });

        card.appendChild(list);
        iocOutputContainer.appendChild(card);
    });

    if (totalFound === 0) {
        const empty = document.createElement('p');
        empty.style.color = 'var(--ops-text-dim)';
        empty.style.fontSize = '13px';
        empty.textContent = 'No IOCs found in the input text.';
        iocOutputContainer.appendChild(empty);
    } else {
        showToast(`Extracted ${totalFound} IOC(s)`, 'success');

        // Update Intel Strip with first IP found
        if (results.IPs.size > 0) {
            updateIntelStrip(Array.from(results.IPs)[0], 'IP');
        } else if (results.Domains.size > 0) {
            updateIntelStrip(Array.from(results.Domains)[0], 'Domain');
        }
    }
}
