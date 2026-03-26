// ---------- HTML Analyzer ---------- //
const analyzerTab = document.getElementById("htmlAnalyzerTab");

// Header
const haHeader = document.createElement('h2');
haHeader.textContent = 'HTML Analyzer';
analyzerTab.appendChild(haHeader);

const haDesc = document.createElement('p');
haDesc.className = 'tab-desc';
haDesc.textContent = 'Paste raw HTML source code or enter a URL to auto-fetch its source. Supports Wannabrowser links and direct URLs.';
analyzerTab.appendChild(haDesc);

// Two-column layout container
const haContainer = document.createElement('div');
haContainer.style.display = 'flex';
haContainer.style.gap = 'var(--sp-4)';
haContainer.style.alignItems = 'flex-start';

// Left Column: Input
const haLeftCol = document.createElement('div');
haLeftCol.style.flex = '1';

// URL Fetch section
const urlFetchSection = document.createElement('div');
urlFetchSection.className = 'ops-inset-panel';
urlFetchSection.style.marginBottom = 'var(--sp-4)';
urlFetchSection.style.padding = 'var(--sp-3) var(--sp-4)';

const urlFetchLabel = document.createElement('label');
urlFetchLabel.textContent = 'Fetch HTML from URL';
urlFetchLabel.style.display = 'block';
urlFetchLabel.style.marginBottom = 'var(--sp-2)';
urlFetchSection.appendChild(urlFetchLabel);

const urlFetchHint = document.createElement('div');
urlFetchHint.style.fontSize = '11px';
urlFetchHint.style.color = 'var(--ops-text-dim)';
urlFetchHint.style.marginBottom = 'var(--sp-2)';
urlFetchHint.textContent = 'Enter a URL to fetch its HTML. If CORS blocks the direct fetch, use "Open in Wannabrowser" — copy the Response Body there and paste it below.';
urlFetchSection.appendChild(urlFetchHint);

const urlInputRow = document.createElement('div');
urlInputRow.style.display = 'flex';
urlInputRow.style.gap = 'var(--sp-2)';

const urlInput = document.createElement('input');
urlInput.type = 'text';
urlInput.id = 'htmlUrlInput';
urlInput.placeholder = 'https://example.com';
urlInput.style.flex = '1';
urlInput.style.margin = '0';
urlInputRow.appendChild(urlInput);

const urlFetchBtn = document.createElement('button');
urlFetchBtn.className = 'action-button';
urlFetchBtn.textContent = 'Fetch';
urlFetchBtn.style.flexShrink = '0';
urlFetchBtn.style.padding = '0 var(--sp-4)';
urlInputRow.appendChild(urlFetchBtn);

const wanBtn = document.createElement('button');
wanBtn.className = 'action-button secondary';
wanBtn.textContent = 'Open in Wannabrowser';
wanBtn.style.flexShrink = '0';
wanBtn.style.padding = '0 var(--sp-3)';
wanBtn.title = 'Open URL in Wannabrowser — copy the Response Body and paste it below';
wanBtn.addEventListener('click', () => {
  const raw = urlInput.value.trim();
  const targetUrl = extractTargetUrl(raw) || raw;
  if (!targetUrl) {
    urlFetchStatus.style.display = 'block';
    urlFetchStatus.style.color = 'var(--threat-amber)';
    urlFetchStatus.textContent = 'Enter a URL first.';
    return;
  }
  const wanUrl = 'https://www.wannabrowser.net/#get=' + encodeURIComponent(targetUrl);
  window.open(wanUrl, '_blank');
  urlFetchStatus.style.display = 'block';
  urlFetchStatus.style.color = 'var(--intel-blue)';
  urlFetchStatus.innerHTML = 'ℹ Wannabrowser opened in a new tab. Copy the <strong>Response Body</strong> from there and paste it into the HTML input below, then click <strong>Analyze Source</strong>.';
});
urlInputRow.appendChild(wanBtn);

urlFetchSection.appendChild(urlInputRow);

// Status indicator
const urlFetchStatus = document.createElement('div');
urlFetchStatus.id = 'urlFetchStatus';
urlFetchStatus.style.fontSize = '12px';
urlFetchStatus.style.marginTop = 'var(--sp-2)';
urlFetchStatus.style.display = 'none';
urlFetchSection.appendChild(urlFetchStatus);

haLeftCol.appendChild(urlFetchSection);

// Divider with "OR" label
const orDivider = document.createElement('div');
orDivider.style.cssText = 'display: flex; align-items: center; gap: var(--sp-3); margin-bottom: var(--sp-3);';
orDivider.innerHTML = `
  <div style="flex: 1; height: 1px; background: var(--ops-border);"></div>
  <span style="font-size: 11px; color: var(--ops-text-dim); text-transform: uppercase; letter-spacing: 0.08em;">or paste manually</span>
  <div style="flex: 1; height: 1px; background: var(--ops-border);"></div>
`;
haLeftCol.appendChild(orDivider);

const haInputLabel = document.createElement('label');
haInputLabel.textContent = 'Raw HTML Input';
haLeftCol.appendChild(haInputLabel);

const htmlInput = document.createElement('textarea');
htmlInput.id = 'htmlInput';
htmlInput.placeholder = 'Paste HTML source code here...';
htmlInput.style.height = '380px';
haLeftCol.appendChild(htmlInput);

const analyzeBtn = document.createElement('button');
analyzeBtn.className = 'action-button';
analyzeBtn.textContent = 'Analyze Source';
analyzeBtn.style.marginTop = 'var(--sp-2)';
analyzeBtn.onclick = runAnalysis;
haLeftCol.appendChild(analyzeBtn);

// ---------- URL Fetch Logic ---------- //
function extractTargetUrl(input) {
    input = input.trim();
    // Wannabrowser URL: extract the target URL from the hash
    const wanMatch = input.match(/wannabrowser\.net\/#(?:get|url)=(.+)/i);
    if (wanMatch) {
        return decodeURIComponent(wanMatch[1]);
    }
    // Plain URL
    if (input.startsWith('http://') || input.startsWith('https://')) {
        return input;
    }
    // Try adding https://
    if (input.includes('.') && !input.includes(' ')) {
        return 'https://' + input;
    }
    return null;
}

async function fetchHtmlSource(targetUrl) {
    const shortUrl = targetUrl.substring(0, 60) + (targetUrl.length > 60 ? '...' : '');
    const setStatus = (color, html) => {
        urlFetchStatus.style.display = 'block';
        urlFetchStatus.style.color = color;
        urlFetchStatus.innerHTML = html;
    };

    const spinnerHtml = txt => `<span style="display:inline-flex;align-items:center;gap:6px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> ${txt}</span>`;

    // 1. Try direct fetch
    setStatus('var(--intel-blue)', spinnerHtml('Trying direct fetch…'));
    try {
        const res = await fetch(targetUrl, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        htmlInput.value = await res.text();
        setStatus('var(--threat-green)', '✓ Fetched directly. Click "Analyze Source" to analyze.');
        showToast('HTML source fetched', 'success');
        return;
    } catch (_) { /* CORS or network — try proxy */ }

    // 2. Try allorigins.win CORS proxy
    setStatus('var(--intel-blue)', spinnerHtml('Direct blocked — trying CORS proxy…'));
    try {
        const proxyUrl = 'https://api.allorigins.win/get?url=' + encodeURIComponent(targetUrl);
        const res = await fetch(proxyUrl, { signal: AbortSignal.timeout(10000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!data.contents) throw new Error('Empty response from proxy');
        htmlInput.value = data.contents;
        setStatus('var(--threat-green)', '✓ Fetched via CORS proxy (allorigins.win). Click "Analyze Source" to analyze.');
        showToast('HTML source fetched via proxy', 'success');
        return;
    } catch (_) { /* proxy also failed — fall back to Wannabrowser */ }

    // 3. Last resort — open Wannabrowser and ask user to paste
    const wanUrl = 'https://www.wannabrowser.net/#get=' + encodeURIComponent(targetUrl);
    window.open(wanUrl, '_blank');
    setStatus('var(--intel-blue)', 'ℹ Both direct fetch and proxy failed — Wannabrowser opened in a new tab.<br><span style="color:var(--ops-text-muted);font-size:11px;">Copy the <strong>Response Body</strong> from Wannabrowser and paste it into the HTML input below, then click <strong>Analyze Source</strong>.</span>');
    showToast('Opened in Wannabrowser', 'info');
}

urlFetchBtn.addEventListener('click', () => {
    const targetUrl = extractTargetUrl(urlInput.value);
    if (!targetUrl) {
        urlFetchStatus.style.display = 'block';
        urlFetchStatus.style.color = 'var(--threat-amber)';
        urlFetchStatus.textContent = 'Please enter a valid URL.';
        return;
    }
    fetchHtmlSource(targetUrl);
});

// Also fetch on Enter key
urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        urlFetchBtn.click();
    }
});

haContainer.appendChild(haLeftCol);

// Right Column: Output
const haRightCol = document.createElement('div');
haRightCol.style.flex = '1';

const haOutputLabel = document.createElement('label');
haOutputLabel.textContent = 'Analysis Results';
haRightCol.appendChild(haOutputLabel);

const outputContainer = document.createElement('div');
outputContainer.id = 'outputContainer';
outputContainer.style.display = 'flex';
outputContainer.style.flexDirection = 'column';
outputContainer.style.gap = 'var(--sp-3)';
outputContainer.style.marginTop = 'var(--sp-2)';
haRightCol.appendChild(outputContainer);

haContainer.appendChild(haRightCol);
analyzerTab.appendChild(haContainer);

// ---------- Whitelists ---------- //

const KNOWN_DOMAINS = new Set([
    // Social media
    'facebook.com', 'www.facebook.com', 'fb.com',
    'twitter.com', 'www.twitter.com', 'x.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'youtube.com', 'www.youtube.com', 'youtu.be',
    'tiktok.com', 'www.tiktok.com',
    'reddit.com', 'www.reddit.com',
    'pinterest.com', 'www.pinterest.com',
    'snapchat.com', 'www.snapchat.com',
    'tumblr.com', 'www.tumblr.com',
    'discord.com', 'discord.gg',

    // Search / general platforms
    'google.com', 'www.google.com',
    'bing.com', 'www.bing.com',
    'yahoo.com', 'www.yahoo.com',
    'duckduckgo.com',
    'wikipedia.org', 'en.wikipedia.org',

    // Email / communication
    'outlook.com', 'outlook.live.com',
    'mail.google.com',
    'teams.microsoft.com',
    'zoom.us',
    'slack.com',

    // News / media
    'bbc.com', 'www.bbc.com', 'bbc.co.uk',
    'cnn.com', 'www.cnn.com',
    'nytimes.com', 'www.nytimes.com',
    'reuters.com', 'www.reuters.com',
    'theguardian.com',

    // E-commerce / common
    'amazon.com', 'www.amazon.com',
    'ebay.com', 'www.ebay.com',
    'apple.com', 'www.apple.com',
    'microsoft.com', 'www.microsoft.com',
    'github.com', 'www.github.com',
    'stackoverflow.com',
    'w3.org', 'www.w3.org',
    'schema.org',
    'gravatar.com',

    // Common CDN / infra hostnames
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'ajax.googleapis.com', 'maps.googleapis.com',
    'www.googletagmanager.com', 'www.google-analytics.com',
    'connect.facebook.net', 'platform.twitter.com',
    'platform.linkedin.com',
]);

const KNOWN_JS_LIBS = new Set([
    // CDN hosts
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'ajax.googleapis.com',
    'code.jquery.com',
    'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com',
    'cdn.bootcss.com',
    'cdn.datatables.net',
    'cdn.tailwindcss.com',

    // Common libraries by path keyword
    'jquery', 'bootstrap', 'react', 'angular', 'vue',
    'lodash', 'moment', 'axios', 'popper', 'd3',
    'chart.js', 'fontawesome', 'font-awesome',
    'google-analytics', 'gtag', 'ga.js', 'analytics',
    'recaptcha', 'grecaptcha',
    'modernizr', 'polyfill',
    'highlight.js', 'prism.js',
    'swiper', 'slick', 'owl.carousel',
    'socket.io', 'signalr',
]);

const SUSPICIOUS_EXTENSIONS = new Set([
    '.hta', '.vbs', '.bat', '.cmd', '.ps1', '.scr', '.pif',
    '.wsf', '.cpl', '.msi', '.jar', '.com', '.inf', '.reg',
    '.exe', '.dll', '.sys', '.lnk', '.chm',
]);

// ---------- Analysis Logic ---------- //

function runAnalysis() {
    const sourceCode = htmlInput.value;
    if (!sourceCode.trim()) {
        outputContainer.innerHTML = '<p style="color: var(--ops-text-dim); font-size: 13px;">Paste valid HTML source code first.</p>';
        return;
    }

    function getDomain(url) {
        if (!url) return null;
        url = url.trim();
        let formatted = url;
        if (formatted.startsWith('//')) formatted = 'http:' + formatted;
        if (!formatted.startsWith('http') && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/|$)/.test(formatted)) {
            formatted = 'http://' + formatted;
        }
        try {
            return new URL(formatted).hostname;
        } catch (e) {
            return null;
        }
    }

    function isKnownDomain(domain) {
        if (!domain) return false;
        // Check exact and parent domain
        if (KNOWN_DOMAINS.has(domain)) return true;
        const parts = domain.split('.');
        if (parts.length > 2) {
            const parent = parts.slice(-2).join('.');
            if (KNOWN_DOMAINS.has(parent)) return true;
        }
        return false;
    }

    function isKnownLib(url) {
        if (!url) return false;
        const domain = getDomain(url);
        if (domain && KNOWN_JS_LIBS.has(domain)) return true;
        const lower = url.toLowerCase();
        for (const lib of KNOWN_JS_LIBS) {
            if (lower.includes(lib)) return true;
        }
        return false;
    }

    function getExtension(url) {
        if (!url) return null;
        try {
            const cleaned = url.split('?')[0].split('#')[0];
            const lastDot = cleaned.lastIndexOf('.');
            if (lastDot === -1) return null;
            return cleaned.substring(lastDot).toLowerCase();
        } catch (e) { return null; }
    }

    function isExternalLib(src) {
        if (!src) return false;
        src = src.trim();
        if (src.startsWith('http') || src.startsWith('//')) return true;
        if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/|$)/.test(src) && !src.startsWith('.') && !src.startsWith('/')) {
            return true;
        }
        return false;
    }

    function addUrlToDomainMap(map, url) {
        if (!url) return;
        url = url.trim();
        let domain = "Relative/Local Paths";
        let formattedUrl = url;

        if (url.startsWith('//')) {
            formattedUrl = 'http:' + url;
        }

        if (formattedUrl.startsWith('http') || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/|$)/.test(formattedUrl)) {
            if (!formattedUrl.startsWith('http')) {
                formattedUrl = 'http://' + formattedUrl;
            }
            try {
                const urlObj = new URL(formattedUrl);
                domain = urlObj.hostname;
            } catch (e) {
                domain = "Unknown/Invalid";
            }
        }

        if (!map[domain]) {
            map[domain] = new Set();
        }
        map[domain].add(url);
    }

    // 1. Extract Links
    const linksByDomain = {};
    const linkRegex = /(?:href|src)\s*=\s*(?:["']([^"'>]+)["']|([^"'>\s]+))/gi;
    let match;
    while ((match = linkRegex.exec(sourceCode)) !== null) {
        let url = match[1] || match[2];
        if (url) addUrlToDomainMap(linksByDomain, url);
    }

    // 2. Extract External Libraries
    const libsByDomain = {};
    const scriptRegex = /<script[^>]+src\s*=\s*(?:["']([^"'>]+)["']|([^"'>\s]+))[^>]*>/gi;
    while ((match = scriptRegex.exec(sourceCode)) !== null) {
        let url = match[1] || match[2];
        if (isExternalLib(url)) {
            addUrlToDomainMap(libsByDomain, url);
        }
    }
    const linkTagRegex = /<link[^>]+>/gi;
    while ((match = linkTagRegex.exec(sourceCode)) !== null) {
        let tag = match[0];
        if (/rel\s*=\s*["']stylesheet["']/i.test(tag)) {
            let hrefMatch = /(?:href)\s*=\s*(?:["']([^"'>]+)["']|([^"'>\s]+))/i.exec(tag);
            if (hrefMatch) {
                let url = hrefMatch[1] || hrefMatch[2];
                if (isExternalLib(url)) {
                    addUrlToDomainMap(libsByDomain, url);
                }
            }
        }
    }

    // 3. Suspicious JS Patterns (expanded)
    const suspiciousFound = [];
    const suspiciousPatterns = [
        { name: "eval() execution", regex: /\beval\s*\(/g },
        { name: "document.write() DOM manipulation", regex: /\bdocument\.write\s*\(/g },
        { name: "atob() Base64 decoding", regex: /\batob\s*\(/g },
        { name: "btoa() Base64 encoding", regex: /\bbtoa\s*\(/g },
        { name: "unescape() usage", regex: /\bunescape\s*\(/g },
        { name: "fetch() network call", regex: /\bfetch\s*\(/g },
        { name: "String.fromCharCode() obfuscation", regex: /\bString\.fromCharCode\s*\(/g },
        { name: "setTimeout with string evaluation", regex: /\bsetTimeout\s*\(\s*["']/g },
        { name: "Hex/Unicode obfuscation (\\x or \\u)", regex: /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g },
        // Windows/ActiveX malicious patterns
        { name: "ActiveXObject reference", regex: /ActiveXObject/g },
        { name: "WScript.Shell", regex: /WScript\.Shell/g },
        { name: "Shell.Application", regex: /Shell\.Application/g },
        { name: "Scripting.FileSystemObject", regex: /Scripting\.FileSystemObject/g },
        { name: "MSXML2.XMLHTTP", regex: /MSXML2\.XMLHTTP/g },
        { name: "ADODB.Stream", regex: /ADODB\.Stream/g },
        { name: 'GetObject("script:...', regex: /GetObject\s*\(\s*["']script:/g },
        { name: "new ActiveXObject", regex: /new\s+ActiveXObject/g },
    ];

    for (const { name, regex } of suspiciousPatterns) {
        const matches = sourceCode.match(regex);
        if (matches) {
            suspiciousFound.push(`${name} — ${matches.length} instance(s)`);
        }
    }

    // 4. Element Summary: <iframe>, <script>, <form>
    const elementSummary = [];

    // Iframes
    const iframeRegex = /<iframe[^>]*>/gi;
    const iframes = [];
    while ((match = iframeRegex.exec(sourceCode)) !== null) {
        const srcMatch = /src\s*=\s*["']([^"']+)["']/i.exec(match[0]);
        iframes.push(srcMatch ? srcMatch[1] : '(no src attribute)');
    }
    if (iframes.length > 0) {
        elementSummary.push(`<iframe> — ${iframes.length} instance(s):`);
        iframes.forEach(src => elementSummary.push(`  ↳ ${src}`));
    }

    // Scripts
    const scriptTagRegex = /<script[^>]*>/gi;
    let inlineScripts = 0, externalScripts = 0;
    const scriptSrcs = [];
    while ((match = scriptTagRegex.exec(sourceCode)) !== null) {
        const srcMatch = /src\s*=\s*["']([^"']+)["']/i.exec(match[0]);
        if (srcMatch) {
            externalScripts++;
            scriptSrcs.push(srcMatch[1]);
        } else {
            inlineScripts++;
        }
    }
    if (inlineScripts + externalScripts > 0) {
        elementSummary.push(`<script> — ${inlineScripts + externalScripts} total (${inlineScripts} inline, ${externalScripts} external)`);
        scriptSrcs.forEach(src => elementSummary.push(`  ↳ ${src}`));
    }

    // Forms
    const formRegex = /<form[^>]*>/gi;
    const forms = [];
    while ((match = formRegex.exec(sourceCode)) !== null) {
        const actionMatch = /action\s*=\s*["']([^"']+)["']/i.exec(match[0]);
        const methodMatch = /method\s*=\s*["']([^"']+)["']/i.exec(match[0]);
        const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
        forms.push(actionMatch ? `${method} → ${actionMatch[1]}` : `${method} → (no action attribute)`);
    }
    if (forms.length > 0) {
        elementSummary.push(`<form> — ${forms.length} instance(s):`);
        forms.forEach(f => elementSummary.push(`  ↳ ${f}`));
    }

    // 5. Suspicious File Extensions
    const suspiciousExtFiles = [];
    const allUrls = [];
    const allUrlRegex = /(?:href|src|action)\s*=\s*(?:["']([^"'>]+)["']|([^"'>\s]+))/gi;
    while ((match = allUrlRegex.exec(sourceCode)) !== null) {
        const u = match[1] || match[2];
        if (u) allUrls.push(u);
    }
    for (const u of allUrls) {
        const ext = getExtension(u);
        if (ext && SUSPICIOUS_EXTENSIONS.has(ext)) {
            suspiciousExtFiles.push(`${ext} → ${u}`);
        }
    }

    // 6. Mark known vs unknown domains in link output
    const unknownDomains = {};
    const knownDomains = {};
    for (const [domain, urls] of Object.entries(linksByDomain)) {
        if (domain === 'Relative/Local Paths' || domain === 'Unknown/Invalid') {
            unknownDomains[domain] = urls;
        } else if (isKnownDomain(domain)) {
            knownDomains[domain] = urls;
        } else {
            unknownDomains[domain] = urls;
        }
    }

    // Mark known vs unknown libs
    const unknownLibs = {};
    const knownLibs = {};
    for (const [domain, urls] of Object.entries(libsByDomain)) {
        const firstUrl = [...urls][0];
        if (isKnownLib(firstUrl) || isKnownDomain(domain)) {
            knownLibs[domain] = urls;
        } else {
            unknownLibs[domain] = urls;
        }
    }

    // Build Output
    outputContainer.innerHTML = '';

    function createToggleCard(title, items, isAlert = false) {
        const card = document.createElement('details');
        card.style.marginBottom = '0';
        card.open = isAlert && items.length > 0;

        const summary = document.createElement('summary');
        summary.textContent = `${title} (${items.length})`;
        if (isAlert && items.length > 0) {
            summary.style.color = 'var(--threat-red)';
        }
        card.appendChild(summary);

        const contentDiv = document.createElement('div');
        contentDiv.style.marginTop = 'var(--sp-3)';

        if (items.length === 0) {
            contentDiv.textContent = "None detected.";
            contentDiv.style.color = 'var(--ops-text-dim)';
            contentDiv.style.fontSize = '13px';
        } else {
            const list = document.createElement('ul');
            list.style.margin = '0';
            list.style.paddingLeft = 'var(--sp-5)';
            list.style.color = 'var(--ops-text)';
            list.style.wordBreak = 'break-all';
            list.style.fontSize = '13px';
            list.style.lineHeight = '1.8';

            items.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                // Indent sub-items
                if (item.startsWith('  ↳')) {
                    li.style.paddingLeft = 'var(--sp-4)';
                    li.style.color = 'var(--ops-text-muted)';
                    li.style.fontSize = '12px';
                }
                list.appendChild(li);
            });
            contentDiv.appendChild(list);
        }

        card.appendChild(contentDiv);
        return card;
    }

    function createGroupedToggleCard(title, mappedItems, dimMapped = null) {
        let totalItems = 0;
        Object.values(mappedItems).forEach(set => totalItems += set.size);
        let dimTotal = 0;
        if (dimMapped) Object.values(dimMapped).forEach(set => dimTotal += set.size);

        const card = document.createElement('details');
        card.style.marginBottom = '0';

        const summary = document.createElement('summary');
        summary.textContent = dimMapped
            ? `${title} (${totalItems} unknown, ${dimTotal} known)`
            : `${title} (${totalItems})`;
        card.appendChild(summary);

        const contentDiv = document.createElement('div');
        contentDiv.style.marginTop = 'var(--sp-3)';

        const totalCombined = totalItems + dimTotal;
        if (totalCombined === 0) {
            contentDiv.textContent = "None detected.";
            contentDiv.style.color = 'var(--ops-text-dim)';
            contentDiv.style.fontSize = '13px';
        } else {
            // Unknown/interesting domains first
            const sortedDomains = Object.keys(mappedItems).sort();
            sortedDomains.forEach(domain => {
                const domainSet = mappedItems[domain];
                const dDetails = document.createElement('details');
                dDetails.style.marginTop = 'var(--sp-2)';
                dDetails.style.marginLeft = 'var(--sp-3)';
                dDetails.style.background = 'transparent';
                dDetails.style.border = 'none';
                dDetails.style.padding = '0';

                const dSummary = document.createElement('summary');
                dSummary.textContent = `${domain} (${domainSet.size})`;
                dSummary.style.color = 'var(--ops-text)';
                dSummary.style.fontSize = '13px';
                dDetails.appendChild(dSummary);

                const list = document.createElement('ul');
                list.style.margin = 'var(--sp-1) 0 var(--sp-2) 0';
                list.style.paddingLeft = 'var(--sp-5)';
                list.style.color = 'var(--ops-text-muted)';
                list.style.wordBreak = 'break-all';
                list.style.fontSize = '12px';
                list.style.lineHeight = '1.8';

                domainSet.forEach(item => {
                    const li = document.createElement('li');
                    li.textContent = item;
                    list.appendChild(li);
                });

                dDetails.appendChild(list);
                contentDiv.appendChild(dDetails);
            });

            // Known/whitelisted domains (dimmed)
            if (dimMapped && Object.keys(dimMapped).length > 0) {
                const knownSection = document.createElement('details');
                knownSection.style.marginTop = 'var(--sp-3)';
                knownSection.style.marginLeft = 'var(--sp-3)';
                knownSection.style.background = 'transparent';
                knownSection.style.border = 'none';
                knownSection.style.padding = '0';
                knownSection.style.opacity = '0.5';

                const knownSummary = document.createElement('summary');
                knownSummary.textContent = `✓ Known/Whitelisted Domains (${dimTotal})`;
                knownSummary.style.color = 'var(--threat-green)';
                knownSummary.style.fontSize = '12px';
                knownSection.appendChild(knownSummary);

                const sortedKnown = Object.keys(dimMapped).sort();
                sortedKnown.forEach(domain => {
                    const domainSet = dimMapped[domain];
                    const dDetails = document.createElement('details');
                    dDetails.style.marginTop = 'var(--sp-1)';
                    dDetails.style.marginLeft = 'var(--sp-3)';
                    dDetails.style.background = 'transparent';
                    dDetails.style.border = 'none';
                    dDetails.style.padding = '0';

                    const dSummary = document.createElement('summary');
                    dSummary.textContent = `${domain} (${domainSet.size})`;
                    dSummary.style.color = 'var(--ops-text-dim)';
                    dSummary.style.fontSize = '12px';
                    dDetails.appendChild(dSummary);

                    const list = document.createElement('ul');
                    list.style.margin = 'var(--sp-1) 0';
                    list.style.paddingLeft = 'var(--sp-5)';
                    list.style.color = 'var(--ops-text-ghost)';
                    list.style.wordBreak = 'break-all';
                    list.style.fontSize = '11px';
                    list.style.lineHeight = '1.6';

                    domainSet.forEach(item => {
                        const li = document.createElement('li');
                        li.textContent = item;
                        list.appendChild(li);
                    });

                    dDetails.appendChild(list);
                    knownSection.appendChild(dDetails);
                });

                contentDiv.appendChild(knownSection);
            }
        }

        card.appendChild(contentDiv);
        return card;
    }

    const alertsCard = createToggleCard("🚨 Suspicious JS Patterns", suspiciousFound, true);
    const extCard = createToggleCard("⚠️ Suspicious File Extensions", suspiciousExtFiles, true);
    const elemCard = createToggleCard("📋 Element Summary (iframe/script/form)", elementSummary, false);
    const libsCard = createGroupedToggleCard("📦 External Libraries & Scripts", unknownLibs, knownLibs);
    const linksCard = createGroupedToggleCard("🔗 All Extracted Links (href/src)", unknownDomains, knownDomains);

    outputContainer.appendChild(alertsCard);
    outputContainer.appendChild(extCard);
    outputContainer.appendChild(elemCard);
    outputContainer.appendChild(libsCard);
    outputContainer.appendChild(linksCard);

    showToast('Analysis complete', 'success');
}
