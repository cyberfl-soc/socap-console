// ---------- Header to Curl ---------- //
const h2cTab = document.getElementById("h2cTab");

// Header
const h2cHeader = document.createElement('h2');
h2cHeader.textContent = 'Header to Curl';
h2cTab.appendChild(h2cHeader);

const h2cDesc = document.createElement('p');
h2cDesc.className = 'tab-desc';
h2cDesc.textContent = 'Paste a raw HTTP request (from browser DevTools, Burp, etc.) to convert it into a curl command.';
h2cTab.appendChild(h2cDesc);

// Input Label
const h2cInputLabel = document.createElement('label');
h2cInputLabel.textContent = 'Raw HTTP Request';
h2cTab.appendChild(h2cInputLabel);

// Input Textarea
const h2cInput = document.createElement('textarea');
h2cInput.id = 'h2cInput';
h2cInput.placeholder = 'GET /path HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n...';
h2cInput.style.height = '250px';
h2cTab.appendChild(h2cInput);

// Convert Button
const convertBtn = document.createElement('button');
convertBtn.className = 'action-button';
convertBtn.textContent = 'Convert to Curl';
convertBtn.style.marginTop = 'var(--sp-2)';
convertBtn.onclick = runH2C;
h2cTab.appendChild(convertBtn);

// Output Card
const h2cOutputCard = document.createElement('div');
h2cOutputCard.className = 'ops-card';
h2cOutputCard.style.marginTop = 'var(--sp-4)';

const h2cOutputHeader = document.createElement('div');
h2cOutputHeader.style.display = 'flex';
h2cOutputHeader.style.justifyContent = 'space-between';
h2cOutputHeader.style.alignItems = 'center';
h2cOutputHeader.style.marginBottom = 'var(--sp-2)';

const h2cOutputTitle = document.createElement('h4');
h2cOutputTitle.textContent = 'Curl Command';
h2cOutputTitle.style.margin = '0';

const h2cCopyBtn = document.createElement('button');
h2cCopyBtn.className = 'action-button secondary';
h2cCopyBtn.textContent = 'Copy';
h2cCopyBtn.style.padding = 'var(--sp-1) var(--sp-3)';
h2cCopyBtn.style.fontSize = '11px';
h2cCopyBtn.onclick = () => copyToClipboard(h2cOutput.value, h2cCopyBtn);

h2cOutputHeader.appendChild(h2cOutputTitle);
h2cOutputHeader.appendChild(h2cCopyBtn);
h2cOutputCard.appendChild(h2cOutputHeader);

const h2cOutput = document.createElement('textarea');
h2cOutput.id = 'h2cOutput';
h2cOutput.placeholder = 'Curl command output...';
h2cOutput.readOnly = true;
h2cOutput.style.background = 'var(--ops-inset)';
h2cOutput.style.marginBottom = '0';
h2cOutputCard.appendChild(h2cOutput);

h2cTab.appendChild(h2cOutputCard);

// ---------- Logic ---------- //
function runH2C() {
  const raw = h2cInput.value.trim();
  if (!raw) return;

  const lines = raw.split('\n');
  if (lines.length === 0) return;

  // content separator
  let bodyStartIndex = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === '') {
      bodyStartIndex = i;
      break;
    }
  }

  const headerLines = bodyStartIndex === -1 ? lines : lines.slice(0, bodyStartIndex);
  const body = bodyStartIndex === -1 ? '' : lines.slice(bodyStartIndex + 1).join('\n');

  const requestLineStr = headerLines[0].trim();
  const requestLine = requestLineStr.match(/^([A-Z]+)\s+(.+?)\s+(HTTP\/\d(?:\.\d)?)$/i);
  if (!requestLine) {
    h2cOutput.value = "Error: Invalid Request Line.\nExpected format: GET /path HTTP/1.1";
    showToast('Invalid request line', 'error');
    return;
  }
  const method = requestLine[1].toUpperCase();
  const path = requestLine[2];

  let host = '';
  const headers = [];

  for (let i = 1; i < headerLines.length; i++) {
    const line = headerLines[i].trim();
    if (!line) continue;

    if (line.toLowerCase().startsWith('host:')) {
      host = line.substring(5).trim();
    }
    headers.push(line);
  }

  let finalUrl = '';
  if (path.startsWith('http://') || path.startsWith('https://')) {
    finalUrl = path;
  } else if (host) {
    const inferredScheme = host.includes(':443') ? 'https://' : 'http://';
    finalUrl = host.startsWith('http') ? `${host}${path}` : `${inferredScheme}${host}${path}`;
  } else {
    h2cOutput.value = "Error: No Host header found and path is not an absolute URL.";
    showToast('Missing Host header', 'error');
    return;
  }

  // Construct Curl
  let curl = `curl -X ${method} "${finalUrl}"`;

  headers.forEach(h => {
    curl += ` \\\n -H "${h.replace(/"/g, '\\"')}"`;
  });

  if (body) {
    curl += ` \\\n -d '${body.replace(/'/g, "'\\''")}'`;
  }

  h2cOutput.value = curl;
  showToast('Converted to curl', 'success');
}