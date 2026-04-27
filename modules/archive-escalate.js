// ═══════════════════════════════════════════════════════════════
//   Archive & Escalate
//
//   Two sub-tabs:
//     ARCHIVE  — rich-content editor (paste the finished ticket
//                + screenshots), package into <Name>.docx inside
//                <Name>/ folder, then download as a zip.
//
//     ESCALATE — quick IT-team summary. Pixel generates a short
//                paragraph with findings + recommendations. If
//                Pixel is offline, a deterministic fallback
//                template is used instead.
// ═══════════════════════════════════════════════════════════════

(function initArchiveEscalate() {

const archiveTab = document.getElementById('archiveEscalateTab');
if (!archiveTab) {
  console.error('[Archive&Escalate] target div #archiveEscalateTab not found — module disabled');
  return;
}

// Libs loaded lazily (CDN script tags injected on first export)
let _docxLib = null;
let _jszipLib = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[src="${src}"]`);
    if (existing) { existing.addEventListener('load', resolve); existing.addEventListener('error', reject); return; }
    const s = document.createElement('script');
    s.src = src; s.onload = resolve; s.onerror = reject;
    document.head.appendChild(s);
  });
}

async function loadDocx() {
  if (_docxLib) return _docxLib;
  await loadScript('https://cdn.jsdelivr.net/npm/docx@8.5.0/build/index.umd.min.js');
  _docxLib = window.docx;
  return _docxLib;
}
async function loadJSZip() {
  if (_jszipLib) return _jszipLib;
  await loadScript('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js');
  _jszipLib = window.JSZip;
  return _jszipLib;
}

// ─── Header ──────────────────────────────────────────────────
const aeHeader = document.createElement('h2');
aeHeader.textContent = 'Archive & Escalate';
archiveTab.appendChild(aeHeader);

const aeDesc = document.createElement('p');
aeDesc.className = 'tab-desc';
aeDesc.textContent = 'Finalize a closed ticket into a Word document + folder (Archive), or send a quick summary with recommendations to the IT team (Escalate).';
archiveTab.appendChild(aeDesc);

// ═════════════════════════════════════════════════════════════
//   ARCHIVE PANE
// ═════════════════════════════════════════════════════════════
const archiveSection = document.createElement('h3');
archiveSection.className = 'ae-section-title';
archiveSection.innerHTML = '📦 Archive';
archiveTab.appendChild(archiveSection);

const archivePane = document.createElement('div');
archivePane.id = 'archiveSub';
archivePane.className = 'ae-pane';
archiveTab.appendChild(archivePane);

// Name input row
const nameRow = document.createElement('div');
nameRow.style.cssText = 'display:flex;gap:var(--sp-3);align-items:flex-end;margin-bottom:var(--sp-4);flex-wrap:wrap;';

const nameWrap = document.createElement('div');
nameWrap.style.cssText = 'flex:1;min-width:260px;';
const nameLabel = document.createElement('label');
nameLabel.textContent = 'Archive name (used for folder + .docx)';
nameLabel.style.cssText = 'display:block;margin-bottom:var(--sp-1);';
const nameInput = document.createElement('input');
nameInput.type = 'text';
nameInput.id = 'archiveName';
nameInput.placeholder = 'e.g. INC-2026-0421-flickystream';
nameInput.style.cssText = 'width:100%;margin:0;';
nameInput.value = '';
nameWrap.appendChild(nameLabel);
nameWrap.appendChild(nameInput);
nameRow.appendChild(nameWrap);

const nameHint = document.createElement('span');
nameHint.style.cssText = 'font-size:11px;color:var(--ops-text-dim);flex-basis:100%;margin-top:-4px;';
nameHint.textContent = 'Exports <name>.zip containing <name>/<name>.docx';
nameRow.appendChild(nameHint);

archivePane.appendChild(nameRow);

// Fill-from-ticket shortcut
const fillRow = document.createElement('div');
fillRow.style.cssText = 'display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3);flex-wrap:wrap;align-items:center;';
const fillTicketBtn = document.createElement('button');
fillTicketBtn.className = 'action-button secondary';
fillTicketBtn.style.cssText = 'padding:4px 12px;font-size:12px;';
fillTicketBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:3px;"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Load current ticket`;
fillTicketBtn.title = 'Copy the Generated Ticket text into the archive editor';
fillTicketBtn.onclick = () => {
  const ticketEl = document.getElementById('output');
  const text = ticketEl?.value || '';
  if (!text) { showToast('No ticket text to load', 'error'); return; }
  // Insert text as a <pre>-ish preformatted block so line breaks are preserved
  const block = document.createElement('pre');
  block.className = 'archive-text-block';
  block.textContent = text;
  archiveEditor.appendChild(block);
  archiveEditor.scrollTop = archiveEditor.scrollHeight;
  showToast('Ticket text loaded into archive', 'success');
};

const addImagesBtn = document.createElement('button');
addImagesBtn.className = 'action-button secondary';
addImagesBtn.style.cssText = 'padding:4px 12px;font-size:12px;';
addImagesBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:3px;"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>Add Images`;
addImagesBtn.title = 'Attach one or more screenshot images';
const imageFileInput = document.createElement('input');
imageFileInput.type = 'file';
imageFileInput.accept = 'image/*';
imageFileInput.multiple = true;
imageFileInput.style.display = 'none';
addImagesBtn.onclick = () => imageFileInput.click();
imageFileInput.onchange = () => {
  Array.from(imageFileInput.files).forEach(addImageToEditor);
  imageFileInput.value = '';
};

const archiveClearBtn = document.createElement('button');
archiveClearBtn.className = 'action-button secondary';
archiveClearBtn.style.cssText = 'padding:4px 12px;font-size:12px;';
archiveClearBtn.textContent = 'Clear';
archiveClearBtn.onclick = () => {
  archiveEditor.innerHTML = '';
  showToast('Archive editor cleared', 'success');
};

const exportBtn = document.createElement('button');
exportBtn.className = 'action-button';
exportBtn.style.cssText = 'padding:4px 14px;font-size:12px;margin-left:auto;';
exportBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:4px;"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Export .zip`;
exportBtn.onclick = () => exportArchive();

fillRow.appendChild(fillTicketBtn);
fillRow.appendChild(addImagesBtn);
fillRow.appendChild(imageFileInput);
fillRow.appendChild(archiveClearBtn);
fillRow.appendChild(exportBtn);
archivePane.appendChild(fillRow);

// Editor surface — contenteditable so analysts can freely arrange text + images
const editorLabel = document.createElement('label');
editorLabel.textContent = 'Content — paste text or drag images here';
editorLabel.style.cssText = 'display:block;margin-bottom:var(--sp-2);';
archivePane.appendChild(editorLabel);

const archiveEditor = document.createElement('div');
archiveEditor.id = 'archiveEditor';
archiveEditor.contentEditable = 'true';
archiveEditor.spellcheck = false;
archiveEditor.style.cssText = `
  min-height:400px; max-height:600px; overflow-y:auto;
  padding:var(--sp-4);
  background:var(--ops-inset); color:var(--ops-text);
  border:1px solid var(--ops-border-med); border-radius:var(--radius-md);
  font-family:'Inter',sans-serif; font-size:13px; line-height:1.55;
`;
archiveEditor.dataset.placeholder = 'Paste the finalized ticket text, drag in screenshots, or click "Load current ticket" above…';
archivePane.appendChild(archiveEditor);

// Custom placeholder styling via inline CSS (since :empty + attr()-based placeholder needs it)
const archStyle = document.createElement('style');
archStyle.textContent = `
  #archiveEditor:empty::before {
    content: attr(data-placeholder);
    color: var(--ops-text-ghost);
    font-style: italic;
  }
  #archiveEditor img {
    max-width: 100%; height: auto;
    border: 1px solid var(--ops-border-med);
    border-radius: var(--radius-sm);
    margin: var(--sp-2) 0; display: block;
  }
  #archiveEditor .archive-img-placeholder {
    margin: var(--sp-2) 0;
    padding: var(--sp-3);
    border: 1px dashed var(--ops-border-med);
    border-radius: var(--radius-sm);
    background: var(--ops-inset);
    color: var(--ops-text-dim);
    font-size: 11px; font-style: italic;
    text-align: center;
  }
  #archiveEditor pre.archive-text-block {
    font-family: 'Fira Code', monospace;
    font-size: 12px; line-height: 1.55;
    white-space: pre-wrap; word-break: break-word;
    background: var(--ops-bg);
    border: 1px solid var(--ops-border);
    border-radius: var(--radius-sm);
    padding: var(--sp-3);
    margin: var(--sp-2) 0;
    color: var(--ops-text);
  }
  .ae-pane { display: block; animation: fadeIn 200ms ease-out; margin-bottom: var(--sp-4); }
  .ae-section-title {
    display: flex; align-items: center; gap: var(--sp-2);
    font-size: 15px; font-weight: 600;
    color: var(--ops-text);
    margin: var(--sp-5) 0 var(--sp-3) 0;
    padding-bottom: var(--sp-2);
    border-bottom: 1px solid var(--ops-border);
    letter-spacing: 0.01em;
  }
  .ae-section-title:first-of-type { margin-top: var(--sp-3); }
  .ae-divider {
    border: none; border-top: 1px dashed var(--ops-border);
    margin: var(--sp-6) 0 0 0;
  }
`;
document.head.appendChild(archStyle);

// Paste handler — capture images from clipboard paste (Ctrl+V from screenshot tools)
// Paste handler — preserves the order of text + images when both are on clipboard.
//
// The key insight: image URLs (blob:, http:, or empty src with a matching
// image file in clipboardData.items) need an async fetch to resolve, but we
// can't `await` inside a tree walk without losing document order. So we do
// this in two synchronous passes:
//
//   Pass 1: Walk the HTML synchronously. For each <img>, immediately append
//           a PLACEHOLDER <div> into the editor, reserving its position in
//           the order. For text, emit a <pre> block inline.
//
//   Pass 2: Asynchronously resolve every placeholder:
//             - If img.src works (data:/fetchable blob:/http:), fetch it
//               and replace the placeholder with the <img> element.
//             - Otherwise, consume the next available image-file from the
//               clipboard items array (Outlook/Office often drops raw image
//               data in items[] while leaving <img src=""> in the HTML).
//             - If we still can't resolve, remove the placeholder.
//
// After pass 2, any image files in items[] that weren't matched to an <img>
// tag are appended at the end (covers screenshot tools that put an image on
// the clipboard alongside unrelated text).
archiveEditor.addEventListener('paste', async (e) => {
  const cd = e.clipboardData;
  if (!cd) return;
  e.preventDefault();

  const html  = cd.getData('text/html');
  const plain = cd.getData('text/plain');

  // Grab any raw image files from the clipboard items (order preserved)
  const clipImageFiles = [];
  for (const item of cd.items || []) {
    if (item.type.startsWith('image/')) {
      const f = item.getAsFile();
      if (f) clipImageFiles.push(f);
    }
  }

  // Path A: HTML clipboard (typical when copying from Word / Outlook / browsers)
  if (html && html.trim()) {
    const doc = new DOMParser().parseFromString(html, 'text/html');

    // Pass 1 — SYNCHRONOUS walk. Emit placeholders in visual order.
    const placeholders = [];  // [{ el, src }]
    let textBuf = '';

    const flushText = () => {
      const cleaned = textBuf.replace(/\u00a0/g, ' ').replace(/\n{3,}/g, '\n\n');
      if (cleaned.trim()) {
        const block = document.createElement('pre');
        block.className = 'archive-text-block';
        block.textContent = cleaned.replace(/^\n+|\n+$/g, '');
        archiveEditor.appendChild(block);
      }
      textBuf = '';
    };

    const walk = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === Node.TEXT_NODE) {
          textBuf += child.textContent;
        } else if (child.nodeType === Node.ELEMENT_NODE) {
          const tag = child.tagName.toLowerCase();
          if (tag === 'img') {
            flushText();
            const el = document.createElement('div');
            el.className = 'archive-img-placeholder';
            el.textContent = '⏳ loading image…';
            archiveEditor.appendChild(el);
            placeholders.push({ el, src: child.getAttribute('src') || '' });
          } else if (tag === 'br') {
            textBuf += '\n';
          } else if (tag === 'p' || tag === 'div' || tag === 'tr' || tag === 'li' || tag === 'h1' || tag === 'h2' || tag === 'h3') {
            textBuf += '\n';
            walk(child);
            textBuf += '\n';
          } else if (tag === 'script' || tag === 'style' || tag === 'meta' || tag === 'link') {
            // skip
          } else {
            walk(child);
          }
        }
      }
    };
    walk(doc.body);
    flushText();

    // Pass 2 — Resolve placeholders asynchronously, in parallel, but each
    // one updates only its own <div> so visual order is preserved.
    let clipIdx = 0;
    await Promise.all(placeholders.map(async (p) => {
      let file = null;
      if (p.src) {
        file = await fileFromSrc(p.src).catch(() => null);
      }
      if (!file && clipIdx < clipImageFiles.length) {
        // Fallback: consume the next raw image from the clipboard items
        file = clipImageFiles[clipIdx++];
      }
      if (!file) {
        p.el.remove();
        return;
      }
      await replacePlaceholderWithImage(p.el, file);
    }));

    // If the HTML had no <img> tags but the clipboard had raw image files
    // (e.g. "Copy as Image" then a paragraph pasted in), append leftovers.
    for (; clipIdx < clipImageFiles.length; clipIdx++) {
      addImageToEditor(clipImageFiles[clipIdx]);
    }

    archiveEditor.scrollTop = archiveEditor.scrollHeight;
    return;
  }

  // Path B: no HTML — plain text and/or loose image files
  if (plain && plain.trim()) {
    const block = document.createElement('pre');
    block.className = 'archive-text-block';
    block.textContent = plain;
    archiveEditor.appendChild(block);
  }
  for (const f of clipImageFiles) addImageToEditor(f);
  archiveEditor.scrollTop = archiveEditor.scrollHeight;
});

// Fetch an image from an arbitrary src (blob:, data:, or http[s]:) → File
async function fileFromSrc(src) {
  if (!src) throw new Error('empty src');
  if (src.startsWith('data:')) {
    const mime = (src.match(/^data:([^;]+);/) || [,'image/png'])[1];
    const b64 = src.split(',')[1];
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return new File([bytes], 'pasted.png', { type: mime });
  }
  const res = await fetch(src);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const blob = await res.blob();
  return new File([blob], 'pasted-image', { type: blob.type || 'image/png' });
}

// Read a File and replace the placeholder <div> with the actual <img> element
function replacePlaceholderWithImage(placeholder, file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = document.createElement('img');
      img.src = reader.result;
      img.alt = file.name || 'screenshot';
      img.dataset.mime = file.type || 'image/png';
      placeholder.replaceWith(img);
      resolve();
    };
    reader.onerror = () => { placeholder.remove(); resolve(); };
    reader.readAsDataURL(file);
  });
}

// Drag-and-drop for images
['dragover','drop'].forEach(evt => {
  archiveEditor.addEventListener(evt, (e) => { e.preventDefault(); });
});
archiveEditor.addEventListener('drop', (e) => {
  const files = Array.from(e.dataTransfer?.files || []);
  files.filter(f => f.type.startsWith('image/')).forEach(addImageToEditor);
});

function addImageToEditor(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const img = document.createElement('img');
    img.src = reader.result;
    img.alt = file.name || 'screenshot';
    img.dataset.mime = file.type || 'image/png';
    archiveEditor.appendChild(img);
    archiveEditor.scrollTop = archiveEditor.scrollHeight;
  };
  reader.readAsDataURL(file);
}

// ─── Export: build .docx, zip inside <name>/, download ──────
async function exportArchive() {
  const name = (nameInput.value || '').trim();
  if (!name) { showToast('Enter an archive name first', 'error'); nameInput.focus(); return; }
  if (!archiveEditor.textContent.trim() && !archiveEditor.querySelector('img')) {
    showToast('Archive is empty', 'error'); return;
  }

  // Sanitise name for filesystem safety
  const safeName = name.replace(/[<>:"/\\|?*\x00-\x1F]/g, '_').trim().slice(0, 80);

  exportBtn.disabled = true;
  const origHtml = exportBtn.innerHTML;
  exportBtn.innerHTML = 'Packaging…';

  try {
    const docxLib = await loadDocx();

    // Walk the editor and flatten into ordered nodes: text blocks + images
    const blocks = [];
    for (const child of archiveEditor.children) {
      if (child.tagName === 'IMG') {
        const dataUrl = child.src;
        if (!dataUrl.startsWith('data:')) continue;
        const b64 = dataUrl.split(',')[1];
        const mime = (dataUrl.match(/^data:([^;]+);/) || [,'image/png'])[1];
        const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        blocks.push({ kind:'image', data: bin, mime });
      } else {
        // Text-ish element
        const text = child.textContent || '';
        if (text.trim()) blocks.push({ kind:'text', text });
      }
    }
    // Also handle direct text nodes the user typed (no wrapping element)
    const directText = Array.from(archiveEditor.childNodes)
      .filter(n => n.nodeType === 3 && n.textContent.trim())
      .map(n => n.textContent).join('\n');
    if (directText.trim() && blocks.length === 0) {
      blocks.push({ kind:'text', text: directText });
    }

    // Build docx children
    const { Document, Packer, Paragraph, TextRun, ImageRun, AlignmentType } = docxLib;
    // Document body is exactly the pasted content — no title/header/timestamp.
    const children = [];

    for (const b of blocks) {
      if (b.kind === 'text') {
        // Split multi-line text into separate paragraphs so line breaks render
        const lines = b.text.split(/\r?\n/);
        for (const line of lines) {
          children.push(new Paragraph({
            children: [new TextRun({ text: line })],
          }));
        }
      } else {
        children.push(new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new ImageRun({
            data: b.data,
            transformation: { width: 540, height: 360 },
            type: b.mime.includes('png')  ? 'png'  :
                  b.mime.includes('jpeg') ? 'jpg'  :
                  b.mime.includes('gif')  ? 'gif'  :
                  b.mime.includes('bmp')  ? 'bmp'  : 'png',
          })],
        }));
        children.push(new Paragraph({ text: '' }));
      }
    }

    // If the editor was empty, write one blank paragraph so docx-lib is happy
    if (children.length === 0) children.push(new Paragraph({ text: '' }));

    const doc = new Document({ sections: [{ children }] });
    const docBlob = await Packer.toBlob(doc);

    // Zip <safeName>/<safeName>.docx and trigger a download
    const JSZipLib = await loadJSZip();
    const zip = new JSZipLib();
    zip.folder(safeName).file(`${safeName}.docx`, docBlob);
    const zipBlob = await zip.generateAsync({ type: 'blob' });

    const url = URL.createObjectURL(zipBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${safeName}.zip`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    showToast(`Archive packaged as ${safeName}.zip`, 'success');
  } catch (err) {
    console.error('[Archive] Export failed:', err);
    showToast(`Export failed: ${err.message || err}`, 'error');
  } finally {
    exportBtn.disabled = false;
    exportBtn.innerHTML = origHtml;
  }
}

// ═════════════════════════════════════════════════════════════
//   ESCALATE PANE
// ═════════════════════════════════════════════════════════════
const escalateDivider = document.createElement('hr');
escalateDivider.className = 'ae-divider';
archiveTab.appendChild(escalateDivider);

const escalateSection = document.createElement('h3');
escalateSection.className = 'ae-section-title';
escalateSection.innerHTML = '📣 Escalate';
archiveTab.appendChild(escalateSection);

const escalatePane = document.createElement('div');
escalatePane.id = 'escalateSub';
escalatePane.className = 'ae-pane';
archiveTab.appendChild(escalatePane);

const escDesc = document.createElement('p');
escDesc.style.cssText = 'font-size:12px;color:var(--ops-text-muted);margin-bottom:var(--sp-4);line-height:1.5;';
escDesc.innerHTML = 'Generate a concise summary for the IT team. Pixel writes a short paragraph with recommendations assuming USF\'s open network (contacting users via NetID, blocking domains/IPs). If Pixel is offline, a deterministic fallback template is used with the data from the Console.';
escalatePane.appendChild(escDesc);

const escBtnRow = document.createElement('div');
escBtnRow.style.cssText = 'display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3);flex-wrap:wrap;';

const escGenBtn = document.createElement('button');
escGenBtn.className = 'action-button';
escGenBtn.style.cssText = 'padding:4px 14px;font-size:12px;';
escGenBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:4px;"><path d="M12 2l2.39 7.36H22l-6.19 4.5L18.2 22 12 17.27 5.8 22l2.39-8.14L2 9.36h7.61z"/></svg>Ask Pixel`;

const escFallbackBtn = document.createElement('button');
escFallbackBtn.className = 'action-button secondary';
escFallbackBtn.style.cssText = 'padding:4px 14px;font-size:12px;';
escFallbackBtn.textContent = 'Use Fallback Template';
escFallbackBtn.title = 'Deterministic template — use when you don\'t need Pixel';

const escCopyBtn = document.createElement('button');
escCopyBtn.className = 'action-button secondary';
escCopyBtn.style.cssText = 'padding:4px 12px;font-size:12px;margin-left:auto;';
escCopyBtn.textContent = 'Copy';

escBtnRow.appendChild(escGenBtn);
escBtnRow.appendChild(escFallbackBtn);
escBtnRow.appendChild(escCopyBtn);
escalatePane.appendChild(escBtnRow);

const escStatus = document.createElement('div');
escStatus.style.cssText = 'font-size:11px;color:var(--ops-text-dim);font-family:"Fira Code",monospace;min-height:16px;margin-bottom:var(--sp-2);';
escalatePane.appendChild(escStatus);

const escOutput = document.createElement('textarea');
escOutput.id = 'escOutput';
escOutput.placeholder = 'Click "Ask Pixel" or "Use Fallback Template" to generate an escalation summary…';
escOutput.style.cssText = 'height:320px;font-family:"Fira Code",monospace;font-size:12px;line-height:1.55;';
escalatePane.appendChild(escOutput);

escCopyBtn.onclick = () => copyToClipboard(escOutput.value, escCopyBtn);

// ─── Extract context for escalation ──────────────────────────
function gatherEscalateContext() {
  const s = window.ticketState || {};
  const c = s.csv  || {};
  const m = s.msIsac || {};
  const k = s.kql  || {};

  // Destination remote IP for blocking recommendation
  const dstIps = [...(c.dstIps || [])].filter(ip =>
    ip && !ip.startsWith('131.247.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && ip.toLowerCase() !== 'null'
  );
  const remoteIp = m.dstIp || dstIps[0] || '';

  // Domains (undefanged so we can redefang for the output)
  const domainsRaw = [...(c.domains || [])].map(d => d.replace(/\[\.\]/g, '.'));
  const domains = [...new Set(domainsRaw)].filter(Boolean).slice(0, 6);

  // Description: prefer MS-ISAC then CSV signatures
  const description = (m.description && m.description.trim())
    || [...(c.descriptions || [])].filter(Boolean).join('; ')
    || '';

  return {
    netid:      (k.netid || '').trim(),
    mac:        (k.mac || '').trim(),
    hostname:   (k.deviceName || '').trim(),
    internalIp: (k.internalIp || '').trim(),
    description,
    remoteIp,
    domains,
    recommendations: (s.pixelRecommendations || '').trim(),
  };
}

function defangForEscalation(s) {
  if (!s) return s;
  // Defang domains (dot→[.])
  return s.replace(/\b([a-zA-Z0-9][a-zA-Z0-9-]{0,61}(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+)\b/g, (m) => {
    // Skip if looks like an IP
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(m)) return m;
    return m.replace(/\./g, '[.]');
  });
}

// ─── Fallback template (deterministic) ──────────────────────
// Produces a single concise paragraph (no line breaks) with an identity
// line, the ticket description, a short block-or-inform recommendation,
// and an OSINT rationale sentence.
function buildFallbackEscalation() {
  const ctx = gatherEscalateContext();

  // Identity: netid / [MAC] / [Hostname]
  const idParts = [
    ctx.netid    || 'somebody@usf.edu',
    ctx.mac      ? `[${ctx.mac}]`      : '[MAC address]',
    ctx.hostname ? `[${ctx.hostname}]` : '[Hostname]',
  ].join(' / ');

  const desc = ctx.description || '[extracted Ticket Description]';

  // Choose the phrasing based on what we have
  const hasIp = !!ctx.remoteIp;
  const hasDomains = ctx.domains.length > 0;
  let blockTarget;
  if (hasIp && hasDomains) {
    const doms = ctx.domains.map(defangForEscalation).join(', ');
    blockTarget = `blocking the IP (${ctx.remoteIp}) and associated domains (${doms})`;
  } else if (hasIp) {
    blockTarget = `blocking the IP (${ctx.remoteIp})`;
  } else if (hasDomains) {
    const doms = ctx.domains.map(defangForEscalation).join(', ');
    blockTarget = `blocking the associated domains (${doms})`;
  } else {
    blockTarget = 'blocking the IP or domain';
  }

  // Pick three OSINT sources — prefer ones commonly used in the Console
  const sources = 'VirusTotal, AnyRun, and Shodan';

  return `${idParts} - ${desc} - We recommend informing the user of this activity on their device and ${blockTarget}. We have determined using various OSINT resources such as ${sources} that this activity is malicious.`;
}

// ─── LLM-generated summary via Pixel ────────────────────────
async function askPixelForEscalation() {
  const cfg = Object.assign({
    url: 'http://localhost:11434',
    model: 'llama3.2',
    timeoutMs: 60000,
  }, window.PIXEL_CONFIG || {});

  const ctx = gatherEscalateContext();

  escGenBtn.disabled = true;
  escFallbackBtn.disabled = true;
  escStatus.textContent = '● thinking…';
  escStatus.style.color = 'var(--intel-blue)';
  escOutput.value = '';

  const system =
`You are Pixel, a SOC analyst assistant writing a short escalation summary for the USF IT team. ` +
`USF's network is very open — it is TYPICAL to contact users via their NetID email and to block malicious domains/IPs. ` +
`Write ONE concise paragraph (3–5 sentences) using ONLY the provided evidence. Do NOT fabricate users, IPs, or hostnames. ` +
`Follow this structure:\n` +
`  <NetID or "the user"> / <MAC> / <Hostname> - <what happened> - We recommend informing <netid> of this activity on their device and blocking the IP (<ip>) and associated domains of: <space-separated defanged domain list>.\n` +
`  Then one more sentence describing the OSINT rationale (VirusTotal, AnyRun, Shodan, URLQuery if relevant).\n\n` +
`DEFANG all external domains and IPs (use [.] for dots). Do NOT defang usf.edu or internal IPs. Output ONLY the paragraph, no headers or commentary.`;

  const user = `Evidence from the ticket:\n${JSON.stringify(ctx, null, 2)}\n\nWrite the escalation paragraph now.`;

  const timeoutId = setTimeout(() => ctrl.abort('timeout'), cfg.timeoutMs);
  const ctrl = new AbortController();
  let fullText = '';

  try {
    const res = await fetch(`${cfg.url.replace(/\/+$/,'')}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.model,
        messages: [{ role:'system', content: system }, { role:'user', content: user }],
        stream: true,
      }),
      signal: ctrl.signal,
    });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream:true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const obj = JSON.parse(line);
          const token = obj.message?.content || '';
          if (token) {
            fullText += token;
            escOutput.value = fullText;
          }
          if (obj.error) throw new Error(obj.error);
        } catch { /* skip non-JSON */ }
      }
    }
    clearTimeout(timeoutId);
    escStatus.textContent = `✓ Generated by Pixel · ${cfg.model}`;
    escStatus.style.color = 'var(--threat-green)';
  } catch (err) {
    clearTimeout(timeoutId);
    console.warn('[Escalate] Pixel unreachable, using fallback:', err);
    escOutput.value = buildFallbackEscalation();
    escStatus.textContent = `⚠ Pixel offline (${err?.message || err}) — using fallback template`;
    escStatus.style.color = 'var(--threat-amber)';
  } finally {
    escGenBtn.disabled = false;
    escFallbackBtn.disabled = false;
  }
}

escGenBtn.addEventListener('click', askPixelForEscalation);
escFallbackBtn.addEventListener('click', () => {
  escOutput.value = buildFallbackEscalation();
  escStatus.textContent = '✓ Fallback template generated';
  escStatus.style.color = 'var(--ops-text-dim)';
});

})();
