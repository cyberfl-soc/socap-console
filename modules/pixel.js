// ═══════════════════════════════════════════════════════════════
//   PIXEL — floating LLM chat widget (Ollama backend)
// ═══════════════════════════════════════════════════════════════
//
//   Standalone floating chatbot. Attached to document.body so it
//   persists across tab switches. Three visibility states:
//     • OPEN      — full panel, pinned bottom-right
//     • MINIMIZED — small pill with avatar + name
//     • CLOSED    — hidden; reopen via the FAB (top-right of main)
//
//   Configuration lives on window.PIXEL_CONFIG (see index.html).
//   Requires window.ticketState (set by csv2ticket.js) for context.
//
//   Fallback: on network/CORS/timeout failure, the chat bubble shows
//   "Pixel's on vacation for the time being, sorry for the inconvenience!"
// ═══════════════════════════════════════════════════════════════

(function initPixel() {
  const PIXEL_DEFAULTS = {
    url: 'http://localhost:11434',
    model: 'llama3.2',
    timeoutMs: 60000,
    maxPromptChars: 12000,
  };
  const cfg = Object.assign({}, PIXEL_DEFAULTS, window.PIXEL_CONFIG || {});
  const FALLBACK_MSG = "Pixel's on vacation for the time being, sorry for the inconvenience!";

  // ─────────────────────────────────────────────────────────────
  //   Pixel's face — chunky CRT-head robot (Cyber Florida mascot)
  // ─────────────────────────────────────────────────────────────
  const PIXEL_ICON_SVG = `
<svg class="pixel-icon" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <line x1="17" y1="6" x2="13" y2="1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="31" y1="6" x2="35" y2="1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <circle cx="13" cy="1.5" r="1.6" fill="currentColor"/>
  <circle cx="35" cy="1.5" r="1.6" fill="currentColor"/>
  <rect x="6" y="7" width="36" height="28" rx="4" ry="4"
        fill="currentColor" fill-opacity="0.12"
        stroke="currentColor" stroke-width="2"/>
  <rect x="10" y="11" width="28" height="20" rx="2" ry="2"
        fill="currentColor" fill-opacity="0.18"/>
  <rect x="14" y="15" width="5" height="3" fill="currentColor"/>
  <rect x="14" y="15" width="3" height="6" fill="currentColor"/>
  <rect x="29" y="15" width="5" height="3" fill="currentColor"/>
  <rect x="31" y="15" width="3" height="6" fill="currentColor"/>
  <rect x="18" y="25" width="12" height="2.5" rx="1" fill="currentColor"/>
  <path d="M18 35 L22 41 L26 41 L30 35 Z"
        fill="currentColor" fill-opacity="0.12"
        stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
</svg>`.trim();

  // ─────────────────────────────────────────────────────────────
  //   SOFT DEFANG — only neuters likely IOCs, not every URL
  // ─────────────────────────────────────────────────────────────
  const BENIGN_DOMAINS = new Set([
    'microsoft.com','google.com','github.com','stackoverflow.com','wikipedia.org',
    'cloudflare.com','mozilla.org','apple.com','amazon.com','linkedin.com',
    'virustotal.com','abuseipdb.com','urlscan.io','shodan.io','censys.io',
    'whois.com','gchq.github.io','rules.evebox.org','recordedfuture.com',
    'anyrun.com','hybrid-analysis.com','joesandbox.com','otx.alienvault.com',
  ]);
  function isPrivateIp(a, b) {
    a = +a; b = +b;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 224 || a === 255) return true;
    // USF public IPv4 space — these are internal university endpoints, never IOCs
    if (a === 131 && b === 247) return true;
    return false;
  }
  function softDefang(str) {
    if (!str) return str;
    return str.replace(
      /(?:\b(?:https?|ftp):\/\/[^\s<>"']+)|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b)/g,
      (m) => {
        if (m.includes('[.]') || /hxxps?:\/\//i.test(m)) return m;
        const urlMatch = m.match(/^(https?|ftp):\/\/([^\/?#:]+)(.*)$/i);
        if (urlMatch) {
          const scheme = urlMatch[1].toLowerCase();
          const host = urlMatch[2].toLowerCase();
          const rest = urlMatch[3] || '';
          if (BENIGN_DOMAINS.has(host) || [...BENIGN_DOMAINS].some(d => host.endsWith('.' + d))) return m;
          if (/^(localhost|127\.|0\.|10\.|192\.168\.|131\.247\.)/.test(host)) return m;
          const defangedScheme = scheme === 'https' ? 'hxxps' : scheme === 'http' ? 'hxxp' : 'fxp';
          return `${defangedScheme}://${host.replace(/\./g, '[.]')}${rest}`;
        }
        const ipMatch = m.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (ipMatch) {
          if (isPrivateIp(ipMatch[1], ipMatch[2])) return m;
          return ipMatch.slice(1).join('[.]');
        }
        const dom = m.toLowerCase();
        if (BENIGN_DOMAINS.has(dom)) return m;
        if ([...BENIGN_DOMAINS].some(d => dom.endsWith('.' + d))) return m;
        const parts = m.split('.');
        if (parts.length < 2 || parts.some(p => !p)) return m;
        return m.replace(/\./g, '[.]');
      }
    );
  }

  // Domain-only variant: defangs domains and URL hosts (so IOCs are not
  // clickable), but leaves bare IP addresses intact. Used when applying
  // Pixel output to the ticket — IPs stay readable for whois lookups.
  function domainOnlyDefang(str) {
    if (!str) return str;
    return str.replace(
      /(?:\b(?:https?|ftp):\/\/[^\s<>"']+)|(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b)/g,
      (m) => {
        if (m.includes('[.]') || /hxxps?:\/\//i.test(m)) return m;
        const urlMatch = m.match(/^(https?|ftp):\/\/([^\/?#:]+)(.*)$/i);
        if (urlMatch) {
          const scheme = urlMatch[1].toLowerCase();
          const host = urlMatch[2].toLowerCase();
          const rest = urlMatch[3] || '';
          if (BENIGN_DOMAINS.has(host) || [...BENIGN_DOMAINS].some(d => host.endsWith('.' + d))) return m;
          if (/^(localhost|127\.|0\.|10\.|192\.168\.|131\.247\.)/.test(host)) return m;
          // If the host is a bare IP, keep it — but neuter the scheme so the
          // URL still won't be auto-linked.
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
            const defangedScheme = scheme === 'https' ? 'hxxps' : scheme === 'http' ? 'hxxp' : 'fxp';
            return `${defangedScheme}://${host}${rest}`;
          }
          const defangedScheme = scheme === 'https' ? 'hxxps' : scheme === 'http' ? 'hxxp' : 'fxp';
          return `${defangedScheme}://${host.replace(/\./g, '[.]')}${rest}`;
        }
        // Bare domain
        const dom = m.toLowerCase();
        if (BENIGN_DOMAINS.has(dom)) return m;
        if ([...BENIGN_DOMAINS].some(d => dom.endsWith('.' + d))) return m;
        const parts = m.split('.');
        if (parts.length < 2 || parts.some(p => !p)) return m;
        return m.replace(/\./g, '[.]');
      }
    );
  }

  // Expose in case other code wants them
  window.softDefang = softDefang;
  window.domainOnlyDefang = domainOnlyDefang;

  // ─────────────────────────────────────────────────────────────
  //   DOM construction — all attached to document.body
  // ─────────────────────────────────────────────────────────────

  // Floating chat panel
  const panel = document.createElement('div');
  panel.id = 'pixelPanel';
  panel.className = 'pixel-panel';
  panel.innerHTML = `
    <div class="pixel-panel-header">
      <button type="button" class="pixel-avatar" id="pixelAvatarBtn" title="Minimize">
        ${PIXEL_ICON_SVG}
      </button>
      <div class="pixel-title">
        <div class="pixel-name">Pixel</div>
        <div class="pixel-status" id="pixelStatus">● connecting…</div>
      </div>
      <button type="button" class="pixel-hdr-btn" id="pixelMinBtn" title="Minimize" aria-label="Minimize">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
             stroke-linecap="round"><line x1="5" y1="19" x2="19" y2="19"/></svg>
      </button>
      <button type="button" class="pixel-hdr-btn pixel-close" id="pixelCloseBtn" title="Close" aria-label="Close">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
             stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>

    <div class="pixel-chat" id="pixelChat"></div>

    <div class="pixel-toolbar">
      <button type="button" class="pixel-quick" data-preset="analyze">🔍 Analyze</button>
      <button type="button" class="pixel-quick" data-preset="recommend">💡 Recommend</button>
      <button type="button" class="pixel-quick" data-preset="both">📋 Full</button>
      <button type="button" class="pixel-apply" id="pixelApplyBtn" disabled
              title="Insert last structured response into the ticket">Apply to Ticket</button>
      <button type="button" class="pixel-clear" id="pixelClearBtn" title="Clear chat history">Clear</button>
    </div>

    <div class="pixel-input-row">
      <textarea class="pixel-input" id="pixelInput" rows="1"
                placeholder="Ask Pixel anything… (Enter to send, Shift+Enter for newline)"></textarea>
      <button type="button" class="pixel-send" id="pixelSendBtn" aria-label="Send">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="22" y1="2" x2="11" y2="13"/>
          <polygon points="22 2 15 22 11 13 2 9 22 2"/>
        </svg>
      </button>
    </div>
  `;
  document.body.appendChild(panel);

  // Minimized pill
  const pill = document.createElement('button');
  pill.id = 'pixelPill';
  pill.type = 'button';
  pill.className = 'pixel-pill';
  pill.title = 'Expand Pixel';
  pill.innerHTML = `<span class="pixel-pill-avatar">${PIXEL_ICON_SVG}</span><span class="pixel-pill-name">Pixel</span>`;
  document.body.appendChild(pill);

  // Floating reopen FAB (only appears when closed)
  const fab = document.createElement('button');
  fab.id = 'pixelFab';
  fab.type = 'button';
  fab.className = 'pixel-fab';
  fab.title = 'Open Pixel';
  fab.innerHTML = PIXEL_ICON_SVG;
  document.body.appendChild(fab);

  // Grab references
  const chatEl       = document.getElementById('pixelChat');
  const statusEl     = document.getElementById('pixelStatus');
  const inputEl      = document.getElementById('pixelInput');
  const sendBtn      = document.getElementById('pixelSendBtn');
  const applyBtn     = document.getElementById('pixelApplyBtn');
  const clearBtn     = document.getElementById('pixelClearBtn');
  const minBtn       = document.getElementById('pixelMinBtn');
  const closeBtn     = document.getElementById('pixelCloseBtn');
  const avatarBtn    = document.getElementById('pixelAvatarBtn');

  // ─────────────────────────────────────────────────────────────
  //   Visibility state machine — persisted across reloads
  // ─────────────────────────────────────────────────────────────
  const STATE_KEY = 'socap-pixel-state';
  const STATES = { OPEN: 'open', MIN: 'minimized', CLOSED: 'closed' };

  function applyState(state) {
    panel.classList.toggle('hidden', state !== STATES.OPEN);
    pill.classList.toggle('hidden',  state !== STATES.MIN);
    fab.classList.toggle('hidden',   state !== STATES.CLOSED);
    try { localStorage.setItem(STATE_KEY, state); } catch {}
    if (state === STATES.OPEN) {
      setTimeout(() => inputEl.focus(), 50);
      chatEl.scrollTop = chatEl.scrollHeight;
    }
  }

  // Initial state: default to open on first visit, otherwise whatever was saved
  let initial = STATES.OPEN;
  try {
    const saved = localStorage.getItem(STATE_KEY);
    if (saved && Object.values(STATES).includes(saved)) initial = saved;
  } catch {}
  applyState(initial);

  minBtn.addEventListener('click',  () => applyState(STATES.MIN));
  closeBtn.addEventListener('click', () => applyState(STATES.CLOSED));
  avatarBtn.addEventListener('click',() => applyState(STATES.MIN));
  pill.addEventListener('click',     () => applyState(STATES.OPEN));
  fab.addEventListener('click',      () => applyState(STATES.OPEN));

  // ─────────────────────────────────────────────────────────────
  //   Chat state + rendering
  // ─────────────────────────────────────────────────────────────
  let chatHistory = [];         // [{role, content}]
  let latestStructured = null;  // { analysis, recommendations }
  let abortCtrl = null;
  let appliedSnapshot = null;   // pre-apply { analysis, recommendations } for revert

  function setStatus(text, color = 'var(--ops-text-dim)') {
    statusEl.textContent = text;
    statusEl.style.color = color;
  }

  function setApplyButtonState(mode) {
    // mode: 'idle' | 'ready' | 'applied'
    if (mode === 'ready') {
      applyBtn.disabled = false;
      applyBtn.textContent = 'Apply to Ticket';
      applyBtn.classList.remove('pixel-apply-revert');
      applyBtn.title = "Insert Pixel's analysis + recommendations into the ticket";
    } else if (mode === 'applied') {
      applyBtn.disabled = false;
      applyBtn.textContent = 'Revert';
      applyBtn.classList.add('pixel-apply-revert');
      applyBtn.title = 'Restore the ticket to its state before Apply';
    } else {  // idle
      applyBtn.disabled = true;
      applyBtn.textContent = 'Apply to Ticket';
      applyBtn.classList.remove('pixel-apply-revert');
      applyBtn.title = 'Ask Pixel for a structured analysis first';
    }
  }

  // Expose the reset so csv2ticket.js can clear the applied state
  // whenever a new CSV or MS-ISAC email is loaded.
  window.pixelResetAppliedState = function() {
    appliedSnapshot = null;
    setApplyButtonState(latestStructured ? 'ready' : 'idle');
  };

  function appendMessage(role, initialText = '') {
    const row = document.createElement('div');
    row.className = `pixel-msg pixel-msg-${role}`;

    if (role === 'assistant') {
      const avatar = document.createElement('span');
      avatar.className = 'pixel-msg-avatar';
      avatar.innerHTML = PIXEL_ICON_SVG;
      row.appendChild(avatar);
    }

    const bubble = document.createElement('div');
    bubble.className = 'pixel-bubble';
    bubble.textContent = initialText;
    row.appendChild(bubble);

    chatEl.appendChild(row);
    chatEl.scrollTop = chatEl.scrollHeight;
    return bubble;
  }

  function clearChat() {
    chatEl.innerHTML = '';
    chatHistory = [];
    latestStructured = null;
    appliedSnapshot = null;
    setApplyButtonState('idle');
    appendMessage('assistant',
      "Hi, I'm Pixel 👋  Load a CSV or paste an MS-ISAC / Stamus email, then ask me about the incident.\n\n" +
      "I treat the email's Analysis field as preliminary vendor context and go deeper using the CSV evidence. If I have investigative facts to add from my own knowledge, I'll ask before pasting them in (you can also share OSINT findings in chat and I'll fold them in). Recommendations are tuned for USF's open network — most remediation goes through the user's NetID email unless it's USF infrastructure.\n\n" +
      "Try the quick buttons below for structured triage, or ask me anything.");
  }

  // ─────────────────────────────────────────────────────────────
  //   Prompt building (pulls from ticketState)
  // ─────────────────────────────────────────────────────────────
  function buildContext() {
    const s = window.ticketState || {};
    const c = s.csv || {};
    const summary = {
      descriptions: [...(c.descriptions || [])].filter(Boolean),
      timestamps:      (c.timestamps || []).slice(0, 10),
      timestamp_count: (c.timestamps || []).length,
      source_ips:      [...(c.srcIps || [])].slice(0, 20),
      source_ports:    [...(c.srcPorts || [])].slice(0, 20),
      dest_ips:        [...(c.dstIps || [])].slice(0, 20),
      dest_ports:      [...(c.dstPorts || [])].slice(0, 20),
      directions:      [...(c.directions || [])],
      app_protocols:   [...(c.appProtos || [])],
      domains:         [...(c.domains || [])].slice(0, 30),
      urls:            [...(c.urls || [])].slice(0, 20),
      tls_subjects:    [...(c.tlsSubjects || [])].slice(0, 10),
      tls_issuers:     [...(c.tlsIssuers || [])].slice(0, 10),
      signature_ids:   [...(c.signatureIds || [])],
      sample_payloads: [...(c.payloads || [])].slice(0, 3).map(p => (p || '').slice(0, 500)),
    };
    const ms = s.msIsac?.loaded ? {
      description: s.msIsac.description || '',
      analysis:    s.msIsac.analysis || '',
      source:      `${s.msIsac.srcIp || ''}${s.msIsac.srcPort ? ':' + s.msIsac.srcPort : ''}`,
      destination: `${s.msIsac.dstIp || ''}${s.msIsac.dstPort ? ':' + s.msIsac.dstPort : ''}`,
    } : null;

    let ctx = '';
    if (ms) ctx += `MS-ISAC Email Context:\n${JSON.stringify(ms, null, 2)}\n\n`;
    if (c.loaded) ctx += `CSV Evidence Summary:\n${JSON.stringify(summary, null, 2)}\n`;
    if (!ctx) ctx = '(No CSV or MS-ISAC context loaded yet.)';

    if (ctx.length > cfg.maxPromptChars) {
      ctx = ctx.slice(0, cfg.maxPromptChars) + '\n\n[...truncated for model context limit]';
    }
    return ctx;
  }

  const SYSTEM_BASE =
`You are Pixel, a SOC analyst assistant embedded in the SOCAP Console at the University of South Florida.
You help triage security incidents from MS-ISAC and Stamus Networks email notifications, paired with
CSV network evidence (Stamus / linkedAlerts).

VOICE / TONE — VERY IMPORTANT
The Analysis and Recommendations sections you produce are pasted directly into a formal incident
ticket. The ticket is read by IT staff, leadership, and (sometimes) outside parties. It must read
as if a human analyst wrote it.

  • ## ANALYSIS section: NEUTRAL, OBJECTIVE, written from the analyst's voice. Third-person /
    passive constructions are preferred ("the traffic indicates…", "the signature is consistent
    with…", "the destination has been observed…"). NO first-person SINGULAR ("I", "me", "my",
    "I think", "I believe", "in my opinion"). Team voice is fine when introducing investigative
    findings — "Our investigation determined that…", "Our analysis confirms…", "Our team's
    review of <indicator> indicates…" all read as the team's collective work.
  • Investigative facts you contribute should be introduced with team-voice attribution ("Our
    investigation determined that…") OR woven in plainly with a real source named ("AbuseIPDB
    lists…", "ET Open documents…", "DNS records show…") — pick whichever fits the sentence
    naturally. NEVER attribute facts to "Pixel" — Pixel is invisible in the ticket.
  • ## RECOMMENDATIONS section: same team voice. "We" / "our team" / first-person plural is
    permitted because remediation is a team effort. Imperative voice is also fine ("Block X at
    the perimeter"). Examples of acceptable phrasings:
        – "We recommend contacting <netid> to remediate the affected device."
        – "Block 162.19.139.181 and the associated mining domains at the perimeter."
        – "Our team should monitor for further connections to the same infrastructure."
    Still avoid first-person SINGULAR ("I recommend") — the recommendation is the team's, not one
    analyst's opinion.
  • Avoid anthropomorphic framing of Pixel anywhere in the structured sections — no "Pixel thinks",
    "Pixel suspects", "Pixel determined", "Pixel-assisted lookup", "Pixel's investigation".
    Pixel is invisible in the ticket; the analyst (or team) is the author.
  • In CONVERSATIONAL chat replies (outside the structured sections) you can speak more naturally
    in first person — that's fine. The neutral tone is required only inside ## Analysis and
    ## Recommendations.

REFERENCE EXAMPLE — the shape and voice an Analysis section should aim for:

  • Source IP 131.247.244.2 (USF endpoint) was observed communicating with destination IP
    52.41.112.221 over port 80/TCP (source port 38722).
  • Network traffic matched the signature "Observed Coruna User-Agent (Outbound)".
  • The destination IP, 52.41.112.221, resolves to clk.aiwsa.com.
  • Timestamp of the observed event: 2026-04-15 00:47:49.

  Our investigation determined that the destination IP 52.41.112.221 does not resolve to a valid
  hostname according to DNS records. The Amazon Web Services (AWS) IP address
  ec2-52-41-112-221.us-west-2.compute.amazonaws.com is associated with the public-facing endpoint
  of the suspected C2 server.

  Further investigation is pending.

  (Notice: 131.247.244.2 is correctly identified as the USF endpoint — the affected host, not the
  threat. The domain association points to the EXTERNAL destination, not the USF source. Clean
  bulleted context, then expanded paragraph with "Our investigation determined…" team-voice
  attribution, then "Further investigation is pending." closer. No first-person singular, no
  Pixel attribution. IOCs are written without defang in the model output — the application layer
  defangs them when the analyst clicks Apply to Ticket.)

WHAT THE TICKET FIELDS MEAN
  • "Analysis" in the email context is the *vendor's preliminary description* of what was observed.
    Treat it as a starting hypothesis, NOT as a final verdict. The CSV evidence may corroborate,
    contradict, or expand on it.
  • The job when producing an Analysis is to deepen the picture: confirm or refute the vendor's
    read using the CSV evidence (signatures, IPs, ports, TLS subjects, payloads, timing), name the
    likely threat family or behavior class with appropriate confidence, and flag what's still
    unknown. Be honest about confidence — phrasings like "consistent with…", "suggestive of…",
    "insufficient evidence for…" are preferred over assertions that aren't supported.
  • You may propose targeted investigation steps (whois, VirusTotal lookup, JA3 fingerprint check,
    DNS history, etc.) and contribute results IF you have high confidence from your training data.
    When contributing investigative facts, use team-voice attribution — "Our investigation
    determined that…", "Our analysis confirms…", "Our team's review of <indicator> indicates…" —
    OR weave them in plainly with a real-source name ("AbuseIPDB lists…", "ET Open documents…",
    "DNS records show…"). Pick whichever fits the sentence naturally. NEVER attribute to Pixel.
    For anything not confident enough to assert, ask the analyst conversationally whether they
    have that information.
  • If the analyst pastes new evidence, OSINT lookups, or notes in chat, integrate them into the
    analysis using neutral attribution like "OSINT lookups confirm…" or simply incorporating the
    facts without first-person framing.

USF NETWORK CONTEXT (this matters for analysis AND recommendations)
  • USF's public IPv4 ranges include 131.247.0.0/16 (and a few other blocks). Any IP in 131.247.x.x
    is a USF endpoint — typically a campus device or affected user host, NOT an external threat.
    When 131.247.x.x appears as the SOURCE in an alert, it is the AFFECTED USF host (the one we
    want to remediate). When 131.247.x.x appears as the DESTINATION, it is a USF asset being
    contacted — the focus shifts to whoever was doing the contacting.
    NEVER label a 131.247.x.x address as the malicious party, the C2, or the suspicious endpoint.
    The non-USF side of the conversation is almost always the indicator of interest.
  • Other RFC1918 / private ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x) are also
    internal — never call these "malicious infrastructure".
  • USF runs a very open campus network. Most affected endpoints are personal user devices
    (students, staff, faculty), NOT centrally-managed corporate workstations.
  • The standard playbook is: contact the user via their NetID email, ask them to remediate their
    own device (run AV, change passwords, reimage if warranted), and apply network-level blocks
    (IP / domain) at the perimeter to stop the bleeding. The blocks target the EXTERNAL indicator
    (the non-USF IP/domain), not the USF host.
  • Direct IT-team remediation (forced reimage, MDM-pushed updates, account-level lockouts) is
    only appropriate when the affected asset is part of USF infrastructure — servers, managed
    workstations, network devices, IoT in lab environments, etc.

HOW TO STRUCTURE A STRUCTURED RESPONSE
When the analyst uses a quick-action button or asks for "analysis and recommendations", reply
EXACTLY in this format with no extra preamble:

## Analysis
<NEUTRAL, OBJECTIVE, written from the analyst's voice. Two-part shape:

  1. CONTEXT BULLETS (always — even if no investigation has been done yet):
     A short bulleted list of the key facts already established from the email and CSV evidence.
     Bullets should be terse and factual — IOCs, signatures, ports, timestamps, observed behavior,
     vendor's preliminary read. Aim for 3–7 bullets. Do not pad. This block is essentially the
     analyst's "here is what we know" summary.

  2. EXPANDED ANALYSIS (only when there is more to say):
     One or two short paragraphs that go beyond the bullets. This is where:
       • Investigative facts from your training are woven into the prose AS IF the analyst found
         them — name a real public source where appropriate ("AbuseIPDB lists…", "ET Open
         documents this signature as…") or state widely-known facts plainly without attribution.
         Do NOT mention Pixel by name in the ticket.
       • The analyst's chat-supplied evidence is incorporated ("OSINT lookups confirm…")
       • Confidence is expressed and unknowns are flagged
     If the email + CSV alone are enough and there's nothing to add yet, skip this section
     entirely or write one sentence stating "Further investigation is pending." — do not invent
     filler analysis.

Cite specific IOCs (IPs, domains, signatures, ports) wherever they appear. The Analysis must read
uniformly as the analyst's own writing — no first-person singular, no Pixel attribution.>

## Recommendations
<Concise, action-oriented bullet list aimed at the IT team. "We" / "our team" / first-person
plural is permitted because remediation is a team effort. Imperative voice is also fine. Examples:
  - "We recommend contacting <netid> to remediate the affected device."
  - "Block 162.19.139.181 and the associated mining domains at the perimeter."
  - "Our team should monitor for further connections to the same infrastructure."
Avoid first-person SINGULAR ("I recommend"). Distinguish:
  - User-side actions (almost always the primary path at USF): contact <netid>, ask them to X.
  - Network-side actions: block IP/domain at perimeter; specify the exact indicators.
  - Infrastructure-side actions (only if applicable): reimage server, rotate credentials, etc.
Keep it to 3-6 bullets. No fluff, no generic "monitor for further activity" filler unless it's
genuinely the right call.>

ASKING PERMISSION BEFORE INCLUDING INVESTIGATIVE FINDINGS
When you want to enrich the ticket with investigative facts you're confident about, BEFORE the
structured response — in conversational first-person tone — briefly tell the analyst what you'd
add and ask if they want it included. Example:

  "Heads up — I can add that 162.19.139.181 has been seen by AbuseIPDB across 30+ reports as a
  2miners pool node, and that 2miners.com is associated with Monero/zcash mining proxies. Want
  me to include that in the analysis? (Reply 'yes' / 'go ahead' to confirm.)"

If the analyst confirms, produce the structured response with those facts woven in using team
voice — either "Our investigation determined that 162.19.139.181 has appeared in 30+ AbuseIPDB
reports as a 2miners pool node…" or by naming the source plainly ("AbuseIPDB lists 162.19.139.181
across 30+ reports as a 2miners pool node…"). Whichever fits naturally. Never attribute to Pixel.
If they decline or correct you, omit the contribution.

For non-structured questions, just answer conversationally — no headings, first person is fine.`;

  function buildFullSystem() {
    return SYSTEM_BASE + '\n\n--- Current Incident Context ---\n' + buildContext();
  }

  function parseStructured(text) {
    const a = text.match(/##?\s*Analysis\s*\n([\s\S]*?)(?=##?\s*Recommendations\b|$)/i);
    const r = text.match(/##?\s*Recommendations\s*\n([\s\S]*?)$/i);
    return {
      analysis: a ? a[1].trim() : '',
      recommendations: r ? r[1].trim() : '',
    };
  }

  // ─────────────────────────────────────────────────────────────
  //   Send / stream
  // ─────────────────────────────────────────────────────────────
  async function sendMessage(text) {
    const trimmed = (text || '').trim();
    if (!trimmed) return;

    if (abortCtrl) abortCtrl.abort();
    abortCtrl = new AbortController();

    chatHistory.push({ role: 'user', content: trimmed });
    appendMessage('user', trimmed);

    const bubble = appendMessage('assistant', '');
    bubble.classList.add('streaming');

    inputEl.value = '';
    autosizeInput();
    sendBtn.disabled = true;
    applyBtn.disabled = true;
    setStatus('● thinking…', 'var(--intel-blue)');

    const messages = [{ role: 'system', content: buildFullSystem() }, ...chatHistory];
    const timeoutId = setTimeout(() => abortCtrl?.abort('timeout'), cfg.timeoutMs);
    let fullText = '';

    try {
      const res = await fetch(`${cfg.url.replace(/\/+$/, '')}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: cfg.model, messages, stream: true }),
        signal: abortCtrl.signal,
      });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const obj = JSON.parse(line);
            const token = obj.message?.content || '';
            if (token) {
              fullText += token;
              // Show raw — IPs/domains stay readable in chat. textContent
              // (not innerHTML) prevents any URLs from rendering as clickable.
              bubble.textContent = fullText;
              chatEl.scrollTop = chatEl.scrollHeight;
            }
            if (obj.error) throw new Error(obj.error);
          } catch { /* skip non-JSON */ }
        }
      }
      clearTimeout(timeoutId);
      bubble.classList.remove('streaming');
      chatHistory.push({ role: 'assistant', content: fullText });

      const parsed = parseStructured(fullText);
      if (parsed.analysis || parsed.recommendations) {
        latestStructured = parsed;
        // New response ⇒ drop any prior applied snapshot (can't revert to an older one)
        appliedSnapshot = null;
        setApplyButtonState('ready');
      }
      setStatus(`● online · ${cfg.model}`, 'var(--threat-green)');
    } catch (err) {
      clearTimeout(timeoutId);
      bubble.classList.remove('streaming');
      bubble.classList.add('error');

      const msg = String(err?.message || err || '');
      let hint = msg.slice(0, 80);
      if (err?.name === 'AbortError')             hint = 'Timed out — model may be loading or too slow';
      else if (location.protocol === 'file:')     hint = 'Serve page over http:// (not file://)';
      else if (msg.includes('Failed to fetch'))   hint = 'Network blocked — set OLLAMA_ORIGINS=* and restart Ollama';
      else if (/model .* not found/i.test(msg))   hint = `Model "${cfg.model}" not installed — run: ollama pull ${cfg.model}`;

      bubble.textContent = `🏖  ${FALLBACK_MSG}\n\nDetails: ${hint}`;
      setStatus(`● offline — ${hint}`, 'var(--threat-red)');
    } finally {
      sendBtn.disabled = false;
      abortCtrl = null;
    }
  }

  // Quick prompts
  const QUICK_PROMPTS = {
    analyze:   'Give me your Analysis only. Two-part shape: (1) a tight bulleted list of the key facts already established from the email + CSV — IOCs, signatures, ports, timestamps, observed behavior, vendor read; 3–7 bullets, no padding. (2) Below the bullets, ONE OR TWO paragraphs of expanded analysis only if there is genuinely more to say (investigative findings from your training, OSINT-supplied facts, confidence, unknowns) — otherwise skip or write a single line like "Further investigation is pending." Do not invent filler. NEUTRAL, OBJECTIVE voice — no first-person SINGULAR ("I"). Investigative additions use team-voice attribution ("Our investigation determined that…", "Our analysis confirms…") OR a real-source name ("AbuseIPDB lists…", "DNS records show…"). NEVER mention Pixel in the output. Confirm substantive additions with me conversationally first.',
    recommend: 'Give me your Recommendations only — concise, action-oriented bullets for the IT team. "We" / "our team" / first-person plural is permitted (remediation is a team effort), as is imperative voice. Avoid first-person SINGULAR ("I recommend"). Remember USF\'s open network: most remediation falls on the user via NetID email. Only suggest direct IT-team remediation if this involves USF infrastructure.',
    both:      'Give me the full structured response with ## Analysis and ## Recommendations. ANALYSIS shape: lead with a tight bulleted list of established context (IOCs / signatures / ports / vendor read; 3–7 bullets, no padding), then ONE OR TWO short paragraphs of expanded analysis ONLY if there\'s more to add (investigative findings from your training, OSINT, confidence, unknowns) — otherwise just the bullets and a one-line "Further investigation is pending." NEUTRAL voice — no first-person SINGULAR. Investigative additions use team-voice ("Our investigation determined that…") or real-source naming ("AbuseIPDB lists…"). NEVER mention Pixel in the output. Recommendations may use "we" / "our team" / imperative. Confirm substantive additions with me first. Recommendations distinguish user-side vs network-side vs infrastructure-side actions, mindful of USF\'s playbook (contact via NetID, user remediates own device).',
  };
  panel.querySelectorAll('.pixel-quick').forEach(btn => {
    btn.addEventListener('click', () => {
      const preset = btn.dataset.preset;
      if (QUICK_PROMPTS[preset]) sendMessage(QUICK_PROMPTS[preset]);
    });
  });

  // Apply / Revert toggle — when applied, stashes the original ticketState
  // values so the analyst can back out the change with one click.
  applyBtn.addEventListener('click', () => {
    window.ticketState = window.ticketState || {};
    const s = window.ticketState;

    if (appliedSnapshot) {
      // REVERT — restore pre-apply values
      s.pixelAnalysis        = appliedSnapshot.analysis        || '';
      s.pixelRecommendations = appliedSnapshot.recommendations || '';
      appliedSnapshot = null;
      if (typeof window.regenerateTicket === 'function') window.regenerateTicket();
      if (typeof window.showToast === 'function') window.showToast('Pixel output reverted', 'success');
      setApplyButtonState(latestStructured ? 'ready' : 'idle');
      return;
    }

    // APPLY — snapshot current values first, then overwrite (with defang applied)
    if (!latestStructured) return;
    appliedSnapshot = {
      analysis:        s.pixelAnalysis        || '',
      recommendations: s.pixelRecommendations || '',
    };
    // Domain-only defang: neuters domains + URL hosts so they aren't clickable,
    // but leaves bare IP addresses intact (so analysts can quickly read /
    // copy them). Benign domains and private IPs pass through untouched.
    s.pixelAnalysis        = domainOnlyDefang(latestStructured.analysis        || '');
    s.pixelRecommendations = domainOnlyDefang(latestStructured.recommendations || '');
    if (typeof window.regenerateTicket === 'function') window.regenerateTicket();
    if (typeof window.showToast === 'function') window.showToast('Pixel output applied to ticket (defanged)', 'success');
    setApplyButtonState('applied');
  });

  clearBtn.addEventListener('click', () => {
    if (!confirm('Clear the chat history?')) return;
    clearChat();
  });

  function autosizeInput() {
    inputEl.style.height = 'auto';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 120) + 'px';
  }
  inputEl.addEventListener('input', autosizeInput);
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(inputEl.value);
    }
  });
  sendBtn.addEventListener('click', () => sendMessage(inputEl.value));

  // Kick off with a greeting
  clearChat();

  // ─────────────────────────────────────────────────────────────
  //   Health ping on load
  // ─────────────────────────────────────────────────────────────
  (async () => {
    if (location.protocol === 'file:') {
      setStatus('● unreachable', 'var(--threat-amber)');
      return;
    }
    try {
      const res = await fetch(`${cfg.url.replace(/\/+$/, '')}/api/tags`, {
        signal: AbortSignal.timeout ? AbortSignal.timeout(2500) : undefined,
      });
      if (!res.ok) { setStatus('● unreachable', 'var(--ops-text-dim)'); return; }
      const data = await res.json().catch(() => null);
      const models = data?.models?.map(m => m.name) || [];
      const hasModel = models.some(n => n === cfg.model || n.startsWith(cfg.model + ':'));
      if (hasModel)      setStatus(`● online · ${cfg.model}`, 'var(--threat-green)');
      else if (models.length) setStatus(`● online, but "${cfg.model}" not pulled`, 'var(--threat-amber)');
      else               setStatus(`● online, no models installed`, 'var(--threat-amber)');
    } catch (e) {
      setStatus('● unreachable', 'var(--threat-red)');
      console.warn('[Pixel] Health check failed:', e);
    }
  })();

})();
