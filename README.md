# SOCAP Console

A SOC analyst workbench for the **University of South Florida** built around the Cyber Florida brand. Triages MS-ISAC and Stamus Networks alerts, parses CSV evidence (Stamus / linkedAlerts), generates incident tickets, runs KQL hunting queries, enriches IOCs across threat-intel sources, archives finished tickets to Word, drafts IT-team escalations, and includes a local LLM analyst named **Pixel** powered by Ollama.

---

## First-time setup

Everything runs locally in a browser. There is no build step.

### 1. Unzip the project somewhere stable

Pick a folder you'll keep, e.g. `C:\Users\<you>\socap-console` on Windows or `~/socap-console` on macOS / Linux. Unzip `socap-console.zip` so the structure looks like:

```
socap-console/
├── index.html
├── modules/
├── assets/
├── README.md
└── TODO.md
```

### 2. Serve the folder over HTTP — do **not** open `index.html` directly

Modern browsers block almost all useful behaviour from `file://` URLs (CORS, cross-origin fetches to `localhost:11434` for Pixel, paste handlers, etc.). You must serve the folder.

The simplest option, requires nothing extra:

**Windows (PowerShell):**
```powershell
cd C:\path\to\socap-console
py -m http.server 8000
```

**macOS / Linux:**
```bash
cd ~/socap-console
python3 -m http.server 8000
```

**Alternative if you have Node:**
```bash
npx serve .
```

Then open **<http://localhost:8000>** (or `http://127.0.0.1:8000` — same thing). Bookmark it.

### 3. Install Ollama for Pixel (the AI analyst)

Pixel is optional — the rest of the console works without it — but it's the headline feature, so you'll probably want it.

Install Ollama from <https://ollama.com/download>, then in a terminal:

```bash
ollama pull llama3.2
ollama serve
```

That pulls the default model (~2 GB) and starts the local API server on `127.0.0.1:11434`.

### 4. Allow the browser to talk to Ollama (CORS)

By default Ollama only accepts requests from a few hardcoded origins. You need to add `*` (or `http://localhost:8000` specifically) so the SOCAP page can reach it:

**Windows — make it permanent:**
1. Quit Ollama from the system tray (right-click → Quit). Confirm with `tasklist | findstr ollama` — should return nothing.
2. Press <kbd>Win</kbd>, type **"Edit environment variables for your account"**, open it.
3. Click **New**, name `OLLAMA_ORIGINS`, value `*`, OK.
4. Open a fresh PowerShell and run `ollama serve`. The first log line should now show `OLLAMA_ORIGINS:[*]` instead of the long default list.

**Just for one session (any OS):**
```powershell
# PowerShell
$env:OLLAMA_ORIGINS = "*"; ollama serve
```
```bash
# bash
OLLAMA_ORIGINS=* ollama serve
```

### 5. Test it works

Open <http://localhost:8000>. Pixel's status indicator (bottom-right) should turn green and read `● online · llama3.2`. If it says `● unreachable` instead, see [Troubleshooting Pixel](#troubleshooting-pixel).

That's it — you're set.

---

## Daily workflow

1. Receive an alert email (MS-ISAC or Stamus).
2. Open SOCAP Console at <http://localhost:8000>.
3. **Console tab**: paste the email into the left card, upload the CSV. The ticket renders live on the right.
4. **DHCP Lookup**: query for the device. The Internal IP, MAC, NetID, Hostname auto-flow back into the ticket.
5. **Enrich IOC**: pick sources, click Open Selected. Selected sources append to the ticket's OSINT section.
6. **Pixel**: click 📋 Full to get an Analysis + Recommendations, click Apply to Ticket. Use chat for follow-up questions or to share OSINT findings you want folded in.
7. **Archive & Escalate**: when the ticket is closed, paste the finished ticket plus screenshots into Archive, name it, click Export .zip. Use Escalate to draft the IT-team summary.

---

## What's in the project

```
socap-console/
├── index.html                         App shell, sidebar, header, all CSS, module loader, Pixel config
├── README.md
├── TODO.md
├── assets/
│   ├── cyber-florida-logo.png         Centered header logo (Geometos Neue ExtraBold)
│   └── fonts/
│       └── GeometosNeue-ExtraBold.otf Brand font (bundled — used by the logo render)
└── modules/
    ├── csv2ticket.js                  Email parser, CSV aggregator, ticket generator
    ├── kql.js                         KQL hunting queries + time-window stepper
    ├── dhcp-lookup.js                 DHCP lease query form + Internal IP sync
    ├── enrich-ioc.js                  IOC enrichment launcher
    ├── archive-escalate.js            Word doc + zip archiver, IT-team escalation drafter
    ├── pixel.js                       Floating Ollama-backed chatbot
    ├── redact.js                      Mask sensitive org info in raw text
    ├── h2c.js                         Raw HTTP request → curl converter
    ├── html-analyzer.js               Suspicious HTML pattern detector
    ├── ioc-extractor.js               Pull IPs/domains/URLs/hashes out of text
    ├── defang.js                      Standalone defang/refang
    ├── encode-decode.js               Base64 / URL / HTML / Hex codec
    └── timestamp.js                   Timestamp format converter
```

---

## Tabs

### Console
The main triage workspace. Two-column layout: inputs (MS-ISAC / Stamus email paste + CSV upload) on the left, live-generated ticket on the right.

- **Email Context (MS-ISAC / Stamus)** — paste the raw email. Description, Analysis, Source/Destination IP+Port are auto-extracted. Detects format heuristically (`[ Stamus Networks Event ]` marker → Stamus; otherwise MS-ISAC). Status line shows `✓ Parsed (Stamus) · src=... · dst=...`.
- **Clear All** — top-right of the email card. Wipes email, parsed state, and generated ticket. No confirmation prompt.
- **CSV upload** — accepts multiple files; combines them. Recognized columns: `event_alertSrcIP`, `event_alertDstIP`, `tls_subject`, `signature_id`, `payload`, `payload_printable`, `event_alertPayload`, `event_decoded_alertPayload`, plus the standard Stamus / linkedAlerts schema.
- **Generated Ticket** — auto-renders on every input change. Sections: Description, Analysis, Recommendations, Supporting Details (with Source / Destination IP+Port, Direction, Application Protocol when applicable), Defender (Internal IP / MAC / NetID), OSINT, Streamdata (Signatures, CyberChef link, Input/Output payload).

### DHCP Lookup
A pre-filled form for ITC's DHCP portal. Pulls Start/End time from the matched CSV row (or MS-ISAC timestamp), syncs Internal IP two-way with the Console's KQL Internal IP field. Submit opens the portal in a new tab.

### Enrich IOC
Pulls IOCs from the ticket and from a free-text input. Detects type (IP/domain/URL/hash). Multi-select sources (VirusTotal, AbuseIPDB, Shodan, urlscan.io, AnyRun, Hybrid Analysis, OTX, Censys, etc.); "Open Selected" launches every chosen source as a tab in one user gesture. Selected sources append to the ticket's OSINT section automatically.

### Archive & Escalate
Two stacked sections (no sub-tabs).

- **📦 Archive** — name the archive, paste the finalized ticket text plus screenshots into a contenteditable editor (drag-and-drop images, Ctrl+V from screenshot tools, "Load current ticket" button to pull from Console). Click Export .zip → downloads `<name>.zip` containing `<name>/<name>.docx`. The .docx body is exactly what's in the editor — no auto-inserted titles or timestamps.
- **📣 Escalate** — generate a concise summary for the IT team. **Ask Pixel** drafts a paragraph with USF-specific phrasing (NetID contact, perimeter blocking). **Use Fallback Template** builds a deterministic single-paragraph summary if Pixel is offline. **Copy** for quick paste into Slack/email.

### Additional Tools
Sub-tabs: Redact, Header → Curl, HTML Analyzer, IOC Extractor, Defang, Encode/Decode, Timestamp.

---

## Pixel (AI analyst)

A floating chat widget pinned to the bottom-right corner of every tab. It persists across tab switches and refreshes (state stored in `localStorage`).

### States
- **Open** — full panel, 380×560px chat
- **Minimized** — small pill with avatar; click to expand
- **Closed** — hidden; reopen via the green FAB that appears in the same corner

### Behaviour
- Pulls **CSV evidence + parsed email** from `window.ticketState` automatically — no manual context-pasting needed.
- Treats the email's "Analysis" field as a **vendor's preliminary read**, not a verdict. Goes deeper using the CSV evidence.
- Knows USF's network: `131.247.0.0/16` is USF endpoints (never the threat). Recommendations assume the open-network playbook (contact via NetID, user remediates own device, block external IPs/domains at perimeter). Direct IT-team remediation is reserved for USF infrastructure.
- Writes Analysis in **analyst's voice** (no first-person "I"); writes Recommendations in **team voice** ("we", "our team", imperative). Investigative findings from the model's training are introduced as "Our investigation determined that…" or with a real source name ("AbuseIPDB lists…", "DNS records show…"). Pixel itself is invisible in the ticket.
- Asks permission before adding non-trivial investigative facts, e.g. "Heads up — I can add that 162.19.139.181 has been seen by AbuseIPDB across 30+ reports as a 2miners pool node. Want me to include that?"

### Quick actions
- **🔍 Analyze** — Analysis section only (bullets + optional expanded paragraph)
- **💡 Recommend** — Recommendations only
- **📋 Full** — both, ready for Apply to Ticket

### Apply / Revert
- **Apply to Ticket** — copies Pixel's structured response into the ticket's Analysis + Recommendations sections. Domains and URL hosts are defanged at apply time (`evil.ru` → `evil[.]ru`, `https://...` → `hxxps://...`); IP addresses stay readable; the chat bubble itself stays raw.
- **Revert** — the button flips amber after Apply; clicking it restores the pre-apply state. New Pixel responses reset the button to Apply mode.

### Configuration
Edit the `PIXEL_CONFIG` block at the bottom of `index.html`:
```js
window.PIXEL_CONFIG = {
  url:   'http://127.0.0.1:11434',  // Ollama host
  model: 'llama3.2',                // any pulled model
  timeoutMs: 60000,
};
```

If you have a decent GPU, larger models give noticeably better analysis. Try:
```bash
ollama pull qwen2.5:14b      # ~9 GB VRAM
ollama pull llama3.1:8b      # ~5 GB VRAM
```
Then update `PIXEL_CONFIG.model` to match.

### Fallback
If Ollama is unreachable, Pixel shows: *"Pixel's on vacation for the time being, sorry for the inconvenience!"*

---

## Troubleshooting Pixel

If Pixel's status shows `● unreachable`:

1. **Open <http://127.0.0.1:11434> in a new tab.** You should see `Ollama is running`. If not, Ollama isn't started — `ollama serve`.
2. **Check `OLLAMA_ORIGINS`.** In the terminal where Ollama is running, the first log line should mention `OLLAMA_ORIGINS:[*]`. If you see the long default list instead, the env var didn't make it in. Re-do step 4 of First-time setup.
3. **Verify CORS from PowerShell:**
   ```powershell
   curl.exe http://localhost:11434/api/tags -H "Origin: http://localhost:8000" -v
   ```
   Look for `Access-Control-Allow-Origin: *` in the response headers.
4. **Confirm you're on `http://`, not `file://`.** The address bar should show `http://localhost:8000` or `http://127.0.0.1:8000`.
5. **Open browser DevTools (F12) → Console tab** and click "Ask Pixel" again. The error there will tell you specifically what's wrong (CORS / network / HTTP code / timeout).
6. **Model not pulled?** Status `● online, but "<model>" not pulled` means Ollama is reachable but the configured model isn't installed. `ollama pull <model>`.

---

## Common questions

**Where is data stored?** Nowhere persistent except `localStorage` for UI preferences (sidebar collapse, Pixel state, theme). Tickets, CSVs, and chat history live only in the page's memory and vanish on refresh. No analytics, no telemetry, no network calls except to Ollama and the OSINT sources you click.

**Can I add a custom OSINT source?** Yes — `modules/enrich-ioc.js` has a `SOURCES` array near the top. Each entry has a `name`, `types` (which IOC types it accepts), and `url` template. Add a new object, refresh.

**Can I host this for my whole team?** Yes — push the project folder to any static host (nginx, Apache, GitHub Pages, S3+CloudFront, etc.). Pixel still needs Ollama; either run it on each user's machine or stand up a central Ollama server reachable from the static host (don't expose Ollama to the open internet — put it behind auth).

**Light / dark mode?** Toggle is in the sidebar at the bottom. Choice persists.
