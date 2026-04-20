// ---------- IOC enrichment sources ---------- //
const ip_links = {
  'Recorded Future': 'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_ip?form.name={ioc}',
  'VirusTotal': 'https://www.virustotal.com/gui/ip-address/{ioc}',
  'AbuseIPDB': 'https://www.abuseipdb.com/check/{ioc}',
  'CentralOps.net': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
  'urlscan.io (search)': 'https://urlscan.io/search/#page.ip%3A{ioc}',
  'urlscan.io (scan)': 'https://urlscan.io/ip/{ioc}',
  'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
  'Validin': 'https://app.validin.com/detail?type=ip&find={ioc}#tab=reputation',
  'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
  'GreyNoise': 'https://viz.greynoise.io/ip/{ioc}',
  'Netify': 'https://www.netify.ai/resources/ips/{ioc}',
  'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
  'URLhaus': 'https://urlhaus.abuse.ch/host/{ioc}/',
  'AlienVault OTX': 'https://otx.alienvault.com/indicator/ip/{ioc}',
  'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/ip/{ioc}',
  'ThreatBook': 'https://threatbook.io/research/{ioc}',
  'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
  'Shodan': 'https://www.shodan.io/host/{ioc}',
  'Censys': 'https://platform.censys.io/hosts/{ioc}',
  'FOFA': 'https://en.fofa.info/result?qbase64={ioc}',
  'Netlas.io': 'https://app.netlas.io/host/{ioc}',
  'ONYPHE': 'https://search.onyphe.io/search?q=category:datascan+ip:{ioc}',
  'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
  'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}',
  'ANY.RUN': 'https://intelligence.any.run/analysis/lookup#{%22query%22:%22destinationIP:%5C%22{ioc}%5C%22%22,%22dateRange%22:180}',
  'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-public-ip={ioc}',
  'Triage': 'https://tria.ge/s?q={ioc}',
  'CAPE Sandbox': 'https://capesandbox.com/analysis/search/?search=ip%3A{ioc}',
  'Criminal IP': 'https://www.criminalip.io/asset/report/{ioc}',
  'threatYeti': 'https://threatyeti.com/search?q={ioc}',
  'Valkyrie Verdict': 'https://verdict.valkyrie.comodo.com/url/ip/result?ip={ioc}',
  'Cloudflare Radar': 'https://radar.cloudflare.com/ip/{ioc}',
  'CrowdSec': 'https://app.crowdsec.net/cti/{ioc}',
  'Maltiverse': 'https://maltiverse.com/ip/{ioc}',
  'Spur': 'https://spur.us/context/{ioc}',
  'ProxySentry': 'https://proxysentry.io/threats/{ioc}',
  'VulDB': 'https://vuldb.com/?ip.{ioc}',
  'IPIntel.ai': 'https://ipintel.ai/ip/{ioc}',
  'IPThreat.net': 'https://ipthreat.net/ip/{ioc}',
  'CleanTalk': 'https://cleantalk.org/blacklists/{ioc}',
  'GitHub': 'https://github.com/search?q={ioc}&type=code',
  'grep.app': 'https://grep.app/search?q={ioc}',
  'Google': 'https://www.google.com/search?q="{ioc}"',
  'Bing': 'https://www.bing.com/search?q="{ioc}"',
  'Gemini': 'https://www.google.com/search?udm=50&q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+blocklists,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.',
  'ChatGPT': 'https://chatgpt.com/?q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Determine:+1.+Appearance+in+threat+feeds,+sandbox+reports,+or+blocklists+2.+Malware+families/Threat+actor+attribution+3.+Associated+Infrastructure/IPs/Domains.+4.+Reputation/Risk+Score+5.+Verdict+(Malicious/Benign)+Format+as+a+concise+Technical+Brief.',
  'Mistral': 'https://chat.mistral.ai/chat?q=Search+the+web+to+conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search:+threat+feeds,+sandbox+reports,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.+Generate+a+detailed+threat+analysis+report.',
  'Exa': 'https://exa.ai/search?q=Give+me+information+on+this+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+malware+families,+threat+actor+attribution,+associated+infrastructure/IPs/domains.&type=deep',
  'Perplexity': 'https://www.perplexity.ai/search?q=Enrich+this+IOC:+"{ioc}"'
};

const domain_links = {
  'Recorded Future': 'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_domain?form.name={ioc}',
  'VirusTotal': 'https://www.virustotal.com/gui/domain/{ioc}',
  'CentralOps.net': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
  'Whois.com': 'https://www.whois.com/whois/{ioc}',
  'urlscan.io (search)': 'https://urlscan.io/search/#page.domain%3A{ioc}',
  'urlscan.io (scan)': 'https://urlscan.io/domain/{ioc}',
  'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
  'Validin': 'https://app.validin.com/detail?type=dom&find={ioc}',
  'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
  'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
  'URLhaus': 'https://urlhaus.abuse.ch/host/{ioc}/',
  'AlienVault OTX': 'https://otx.alienvault.com/indicator/hostname/{ioc}',
  'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
  'ThreatBook': 'https://threatbook.io/research/{ioc}',
  'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
  'Shodan': 'https://www.shodan.io/domain/{ioc}',
  'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
  'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}',
  'ANY.RUN': 'https://intelligence.any.run/analysis/lookup#{%22query%22:%22domainName:%5C%22{ioc}%5C%22%22,%22dateRange%22:180}',
  'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-domain={ioc}',
  'Triage': 'https://tria.ge/s?q={ioc}',
  'CAPE Sandbox': 'https://capesandbox.com/analysis/search/?search=domain%3A{ioc}',
  'threatYeti': 'https://threatyeti.com/search?q={ioc}',
  'BuiltWith': 'https://builtwith.com/{ioc}',
  'Netcraft': 'https://sitereport.netcraft.com/?url=http://{ioc}',
  'URLVoid': 'https://www.urlvoid.com/scan/{ioc}/',
  'Sucuri SiteCheck': 'https://sitecheck.sucuri.net/results/{ioc}',
  'Symantec WebPulse': 'https://sitereview.bluecoat.com/#/lookup-result/{ioc}',
  'Valkyrie Verdict': 'https://verdict.valkyrie.comodo.com/url/domain/result?domain={ioc}',
  'Cloudflare Radar': 'https://radar.cloudflare.com/domains/domain/{ioc}',
  'EveBox': 'https://rules.evebox.org/search?q={ioc}',
  'Wayback Machine': 'https://web.archive.org/web/20250000000000*/{ioc}',
  'GitHub': 'https://github.com/search?q={ioc}&type=code',
  'grep.app': 'https://grep.app/search?q={ioc}',
  'Google': 'https://www.google.com/search?q="{ioc}"',
  'Bing': 'https://www.bing.com/search?q="{ioc}"',
  'Gemini': 'https://www.google.com/search?udm=50&q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+blocklists,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.',
  'ChatGPT': 'https://chatgpt.com/?q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Determine:+1.+Appearance+in+threat+feeds,+sandbox+reports,+or+blocklists+2.+Malware+families/Threat+actor+attribution+3.+Associated+Infrastructure/IPs/Domains.+4.+Reputation/Risk+Score+5.+Verdict+(Malicious/Benign)+Format+as+a+concise+Technical+Brief.',
  'Mistral': 'https://chat.mistral.ai/chat?q=Search+the+web+to+conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search:+threat+feeds,+sandbox+reports,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.+Generate+a+detailed+threat+analysis+report.',
  'Exa': 'https://exa.ai/search?q=Give+me+information+on+this+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+malware+families,+threat+actor+attribution,+associated+infrastructure/IPs/domains.&type=deep',
  'Perplexity': 'https://www.perplexity.ai/search?q=Enrich+this+IOC:+"{ioc}"'
};

const url_links = {
  'Recorded Future': 'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_url?form.name={ioc}',
  'URLhaus': 'https://urlhaus.abuse.ch/browse.php?search={ioc}',
  'urlscan.io (search)': 'https://urlscan.io/search/#page.url%3A{ioc}',
  'urlscan.io (scan)': 'https://urlscan.io/#{ioc}',
  'VirusTotal': 'https://www.virustotal.com/gui/url/{ioc}',
  'AlienVault OTX': 'https://otx.alienvault.com/indicator/url/{ioc}',
  'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
  'ANY.RUN': 'https://intelligence.any.run/analysis/lookup#{%22query%22:%22url:%5C%22{ioc}%5C%22%22,%22dateRange%22:180}',
  'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
  'Sucuri SiteCheck': 'https://sitecheck.sucuri.net/results/{ioc}',
  'Wannabrowser': 'https://www.wannabrowser.net/#get={ioc}',
  'Netcraft': 'https://sitereport.netcraft.com/?url={ioc}',
  'Google': 'https://www.google.com/search?q="{ioc}"',
  'Bing': 'https://www.bing.com/search?q="{ioc}"'
};

const hash_links = {
  'Recorded Future': 'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_hash?form.name={ioc}',
  'VirusTotal': 'https://www.virustotal.com/gui/file/{ioc}',
  'MalwareBazaar': 'https://bazaar.abuse.ch/sample/{ioc}',
  'YARAify': 'https://yaraify.abuse.ch/sample/{ioc}',
  'AlienVault OTX': 'https://otx.alienvault.com/indicator/file/{ioc}',
  'Validin': 'https://app.validin.com/detail?type=hash&find={ioc}#tab=reputation',
  'Triage': 'https://tria.ge/s?q={ioc}',
  'Hybrid Analysis': 'https://hybrid-analysis.com/sample/{ioc}',
  'ANY.RUN': 'https://intelligence.any.run/analysis/lookup#{%22query%22:%22sha256:%5C%22{ioc}%5C%22%22,%22dateRange%22:180}',
  'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?q={ioc}',
  'Kaspersky OpenTIP': 'https://opentip.kaspersky.com/{ioc}/results',
  'VMRay Threat Feed': 'https://threatfeed.vmray.com/?textSearch={ioc}',
  'CAPE Sandbox': 'https://capesandbox.com/analysis/search/?search=target_sha256%3A{ioc}',
  'PolySwarm': 'https://polyswarm.network/scan/results/file/{ioc}',
  'Malprob': 'https://malprob.io/report/{ioc}',
  'Threat.Zone': 'https://app.threat.zone/submissions/public-submissions?sha256={ioc}',
  'Neiki': 'https://threat.rip/file/{ioc}',
  'MetaDefender': 'https://metadefender.com/results/hash/{ioc}',
  'Intezer': 'https://analyze.intezer.com/files/{ioc}',
  'Gridinsoft': 'https://gridinsoft.com/online-virus-scanner/id/{ioc}',
  'Docguard': 'https://www.docguard.io/?hash={ioc}',
  'YOMI': 'https://yomi.yoroi.company/submissions/{ioc}',
  'ELF DIGEST': 'https://elfdigest.com/report/{ioc}',
  'Kunai Sandbox': 'https://sandbox.kunai.rocks/analysis/list?search={ioc}',
  'Koodous': 'https://koodous.com/apks/{ioc}/general-information',
  'GitHub': 'https://github.com/search?q={ioc}&type=code',
  'grep.app': 'https://grep.app/search?q={ioc}',
  'Google': 'https://www.google.com/search?q="{ioc}"',
  'Bing': 'https://www.bing.com/search?q="{ioc}"',
  'Gemini': 'https://www.google.com/search?udm=50&q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+blocklists,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.',
  'ChatGPT': 'https://chatgpt.com/?q=Conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Determine:+1.+Appearance+in+threat+feeds,+sandbox+reports,+or+blocklists+2.+Malware+families/Threat+actor+attribution+3.+Associated+Infrastructure/IPs/Domains.+4.+Reputation/Risk+Score+5.+Verdict+(Malicious/Benign)+Format+as+a+concise+Technical+Brief.',
  'Mistral': 'https://chat.mistral.ai/chat?q=Search+the+web+to+conduct+a+thorough+threat+assessment+for+IOC:+"{ioc}".+Search:+threat+feeds,+sandbox+reports,+associated+malware+families/threat+actors,+associated+infrastucture,+and+reputation.+Generate+a+detailed+threat+analysis+report.',
  'Exa': 'https://exa.ai/search?q=Give+me+information+on+this+IOC:+"{ioc}".+Search+threat+feeds,+sandbox+reports,+malware+families,+threat+actor+attribution,+associated+infrastructure/IPs/domains.&type=deep',
  'Perplexity': 'https://www.perplexity.ai/search?q=Enrich+this+IOC:+"{ioc}"'
};

// ---------- Source icons ---------- //
const source_icons = {
  'Recorded Future': 'assets/rf.ico',
  'VirusTotal': 'assets/vt.ico',
  'AbuseIPDB': 'assets/abuseipdb.ico',
  'CentralOps.net': 'assets/centralops.ico',
  'urlscan.io (search)': 'assets/urlscan.ico',
  'urlscan.io (scan)': 'assets/urlscan.ico',
  'urlquery.net': 'assets/urlquery.ico',
  'Validin': 'assets/validin.ico',
  'SecureFeed': 'assets/securefeed.ico',
  'GreyNoise': 'assets/greynoise.ico',
  'Netify': 'assets/netify.ico',
  'ThreatFox': 'assets/abusech.ico',
  'URLhaus': 'assets/abusech.ico',
  'AlienVault OTX': 'assets/otx.ico',
  'IBM X-Force': 'assets/ibmxforce.ico',
  'ThreatBook': 'assets/threatbook.ico',
  'Cisco Talos': 'assets/talos.ico',
  'Shodan': 'assets/shodan.ico',
  'Censys': 'assets/censys.ico',
  'FOFA': 'assets/fofa.ico',
  'Netlas.io': 'assets/netlas.ico',
  'ONYPHE': 'assets/onyphe.ico',
  'IOC Radar': 'assets/socradar.ico',
  'Hybrid Analysis': 'assets/hybridanalysis.ico',
  'ANY.RUN': 'assets/anyrun.ico',
  'Joe Sandbox': 'assets/joe.ico',
  'Triage': 'assets/triage.ico',
  'CAPE Sandbox': 'assets/capesandbox.ico',
  'Criminal IP': 'assets/criminalip.ico',
  'threatYeti': 'assets/threatyeti.ico',
  'Valkyrie Verdict': 'assets/valkyrie.ico',
  'Cloudflare Radar': 'assets/cloudflare.ico',
  'CrowdSec': 'assets/crowdsec.ico',
  'Maltiverse': 'assets/maltiverse.ico',
  'Spur': 'assets/spur.ico',
  'ProxySentry': 'assets/proxysentry.ico',
  'VulDB': 'assets/vuldb.ico',
  'IPIntel.ai': 'assets/ipintel.ico',
  'IPThreat.net': 'assets/ipthreat.ico',
  'CleanTalk': 'assets/cleantalk.ico',
  'GitHub': 'assets/github.ico',
  'grep.app': 'assets/grepapp.ico',
  'Google': 'assets/google.ico',
  'Bing': 'assets/microsoft.ico',
  'Whois.com': 'assets/whois.ico',
  'BuiltWith': 'assets/builtwith.ico',
  'Netcraft': 'assets/netcraft.ico',
  'URLVoid': 'assets/urlvoid.ico',
  'Sucuri SiteCheck': 'assets/sucuri.ico',
  'Symantec WebPulse': 'assets/symantec.ico',
  'EveBox': 'assets/evebox.ico',
  'Wayback Machine': 'assets/webarchive.ico',
  'Wannabrowser': 'assets/wannabrowser.ico',
  'MalwareBazaar': 'assets/abusech.ico',
  'YARAify': 'assets/abusech.ico',
  'Kaspersky OpenTIP': 'assets/kaspersky.ico',
  'VMRay Threat Feed': 'assets/vmray.ico',
  'PolySwarm': 'assets/polyswarm.ico',
  'Malprob': 'assets/malprob.ico',
  'Threat.Zone': 'assets/threatzone.ico',
  'Neiki': 'assets/neiki.ico',
  'MetaDefender': 'assets/metadefender.ico',
  'Intezer': 'assets/intezer.ico',
  'Gridinsoft': 'assets/gridinsoft.ico',
  'Docguard': 'assets/docguard.ico',
  'YOMI': 'assets/yomi.ico',
  'ELF DIGEST': 'assets/elfdigest.ico',
  'Kunai Sandbox': 'assets/kunai.ico',
  'Koodous': 'assets/koodous.ico',
  'Gemini': 'assets/gemini.ico',
  'ChatGPT': 'assets/chatgpt.ico',
  'Mistral': 'assets/mistral.ico',
  'Exa': 'assets/exa.ico',
  'Perplexity': 'assets/perplexity.ico',
};

// ---------- Defang substitutions ---------- //
const subs = {
  '[.]': '.',
  ' .': '.',
  '[:]': ':',
  'hxxp': 'http',
  'hxxps': 'https'
};

// ---------- IOC regex patterns ---------- //
const regex_patterns = {
  IP: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/,
  Domain: /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  URL: /^https?:\/\/.+$/,
  SHA256: /^[a-fA-F0-9]{64}$/,
  url_scheme: /(?:https?:\/\/)(.+)/,
  short_url: /(https?:\/\/[^/]+)/,
  SLD: /[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/
};

// ---------- Source Categories ---------- //
const sourceCategories = {
  'Reputation & Intel': ['Recorded Future', 'VirusTotal', 'AbuseIPDB', 'CentralOps.net', 'AlienVault OTX', 'IBM X-Force', 'ThreatBook', 'Cisco Talos', 'GreyNoise', 'CrowdSec', 'Criminal IP', 'IOC Radar', 'ThreatFox', 'URLhaus', 'Maltiverse', 'Spur', 'ProxySentry', 'VulDB', 'IPIntel.ai', 'IPThreat.net', 'CleanTalk', 'Cloudflare Radar', 'SecureFeed', 'Valkyrie Verdict', 'Symantec WebPulse', 'threatYeti'],
  'Scanning & Recon': ['urlscan.io (search)', 'urlscan.io (scan)', 'urlquery.net', 'Shodan', 'Censys', 'FOFA', 'Netlas.io', 'ONYPHE', 'BuiltWith', 'Netcraft', 'Netify', 'URLVoid', 'Sucuri SiteCheck', 'Whois.com', 'Validin', 'Wannabrowser', 'EveBox', 'Wayback Machine'],
  'Sandboxes': ['Hybrid Analysis', 'ANY.RUN', 'Joe Sandbox', 'Triage', 'CAPE Sandbox', 'MalwareBazaar', 'YARAify', 'Kaspersky OpenTIP', 'VMRay Threat Feed', 'PolySwarm', 'Malprob', 'Threat.Zone', 'Neiki', 'MetaDefender', 'Intezer', 'Gridinsoft', 'Docguard', 'YOMI', 'ELF DIGEST', 'Kunai Sandbox', 'Koodous'],
  'Search Engines & LLMs': ['GitHub', 'grep.app', 'Google', 'Bing', 'Gemini', 'ChatGPT', 'Mistral', 'Exa', 'Perplexity'] 
};

// ---------- UI ---------- //
const enrichTab = document.getElementById("enrichTab");

// Header
const enrichHeader = document.createElement('h2');
enrichHeader.textContent = 'Enrich IOC';

// Help (?) button
const helpBtn = document.createElement('button');
helpBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
helpBtn.style.cssText = 'background: transparent; border: none; color: var(--ops-text-dim); cursor: pointer; padding: 2px; margin-left: 8px; vertical-align: middle; position: relative; display: inline-flex; align-items: center; opacity: 0.6; transition: opacity 0.15s ease;';
helpBtn.addEventListener('mouseenter', () => { helpBtn.style.opacity = '1'; });
helpBtn.addEventListener('mouseleave', () => { helpBtn.style.opacity = '0.6'; });

const helpTooltip = document.createElement('div');
helpTooltip.style.cssText = 'display: none; position: absolute; top: 130%; left: -8px; z-index: 100; background: var(--ops-elevated); border: 1px solid var(--ops-border-med); border-radius: var(--radius-md); padding: 16px 20px; font-size: 12px; color: var(--ops-text-muted); width: 420px; line-height: 1.7; font-weight: 400; box-shadow: 0 8px 24px rgba(0,0,0,0.4);';
helpTooltip.innerHTML = `
<div style="font-size: 13px; font-weight: 600; color: var(--ops-text); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--intel-blue)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
  Allow Pop-ups &amp; Redirects
</div>
<div style="font-size: 11.5px; color: var(--ops-text-dim); margin-bottom: 12px;">This tool opens multiple browser tabs at once. Add a pop-ups and redirects exception for <code style="font-size: 10.5px; background: var(--ops-inset); padding: 1px 4px; border-radius: 3px;">file:///&lt;path to socap-console&gt;/index.html</code></div>
<div style="display: flex; flex-direction: column; gap: 10px; font-size: 11.5px;">
  <div>
    <span style="font-weight: 600; color: var(--ops-text);">Chrome</span>
    <ol style="margin: 4px 0 0 0; padding-left: 18px; color: var(--ops-text-dim); line-height: 1.8;">
      <li>Settings → Privacy and Security → Pop-ups and redirects</li>
      <li>Add <code style="font-size: 10.5px; background: var(--ops-inset); padding: 1px 4px; border-radius: 3px;">file:///&lt;path&gt;/index.html</code> to the allowed list</li>
    </ol>
  </div>
  <div>
    <span style="font-weight: 600; color: var(--ops-text);">Edge</span>
    <ol style="margin: 4px 0 0 0; padding-left: 18px; color: var(--ops-text-dim); line-height: 1.8;">
      <li>Settings → Privacy, search, and services → Site permissions → All permissions → Pop-ups and redirects</li>
      <li>Add <code style="font-size: 10.5px; background: var(--ops-inset); padding: 1px 4px; border-radius: 3px;">file:///&lt;path&gt;/index.html</code> to the allowed list</li>
    </ol>
  </div>
  <div>
    <span style="font-weight: 600; color: var(--ops-text);">Firefox</span>
    <ol style="margin: 4px 0 0 0; padding-left: 18px; color: var(--ops-text-dim); line-height: 1.8;">
      <li>Settings → Privacy &amp; Security → Manage pop-up and third-party redirect exceptions</li>
      <li>Add <code style="font-size: 10.5px; background: var(--ops-inset); padding: 1px 4px; border-radius: 3px;">file:///&lt;path&gt;/index.html</code> to the allowed list</li>
    </ol>
  </div>
</div>`;
helpBtn.appendChild(helpTooltip);
helpBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  helpTooltip.style.display = helpTooltip.style.display === 'none' ? 'block' : 'none';
});
document.addEventListener('click', () => { helpTooltip.style.display = 'none'; });

const headerWrapper = document.createElement('div');
headerWrapper.style.display = 'flex';
headerWrapper.style.alignItems = 'center';
headerWrapper.style.marginBottom = 'var(--sp-1)';
headerWrapper.appendChild(enrichHeader);
headerWrapper.appendChild(helpBtn);
enrichTab.prepend(headerWrapper);

const enrichDesc = document.createElement('p');
enrichDesc.className = 'tab-desc';
enrichDesc.textContent = 'Enter an IOC to query across multiple threat intelligence sources. Select sources and open them all at once.';
enrichTab.insertBefore(enrichDesc, enrichTab.children[1] || null);

// IOC input box
const inputDiv = document.createElement('div');
inputDiv.style.marginBottom = 'var(--sp-4)';

const iocInputLabel_e = document.createElement('label');
iocInputLabel_e.textContent = 'IOC Input';
inputDiv.appendChild(iocInputLabel_e);

const iocInputField = document.createElement('input');
iocInputField.type = 'text';
iocInputField.id = 'iocInput';
iocInputField.placeholder = 'IP, Domain, URL, or SHA256 Hash';
inputDiv.appendChild(iocInputField);

// info string
const infoDiv = document.createElement('div');
infoDiv.id = 'iocInfo';
infoDiv.style.marginTop = 'var(--sp-1)';
infoDiv.style.fontSize = '12px';
infoDiv.style.color = 'var(--ops-text-dim)';
inputDiv.appendChild(infoDiv);

enrichTab.appendChild(inputDiv);

// Action button row (Select All / Deselect All / Open / Clear)
const actionRow = document.createElement('div');
actionRow.style.display = 'flex';
actionRow.style.gap = 'var(--sp-2)';
actionRow.style.marginBottom = 'var(--sp-4)';
actionRow.style.flexWrap = 'wrap';
actionRow.id = 'enrichActionRow';
actionRow.style.display = 'none';

const selectAllBtn = document.createElement('button');
selectAllBtn.className = 'action-button secondary';
selectAllBtn.textContent = 'Select All';
selectAllBtn.onclick = () => {
  document.querySelectorAll('#sourcesDiv .source-btn').forEach(b => b.classList.add('selected'));
};

const deselectAllBtn = document.createElement('button');
deselectAllBtn.className = 'action-button secondary';
deselectAllBtn.textContent = 'Deselect All';
deselectAllBtn.onclick = () => {
  document.querySelectorAll('#sourcesDiv .source-btn').forEach(b => b.classList.remove('selected'));
};

const launchBtn = document.createElement('button');
launchBtn.textContent = 'Open Selected';
launchBtn.className = 'action-button';

const clearBtn = document.createElement('button');
clearBtn.textContent = 'Clear';
clearBtn.className = 'action-button secondary';
clearBtn.addEventListener('click', () => {
  document.querySelectorAll('#sourcesDiv .source-btn.selected').forEach(btn => btn.classList.remove('selected'));
});

actionRow.appendChild(deselectAllBtn);
actionRow.appendChild(launchBtn);
enrichTab.appendChild(actionRow);

// Sources container
const sourcesDiv = document.createElement('div');
sourcesDiv.id = 'sourcesDiv';
sourcesDiv.style.marginTop = 'var(--sp-2)';
enrichTab.appendChild(sourcesDiv);

// ---------- Helper funcs ---------- //
function defang(ioc) {
  for (let k in subs) ioc = ioc.replaceAll(k, subs[k]);
  return ioc.trim();
}

function detectIOCtype(ioc) {
  if (regex_patterns.IP.test(ioc)) return 'IP';
  if (regex_patterns.SHA256.test(ioc)) return 'SHA256 Hash';
  if (regex_patterns.URL.test(ioc)) return 'URL';
  if (regex_patterns.Domain.test(ioc)) return 'Domain';
  return null;
}

async function url_hasher(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function renderSourceButtons(links) {
  sourcesDiv.innerHTML = '';

  // Group by category
  for (const [category, sourceNames] of Object.entries(sourceCategories)) {
    const availableSources = sourceNames.filter(name => links[name]);
    if (availableSources.length === 0) continue;

    const catSection = document.createElement('div');
    catSection.style.marginBottom = 'var(--sp-4)';

    const catLabel = document.createElement('div');
    catLabel.style.fontSize = '11px';
    catLabel.style.fontWeight = '600';
    catLabel.style.color = 'var(--ops-text-dim)';
    catLabel.style.textTransform = 'uppercase';
    catLabel.style.letterSpacing = '0.05em';
    catLabel.style.marginBottom = 'var(--sp-2)';
    catLabel.textContent = category;
    catSection.appendChild(catLabel);

    const grid = document.createElement('div');
    grid.style.display = 'grid';
    grid.style.gridTemplateColumns = 'repeat(3, 1fr)';
    grid.style.gap = 'var(--sp-1)';

    availableSources.forEach(name => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'source-btn';
      btn.dataset.url = links[name];
      btn.dataset.name = name;

      const img = document.createElement('img');
      img.src = source_icons[name] || '';
      img.alt = '';

      const text = document.createElement('span');
      text.textContent = name;
      text.style.overflow = 'hidden';
      text.style.textOverflow = 'ellipsis';
      text.style.whiteSpace = 'nowrap';

      btn.appendChild(img);
      btn.appendChild(text);

      btn.addEventListener('click', () => {
        btn.classList.toggle('selected');
      });

      grid.appendChild(btn);
    });

    catSection.appendChild(grid);
    sourcesDiv.appendChild(catSection);
  }

  // Handle uncategorized sources
  const allCategorized = new Set(Object.values(sourceCategories).flat());
  const uncategorized = Object.keys(links).filter(name => !allCategorized.has(name));
  if (uncategorized.length > 0) {
    const grid = document.createElement('div');
    grid.style.display = 'grid';
    grid.style.gridTemplateColumns = 'repeat(3, 1fr)';
    grid.style.gap = 'var(--sp-1)';
    grid.style.marginTop = 'var(--sp-2)';

    uncategorized.forEach(name => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'source-btn';
      btn.dataset.url = links[name];
      btn.dataset.name = name;

      const img = document.createElement('img');
      img.src = source_icons[name] || '';
      img.alt = '';
      const text = document.createElement('span');
      text.textContent = name;
      btn.appendChild(img);
      btn.appendChild(text);
      btn.addEventListener('click', () => btn.classList.toggle('selected'));
      grid.appendChild(btn);
    });

    sourcesDiv.appendChild(grid);
  }
}

// ---------- Events ---------- //
document.getElementById('iocInput').addEventListener('input', e => {
  const rawIOC = e.target.value;
  const ioc = defang(rawIOC);
  const iocType = detectIOCtype(ioc);

  infoDiv.textContent = iocType
    ? `Detected: ${iocType} — "${ioc}"`
    : rawIOC.trim() ? 'Could not detect IOC type' : '';

  if (iocType) {
    actionRow.style.display = 'flex';
    updateIntelStrip(ioc, iocType);
  } else {
    actionRow.style.display = 'none';
  }

  let links = {};
  if (iocType === 'IP') links = ip_links;
  else if (iocType === 'Domain') links = domain_links;
  else if (iocType === 'URL') links = url_links;
  else if (iocType === 'SHA256 Hash') links = hash_links;

  if (iocType) {
    renderSourceButtons(links);
  } else {
    sourcesDiv.innerHTML = '';
  }
});

// ---------- Open selected sources ---------- //
launchBtn.addEventListener('click', async () => {
  const ioc = defang(document.getElementById('iocInput').value);
  const iocType = detectIOCtype(ioc);
  if (!iocType) { showToast('Invalid IOC', 'error'); return; }

  const selected = Array.from(
    document.querySelectorAll('#sourcesDiv .source-btn.selected')
  );
  if (!selected.length) { showToast('Select at least one source', 'error'); return; }

  showToast(`Opening ${selected.length} source(s)...`, 'info');

  for (const btn of selected) {
    let url = btn.dataset.url;
    const sourceName = btn.dataset.name;

    // IP edge case
    if (iocType === 'IP' && sourceName === 'FOFA') {
      const b64 = btoa(ioc).replace('=', '%3D');
      url = url.replace('{ioc}', b64);
    }

    // Domain edge cases
    if (iocType === 'Domain' && ['Valkyrie Verdict', 'URLVoid'].includes(sourceName)) {
      const sld = ioc.match(regex_patterns.SLD)[0];
      url = url.replace('{ioc}', sld);
    }

    // URL edge cases
    if (iocType === 'URL') {
      if (sourceName === 'URLhaus') {
        const urlScheme = ioc.match(regex_patterns.url_scheme)[1];
        url = url.replace('{ioc}', urlScheme);
      }
      else if (sourceName === 'urlscan.io (search)') {
        const escaped = ioc.replace(/:/g, '\\:').replace(/\//g, '\\/');
        url = url.replace('{ioc}', escaped);
      }
      else if (sourceName === 'VirusTotal') {
        const url_hash = await url_hasher(ioc);
        url = url.replace('{ioc}', url_hash);
      }
    }

    // For URL IOCs, encode the IOC for safe substitution into query strings
    const finalIoc = iocType === 'URL' ? encodeURIComponent(ioc) : ioc;
    window.open(url.replace('{ioc}', finalIoc), '_blank');
    await new Promise(r => setTimeout(r, 250));
  }
});