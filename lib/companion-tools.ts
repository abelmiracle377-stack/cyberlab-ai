// Maps a natural-language instruction to a concrete companion tool request so the
// agent console can offer to run it on the user's own paired machine. This only
// proposes a request; execution still goes through explicit approval and the
// companion's own validation. nmap keeps its existing dedicated scan flow and is
// intentionally not handled here.

export type CompanionToolRequest = {
  tool: string;
  label: string;
  parameters: Record<string, string | number>;
  active: boolean;
  targetParam?: string;
  // Parameters the operator still has to supply before the run can start.
  missing: string[];
};

const HOST = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b/i;
const IPV4 = /\b((?:\d{1,3}\.){3}\d{1,3})\b/;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/i;

function extractUrl(text: string): string | null {
  const match = text.match(URL_RE);
  return match ? match[0].replace(/[),.]+$/, "") : null;
}

function extractHost(text: string): string | null {
  const urlMatch = text.match(URL_RE);
  if (urlMatch) {
    try { return new URL(urlMatch[0]).hostname; } catch { /* fall through */ }
  }
  const ip = text.match(IPV4);
  if (ip) return ip[1];
  const host = text.match(HOST);
  return host ? host[1] : null;
}

function extractPorts(text: string): string | null {
  const match = text.match(/\bports?\s+([0-9][0-9,\-\s]*)/i);
  if (!match) return null;
  const spec = match[1].replace(/\s+/g, "");
  return /^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$/.test(spec) ? spec : null;
}

function extractWordlist(text: string): string | null {
  const match = text.match(/(\/[^\s"']+\.(?:txt|lst|dic|wordlist)|\/[^\s"']*(?:wordlist|rockyou|seclists)[^\s"']*)/i);
  return match ? match[1] : null;
}

function extractSinglePort(text: string): number | null {
  const match = text.match(/\bport\s+(\d{1,5})\b|:(\d{1,5})\b/i);
  if (!match) return null;
  const port = Number(match[1] || match[2]);
  return port >= 1 && port <= 65535 ? port : null;
}

function extractSearchTerm(text: string): string | null {
  // Prefer a concrete identifier (CVE or MS advisory) when present.
  const cve = text.match(/\b(CVE-\d{4}-\d{4,7}|ms\d{2}-\d{3})\b/i);
  if (cve) return cve[1];
  // Otherwise take the keyword(s) after a search-style verb and drop filler words.
  const match = text.match(/\b(?:search|find|look\s+up)\s+(.+)$/i);
  if (!match) return null;
  const cleaned = match[1]
    .replace(/\b(?:for|in|the|a|an|metasploit|msf|msfconsole|module|modules|exploit|exploits)\b/gi, " ")
    .replace(/[^A-Za-z0-9 _/.:+-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length >= 2 ? cleaned : null;
}

export function planCompanionToolRequest(prompt: string): CompanionToolRequest | null {
  if (typeof prompt !== "string" || !prompt.trim()) return null;
  const text = prompt.toLowerCase();

  // gobuster — directory/content discovery (check before generic web verbs).
  if (/\bgobuster\b|\b(?:directory|content|dir)\s+(?:brute|busting|discovery|enum)/.test(text)) {
    const url = extractUrl(prompt);
    const wordlist = extractWordlist(prompt);
    if (url) {
      const parameters: Record<string, string | number> = { url, threads: 10 };
      if (wordlist) parameters.wordlist = wordlist;
      return { tool: "gobuster-dir", label: "Directory discovery (gobuster)", parameters,
        active: true, targetParam: "url", missing: wordlist ? [] : ["wordlist"] };
    }
  }

  // wpscan — WordPress enumeration.
  if (/\bwpscan\b|wordpress\s+(?:scan|enum)/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "wpscan", label: "WordPress enumeration (wpscan)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // nuclei — template-based checks.
  if (/\bnuclei\b/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "nuclei", label: "Template checks (nuclei)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // wafw00f — WAF detection.
  if (/\bwafw00f\b|detect\s+waf|web\s+application\s+firewall/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "wafw00f", label: "WAF detection (wafw00f)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // ffuf — web fuzzing.
  if (/\bffuf\b|web\s+fuzz/.test(text)) {
    const url = extractUrl(prompt);
    const wordlist = extractWordlist(prompt);
    if (url) {
      const parameters: Record<string, string | number> = { url, threads: 20 };
      if (wordlist) parameters.wordlist = wordlist;
      return { tool: "ffuf", label: "Web content fuzzing (ffuf)", parameters,
        active: true, targetParam: "url", missing: wordlist ? [] : ["wordlist"] };
    }
  }

  // SMB / NetBIOS / SSH enumeration.
  if (/\benum4linux\b|smb\s+enum/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "enum4linux-ng", label: "SMB enumeration (enum4linux-ng)",
      parameters: { host }, active: true, targetParam: "host", missing: [] };
  }
  if (/\bsmbmap\b|smb\s+shares/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "smbmap", label: "SMB share enumeration (smbmap)",
      parameters: { host }, active: true, targetParam: "host", missing: [] };
  }
  if (/\bnbtscan\b|netbios/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "nbtscan", label: "NetBIOS scan (nbtscan)",
      parameters: { host }, active: true, targetParam: "host", missing: [] };
  }
  if (/\bssh[-\s]?audit\b|audit\s+ssh/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "ssh-audit", label: "SSH configuration audit (ssh-audit)",
      parameters: { host }, active: true, targetParam: "host", missing: [] };
  }

  // Passive DNS/OSINT recon tools.
  if (/\bdnsenum\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "dnsenum", label: "DNS enumeration (dnsenum)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bfierce\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "fierce", label: "DNS recon (fierce)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bsublist3r\b|subdomain(?:s)?\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "sublist3r", label: "Subdomain enumeration (sublist3r)", parameters: { host }, active: false, missing: [] };
  }
  if (/\btheharvester\b|\bharvester\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "theharvester", label: "OSINT discovery (theHarvester)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bdig\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "dig", label: "DNS A-record lookup (dig)", parameters: { host }, active: false, missing: [] };
  }

  // feroxbuster — content discovery (check before generic web verbs).
  if (/\bferoxbuster\b|\bferox\b/.test(text)) {
    const url = extractUrl(prompt);
    const wordlist = extractWordlist(prompt);
    if (url) {
      const parameters: Record<string, string | number> = { url, threads: 10 };
      if (wordlist) parameters.wordlist = wordlist;
      return { tool: "feroxbuster", label: "Content discovery (feroxbuster)", parameters,
        active: true, targetParam: "url", missing: wordlist ? [] : ["wordlist"] };
    }
  }

  // dalfox — XSS testing.
  if (/\bdalfox\b|\bxss\b/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "dalfox", label: "Reflected-XSS test (dalfox)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // httpx / katana — web probe / crawl.
  if (/\bhttpx\b|probe\s+(?:the\s+)?url/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "httpx", label: "URL probe (httpx)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }
  if (/\bkatana\b|crawl\s+(?:the\s+)?(?:site|url)/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "katana", label: "Crawl (katana)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // naabu — fast port scan.
  if (/\bnaabu\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "naabu", label: "Fast port scan (naabu)", parameters: { host },
      active: true, targetParam: "host", missing: [] };
  }

  // sslyze / testssl — TLS analysis.
  if (/\bsslyze\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "sslyze", label: "TLS analysis (sslyze)", parameters: { host },
      active: true, targetParam: "host", missing: [] };
  }
  if (/\btestssl\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "testssl", label: "TLS assessment (testssl.sh)", parameters: { host },
      active: true, targetParam: "host", missing: [] };
  }

  // amass / subfinder / assetfinder / gau — passive subdomain & URL OSINT.
  if (/\bamass\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "amass", label: "Attack-surface OSINT (amass)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bsubfinder\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "subfinder", label: "Subdomain discovery (subfinder)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bassetfinder\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "assetfinder", label: "Subdomain discovery (assetfinder)", parameters: { host }, active: false, missing: [] };
  }
  if (/\bgau\b|wayback\s+urls?/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "gau", label: "Archived URL discovery (gau)", parameters: { host }, active: false, missing: [] };
  }

  // sqlmap — SQL injection testing.
  if (/\bsqlmap\b|sql\s*injection|sqli\b/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "sqlmap", label: "SQL-injection test (sqlmap, level 1)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // metasploit module search (metadata only, no target).
  if (/\b(?:metasploit|msfconsole|msf)\b|search\s+(?:exploit|module)/.test(text)) {
    const query = extractSearchTerm(prompt);
    if (query) return { tool: "metasploit-search", label: "Metasploit module search", parameters: { query },
      active: false, missing: [] };
  }

  // anonymous FTP listing.
  if (/\bftp\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "ftp-anon", label: "Anonymous FTP listing", parameters: { host },
      active: true, targetParam: "host", missing: [] };
  }

  // netcat banner grab — host + port.
  if (/\b(?:netcat|\bnc\b|banner\s*grab)\b/.test(text)) {
    const host = extractHost(prompt);
    const port = extractSinglePort(prompt);
    if (host && port) return { tool: "netcat-banner", label: "Service banner grab (netcat)",
      parameters: { host, port }, active: true, targetParam: "host", missing: [] };
  }

  // sslscan — TLS review.
  if (/\bsslscan\b|tls\s+(?:scan|review|check)|ssl\s+(?:scan|check)/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "sslscan", label: "TLS review (sslscan)", parameters: { host },
      active: true, targetParam: "host", missing: [] };
  }

  // masscan — fast port discovery.
  if (/\bmasscan\b/.test(text)) {
    const host = extractHost(prompt);
    const ports = extractPorts(prompt) || "1-1000";
    if (host) return { tool: "masscan", label: "Fast port discovery (masscan)",
      parameters: { host, ports, rate: 1000 }, active: true, targetParam: "host", missing: [] };
  }

  // nikto — web server checks.
  if (/\bnikto\b|web\s+server\s+(?:scan|check)/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "nikto", label: "Web server checks (nikto)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // whatweb — technology fingerprint.
  if (/\bwhatweb\b|fingerprint|what\s+(?:web|tech)/.test(text)) {
    const url = extractUrl(prompt);
    if (url) return { tool: "whatweb", label: "Web technology fingerprint (whatweb)", parameters: { url },
      active: true, targetParam: "url", missing: [] };
  }

  // dnsrecon — DNS enumeration.
  if (/\bdnsrecon\b|\bdns\s+(?:recon|records?|enum)/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "dnsrecon", label: "DNS enumeration (dnsrecon)", parameters: { host },
      active: false, missing: [] };
  }

  // whois — registration lookup (passive).
  if (/\bwhois\b/.test(text)) {
    const host = extractHost(prompt);
    if (host) return { tool: "whois", label: "Registration lookup (whois)", parameters: { host },
      active: false, missing: [] };
  }

  return null;
}
