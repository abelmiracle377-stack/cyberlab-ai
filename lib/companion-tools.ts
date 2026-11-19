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

// Ignore the optional ports helper unless a port scan path uses it later.
export const __internal = { extractPorts };
