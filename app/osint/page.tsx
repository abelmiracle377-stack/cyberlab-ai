"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Search, Fingerprint, ShieldCheck, AlertTriangle, Globe2, Server, CalendarDays, FileText } from "lucide-react";

type Result = {
  domain: string;
  rdap: { available: boolean; error?: string; handle?: string | null; registrar?: string | null; created?: string | null; updated?: string | null; expires?: string | null; nameservers?: string[]; statuses?: string[] };
  certificates: { available: boolean; error?: string; names?: string[]; totalUnique?: number };
  sources: string[];
  privacy: string;
  disclaimer: string;
};

function date(value?: string | null) {
  if (!value) return "Not disclosed";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleDateString();
}

export default function OsintPage() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function search(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch(`/api/osint/domain?domain=${encodeURIComponent(domain)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "OSINT lookup failed.");
      setResult(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unexpected lookup error.");
    } finally { setBusy(false); }
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
      <div className="agent-brand"><Fingerprint size={16} /> CYBERLAB AI <span className="agent-top-sep">/</span> OSINT</div>
      <span className="agent-secure-label"><span /> PUBLIC SOURCES</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">OPEN-SOURCE INTELLIGENCE / 003</div>
        <h1>Domain intelligence</h1>
        <p>Review public registration metadata and certificate-transparency observations for a domain.</p>
      </div>
      <form className="osint-search" onSubmit={search}>
        <label htmlFor="osint-domain">Domain name</label>
        <div><Globe2 size={15}/><input id="osint-domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" autoComplete="off" required/><button disabled={busy || !domain.trim()}>{busy ? "Searching…" : <><Search size={13}/> Investigate</>}</button></div>
        <small>Enter a domain you own or are authorised to assess. Do not enter URLs, IP addresses or personal information.</small>
      </form>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {result && <>
        <div className="osint-result-head"><div><div className="agent-overline">INVESTIGATION TARGET</div><h2>{result.domain}</h2></div><span className="osint-public-tag">PUBLIC DATA ONLY</span></div>
        <div className="osint-grid">
          <section className="network-results">
            <h2><Server size={14}/> Registration data (RDAP)</h2>
            {result.rdap.available ? <>
              <div className="osint-kv"><span>Registrar</span><strong>{result.rdap.registrar || "Not disclosed"}</strong></div>
              <div className="osint-kv"><span>Registry handle</span><strong>{result.rdap.handle || "Not disclosed"}</strong></div>
              <div className="osint-kv"><span>Registered</span><strong>{date(result.rdap.created)}</strong></div>
              <div className="osint-kv"><span>Last updated</span><strong>{date(result.rdap.updated)}</strong></div>
              <div className="osint-kv"><span>Expires</span><strong>{date(result.rdap.expires)}</strong></div>
              <h3>Nameservers</h3>{result.rdap.nameservers?.length ? result.rdap.nameservers.map((name) => <div className="osint-chip" key={name}>{name}</div>) : <p>None published.</p>}
              <h3>Registry status</h3>{result.rdap.statuses?.length ? result.rdap.statuses.map((status) => <div className="osint-chip" key={status}>{status}</div>) : <p>No status values published.</p>}
            </> : <p>Registration lookup unavailable: {result.rdap.error}</p>}
          </section>
          <section className="network-results">
            <h2><FileText size={14}/> Certificate transparency</h2>
            {result.certificates.available ? <>
              <div className="osint-count"><strong>{result.certificates.totalUnique}</strong><span>unique DNS names observed</span></div>
              {result.certificates.names?.length ? result.certificates.names.map((name) => <div className="osint-chip" key={name}>{name}</div>) : <p>No matching certificate names returned.</p>}
            </> : <p>Certificate lookup unavailable: {result.certificates.error}</p>}
          </section>
        </div>
        <div className="network-results osint-source-list"><h2><CalendarDays size={14}/> Sources and limitations</h2><p>{result.sources.join(" · ")}</p><p>{result.privacy}</p><p>{result.disclaimer}</p></div>
      </>}
      <div className="agent-disclaimer"><ShieldCheck size={12}/> Public-source domain research only. No account enumeration, private registrant identity disclosure, port scanning or exploitation.</div>
    </section>
  </main>;
}
