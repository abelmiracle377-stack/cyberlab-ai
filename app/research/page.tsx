"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Search, ExternalLink, ShieldCheck, AlertTriangle, LoaderCircle, Globe2 } from "lucide-react";

type ResearchResult = { answer: string; citations: string[]; results: { title?: string; url?: string; date?: string; snippet?: string }[]; source: string; note: string };

export default function LiveResearchPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<ResearchResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function search(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/research/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Live research failed.");
      setResult(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unexpected research error."); }
    finally { setBusy(false); }
  }

  const links = result ? [...new Set([...(result.results || []).map((item) => item.url || ""), ...(result.citations || [])])].filter((url) => /^https:\/\//i.test(url)) : [];

  return <main className="agent-shell">
    <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Globe2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> LIVE RESEARCH</div><span className="agent-secure-label"><span/> WEB-CONNECTED</span></header>
    <section className="agent-main">
      <div className="agent-heading"><div className="agent-overline">PUBLIC-SOURCE INTELLIGENCE / 010</div><h1>Live security research</h1><p>Search current public advisories, CVEs, vendor bulletins, project documentation and security news.</p></div>
      <form className="osint-search" onSubmit={search}>
        <label htmlFor="research-query">Research question</label>
        <div><Search size={15}/><input id="research-query" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Latest OpenSSH security advisories and affected versions" required minLength={4} maxLength={1200}/><button disabled={busy || query.trim().length < 4}>{busy ? <><LoaderCircle size={13}/> Searching…</> : "Search web"}</button></div>
        <small>Powered by Perplexity Sonar through your existing OpenRouter key. Web-search usage may incur provider charges.</small>
      </form>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {result && <>
        <div className="network-results"><h2>Research findings</h2><p style={{ whiteSpace: "pre-wrap", color: "#d0dcd3", lineHeight: 1.9 }}>{result.answer}</p><p>{result.source}</p></div>
        <div className="network-results"><h2>Sources and citations</h2>{links.length ? <div className="cve-links">{links.map((url) => <a key={url} href={url} target="_blank" rel="noreferrer">{new URL(url).hostname} <ExternalLink size={10}/></a>)}</div> : <p>No source URLs were returned. Verify the answer independently.</p>}<p>{result.note}</p></div>
      </>}
      <div className="agent-disclaimer"><ShieldCheck size={12}/> Public web research only. Search snippets and AI summaries are not proof; verify security-critical claims against original vendor and maintainer sources.</div>
    </section>
  </main>;
}
