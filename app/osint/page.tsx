"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Search, ShieldCheck, Globe2, AlertTriangle, ExternalLink } from "lucide-react";
type Result = { domain: string; registration: null | { domain: string; status: string[]; events: {action:string;date:string}[]; nameservers: string[]; registrar: string | null }; certificates: { commonName: string; issuer: string; notBefore: string; notAfter: string }[]; errors: string[]; sources: { name: string; url: string; description: string }[]; note: string };
export default function OsintPage() {
 const [domain,setDomain]=useState(""); const [result,setResult]=useState<Result|null>(null); const [error,setError]=useState(""); const [busy,setBusy]=useState(false);
 async function lookup(event: React.FormEvent) {
  event.preventDefault(); setBusy(true); setError(""); setResult(null);
  try { const response=await fetch("/api/osint/domain",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain})}); const data=await response.json(); if(!response.ok) throw new Error(data.error||"Lookup failed."); setResult(data); }
  catch(cause) { setError(cause instanceof Error?cause.message:"Unexpected lookup error."); } finally { setBusy(false); }
 }
 return <main className="agent-shell">
  <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Globe2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> OSINT</div><span className="agent-secure-label"><span/> PASSIVE PUBLIC SOURCES</span></header>
  <section className="agent-main">
   <div className="agent-heading"><div className="agent-overline">PUBLIC INTELLIGENCE / 003</div><h1>Domain intelligence</h1><p>Review public registration events, nameservers and certificate transparency records for a domain.</p></div>
   <form className="osint-search" onSubmit={lookup}><label htmlFor="osint-domain">Domain name</label><div><input id="osint-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" autoComplete="off"/><button disabled={busy||!domain.trim()}><Search size={14}/>{busy?"Searching…":"Research domain"}</button></div><small>Use a domain you own or are authorised to investigate. No port scans or login attempts are performed.</small></form>
   {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
   {result&&<>
    {result.errors.length>0&&<div className="agent-error"><AlertTriangle size={14}/>{result.errors.join(" ")}</div>}
    <div className="osint-section"><div className="osint-section-head"><h2>Registration intelligence</h2><span>{result.domain}</span></div>
     {result.registration?<><div className="osint-kv"><span>Registered domain</span><strong>{result.registration.domain}</strong></div><div className="osint-kv"><span>Registrar</span><strong>{result.registration.registrar||"Not disclosed"}</strong></div><div className="osint-kv"><span>Domain status</span><strong>{result.registration.status.join(", ")||"Not reported"}</strong></div>
      <h3>Registration events</h3>{result.registration.events.length?result.registration.events.map((item,index)=><div className="osint-row" key={index}><span>{item.action.replaceAll("_"," ")}</span><time>{item.date}</time></div>):<p>No registration events returned.</p>}
      <h3>Nameservers</h3><div className="osint-chips">{result.registration.nameservers.length?result.registration.nameservers.map(ns=><span key={ns}>{ns}</span>):<span>None returned</span>}</div></>:<p>Registration information was not available from the RDAP service.</p>}
    </div>
    <div className="osint-section"><div className="osint-section-head"><h2>Certificate transparency</h2><span>{result.certificates.length} names shown</span></div><p>Public certificate records can reveal hostnames included in certificates. They do not establish that a host is currently online.</p>
     {result.certificates.length?<div className="osint-certs">{result.certificates.map((cert,index)=><div className="osint-cert" key={index}><strong>{cert.commonName}</strong><span>Issuer: {cert.issuer||"Not reported"}</span><small>{cert.notBefore||"Unknown start"} — {cert.notAfter||"Unknown expiry"}</small></div>)}</div>:<p>No matching certificate records returned.</p>}
    </div>
    <div className="osint-section"><h2>Sources</h2>{result.sources.map(source=><a className="osint-source" href={source.url} target="_blank" rel="noreferrer" key={source.name}><span><strong>{source.name}</strong><small>{source.description}</small></span><ExternalLink size={13}/></a>)}</div>
    <p className="network-note"><ShieldCheck size={13}/>{result.note}</p>
   </>}
   <div className="agent-disclaimer"><ShieldCheck size={12}/> Passive public-source lookups only. Do not use findings to identify or target private individuals.</div>
  </section>
 </main>;
}
