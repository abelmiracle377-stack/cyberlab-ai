"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Search, ShieldCheck, Globe2, AlertTriangle, ExternalLink, Network } from "lucide-react";
type DnsResult = { domain: string; records: Record<string, unknown>; source: string; note: string };
type Result = { domain: string; registration: null | { domain: string; status: string[]; events: {action:string;date:string}[]; nameservers: string[]; registrar: string | null }; certificates: { commonName: string; issuer: string; notBefore: string; notAfter: string }[]; errors: string[]; sources: { name: string; url: string; description: string }[]; note: string };
export default function OsintPage() {
 const [domain,setDomain]=useState(""); const [result,setResult]=useState<Result|null>(null); const [error,setError]=useState(""); const [busy,setBusy]=useState(false);
 const [dnsDomain,setDnsDomain]=useState(""); const [dnsResult,setDnsResult]=useState<DnsResult|null>(null); const [dnsError,setDnsError]=useState(""); const [dnsBusy,setDnsBusy]=useState(false);
 async function lookupDns(event: React.FormEvent) {
  event.preventDefault(); setDnsBusy(true); setDnsError(""); setDnsResult(null);
  try { const response=await fetch("/api/osint/dns",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:dnsDomain})}); const data=await response.json(); if(!response.ok) throw new Error(data.error||"DNS lookup failed."); setDnsResult(data); }
  catch(cause) { setDnsError(cause instanceof Error?cause.message:"Unexpected DNS lookup error."); } finally { setDnsBusy(false); }
 }
 async function lookup(event: React.FormEvent) {
  event.preventDefault(); setBusy(true); setError(""); setResult(null);
  try { const response=await fetch("/api/osint/domain",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain})}); const data=await response.json(); if(!response.ok) throw new Error(data.error||"Lookup failed."); setResult(data); }
  catch(cause) { setError(cause instanceof Error?cause.message:"Unexpected lookup error."); } finally { setBusy(false); }
 }
 return <main className="agent-shell">
  <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Globe2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> OSINT</div><span className="agent-secure-label"><span/> PASSIVE PUBLIC SOURCES</span></header>
  <section className="agent-main">
   <div className="agent-heading"><div className="agent-overline">PUBLIC INTELLIGENCE / 003</div><h1>OSINT workspace</h1><p>Investigate public domain registration, DNS records and certificate transparency. Enter the target yourself; nothing is pre-filled.</p></div>
  <div className="agent-config"><Link className="agent-back" href="/ip-intelligence"><Globe2 size={14}/> IP intelligence</Link><Link className="agent-back" href="/agent"><Network size={14}/> AI research agent</Link></div>
  <div className="osint-section"><h2>DNS record lookup</h2><p>Resolve public A, AAAA, MX, NS and TXT records for a domain.</p><form className="osint-search" onSubmit={lookupDns}><label htmlFor="dns-domain">Domain name</label><div><input id="dns-domain" value={dnsDomain} onChange={e=>setDnsDomain(e.target.value)} placeholder="Enter a domain (e.g. example.com)" autoComplete="off"/><button disabled={dnsBusy||!dnsDomain.trim()}><Search size={14}/>{dnsBusy?"Resolving…":"Lookup DNS"}</button></div></form>{dnsError&&<div className="agent-error"><AlertTriangle size={14}/>{dnsError}</div>}{dnsResult&&<><div className="osint-kv"><span>Domain</span><strong>{dnsResult.domain}</strong></div>{Object.entries(dnsResult.records).map(([type,value])=><div className="osint-kv" key={type}><span>{type} records</span><strong>{Array.isArray(value)?(value.length?value.map(item=>typeof item==="string"?item:JSON.stringify(item)).join(" · "):"No records returned"):JSON.stringify(value)}</strong></div>)}<p className="network-note"><ShieldCheck size={13}/>{dnsResult.note}</p></>}</div>
   <form className="osint-search" onSubmit={lookup}><label htmlFor="osint-domain">Domain name</label><div><input id="osint-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" autoComplete="off"/><button disabled={busy||!domain.trim()}><Search size={14}/>{busy?"Searching…":"Research domain"}</button></div><small>Enter a domain name. This lookup uses public RDAP and certificate-transparency sources; no port scans or login attempts are performed.</small></form>
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
