"use client";
import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Globe2, Search, ShieldCheck, AlertTriangle, Network } from "lucide-react";
type Result={ip:string;version:string;location:{continent:string|null;country:string|null;region:string|null;city:string|null;latitude:number|null;longitude:number|null};network:{asn:number|null;org:string|null;isp:string|null;domain:string|null};timezone:string|null;reverseDns:string[];note:string};
export default function IpIntelligencePage(){
 const [ip,setIp]=useState("");const [result,setResult]=useState<Result|null>(null);const [error,setError]=useState("");const [busy,setBusy]=useState(false);
 async function lookup(event:React.FormEvent){event.preventDefault();setBusy(true);setError("");setResult(null);try{const response=await fetch("/api/intelligence/ip",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Lookup failed.");setResult(data);}catch(cause){setError(cause instanceof Error?cause.message:"Unexpected lookup error.");}finally{setBusy(false);}}
 const coordinates=result&&result.location.latitude!==null&&result.location.longitude!==null?String(result.location.latitude)+", "+String(result.location.longitude):null;
 return <main className="agent-shell"><header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Globe2 size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> IP INTELLIGENCE</div><span className="agent-secure-label"><span/> PASSIVE LOOKUP</span></header>
 <section className="agent-main"><div className="agent-heading"><div className="agent-overline">NETWORK INTELLIGENCE / 006</div><h1>IP intelligence</h1><p>Look up public IP registration, ASN, ISP, approximate region and reverse DNS.</p></div>
 <form className="osint-search" onSubmit={lookup}><label htmlFor="ip-query">Public IP address</label><div><input id="ip-query" value={ip} onChange={e=>setIp(e.target.value)} placeholder="Enter a public IP address" autoComplete="off"/><button disabled={busy||!ip.trim()}><Search size={14}/>{busy?"Looking up…":"Lookup IP"}</button></div><small>Private, loopback, link-local and reserved addresses are rejected.</small></form>
 {error&&<div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
 {result&&<><div className="ip-result-head"><div><span>LOOKUP RESULT</span><h2>{result.ip}</h2></div><span>{result.version}</span></div>
 <div className="ip-grid"><section className="osint-section"><h2><Globe2 size={13}/> Approximate location</h2>{[["Country",result.location.country],["Region",result.location.region],["City",result.location.city],["Continent",result.location.continent],["Coordinates",coordinates],["Timezone",result.timezone]].map(([k,v])=><div className="osint-kv" key={k}><span>{k}</span><strong>{v||"Not reported"}</strong></div>)}</section>
 <section className="osint-section"><h2><Network size={13}/> Network ownership</h2>{[["ASN",result.network.asn?"AS"+result.network.asn:null],["Organisation",result.network.org],["ISP",result.network.isp],["Network domain",result.network.domain]].map(([k,v])=><div className="osint-kv" key={k}><span>{k}</span><strong>{v||"Not reported"}</strong></div>)}<h3>Reverse DNS (PTR)</h3>{result.reverseDns.length?result.reverseDns.map(x=><div className="osint-row" key={x}><span>{x}</span></div>):<p>No PTR hostname was returned.</p>}</section></div>
 <p className="network-note"><ShieldCheck size={13}/>{result.note}</p></>}
 <div className="agent-disclaimer"><ShieldCheck size={12}/> Passive public metadata only. This lookup cannot identify a private subscriber or determine a device's exact location.</div>
 </section></main>;
}
