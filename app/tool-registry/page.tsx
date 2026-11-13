"use client";
import { useEffect,useState } from "react";
import { ArrowLeft,RefreshCw,ShieldCheck,Activity,ExternalLink } from "lucide-react";
type Tool={id:string;name:string;category:string;description:string;state:"operational"|"configured"|"partial"|"requires-setup"|"planned";route:string;permission:string;dependency?:string};
const labels:Record<Tool["state"],string>={operational:"OPERATIONAL",configured:"CONFIGURED",partial:"PARTIAL", "requires-setup":"REQUIRES SETUP",planned:"PLANNED"};
export default function ToolRegistryPage(){
 const [tools,setTools]=useState<Tool[]>([]);const [loading,setLoading]=useState(true);const [error,setError]=useState("");
 async function load(){setLoading(true);setError("");try{const r=await fetch("/api/tool-registry",{cache:"no-store"});const d=await r.json();if(!r.ok)throw new Error(d.error||"Registry unavailable");setTools(d.tools||[])}catch(e){setError((e as Error).message)}finally{setLoading(false)}}
 useEffect(()=>{void load()},[]);
 const counts=tools.reduce((a,t)=>(a[t.state]=(a[t.state]||0)+1,a),{} as Record<string,number>);
 return <main className="tool-registry-page"><a href="/" className="connection-link"><ArrowLeft size={13}/> COMMAND CENTER</a><div className="eyebrow" style={{marginTop:30}}>OPERATIONS // TOOL DISCOVERY</div><div className="registry-heading"><div><h1>Tool Registry<span className="heading-cursor">_</span></h1><p>Capability inventory · dependency state · permission boundary</p></div><button className="registry-refresh" onClick={()=>void load()}><RefreshCw size={13}/> REFRESH</button></div>
 <div className="registry-counts">{(["operational","configured","partial","requires-setup","planned"] as const).map(s=><div key={s}><span>{labels[s]}</span><b>{counts[s]||0}</b></div>)}</div>
 {error&&<div className="registry-error">{error}</div>}{loading?<p className="registry-loading">QUERYING LOCAL CAPABILITY REGISTRY...</p>:<div className="registry-list">{tools.map(t=><article className="registry-item" key={t.id}><div className="registry-item-main"><div className="registry-item-title">{t.name}<span className={`registry-state state-${t.state}`}>{labels[t.state]}</span></div><p>{t.description}</p><div className="registry-meta"><span>{t.category}</span><span>PERMISSION: {t.permission.toUpperCase()}</span>{t.dependency&&<span>DEPENDENCY: {t.dependency}</span>}</div></div><a href={t.route} aria-label={`Open ${t.name}`}><ExternalLink size={14}/></a></article>)}</div>}
 <div className="registry-foot"><ShieldCheck size={14}/> States reflect implemented code and known configuration requirements. Planned entries are not executable integrations.</div></main>
}
