"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Plus, RefreshCw, ShieldCheck, Activity, FileText } from "lucide-react";

type Event = { id:string; source:string; event_type:string; severity:string; title:string; details:Record<string,unknown>; occurred_at:string };
type Case = { id:string; title:string; status:string; severity:string; summary:string; scope:string; tags:string[]; created_at:string; updated_at:string; investigation_events?:Event[] };

export default function InvestigationsPage(){
 const [cases,setCases]=useState<Case[]>([]); const [selected,setSelected]=useState("");
 const [title,setTitle]=useState(""); const [summary,setSummary]=useState(""); const [scope,setScope]=useState(""); const [severity,setSeverity]=useState("medium");
 const [eventTitle,setEventTitle]=useState(""); const [eventSource,setEventSource]=useState("CyberLab Analyst"); const [eventType,setEventType]=useState("analyst_note"); const [eventSeverity,setEventSeverity]=useState("informational"); const [eventDetails,setEventDetails]=useState("{}");
 const [error,setError]=useState(""); const [message,setMessage]=useState(""); const [busy,setBusy]=useState(false);
 const current=cases.find(c=>c.id===selected)||null;
 const load=useCallback(async()=>{setBusy(true);setError("");try{const r=await fetch("/api/investigations",{cache:"no-store"});const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not load cases.");setCases(d.cases||[]);if(selected&&!d.cases?.some((c:Case)=>c.id===selected))setSelected("");}catch(e){setError(e instanceof Error?e.message:"Could not load cases.");}finally{setBusy(false);}},[selected]);
 useEffect(()=>{void load();},[load]);
 async function createCase(e:React.FormEvent){e.preventDefault();setBusy(true);setError("");setMessage("");try{const r=await fetch("/api/investigations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title,summary,scope,severity})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not create case.");setTitle("");setSummary("");setScope("");setCases(v=>[d.case,...v]);setSelected(d.case.id);setMessage("Investigation case created.");}catch(e){setError(e instanceof Error?e.message:"Could not create case.");}finally{setBusy(false);}}
 async function addEvent(e:React.FormEvent){e.preventDefault();if(!current)return;setBusy(true);setError("");setMessage("");try{let details:Record<string,unknown>;try{details=JSON.parse(eventDetails);}catch{throw new Error("Event details must be valid JSON.");}const r=await fetch("/api/investigations/"+current.id+"/events",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:eventTitle,source:eventSource,event_type:eventType,severity:eventSeverity,details})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not add event.");setCases(v=>v.map(c=>c.id===current.id?{...c,investigation_events:[d.event,...(c.investigation_events||[])]}:c));setEventTitle("");setMessage("Timeline event added.");}catch(e){setError(e instanceof Error?e.message:"Could not add event.");}finally{setBusy(false);}}
 async function updateStatus(status:string){if(!current)return;setBusy(true);setError("");try{const r=await fetch("/api/investigations",{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:current.id,status})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Update failed.");setCases(v=>v.map(c=>c.id===current.id?{...c,...d.case}:c));setMessage("Case status updated.");}catch(e){setError(e instanceof Error?e.message:"Update failed.");}finally{setBusy(false);}}
 function exportCase(){if(!current)return;const lines=["# "+current.title,"","Case: "+current.id,"Severity: "+current.severity,"Status: "+current.status,"Summary: "+current.summary,"Scope: "+current.scope,"","## Timeline"];for(const ev of current.investigation_events||[]){lines.push("### "+ev.title,"- "+ev.source+" / "+ev.event_type+" / "+ev.severity,"- "+new Date(ev.occurred_at).toISOString(),JSON.stringify(ev.details,null,2),"");}const url=URL.createObjectURL(new Blob([lines.join("\n")],{type:"text/markdown"}));const a=document.createElement("a");a.href=url;a.download="investigation-"+current.id+".md";a.click();URL.revokeObjectURL(url);}
 return <main className="agent-shell">
  <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Activity size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> INVESTIGATIONS</div><span className="agent-secure-label"><span/> CASE MANAGEMENT</span></header>
  <section className="agent-main">
   <div className="agent-heading"><div className="agent-overline">SOC / INCIDENT RESPONSE / 006</div><h1>Investigation workspace</h1><p>Build a persistent case timeline from analyst notes, malware analysis, detection checks and SOC observations.</p></div>
   <div className="malware-warning"><ShieldCheck size={15}/><span>Cases are private to the signed-in user through Supabase Row Level Security. Apply the included database migration before using persistent storage. Avoid storing credentials, secrets or unnecessary personal data in evidence notes.</span></div>
   {error&&<div className="agent-error">{error}</div>}{message&&<div className="network-note">{message}</div>}
   <div className="report-layout">
    <section className="report-editor"><div className="malware-result-head"><h2>New investigation</h2><span>CASE RECORD</span></div><form onSubmit={createCase}>
     <label>Case title<input required maxLength={160} value={title} onChange={e=>setTitle(e.target.value)} placeholder="e.g. Endpoint alert investigation"/></label>
     <label>Severity<select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="informational">Informational</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
     <label>Summary<textarea maxLength={5000} value={summary} onChange={e=>setSummary(e.target.value)} placeholder="What happened? What is known so far?"/></label>
     <label>Scope / affected assets<textarea maxLength={3000} value={scope} onChange={e=>setScope(e.target.value)} placeholder="Authorised assets, environment, exclusions and case boundaries"/></label>
     <button className="report-download" disabled={busy||!title.trim()}><Plus size={14}/> Create case</button>
    </form></section>
    <section className="report-preview"><div className="report-preview-head"><strong>INVESTIGATION CASES</strong><button type="button" onClick={()=>void load()} disabled={busy}><RefreshCw size={13}/> Refresh</button></div>
     {cases.length===0?<p>No cases loaded. Sign in and apply the database migration to enable persistent case storage.</p>:cases.map(c=><button type="button" key={c.id} className="module-card" style={{width:"100%",textAlign:"left",marginBottom:10,borderColor:selected===c.id?"var(--accent)":"var(--line)"}} onClick={()=>setSelected(c.id)}><strong>{c.title}</strong><div className="malware-kv"><span>{c.severity.toUpperCase()}</span><span>{c.status.toUpperCase()}</span></div><small>{(c.investigation_events||[]).length} timeline events · Updated {new Date(c.updated_at).toLocaleString()}</small></button>)}
    </section>
   </div>
   {current&&<section className="malware-results" style={{marginTop:24}}>
    <div className="malware-result-head"><h2>{current.title}</h2><span>{current.id.slice(0,8).toUpperCase()}</span></div>
    <div className="malware-kv"><span>Severity</span><strong>{current.severity.toUpperCase()}</strong></div>
    <div className="malware-kv"><span>Status</span><select value={current.status} onChange={e=>void updateStatus(e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></div>
    <p>{current.summary||"No summary supplied."}</p><div className="malware-kv"><span>Scope</span><strong>{current.scope||"Not specified"}</strong></div>
    <div className="report-editor" style={{marginTop:18}}><h3>Add timeline event</h3><form onSubmit={addEvent}>
     <label>Event title<input required maxLength={200} value={eventTitle} onChange={e=>setEventTitle(e.target.value)} placeholder="e.g. YARA structural checks completed"/></label>
     <div className="report-two"><label>Source<input maxLength={80} value={eventSource} onChange={e=>setEventSource(e.target.value)}/></label><label>Event type<input maxLength={120} value={eventType} onChange={e=>setEventType(e.target.value)}/></label></div>
     <label>Severity<select value={eventSeverity} onChange={e=>setEventSeverity(e.target.value)}><option value="informational">Informational</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
     <label>Structured details (JSON)<textarea rows={5} value={eventDetails} onChange={e=>setEventDetails(e.target.value)}/></label>
     <button className="report-download" disabled={busy||!eventTitle.trim()}><Plus size={14}/> Add timeline event</button>
    </form></div>
    <h3>Case timeline</h3>
    {(current.investigation_events||[]).length===0?<p>No timeline events yet.</p>:(current.investigation_events||[]).map(ev=><div className="malware-kv" key={ev.id} style={{display:"block",padding:12,borderBottom:"1px solid var(--line)"}}><strong>{ev.title}</strong><div><small>{ev.source} · {ev.event_type} · {ev.severity} · {new Date(ev.occurred_at).toLocaleString()}</small></div><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{JSON.stringify(ev.details,null,2)}</pre></div>)}
    <button type="button" className="network-run" onClick={exportCase}><FileText size={14}/> Export case timeline</button>
   </section>}
   <div className="agent-disclaimer"><ShieldCheck size={12}/> Timeline records are analyst-supplied. Integrations must preserve provenance and require explicit approval before attaching automated findings.</div>
  </section>
 </main>;
}
