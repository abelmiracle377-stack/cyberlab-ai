"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ClipboardCheck, Download, ShieldCheck, AlertTriangle } from "lucide-react";
const checks=["Confirm written authorisation and named approver","Verify every in-scope asset with the client","Review exclusions and third-party dependencies","Agree test window, rate limits and stop conditions","Confirm backup, monitoring and incident contacts","Record evidence and timestamps during the engagement","Validate findings and agree remediation priorities"];
export default function PentestPlannerPage(){
 const [name,setName]=useState("");const [client,setClient]=useState("");const [reference,setReference]=useState("");const [start,setStart]=useState("");const [end,setEnd]=useState("");const [assets,setAssets]=useState("");const [exclusions,setExclusions]=useState("");const [constraints,setConstraints]=useState("No denial-of-service, destructive testing, credential spraying, persistence or social engineering. Stop immediately if service instability is observed.");
 const [completed,setCompleted]=useState<string[]>([]);
 const plan=useMemo(()=>[
 "# Authorised Security Assessment Plan","",
 "**Engagement:** "+(name||"Not specified"),"**Client:** "+(client||"Not specified"),"**Authorisation reference:** "+(reference||"Not supplied"),"**Test window:** "+(start||"TBD")+" to "+(end||"TBD"),"",
 "## In-scope assets",assets.trim()||"Not supplied","",
 "## Explicit exclusions",exclusions.trim()||"Not supplied","",
 "## Operating constraints",constraints.trim()||"Not supplied","",
 "## Pre-engagement checklist",...checks.map(x=>"- ["+(completed.includes(x)?"x":" ")+"] "+x),"",
 "## Execution boundary","This plan documents scope and governance only. It does not initiate scans, exploit systems, authenticate to targets or verify authorisation.","",
 "Generated with CyberLab AI. Obtain and verify written approval before any active testing."
 ].join("\n"),[name,client,reference,start,end,assets,exclusions,constraints,completed]);
 function exportPlan(){const blob=new Blob([plan],{type:"text/markdown;charset=utf-8"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="authorised-assessment-plan.md";document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);}
 return <main className="agent-shell"><header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><ClipboardCheck size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> PENETRATION TESTING</div><span className="agent-secure-label"><span/> SCOPE PLANNING</span></header>
 <section className="agent-main"><div className="agent-heading"><div className="agent-overline">AUTHORISED ASSESSMENT / 007</div><h1>Engagement scope planner</h1><p>Prepare an assessment scope, exclusions, operating constraints and pre-engagement checklist.</p></div>
 <div className="scope-warning"><AlertTriangle size={14}/>This planner does not verify legal authorisation or perform tests. Obtain written permission from the system owner before any active assessment.</div>
 <div className="scope-layout"><section className="report-editor">
 <label>Engagement name<input value={name} onChange={e=>setName(e.target.value)} placeholder="External security assessment"/></label>
 <label>Client / organisation<input value={client} onChange={e=>setClient(e.target.value)} placeholder="Organisation name"/></label>
 <label>Authorisation reference<input value={reference} onChange={e=>setReference(e.target.value)} placeholder="Contract, ticket or approval reference"/></label>
 <div className="report-two"><label>Start date<input type="date" value={start} onChange={e=>setStart(e.target.value)}/></label><label>End date<input type="date" value={end} onChange={e=>setEnd(e.target.value)}/></label></div>
 <label>In-scope assets<textarea className="report-large" value={assets} onChange={e=>setAssets(e.target.value)} placeholder={"One asset per line\nexample.com\n192.0.2.10"}/></label>
 <label>Out-of-scope assets<textarea value={exclusions} onChange={e=>setExclusions(e.target.value)} placeholder="List excluded hosts, IPs, environments and third-party services."/></label>
 <label>Operating constraints<textarea value={constraints} onChange={e=>setConstraints(e.target.value)}/></label>
 <div className="scope-checks"><h2>Pre-engagement checklist</h2>{checks.map(item=><label key={item}><input type="checkbox" checked={completed.includes(item)} onChange={e=>setCompleted(old=>e.target.checked?[...old,item]:old.filter(x=>x!==item))}/>{item}</label>)}</div>
 <button className="report-download" onClick={exportPlan}><Download size={14}/> Export scope plan</button>
 </section><aside className="report-preview"><div className="report-preview-head"><strong>LIVE PLAN PREVIEW</strong><span>MARKDOWN</span></div><pre>{plan}</pre></aside></div>
 <div className="agent-disclaimer"><ShieldCheck size={12}/> Treat scope as an allowlist. Exclusions always override broader asset descriptions. Do not begin testing until approval and stop conditions are confirmed.</div>
 </section></main>;
}
