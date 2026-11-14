"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Download, FileText, ShieldCheck } from "lucide-react";

export default function ReportsPage(){
 const [title,setTitle]=useState("Security Assessment Report");
 const [client,setClient]=useState("");
 const [scope,setScope]=useState("");
 const [date,setDate]=useState(new Date().toISOString().slice(0,10));
 const [summary,setSummary]=useState("");
 const [findings,setFindings]=useState("");
 const [recommendations,setRecommendations]=useState("");
 const [limitations,setLimitations]=useState("This report is based only on the evidence and information supplied by the analyst. Findings should be validated before remediation decisions.");
 const report=useMemo(()=>[
  `# ${title.trim()||"Security Assessment Report"}`,
  "",
  `**Client / project:** ${client.trim()||"Not specified"}  `,
  `**Assessment date:** ${date||"Not specified"}  `,
  `**Scope:** ${scope.trim()||"Not specified"}`,
  "",
  "## Executive summary",
  summary.trim()||"No executive summary supplied.",
  "",
  "## Findings",
  findings.trim()||"No findings supplied.",
  "",
  "## Recommendations",
  recommendations.trim()||"No recommendations supplied.",
  "",
  "## Limitations",
  limitations.trim()||"No limitations supplied.",
  "",
  "---",
  "Generated with CyberLab AI. Verify evidence, scope and remediation guidance before distribution."
 ].join("\n"),[title,client,scope,date,summary,findings,recommendations,limitations]);
 function download(){
  const blob=new Blob([report],{type:"text/markdown;charset=utf-8"});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement("a");
  anchor.href=url;anchor.download=(title.trim()||"security-report").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")+".md";
  document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url);
 }
 return <main className="agent-shell">
  <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><FileText size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> REPORTS</div><span className="agent-secure-label"><span/> LOCAL EXPORT</span></header>
  <section className="agent-main">
   <div className="agent-heading"><div className="agent-overline">EVIDENCE & OUTPUT / 005</div><h1>Security report builder</h1><p>Draft a structured report and export it as Markdown. Nothing is saved to a server.</p></div>
   <div className="report-layout">
    <section className="report-editor">
     <label>Report title<input value={title} onChange={e=>setTitle(e.target.value)}/></label>
     <div className="report-two"><label>Client / project<input value={client} onChange={e=>setClient(e.target.value)} placeholder="Project name"/></label><label>Assessment date<input type="date" value={date} onChange={e=>setDate(e.target.value)}/></label></div>
     <label>Assessment scope<textarea value={scope} onChange={e=>setScope(e.target.value)} placeholder="Authorised assets, environments and exclusions"/></label>
     <label>Executive summary<textarea value={summary} onChange={e=>setSummary(e.target.value)} placeholder="Summarise the assessment and its key outcomes."/></label>
     <label>Findings<textarea className="report-large" value={findings} onChange={e=>setFindings(e.target.value)} placeholder="Finding, severity, affected asset, evidence and impact."/></label>
     <label>Recommendations<textarea value={recommendations} onChange={e=>setRecommendations(e.target.value)} placeholder="Prioritised remediation actions."/></label>
     <label>Limitations<textarea value={limitations} onChange={e=>setLimitations(e.target.value)}/></label>
     <button className="report-download" onClick={download}><Download size={14}/> Export Markdown report</button>
    </section>
    <aside className="report-preview"><div className="report-preview-head"><strong>LIVE PREVIEW</strong><span>MARKDOWN</span></div><pre>{report}</pre></aside>
   </div>
   <div className="agent-disclaimer"><ShieldCheck size={12}/> Analyst-authored content only. Verify every claim, source, severity and scope statement before sharing the report.</div>
  </section>
 </main>;
}
