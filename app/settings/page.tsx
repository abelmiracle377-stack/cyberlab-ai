"use client";

import { ArrowLeft, ShieldCheck, Bot, Terminal, Database, LockKeyhole, ExternalLink } from "lucide-react";

const panels = [
  { title:"AI PROVIDERS", detail:"Configure model access and provider credentials in the AI Agent workspace.", icon:Bot, href:"/agent", action:"OPEN AI AGENT" },
  { title:"KALI COMPANION", detail:"Pair the local bridge before requesting an approved Nmap scan.", icon:Terminal, href:"/kali-connection", action:"PAIR LOCAL BRIDGE" },
  { title:"EVIDENCE STORAGE", detail:"Evidence Vault data is encrypted and stored locally in this browser.", icon:Database, href:"/evidence-vault", action:"OPEN VAULT" },
  { title:"ACCESS & IDENTITY", detail:"Authentication is optional unless Supabase environment settings are configured.", icon:LockKeyhole, href:"/account", action:"ACCOUNT SETTINGS" },
];

export default function SettingsPage() {
 return <main style={{minHeight:"100vh",background:"#050706",color:"#e8efeb",padding:"28px max(18px,calc((100vw - 980px)/2))",fontFamily:"var(--sans)"}}>
  <a href="/" style={{display:"inline-flex",alignItems:"center",gap:8,color:"#a6f000",font:"10px var(--mono)",textDecoration:"none"}}><ArrowLeft size={14}/> RETURN TO COMMAND CENTER</a>
  <div style={{marginTop:32,color:"#9ab36a",font:"9px var(--mono)",letterSpacing:2}}>SYSTEM // CONFIGURATION</div>
  <h1 style={{fontSize:30,letterSpacing:-1,margin:"10px 0 8px"}}>System settings<span style={{color:"#a6f000"}}>_</span></h1>
  <p style={{color:"#8b9881",font:"11px var(--mono)",lineHeight:1.8,maxWidth:650}}>Configuration entry points for connected services, local tools, evidence storage and account access. Secrets are configured in their respective secure provider or deployment settings—not displayed here.</p>
  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:12,marginTop:28}}>
   {panels.map(p=>{const Icon=p.icon;return <section key={p.title} style={{border:"1px solid #29351b",background:"#090d08",padding:18,minHeight:170}}>
    <Icon size={18} color="#a6f000"/><h2 style={{font:"11px var(--mono)",letterSpacing:1,margin:"15px 0 9px"}}>{p.title}</h2><p style={{color:"#87917e",fontSize:11,lineHeight:1.7,minHeight:42}}>{p.detail}</p><a href={p.href} style={{display:"inline-flex",alignItems:"center",gap:7,color:"#a6f000",font:"9px var(--mono)",textDecoration:"none",marginTop:10}}>{p.action}<ExternalLink size={11}/></a>
   </section>})}
  </div>
  <div style={{border:"1px solid #66551d",background:"#151205",padding:14,marginTop:20,color:"#d6c27a",font:"10px var(--mono)",lineHeight:1.7}}><ShieldCheck size={14} style={{verticalAlign:"middle",marginRight:8}}/>SECURITY NOTE: This page does not claim that external services are connected. Check each integration in its own workspace before use.</div>
 </main>
}
