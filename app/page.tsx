"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity, ArrowRight, Bell, Bot, BookOpen, Bug, Cable, Camera, ChevronDown, CircleHelp, Code2, Command, CreditCard, Laptop, FileCode2,
  Database, FileLock2, FileSearch, Fingerprint, HardDriveDownload, Globe, Globe2, Layers3, Menu, Network,
  Radar, Search, Server, Settings2, Shield, ShieldCheck, Terminal, Workflow, Wallet, X, Zap,
  MessageCircle,
  ShieldAlert,
} from "lucide-react";

const groups = [
  { title: "COMMAND CENTER", items: [
    { label: "Overview", icon: Layers3, href: "/" },
    { label: "Billing", icon: CreditCard, href: "/billing" },
    { label: "AI Agent", icon: Bot, href: "/agent" },
    { label: "Model Intelligence", icon: Workflow, href: "/models" },
    { label: "CyberLab OS", icon: Laptop, href: "/os" },
  ]},
  { title: "INTELLIGENCE", items: [
    { label: "IP Intelligence", icon: Globe2, href: "/ip-intelligence" },
    { label: "OSINT", icon: Fingerprint, href: "/osint" },
    { label: "Domain & Privacy Verification", icon: ShieldCheck, href: "/verification" },
    { label: "Live Research", icon: Globe, href: "/research" },
    { label: "Website Assessment", icon: Globe2, href: "/website-assessment" },
  ]},
  { title: "ASSESSMENT", items: [
    { label: "Network Analysis", icon: Network, href: "/network-analysis" },
    { label: "Network Intelligence", icon: Activity, href: "/network-intelligence" },
    { label: "Native Web Workbench", icon: Globe, href: "/web-workbench" },
    { label: "Native Web Repeater", icon: Workflow, href: "/web-repeater" },
    { label: "Native Web Crawler", icon: Radar, href: "/web-crawler" },
    { label: "Safe Active Web Checks", icon: Bug, href: "/web-scanner" },
    { label: "Burp Suite Connector", icon: Cable, href: "/burp-suite" },
    { label: "Penetration Testing", icon: Radar, href: "/penetration-testing" },
    { label: "Active Security Lab", icon: Radar, href: "/active-security-lab" },
    { label: "Vulnerability Lab", icon: Bug, href: "/vulnerability-lab" },
    { label: "Solidity Lab", icon: FileCode2, href: "/solidity" },
    { label: "Crypto Wallet Recovery", icon: Wallet, href: "/wallet-recovery" },
  ]},
  { title: "ANALYSIS & EVIDENCE", items: [
    { label: "Malware Lab", icon: Shield, href: "/malware-lab" },
    { label: "Reverse Engineering", icon: Code2, href: "/reverse-engineering" },
    { label: "Reports", icon: FileSearch, href: "/reports" },
    { label: "Evidence Vault", icon: FileLock2, href: "/evidence-vault" },
    { label: "File & Picture Recovery", icon: HardDriveDownload, href: "/forensics-recovery" },
  ]},
  { title: "OPERATIONS", items: [
    { label: "Tool Registry", icon: Cable, href: "/tool-registry" },
    { label: "Tool Runner", icon: Terminal, href: "/tool-runner" },
    { label: "SOC Host Telemetry", icon: Activity, href: "/kali-connection" },
    { label: "Investigations", icon: FileSearch, href: "/investigations" },
    { label: "Kali Connection", icon: Terminal, href: "/kali-connection" },
    { label: "Camera Intelligence", icon: Camera, href: "/kali-connection#camera-intelligence" },
    { label: "Personal VPS Gateway", icon: Server, href: "/kali-connection#vps-gateway" },
    { label: "Settings", icon: Settings2, href: "/settings" },
  ]},
  { title: "COMMUNITY", items: [
    { label: "Chat", icon: MessageCircle, href: "/chat" },
  ]},
  { title: "CYBERSOC", items: [
    { label: "CyberSOC", icon: ShieldAlert, href: "/soc" },
  ]},
];

const modules = [
  { name:"CyberLab OS", desc:"Manage local Linux environments, detect runtimes and prepare isolated security workspaces.", icon:Laptop, state:"FOUNDATION", href:"/os" },
  { name:"AI Agent", desc:"Coordinate scoped security workflows with tool-assisted analysis.", icon:Bot, state:"CONFIG CHECK", href:"/agent" },
  { name:"IP Intelligence", desc:"Inspect public IP, ASN, DNS, hosting and ownership signals.", icon:Globe2, state:"AVAILABLE", href:"/ip-intelligence" },
  { name:"OSINT", desc:"Collect public-source findings with provenance and confidence.", icon:Fingerprint, state:"AVAILABLE", href:"/osint" },
  { name:"Domain & Privacy Verification", desc:"Review SPF, DMARC, DKIM, CAA, historical URLs and local browser attributes.", icon:ShieldCheck, state:"NEW", href:"/verification" },
  { name:"Network Analysis", desc:"Import and interpret Nmap XML evidence.", icon:Network, state:"IMPORT / ANALYSE", href:"/network-analysis" },
  { name:"Network Intelligence", desc:"Capture bounded passive traffic and inspect protocol metadata locally through the paired companion.", icon:Activity, state:"PASSIVE / LOCAL", href:"/network-intelligence" },
  { name:"Native Web Workbench", desc:"Inspect and replay bounded HTTP requests through CyberLab's scoped local proxy.", icon:Globe, state:"NATIVE / AUTHORISED", href:"/web-workbench" },
  { name:"Native Web Repeater", desc:"Edit and resend explicitly approved HTTP requests through the native workbench.", icon:Workflow, state:"MANUAL / SCOPED", href:"/web-repeater" },
  { name:"Native Web Crawler", desc:"Discover same-origin pages with bounded, approved GET requests.", icon:Radar, state:"NATIVE / GET ONLY", href:"/web-crawler" },
  { name:"Safe Active Web Checks", desc:"Run bounded CORS and query-reflection checks with explicit approval.", icon:Bug, state:"NATIVE / LIMITED", href:"/web-scanner" },
  { name:"Burp Suite Connector", desc:"Connect the local companion to Burp Suite and inspect proxy history, site map and issues.", icon:Cable, state:"LOCAL / PAIRED", href:"/burp-suite" },
  { name:"Penetration Testing", desc:"Plan authorised assessments and document scope.", icon:Radar, state:"WORKSPACE", href:"/penetration-testing" },
  { name:"Active Security Lab", desc:"Limited TCP checks after exact target and authorisation confirmation.", icon:Zap, state:"CONTROLLED", href:"/active-security-lab" },
  { name:"Live Research", desc:"Research current CVEs, advisories and technical references.", icon:Globe, state:"PROVIDER REQUIRED", href:"/research" },
  { name:"Website Assessment", desc:"Passive HTTPS, headers and cookie security review.", icon:Globe2, state:"AVAILABLE", href:"/website-assessment" },
  { name:"Vulnerability Lab", desc:"Research CVEs, impact and remediation guidance.", icon:Bug, state:"AVAILABLE", href:"/vulnerability-lab" },
  { name:"Solidity Lab", desc:"Review Solidity source for security-sensitive patterns and contract surface.", icon:FileCode2, state:"HEURISTIC REVIEW", href:"/solidity" },
  { name:"Crypto Wallet Recovery", desc:"Inspect owned wallet backup formats locally without uploading recovery secrets.", icon:Wallet, state:"LOCAL TRIAGE", href:"/wallet-recovery" },
  { name:"File & Picture Recovery", desc:"Carve supported file signatures from a supplied evidence image and use the paired Linux companion for guarded disk workflows.", icon:HardDriveDownload, state:"LOCAL / AUTHORISED", href:"/forensics-recovery" },
  { name:"Malware Lab", desc:"Static triage, inert threat fixtures, YARA/Sigma structural checks and SOC behaviour simulations.", icon:Shield, state:"DEFENSIVE ANALYSIS", href:"/malware-lab" },
  { name:"Reverse Engineering", desc:"Inspect executable formats and supplied binaries.", icon:Code2, state:"ANALYSIS", href:"/reverse-engineering" },
  { name:"Reports", desc:"Turn findings and evidence into technical reports.", icon:FileSearch, state:"AVAILABLE", href:"/reports" },
  { name:"Evidence Vault", desc:"Keep investigation notes in a browser-local encrypted vault.", icon:FileLock2, state:"LOCAL", href:"/evidence-vault" },
  { name:"File & Picture Recovery", desc:"Carve contiguous JPEG, PNG, GIF and PDF candidates from a supplied evidence image without modifying the source.", icon:HardDriveDownload, state:"LIMITED / LOCAL", href:"/forensics-recovery" },
  { name:"SOC Host Telemetry", desc:"Read-only, on-demand health metrics from a paired local Kali host.", icon:Activity, state:"LOCAL / ON DEMAND", href:"/kali-connection" },
  { name:"Camera Intelligence", desc:"Discover devices only on an operator-selected private LAN or view one explicitly authorised camera through the local Kali companion.", icon:Camera, state:"LOCAL / EXPLICIT CONSENT", href:"/kali-connection#camera-intelligence" },
  { name:"Personal VPS Gateway", desc:"Optional separately deployed personal gateway with revocable per-device permissions; not hosted by Vercel.", icon:Server, state:"OPTIONAL / NOT DEPLOYED", href:"/kali-connection#vps-gateway" },
  { name:"Investigations", desc:"Persistent case records and analyst-authored event timelines across security modules.", icon:FileSearch, state:"SUPABASE REQUIRED", href:"/investigations" },
];

type Cockpit = "COMMAND" | "SOC" | "VITALS";

export default function Home() {
  const [activeCockpit,setActiveCockpit]=useState<Cockpit>("COMMAND");
  const [query,setQuery]=useState("");
  const [mobileNav,setMobileNav]=useState(false);
  const [navCollapsed,setNavCollapsed]=useState(false);
  const [notice,setNotice]=useState("");
  const [isAdmin,setIsAdmin]=useState(false);
  useEffect(()=>{fetch("/api/admin/auth",{cache:"no-store"}).then(r=>setIsAdmin(r.ok)).catch(()=>setIsAdmin(false));},[]);
  const filtered=useMemo(()=>modules.filter(m=>(m.name+" "+m.desc).toLowerCase().includes(query.toLowerCase())),[query]);
  const activeLabel=groups.flatMap(g=>g.items).find(i=>i.href==="/")?.label ?? "Overview";

  return <div className={`shell command-shell ${mobileNav?"nav-open":""} ${navCollapsed?"nav-collapsed":""}`}>
    <aside className="sidebar command-sidebar">
      <div className="brand command-brand">
        <div className="brand-mark"><ShieldCheck size={20}/></div>
        <div className="brand-copy"><div className="brand-name">CYBERLAB<span className="brand-ai">/AI</span></div><div className="brand-sub">SECURITY OPERATIONS SYSTEM</div></div>
        <button className="mobile-close" onClick={()=>setMobileNav(false)} aria-label="Close navigation"><X size={17}/></button>
      </div>
      <div className="command-status"><span className="status-led amber-led"/><span>LOCAL WORKSPACE</span><b>EARLY ACCESS</b></div>
      <div className="nav-search"><Search size={14}/><input aria-label="Search tools" placeholder="Search modules..." value={query} onChange={e=>setQuery(e.target.value)}/><kbd>/</kbd></div>
      <nav className="command-nav" aria-label="Main navigation">
        {isAdmin&&<section className="nav-group"><div className="workspace-label">ADMINISTRATION</div><a href="/admin" className="nav-item"><span className="nav-icon"><ShieldCheck size={15}/></span><span className="nav-label">Admin Panel</span></a><a href="/learning" className="nav-item"><span className="nav-icon"><BookOpen size={15}/></span><span className="nav-label">AI Knowledge</span></a></section>}
        {groups.map(group=><section className="nav-group" key={group.title}>
          <div className="workspace-label">{group.title}</div>
          {group.items.map(item=>{const Icon=item.icon;return <a key={item.href} href={item.href} className={`nav-item ${item.href==="/"?"active":""}`} onClick={()=>setMobileNav(false)}><span className="nav-icon"><Icon size={15}/></span><span className="nav-label">{item.label}</span>{item.href==="/agent"&&<span className="nav-tag">AI</span>}</a>})}
        </section>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="connection-card">
          <div className="connection-head"><span>LOCAL KALI BRIDGE</span><span className="connection-state">PAIR TO CHECK</span></div>
          <div className="connection-copy">Nmap execution is available only through the paired local companion and explicit scan approval.</div>
          <a className="connection-link" href="/kali-connection">Open connection <ArrowRight size={11}/></a>
        </div>
        <div className="profile"><div className="avatar">CL</div><div><div className="profile-name">Research workspace</div><div className="profile-role">Authentication optional</div></div></div>
      </div>
    </aside>
    {mobileNav&&<button className="nav-scrim" aria-label="Close navigation" onClick={()=>setMobileNav(false)}/>}
    <main className="main command-main">
      <header className="topbar command-topbar">
        <div className="topbar-left"><button className="mobile-menu" onClick={()=>setMobileNav(true)} aria-label="Open navigation"><Menu size={18}/></button><div className="breadcrumb">CYBERLAB <span>/</span> <strong>COMMAND CENTER</strong></div></div>
        <div className="top-actions"><div className="environment"><span className="dot amber-dot"/>RESEARCH ENVIRONMENT</div><button className="icon-button" aria-label="Notifications" onClick={()=>setNotice("No notifications have been generated in this session.")}><Bell size={15}/></button><button className="icon-button" aria-label="Help" onClick={()=>setNotice("Select a module to open its dedicated workspace. Tool availability is shown only when verified.")}><CircleHelp size={15}/></button></div>
      </header>
      <div className="content command-content">
        <div className="command-hero">
          <div><div className="eyebrow">CONTROL PLANE // 001</div><h1>Security Operations<span className="heading-cursor">_</span></h1><p>Intelligence. Assessment. Analysis. Evidence.</p></div>
          <div className="hero-stamp"><span className="status-led amber-led"/>SYSTEM STATE: PARTIAL CONFIGURATION<br/><small>NO BACKGROUND SCANS RUNNING</small></div>
        </div>
        <div className="cockpit-bar"><div className="cockpit-label"><Command size={13}/> COCKPIT MODE</div><div className="cockpit-switch">{(["COMMAND","SOC","VITALS"] as Cockpit[]).map(mode=><button key={mode} className={activeCockpit===mode?"selected":""} onClick={()=>setActiveCockpit(mode)}>{mode}</button>)}</div><button className="collapse-nav" onClick={()=>setNavCollapsed(v=>!v)}><ChevronDown size={13}/> {navCollapsed?"EXPAND NAV":"COMPACT NAV"}</button></div>
        {notice&&<div className="notice command-notice"><CircleHelp size={15}/>{notice}<button onClick={()=>setNotice("")}>DISMISS</button></div>}
        <div className="section-heading"><h2>{activeCockpit==="COMMAND"?"OPERATIONAL SNAPSHOT":activeCockpit==="SOC"?"SOC / TELEMETRY READINESS":"SYSTEM VITALS / CONNECTIVITY"}</h2><span className="section-meta">LIVE STATE · NO SIMULATED METRICS</span></div>
        <div className="metrics command-metrics">
          <a className="metric metric-link metric-state-red" href="/agent" aria-label="Open AI Agent configuration">
            <div className="metric-top"><span>AI RUNTIME</span><Bot size={14}/></div><div className="metric-value warning-value">NOT VERIFIED</div><div className="metric-note">Open AI Agent to configure provider</div><div className="metric-action">OPEN CONFIG <ArrowRight size={11}/></div>
          </a>
          <a className="metric metric-link metric-state-blue" href="/kali-connection" aria-label="Open local tool bridge connection">
            <div className="metric-top"><span>LOCAL TOOL BRIDGE</span><Cable size={14}/></div><div className="metric-value warning-value">NOT PAIRED</div><div className="metric-note">Pair your Kali companion</div><div className="metric-action">PAIR BRIDGE <ArrowRight size={11}/></div>
          </a>
          <a className="metric metric-link metric-state-green" href="/evidence-vault" aria-label="Open evidence vault">
            <div className="metric-top"><span>EVIDENCE STORAGE</span><Database size={14}/></div><div className="metric-value">BROWSER LOCAL</div><div className="metric-note">Encrypted vault workspace</div><div className="metric-action">OPEN VAULT <ArrowRight size={11}/></div>
          </a>
          <a className="metric metric-link metric-state-gray" href="/investigations" aria-label="Open monitoring and investigations">
            <div className="metric-top"><span>MONITORING</span><Activity size={14}/></div><div className="metric-value">MANUAL</div><div className="metric-note">No continuous host telemetry</div><div className="metric-action">OPEN CASES <ArrowRight size={11}/></div>
          </a>
        </div>
        <div className="section-heading module-section-heading"><h2>MODULE DIRECTORY</h2><span className="section-meta">{filtered.length} MODULES · SELECT TO OPEN</span></div>
        <div className="module-search-mobile"><Search size={14}/><input placeholder="Filter operational modules..." value={query} onChange={e=>setQuery(e.target.value)}/></div>
        <div className="modules-grid command-modules">{filtered.map(module=>{const Icon=module.icon;return <a className="module-card command-module" key={module.name} href={module.href}><div className="module-top"><span className="module-icon"><Icon size={16}/></span><span className="module-status">{module.state}</span></div><div className="module-name">{module.name}</div><div className="module-desc">{module.desc}</div><div className="module-open">OPEN MODULE <ArrowRight size={12}/></div></a>})}</div>
        {filtered.length===0&&<div className="empty-search">NO MODULE MATCHES THAT QUERY. TRY ANOTHER TERM.</div>}
        <div className="command-footer"><span>CYBERLAB AI // SECURITY RESEARCH WORKSPACE</span><span>AUTHORISED SYSTEMS ONLY · HUMAN APPROVAL REQUIRED</span></div>
      </div>
    </main>
  </div>;
}
