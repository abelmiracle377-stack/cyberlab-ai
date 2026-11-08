"use client";

import { useState } from "react";
import {
  Activity, ArrowLeft, ArrowRight, Bell, Bot, Bug, Cable, CircleHelp, Code2, Database,
  FileSearch, Fingerprint, Globe2, Layers3, Network, FileLock2, Radar, Shield, ShieldCheck, Terminal, Workflow,
} from "lucide-react";

const navigation = [
  { label: "Overview", icon: Layers3, group: "workspace" },
  { label: "AI Agent", icon: Bot, group: "workspace" },
  { label: "IP Intelligence", icon: Globe2, group: "intelligence" },
  { label: "OSINT", icon: Fingerprint, group: "intelligence" },
  { label: "Network Analysis", icon: Network, group: "security" },
  { label: "Penetration Testing", icon: Radar, group: "security" },
  { label: "Vulnerability Lab", icon: Bug, group: "security" },
  { label: "Malware Lab", icon: Shield, group: "research" },
  { label: "Reverse Engineering", icon: Code2, group: "research" },
  { label: "Reports", icon: FileSearch, group: "research" },
  { label: "Evidence Vault", icon: FileLock2, group: "research" },
  { label: "Kali Connection", icon: Terminal, group: "system" },
  { label: "Settings", icon: Workflow, group: "system" },
];

const modules = [
  { name: "AI Agent", description: "Coordinate scoped security workflows with tool-assisted analysis.", icon: Bot, status: "Foundation" },
  { name: "IP Intelligence", description: "Inspect IP, ASN, DNS, hosting and network ownership signals.", icon: Globe2, status: "Available" },
  { name: "OSINT", description: "Organise public-source findings with provenance and confidence.", icon: Fingerprint, status: "Available" },
  { name: "Network Analysis", description: "Review network evidence and interpret authorised scan results.", icon: Network, status: "Available" },
  { name: "Penetration Testing", description: "Plan and document assessments within an explicit scope.", icon: Radar, status: "Available" },
  { name: "Vulnerability Lab", description: "Research CVEs, assess impact and prioritise remediation.", icon: Bug, status: "Available" },
  { name: "Malware Lab", description: "Triage suspicious files through safe, isolated analysis workflows.", icon: Shield, status: "Available" },
  { name: "Reverse Engineering", description: "Inspect software behaviour, formats and application components.", icon: Code2, status: "Available" },
  { name: "Reports", description: "Turn verified evidence into structured technical reports.", icon: FileSearch, status: "Available" },
  { name: "Evidence Vault", description: "Store investigation notes in a passphrase-encrypted local vault.", icon: FileLock2, status: "Available" },
];

const capabilities = [
  "Evidence-first analysis and source attribution",
  "Human approval for sensitive operations",
  "Provider and model selection",
  "Scoped, authorised assessment workflows",
  "Reproducible findings and audit history",
  "Kali Linux companion integration",
];

export default function Home() {
  const [active, setActive] = useState("Overview");
  const [notice, setNotice] = useState("");
  const selectedModule = modules.find((module) => module.name === active);
  const SelectedIcon = selectedModule?.icon ?? Bot;

  function selectModule(name: string) {
    const routes: Record<string, string> = { "AI Agent": "/agent", "IP Intelligence": "/ip-intelligence", "Network Analysis": "/network-analysis", "OSINT": "/osint", "Malware Lab": "/malware-lab", "Reverse Engineering": "/reverse-engineering", "Vulnerability Lab": "/vulnerability-lab", "Reports": "/reports", "Evidence Vault": "/evidence-vault", "Penetration Testing": "/penetration-testing", "Kali Connection": "/kali-connection" };
    if (routes[name]) { window.location.href = routes[name]; return; }
    setActive(name);
    setNotice("");
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={19} /></div>
          <div>
            <div className="brand-name">CyberLab AI</div>
            <div className="brand-sub">SECURITY RESEARCH WORKSPACE</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="nav-list" aria-label="Main navigation">
          {navigation.filter((item) => item.group === "workspace").map((item) => {
            const Icon = item.icon;
            return <button key={item.label} className={`nav-item ${active === item.label ? "active" : ""}`} onClick={() => selectModule(item.label)}><span className="nav-icon"><Icon size={15} /></span>{item.label}</button>;
          })}
        </nav>
        <div className="workspace-label">INTELLIGENCE</div>
        <nav className="nav-list" aria-label="Intelligence">
          {navigation.filter((item) => item.group === "intelligence").map((item) => {
            const Icon = item.icon;
            return <button key={item.label} className={`nav-item ${active === item.label ? "active" : ""}`} onClick={() => selectModule(item.label)}><span className="nav-icon"><Icon size={15} /></span>{item.label}</button>;
          })}
        </nav>
        <div className="workspace-label">SECURITY OPERATIONS</div>
        <nav className="nav-list" aria-label="Security operations">
          {navigation.filter((item) => item.group === "security").map((item) => {
            const Icon = item.icon;
            return <button key={item.label} className={`nav-item ${active === item.label ? "active" : ""}`} onClick={() => selectModule(item.label)}><span className="nav-icon"><Icon size={15} /></span>{item.label}</button>;
          })}
        </nav>
        <div className="workspace-label">RESEARCH & OUTPUT</div>
        <nav className="nav-list" aria-label="Research and output">
          {navigation.filter((item) => item.group === "research").map((item) => {
            const Icon = item.icon;
            return <button key={item.label} className={`nav-item ${active === item.label ? "active" : ""}`} onClick={() => selectModule(item.label)}><span className="nav-icon"><Icon size={15} /></span>{item.label}</button>;
          })}
        </nav>
        <div className="nav-divider" />
        <div className="workspace-label">SYSTEM</div>
        <nav className="nav-list" aria-label="System">
          {navigation.filter((item) => item.group === "system").map((item) => {
            const Icon = item.icon;
            return <button key={item.label} className={`nav-item ${active === item.label ? "active" : ""}`} onClick={() => selectModule(item.label)}><span className="nav-icon"><Icon size={15} /></span>{item.label}</button>;
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-card">
            <div className="connection-head"><span>AI model service</span><span className="connection-state">CHECK IN AGENT</span></div>
            <div className="connection-copy">Open the agent console to check model availability and send a test message.</div>
            <button className="connection-link" onClick={() => selectModule("Settings")}>Configure providers <ArrowRight size={11} style={{ verticalAlign: "middle", marginLeft: 3 }} /></button>
          </div>
          <div className="profile">
            <div className="avatar">AM</div>
            <div><div className="profile-name">Local workspace</div><div className="profile-role">Authentication not configured</div></div>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">CyberLab AI <span style={{ color: "#526057", margin: "0 8px" }}>/</span> <strong>{active}</strong></div>
          <div className="top-actions">
            <div className="environment"><span className="dot" /> RESEARCH WORKSPACE</div>
            <button className="icon-button" aria-label="Help" onClick={() => setNotice("Choose an available workspace below. Each tool reports its own live lookup or service status.")}><CircleHelp size={14} /></button>
            <button className="icon-button" aria-label="Notifications" onClick={() => setNotice("No system notifications yet.")}><Bell size={14} /></button>
          </div>
        </header>

        <div className="content">
          {active === "Overview" ? (
            <>
              <div className="eyebrow">CONTROL CENTER / 001</div>
              <div className="page-heading">
                <div><h1>Security workspace</h1><div className="subtitle">A focused environment for intelligence, analysis and authorised security research.</div></div>
                <div className="date-stamp">CYBERLAB AI <span style={{ color: "#4d5b52" }}>/</span> EARLY ACCESS</div>
              </div>

              {notice && <div className="notice"><CircleHelp size={15} className="notice-icon" /><div><div className="notice-title">Workspace message</div><div className="notice-text">{notice}</div></div></div>}
              <div className="notice">
                <ShieldCheck size={16} className="notice-icon" />
                <div><div className="notice-title">Start an investigation</div><div className="notice-text">Choose an operational tool. IP and domain intelligence use passive public sources; the AI agent uses the selected model and reports provider errors when unavailable.</div></div>
              </div>

              <div className="section-heading"><h2>Workspace status</h2><span className="section-meta">CURRENT CAPABILITIES</span></div>
              <div className="metrics">
                <div className="metric"><div className="metric-top"><span>AI runtime</span><Bot size={14} className="metric-symbol" /></div><div className="metric-value" style={{ color: "#d7b77b" }}>Check in Agent</div><div className="metric-note">Live provider status appears in chat</div></div>
                <div className="metric"><div className="metric-top"><span>Connected tools</span><Cable size={14} className="metric-symbol" /></div><div className="metric-value">3</div><div className="metric-note">Passive intelligence routes</div></div>
                <div className="metric"><div className="metric-top"><span>Saved projects</span><Database size={14} className="metric-symbol" /></div><div className="metric-value">Local</div><div className="metric-note">Evidence vault stays in browser</div></div>
                <div className="metric"><div className="metric-top"><span>Security events</span><Activity size={14} className="metric-symbol" /></div><div className="metric-value">Manual</div><div className="metric-note">No background monitoring</div></div>
              </div>

              <div className="dashboard-grid">
                <section>
                  <div className="section-heading"><h2>AI research agent</h2><span className="section-meta">CORE SERVICE</span></div>
                  <div className="panel">
                    <div className="panel-header"><span className="panel-title">Agent workspace</span><span className="panel-kicker">AGENT / 00</span></div>
                    <div className="agent-placeholder">
                      <div className="agent-orb"><Bot size={22} /></div>
                      <div className="agent-title">Open the AI research agent</div>
                      <div className="agent-desc">Select a supported model, send a question, and receive a streamed response with public research and passive intelligence tools when available.</div>
                      <a className="connection-link" href="/agent">Launch AI Agent <ArrowRight size={12} /></a>
                    </div>
                  </div>
                </section>
                <section>
                  <div className="section-heading"><h2>System activity</h2><span className="section-meta">RECENT</span></div>
                  <div className="panel">
                    <div className="panel-header"><span className="panel-title">Available tools</span><span className="panel-kicker">LOCAL STATUS</span></div>
                    <div className="panel-body activity-list">
                      <div className="activity-row"><span className="activity-bullet" /><div><div className="activity-name">IP Intelligence</div><div className="activity-detail">User-entered public IP lookup</div></div><span className="activity-time">DONE</span></div>
                      <div className="activity-row"><span className="activity-bullet" /><div><div className="activity-name">Domain OSINT</div><div className="activity-detail">RDAP and certificate transparency</div></div><span className="activity-time">DONE</span></div>
                      <div className="activity-row"><span className="activity-bullet" style={{ background: "#b38d54" }} /><div><div className="activity-name">AI model</div><div className="activity-detail">Choose a model in the agent console</div></div><span className="activity-time">CHECK</span></div>
                      <div className="activity-row"><span className="activity-bullet" style={{ background: "#b38d54" }} /><div><div className="activity-name">Network analysis</div><div className="activity-detail">Import an existing Nmap XML report</div></div><span className="activity-time">READY</span></div>
                    </div>
                  </div>
                </section>
              </div>

              <div className="section-heading"><h2>Research modules</h2><span className="section-meta">OPEN A WORKSPACE</span></div>
              <div className="modules-grid">
                {modules.filter((module) => module.name !== "AI Agent").map((module) => {
                  const Icon = module.icon;
                  return <button className="module-card" key={module.name} onClick={() => selectModule(module.name)}>
                    <div className="module-top"><span className="module-icon"><Icon size={15} /></span><span className="module-status">{module.status}</span></div>
                    <div className="module-name">{module.name}</div><div className="module-desc">{module.description}</div>
                  </button>;
                })}
              </div>
            </>
          ) : (
            <div className="module-page">
              <button className="back-link" onClick={() => selectModule("Overview")}><ArrowLeft size={12} style={{ verticalAlign: "middle", marginRight: 5 }} /> Back to overview</button>
              <div className="eyebrow">WORKSPACE</div>
              <div className="page-heading"><div><h1>{active}</h1><div className="subtitle">Open the corresponding tool to run a real lookup or analysis.</div></div></div>
              <div className="panel module-page-panel"><h2 style={{ fontSize: 16, margin: "18px 0 7px" }}>{active}</h2><p>Use the dedicated workspace to submit your own target or evidence. No target is pre-filled and no investigation runs automatically.</p><div className="capability-list"><a className="connection-link" href={active === "AI Agent" ? "/agent" : active === "IP Intelligence" ? "/ip-intelligence" : active === "OSINT" ? "/osint" : active === "Network Analysis" ? "/network-analysis" : "/reports"}>Open {active} <ArrowRight size={12} /></a></div></div>
            </div>

          )}
          <div className="footer-note">CYBERLAB AI · OPEN-SOURCE SECURITY RESEARCH WORKSPACE · USE ONLY ON SYSTEMS YOU OWN OR ARE AUTHORISED TO ASSESS</div>
        </div>
      </main>
    </div>
  );
}