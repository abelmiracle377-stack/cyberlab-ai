"use client";

import { useMemo, useState } from "react";
import {
  Activity, ArrowDownRight, ArrowLeft, ArrowRight, ArrowUpRight, Bell,
  Bot, Bug, Cable, ChevronRight, CircleHelp, Clock3, Code2, Database,
  FileSearch, Fingerprint, Globe2, Layers3, LockKeyhole, Network,
  Radar, Search, Server, Shield, ShieldCheck, Terminal, Workflow,
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
  { name: "Reverse Engineering", description: "Inspect software behaviour, formats and application components.", icon: Code2, status: "Planned" },
  { name: "Reports", description: "Turn verified evidence into structured technical reports.", icon: FileSearch, status: "Available" },
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
  const [query, setQuery] = useState("");
  const [notice, setNotice] = useState("");
  const filteredModules = useMemo(
    () => modules.filter((module) => (module.name + " " + module.description).toLowerCase().includes(query.toLowerCase())),
    [query],
  );
  const selectedModule = modules.find((module) => module.name === active);
  const SelectedIcon = selectedModule?.icon ?? Bot;

  function selectModule(name: string) {
    const routes: Record<string, string> = { "AI Agent": "/agent", "IP Intelligence": "/ip-intelligence", "Network Analysis": "/network-analysis", "OSINT": "/osint", "Malware Lab": "/malware-lab", "Vulnerability Lab": "/vulnerability-lab", "Reports": "/reports", "Penetration Testing": "/penetration-testing", "Kali Connection": "/kali-connection" };
    if (routes[name]) { window.location.href = routes[name]; return; }
    setActive(name);
    setQuery("");
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
            <div className="connection-head"><span>Agent runtime</span><span className="connection-state">NOT CONNECTED</span></div>
            <div className="connection-copy">Connect a model provider to enable agent planning and tool execution.</div>
            <button className="connection-link" onClick={() => selectModule("Settings")}>Configure providers <ArrowRight size={11} style={{ verticalAlign: "middle", marginLeft: 3 }} /></button>
          </div>
          <div className="profile">
            <div className="avatar">AM</div>
            <div><div className="profile-name">Workspace owner</div><div className="profile-role">Administrator</div></div>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">CyberLab AI <span style={{ color: "#526057", margin: "0 8px" }}>/</span> <strong>{active}</strong></div>
          <div className="top-actions">
            <div className="environment"><span className="dot" /> INITIAL SETUP</div>
            <button className="icon-button" aria-label="Help" onClick={() => setNotice("CyberLab AI is in its initial setup stage. Modules will become available as their services are implemented.")}><CircleHelp size={14} /></button>
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
                <div><div className="notice-title">Workspace initialised — services not yet connected</div><div className="notice-text">This is the first interface build. No scans, lookups or AI actions are running yet. Connect a model and configure data services before using operational features.</div></div>
              </div>

              <div className="section-heading"><h2>Workspace status</h2><span className="section-meta">LIVE CONFIGURATION</span></div>
              <div className="metrics">
                <div className="metric"><div className="metric-top"><span>AI runtime</span><Bot size={14} className="metric-symbol" /></div><div className="metric-value" style={{ color: "#d7b77b" }}>Offline</div><div className="metric-note">No provider configured</div></div>
                <div className="metric"><div className="metric-top"><span>Connected tools</span><Cable size={14} className="metric-symbol" /></div><div className="metric-value">00</div><div className="metric-note">Integrations pending</div></div>
                <div className="metric"><div className="metric-top"><span>Saved projects</span><Database size={14} className="metric-symbol" /></div><div className="metric-value">00</div><div className="metric-note">Storage not configured</div></div>
                <div className="metric"><div className="metric-top"><span>Security events</span><Activity size={14} className="metric-symbol" /></div><div className="metric-value">—</div><div className="metric-note">No event source connected</div></div>
              </div>

              <div className="dashboard-grid">
                <section>
                  <div className="section-heading"><h2>AI research agent</h2><span className="section-meta">CORE SERVICE</span></div>
                  <div className="panel">
                    <div className="panel-header"><span className="panel-title">Agent workspace</span><span className="panel-kicker">AGENT / 00</span></div>
                    <div className="agent-placeholder">
                      <div className="agent-orb"><Bot size={22} /></div>
                      <div className="agent-title">Your agent workspace is ready</div>
                      <div className="agent-desc">The orchestration layer will plan tasks, request approval for sensitive actions, call enabled tools and organise evidence. Choose a provider to begin configuration.</div>
                      <span className="agent-state">WAITING FOR MODEL PROVIDER</span>
                    </div>
                  </div>
                </section>
                <section>
                  <div className="section-heading"><h2>System activity</h2><span className="section-meta">RECENT</span></div>
                  <div className="panel">
                    <div className="panel-header"><span className="panel-title">Setup log</span><span className="panel-kicker">LOCAL STATUS</span></div>
                    <div className="panel-body activity-list">
                      <div className="activity-row"><span className="activity-bullet" /><div><div className="activity-name">Workspace created</div><div className="activity-detail">CyberLab AI project initialised</div></div><span className="activity-time">DONE</span></div>
                      <div className="activity-row"><span className="activity-bullet" /><div><div className="activity-name">Dashboard scaffold</div><div className="activity-detail">Navigation and module layout</div></div><span className="activity-time">DONE</span></div>
                      <div className="activity-row"><span className="activity-bullet" style={{ background: "#b38d54" }} /><div><div className="activity-name">Model provider</div><div className="activity-detail">Credentials and routing not configured</div></div><span className="activity-time">PENDING</span></div>
                      <div className="activity-row"><span className="activity-bullet" style={{ background: "#b38d54" }} /><div><div className="activity-name">Tool integrations</div><div className="activity-detail">Awaiting backend implementation</div></div><span className="activity-time">PENDING</span></div>
                    </div>
                  </div>
                </section>
              </div>

              <div className="section-heading"><h2>Research modules</h2><span className="section-meta">SELECT A MODULE TO EXPLORE</span></div>
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
              <div className="eyebrow">CYBERLAB MODULE / WORK IN PROGRESS</div>
              <div className="page-heading"><div><h1>{active}</h1><div className="subtitle">{selectedModule?.description ?? "Configure the CyberLab AI workspace and its connected services."}</div></div></div>
              {notice && <div className="notice"><CircleHelp size={15} className="notice-icon" /><div><div className="notice-title">Workspace message</div><div className="notice-text">{notice}</div></div></div>}
              <div className="panel module-page-panel">
                <div className="module-top"><span className="module-icon"><SelectedIcon size={18} /></span><span className="module-status">NOT YET CONNECTED</span></div>
                <h2 style={{ fontSize: 16, margin: "18px 0 7px" }}>{active} workspace</h2>
                <p>This module is part of the CyberLab AI roadmap. Its interface will be connected to real data sources and analysis tools in a later implementation step. No operational activity is being performed from this screen.</p>
                <div className="capability-list">{capabilities.map((capability) => <div className="capability" key={capability}><ShieldCheck size={13} />{capability}</div>)}</div>
                <div style={{ marginTop: 20, padding: 12, border: "1px solid #3e392b", background: "#1b1912", borderRadius: 7, color: "#c8b48e", fontSize: 10, lineHeight: 1.7 }}>
                  <strong>Implementation status:</strong> UI foundation only. Backend, provider credentials and module-specific integrations are not configured yet.
                </div>
              </div>
            </div>
          )}
          <div className="footer-note">CYBERLAB AI · OPEN-SOURCE SECURITY RESEARCH WORKSPACE · USE ONLY ON SYSTEMS YOU OWN OR ARE AUTHORISED TO ASSESS</div>
        </div>
      </main>
    </div>
  );
}