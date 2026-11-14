"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, ArrowLeft, Box, Cpu, HardDrive, Laptop, Network, RefreshCw, ShieldCheck, Terminal, Workflow } from "lucide-react";

type RuntimeInfo = { installed: boolean; executable: string | null };
type Capabilities = {
  platform: string;
  distribution: string;
  distribution_id: string;
  architecture: string;
  cpu_count: number | null;
  hardware_virtualization_device: boolean;
  wsl: boolean;
  runtimes: Record<string, RuntimeInfo>;
  detected_at: string;
  scope: string;
};
type Metrics = {
  memory_bytes?: Record<string, number>;
  disk_root_bytes?: { total: number; used: number; free: number };
  uptime_seconds?: number | null;
};

const runtimeLabels: Record<string, string> = {
  docker: "Docker",
  podman: "Podman",
  qemu: "QEMU",
  libvirt: "libvirt",
  virtualbox: "VirtualBox",
};

function formatBytes(value?: number) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "Unavailable";
  const units = ["B", "KB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return amount.toFixed(unit === 0 ? 0 : 1) + " " + units[unit];
}

export default function CyberLabOsPage() {
  const [token, setToken] = useState("");
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [checkedAt, setCheckedAt] = useState("");

  useEffect(() => {
    setToken(sessionStorage.getItem("cyberlab.kaliBridgeToken") || "");
  }, []);

  async function discover() {
    const pairedToken = token.trim();
    if (!pairedToken) {
      setError("Pair your local Kali companion first. The existing pairing token is shared with the Models workspace.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const headers = { Authorization: "Bearer " + pairedToken };
      const [capResponse, systemResponse] = await Promise.all([
        fetch("http://127.0.0.1:8765/capabilities", { headers, cache: "no-store" }),
        fetch("http://127.0.0.1:8765/system", { headers, cache: "no-store" }),
      ]);
      const capData = await capResponse.json();
      const systemData = await systemResponse.json();
      if (!capResponse.ok) throw new Error(capData.error || "Host capability discovery failed.");
      if (!systemResponse.ok) throw new Error(systemData.error || "Host telemetry could not be read.");
      setCapabilities(capData.capabilities as Capabilities);
      setMetrics(systemData.metrics as Metrics);
      setCheckedAt(new Date().toLocaleString());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not connect to the local CyberLab companion.");
      setCapabilities(null);
      setMetrics(null);
    } finally {
      setBusy(false);
    }
  }

  const cardStyle = { border: "1px solid rgba(148,163,184,.2)", borderRadius: 14, padding: 18, background: "rgba(15,23,42,.52)" };
  const muted = { color: "var(--muted-foreground, #94a3b8)" } as const;

  return (
    <main className="agent-shell">
      <header className="agent-topbar">
        <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
        <div className="agent-brand"><Laptop size={16} /> CYBERLAB OS <span className="agent-top-sep">/</span> ENVIRONMENT CONTROL</div>
        <Link href="/kali-connection" className="agent-secure-label">KALI COMPANION ↗</Link>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">CYBERLAB OS / LOCAL ENVIRONMENT MANAGER</div>
          <h1>Your security workstation</h1>
          <p>Discover local Linux, container and virtualisation capabilities. This first workspace is read-only: it does not install software, create environments, start virtual machines or execute terminal commands.</p>
        </div>

        <section style={{ ...cardStyle, marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}><ShieldCheck size={17} /> Local companion connection</div>
              <p style={{ ...muted, margin: "7px 0 0" }}>{token ? "A pairing token is available in this browser tab." : "No paired companion token found in this browser tab."}</p>
            </div>
            <button className="report-download" type="button" onClick={discover} disabled={busy || !token}>
              <RefreshCw size={14} /> {busy ? "Discovering…" : "Discover this host"}
            </button>
          </div>
          {error && <p role="alert" style={{ color: "#fca5a5", marginTop: 12 }}>{error}</p>}
          {checkedAt && <p style={{ ...muted, marginBottom: 0 }}>Last checked: {checkedAt}</p>}
        </section>

        {capabilities ? (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 12, marginBottom: 16 }}>
              <div style={cardStyle}><Laptop size={18} /><p style={muted}>Operating system</p><strong>{capabilities.distribution}</strong><p style={muted}>{capabilities.platform} · {capabilities.architecture}</p></div>
              <div style={cardStyle}><Cpu size={18} /><p style={muted}>CPU cores</p><strong>{capabilities.cpu_count ?? "Unavailable"}</strong><p style={muted}>Hardware virtualisation device: {capabilities.hardware_virtualization_device ? "Detected" : "Not detected"}</p></div>
              <div style={cardStyle}><Activity size={18} /><p style={muted}>Memory available</p><strong>{formatBytes(metrics?.memory_bytes?.MemAvailable)}</strong><p style={muted}>Total: {formatBytes(metrics?.memory_bytes?.MemTotal)}</p></div>
              <div style={cardStyle}><HardDrive size={18} /><p style={muted}>Root disk free</p><strong>{formatBytes(metrics?.disk_root_bytes?.free)}</strong><p style={muted}>Total: {formatBytes(metrics?.disk_root_bytes?.total)}</p></div>
            </div>

            <section style={{ ...cardStyle, marginBottom: 16 }}>
              <h2 style={{ marginTop: 0 }}>Environment runtimes</h2>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10 }}>
                {Object.entries(capabilities.runtimes).map(([id, runtime]) => (
                  <div key={id} style={{ border: "1px solid rgba(148,163,184,.18)", borderRadius: 10, padding: 13 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                      <strong>{runtimeLabels[id] || id}</strong>
                      <span style={{ color: runtime.installed ? "#86efac" : "#fbbf24", fontSize: 12 }}>{runtime.installed ? "Detected" : "Not detected"}</span>
                    </div>
                    <p style={{ ...muted, fontSize: 12, overflowWrap: "anywhere", marginBottom: 0 }}>{runtime.executable || "No executable found on PATH"}</p>
                  </div>
                ))}
              </div>
              <p style={muted}>WSL: {capabilities.wsl ? "Detected" : "Not detected"} · KVM device: {capabilities.hardware_virtualization_device ? "Present" : "Not present"}</p>
              <p style={muted}>{capabilities.scope}</p>
            </section>
          </>
        ) : (
          <section style={{ ...cardStyle, marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}><Activity size={18} /><strong>Host discovery has not run</strong></div>
            <p style={muted}>Pair your existing Kali companion and select “Discover this host”. If you are using another computer, install and pair the companion there. The browser cannot inspect a remote host without that local bridge.</p>
          </section>
        )}

        <h2 style={{ margin: "24px 0 12px" }}>Environment catalogue</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(230px,1fr))", gap: 12 }}>
          <div style={cardStyle}><Terminal size={18} /><h3>CyberLab Terminal</h3><span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span><p style={muted}>Paired local terminal with allowlisted commands, approval gates and an audit trail.</p></div>
          <div style={cardStyle}><ShieldCheck size={18} /><h3>Kali Linux</h3><span style={{ color: "#86efac", fontSize: 12 }}>Existing integration</span><p style={muted}>Retains the current companion, authorised Nmap workflow, host telemetry and local Ollama connection.</p><Link href="/kali-connection">Open Kali connection</Link></div>
          <div style={cardStyle}><Box size={18} /><h3>Ubuntu / containers</h3><span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span><p style={muted}>Optional isolated Ubuntu and CyberLab profiles after runtime support and resource limits are verified.</p></div>
          <div style={cardStyle}><Workflow size={18} /><h3>Virtual machines</h3><span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span><p style={muted}>Local QEMU/KVM, VirtualBox or other supported hypervisor integration with explicit lifecycle approvals.</p></div>
        </div>
        <p className="agent-disclaimer" style={{ marginTop: 18 }}>CyberLab OS is currently an environment-management foundation, not a bootable Linux distribution or a hypervisor. The future bootable image will be built only after the local environment and update model are validated.</p>
      </section>
    </main>
  );
}
