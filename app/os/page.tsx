"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, ArrowLeft, Box, Cpu, Download, HardDrive, Laptop, Network, RefreshCw, ShieldCheck, Terminal, Workflow } from "lucide-react";

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
  const units = ["B", "KB", "MB", "GB", "TB"];
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
    setBusy(true);
    setError("");
    try {
      const headers = { Authorization: "Bearer " + pairedToken };
      const [capResponse, systemResponse] = await Promise.all([
        fetch("/api/kali/capabilities", { headers, cache: "no-store" }),
        fetch("/api/kali/system", { headers, cache: "no-store" }),
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
  const osBase = "https://github.com/abelmiracle377-stack/cyberlab-ai/releases/latest/download/";
  const osReleases = "https://github.com/abelmiracle377-stack/cyberlab-ai/releases/latest";
  const osDownloads = [
    { file: "cyberlab-ai-os-desktop-lite-amd64.iso", label: "Bootable ISO", desc: "Physical hardware, or a new VM with the ISO attached. BIOS + UEFI, QEMU boot-tested in CI." },
    { file: "cyberlab-ai-os-desktop-lite-amd64.ova", label: "VirtualBox / VMware (OVA)", desc: "VirtualBox: File → Import Appliance. VMware: open the .ova. Boots straight into the workstation." },
    { file: "cyberlab-ai-os-desktop-lite-amd64.vmdk", label: "VMware disk (VMDK)", desc: "Attach to a new 64-bit Debian VM (BIOS firmware) as the primary disk and boot." },
  ];

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
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}><HardDrive size={17} /> Download CyberLab AI OS</div>
          <p style={{ ...muted, margin: "7px 0 14px" }}>Prebuilt, standalone bootable security OS — Debian-based, XFCE desktop, the curated toolset and the CyberLab companion preinstalled. Download an image and run it; you do not build the OS yourself. Permanent latest-release links.</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 10 }}>
            {osDownloads.map(d => (
              <a key={d.file} href={osBase + d.file} target="_blank" rel="noreferrer" style={{ border: "1px solid rgba(148,163,184,.22)", borderRadius: 10, padding: 13, textDecoration: "none", color: "inherit", display: "block" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}><strong>{d.label}</strong><Download size={14} /></div>
                <p style={{ ...muted, fontSize: 12, margin: "6px 0 0", overflowWrap: "anywhere" }}>{d.desc}</p>
              </a>
            ))}
          </div>
          <p style={{ ...muted, fontSize: 12, margin: "12px 0 0" }}>A <code>terminal</code> edition and the full desktop ISO are published too. Links resolve once a version tag is released. <a href={osReleases} target="_blank" rel="noreferrer">All images &amp; checksums ↗</a></p>
        </section>

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
          <details style={cardStyle}><summary style={{ cursor: "pointer" }}><Terminal size={18} /> <strong>CyberLab Terminal</strong> <span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span></summary><p style={muted}>Paired local terminal with allowlisted commands, approval gates and an audit trail.</p><p style={muted}>Not available yet. It opens after the command allowlist, approval gates and audit log are built and tested.</p></details>
          <div style={cardStyle}><ShieldCheck size={18} /><h3>Kali Linux</h3><span style={{ color: "#86efac", fontSize: 12 }}>Existing integration</span><p style={muted}>Retains the current companion, authorised Nmap workflow, host telemetry and local Ollama connection.</p><Link href="/kali-connection">Open Kali connection</Link></div>
          <details style={cardStyle}><summary style={{ cursor: "pointer" }}><Box size={18} /> <strong>Ubuntu / containers</strong> <span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span></summary><p style={muted}>Optional isolated Ubuntu and CyberLab profiles after runtime support and resource limits are verified.</p><p style={muted}>Not available yet. It waits for runtime support and resource-limit testing.</p></details>
          <details style={cardStyle}><summary style={{ cursor: "pointer" }}><Workflow size={18} /> <strong>Virtual machines</strong> <span style={{ color: "#fbbf24", fontSize: 12 }}>Planned</span></summary><p style={muted}>Local QEMU/KVM, VirtualBox or other supported hypervisor integration with explicit lifecycle approvals.</p><p style={muted}>Not available yet. To use a VM today, download the CyberLab AI OS image above.</p></details>
        </div>
        <p className="agent-disclaimer" style={{ marginTop: 18 }}>CyberLab AI OS ships as prebuilt bootable images (ISO plus VirtualBox/VMware appliances) with the CyberLab tools and companion preinstalled — download them above. This page is also an environment-management foundation for discovering and, in future, managing local Linux, container and virtualisation environments on a host you have paired; it is not itself a hypervisor.</p>
      </section>
    </main>
  );
}
