"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, ArrowLeft, AlertTriangle, CheckCircle2, RefreshCw, ShieldCheck, Radio, LockKeyhole } from "lucide-react";

const BRIDGE = "http://127.0.0.1:8765";

type InterfaceItem = { index:number; name:string; state:string; loopback:boolean };
type CaptureResult = {
  status:string; capture_id?:string; interface?:string; filter?:string; duration_seconds?:number;
  packet_limit?:number; snaplen_bytes?:number; file_name?:string; local_file?:string;
  file_size_bytes?:number; sha256?:string; packet_count?:number; ssh_packet_count?:number;
  protocol_counts?:Record<string,number>; top_endpoints?:{endpoint:string;packets:number}[];
  authorization_reference?:string; payload_exported?:boolean; note?:string; error?:string;
};

export default function NetworkIntelligencePage() {
  const [token,setToken] = useState("");
  const [interfaces,setInterfaces] = useState<InterfaceItem[]>([]);
  const [selectedInterface,setSelectedInterface] = useState("");
  const [confirmationInterface,setConfirmationInterface] = useState("");
  const [authorizationReference,setAuthorizationReference] = useState("");
  const [authorizationConfirmed,setAuthorizationConfirmed] = useState(false);
  const [filter,setFilter] = useState("ssh");
  const [durationSeconds,setDurationSeconds] = useState(10);
  const [packetLimit,setPacketLimit] = useState(500);
  const [loadingInterfaces,setLoadingInterfaces] = useState(false);
  const [capturing,setCapturing] = useState(false);
  const [error,setError] = useState("");
  const [result,setResult] = useState<CaptureResult|null>(null);

  async function loadInterfaces(savedToken = token) {
    if (!savedToken.trim()) return;
    setLoadingInterfaces(true);
    setError("");
    try {
      const response = await fetch(BRIDGE + "/network/interfaces", {
        headers: { Authorization: "Bearer " + savedToken.trim() }, cache: "no-store"
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not read local network interfaces.");
      const items = Array.isArray(data.interfaces) ? data.interfaces as InterfaceItem[] : [];
      setInterfaces(items);
      setSelectedInterface(current => current && items.some(item => item.name === current) ? current : (items[0]?.name || ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Kali bridge is unavailable.");
    } finally {
      setLoadingInterfaces(false);
    }
  }

  useEffect(() => {
    const saved = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
    setToken(saved);
    if (saved) void loadInterfaces(saved);
  }, []);

  async function startCapture() {
    if (!token.trim() || !selectedInterface || confirmationInterface !== selectedInterface ||
        !authorizationConfirmed || !authorizationReference.trim()) {
      setError("Pair Kali, confirm the exact interface name, accept the authorisation statement and provide an engagement or lab reference.");
      return;
    }
    setCapturing(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch(BRIDGE + "/network/capture", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({
          interface: selectedInterface,
          confirmationInterface,
          authorizationConfirmed,
          authorizationReference,
          durationSeconds,
          packetLimit,
          filter
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.detail || data.status || "Packet capture failed.");
      setResult(data as CaptureResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Packet capture failed.");
    } finally {
      setCapturing(false);
    }
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link>
      <div className="agent-brand"><Activity size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> NETWORK INTELLIGENCE</div>
      <span className="agent-secure-label"><span/> PASSIVE / LOCAL</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">NETWORK FORENSICS / KALI COMPANION</div>
        <h1>Network Intelligence</h1>
        <p>Capture a short, authorised sample of local network traffic and inspect packet-level metadata without forwarding packet payloads to the AI.</p>
      </div>

      <div className="scope-warning"><AlertTriangle size={14}/> Passive capture only. Capture only networks you own or are explicitly authorised to monitor. SSH payloads remain encrypted; this module does not reveal passwords, commands or terminal contents.</div>

      {!token && <section className="network-results">
        <h2>Kali pairing required</h2>
        <p>Pair the local Kali companion before discovering interfaces or capturing traffic.</p>
        <Link href="/kali-connection" className="report-download">Open Kali Connection</Link>
      </section>}

      <section className="network-results">
        <div className="scope-checks"><span>LOCAL INTERFACE DISCOVERY</span><span>{interfaces.length} INTERFACES</span></div>
        <div className="report-editor">
          <div className="report-editor-head">
            <h2><Radio size={15}/> Capture configuration</h2>
            <button className="report-download" onClick={() => void loadInterfaces()} disabled={!token || loadingInterfaces || capturing}>
              <RefreshCw size={14}/> {loadingInterfaces ? "Refreshing…" : "Refresh interfaces"}
            </button>
          </div>
          <label>Network interface
            <select value={selectedInterface} onChange={e=>{setSelectedInterface(e.target.value);setConfirmationInterface("");}} disabled={!interfaces.length || capturing}>
              {interfaces.map(item=><option key={item.name} value={item.name}>{item.name} · {item.state}{item.loopback ? " · loopback" : ""}</option>)}
            </select>
          </label>
          <label>Retype interface name to confirm
            <input value={confirmationInterface} onChange={e=>setConfirmationInterface(e.target.value)} placeholder={selectedInterface || "e.g. eth0"} disabled={!selectedInterface || capturing}/>
          </label>
          <label>Capture filter
            <select value={filter} onChange={e=>setFilter(e.target.value)} disabled={capturing}>
              <option value="ssh">SSH · TCP port 22</option>
              <option value="dns">DNS · port 53</option>
              <option value="tcp">TCP traffic</option>
              <option value="udp">UDP traffic</option>
              <option value="icmp">ICMP / ICMPv6</option>
            </select>
          </label>
          <div className="scope-checks">
            <label>Duration (1–30 seconds)
              <input type="number" min={1} max={30} value={durationSeconds} onChange={e=>setDurationSeconds(Number(e.target.value))} disabled={capturing}/>
            </label>
            <label>Packet limit (1–2,000)
              <input type="number" min={1} max={2000} value={packetLimit} onChange={e=>setPacketLimit(Number(e.target.value))} disabled={capturing}/>
            </label>
          </div>
          <label>Authorisation / lab reference
            <input value={authorizationReference} onChange={e=>setAuthorizationReference(e.target.value)} maxLength={160} placeholder="e.g. LAB-ENGAGEMENT-001" disabled={capturing}/>
          </label>
          <label className="scope-confirm"><input type="checkbox" checked={authorizationConfirmed} onChange={e=>setAuthorizationConfirmed(e.target.checked)} disabled={capturing}/> I own this network or have explicit authorisation to monitor the selected interface.</label>
          <button className="report-download" onClick={()=>void startCapture()} disabled={!token || !selectedInterface || confirmationInterface !== selectedInterface || !authorizationConfirmed || !authorizationReference.trim() || capturing || loadingInterfaces || durationSeconds < 1 || durationSeconds > 30 || packetLimit < 1 || packetLimit > 2000}>
            <Activity size={14}/> {capturing ? "Capturing locally…" : "Start passive capture"}
          </button>
          <p className="muted-copy"><LockKeyhole size={13}/> Captures are limited to 30 seconds, 2,000 packets and a 96-byte snap length. PCAP files stay on the paired workstation with owner-only permissions.</p>
        </div>
      </section>

      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}

      {result && <section className="network-results">
        <h2><CheckCircle2 size={15}/> Capture completed</h2>
        <div className="scope-checks"><span>{result.capture_id}</span><span>{result.filter?.toUpperCase()} FILTER</span></div>
        <div className="scope-checks">
          <div><strong>{result.packet_count ?? 0}</strong><p>Packets analysed</p></div>
          <div><strong>{result.ssh_packet_count ?? 0}</strong><p>SSH packets</p></div>
          <div><strong>{result.duration_seconds ?? 0}s</strong><p>Capture duration</p></div>
        </div>
        <p>Interface: <strong>{result.interface}</strong> · PCAP size: <strong>{result.file_size_bytes ?? 0} bytes</strong> · Snap length: <strong>{result.snaplen_bytes} bytes</strong></p>
        <p>Local evidence file: <code>{result.local_file}</code></p>
        <p>SHA-256: <code>{result.sha256}</code></p>
        <h3>Protocol counts</h3>
        <ul>{Object.entries(result.protocol_counts || {}).map(([name,count])=><li key={name}>{name.toUpperCase()}: {count}</li>)}</ul>
        <h3>Top endpoints</h3>
        {result.top_endpoints?.length ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Endpoint</th><th>Packets</th></tr></thead><tbody>{result.top_endpoints.map(item=><tr key={item.endpoint}><td>{item.endpoint}</td><td>{item.packets}</td></tr>)}</tbody></table></div> : <p>No packet endpoint metadata was available for this sample.</p>}
        <p>{result.note}</p>
      </section>}
    </section>
  </main>;
}
