"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Radar, ShieldCheck, AlertTriangle, LoaderCircle, Network } from "lucide-react";

const choices = [21, 22, 80, 443, 3000, 5000, 8000, 8080, 8443];
type ScanResult = { target: string; resolvedAddress: string; checkedAt: string; method: string; results: { port: number; status: string; service: string }[]; note: string };

export default function ActiveSecurityLabPage() {
  const [target, setTarget] = useState("");
  const [confirmationTarget, setConfirmationTarget] = useState("");
  const [reference, setReference] = useState("");
  const [ports, setPorts] = useState<number[]>([22, 80, 443, 8080, 8443]);
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function togglePort(port: number) { setPorts((old) => old.includes(port) ? old.filter((item) => item !== port) : old.length < 5 ? [...old, port] : old); }

  async function run(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/security/port-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, confirmationTarget, authorizationReference: reference, authorizationConfirmed: confirmed, ports }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "TCP checks failed.");
      setResult(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unexpected assessment error."); }
    finally { setBusy(false); }
  }

  return <main className="agent-shell">
    <header className="agent-topbar"><Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link><div className="agent-brand"><Radar size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> ACTIVE SECURITY LAB</div><span className="agent-secure-label"><span/> AUTHORISED ONLY</span></header>
    <section className="agent-main">
      <div className="agent-heading"><div className="agent-overline">CONTROLLED NETWORK CHECKS / 011</div><h1>Active security lab</h1><p>Run a small, low-volume TCP reachability check against a public IPv4 address or domain you own or are authorised to assess.</p></div>
      <div className="scope-warning"><AlertTriangle size={14}/> This performs real network connections. Only test assets covered by written permission. Third-party, shared-hosting and cloud-provider infrastructure may require separate approval. No exploit attempts, authentication, banner grabbing or denial-of-service testing are performed.</div>
      <form className="report-editor" onSubmit={run}>
        <label>Target host<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="your-domain.example or public IPv4" required maxLength={253}/></label>
        <label>Retype exact target to confirm scope<input value={confirmationTarget} onChange={(event) => setConfirmationTarget(event.target.value)} placeholder="Type the same host again" required maxLength={253}/></label>
        <label>Authorisation reference<input value={reference} onChange={(event) => setReference(event.target.value)} placeholder="Ticket, contract or approval reference" required maxLength={160}/></label>
        <div className="scope-checks"><h2>TCP ports · choose up to five</h2><div className="port-choice-grid">{choices.map((port) => <label key={port}><input type="checkbox" checked={ports.includes(port)} onChange={() => togglePort(port)}/><span>{port}</span></label>)}</div><small>Only these common service ports are available. Checks are sequential in small batches with a short timeout.</small></div>
        <div className="scope-checks"><label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}/> I own this target or have explicit written authorisation to perform these TCP connection checks. I have confirmed the target is in scope and accept responsibility for the test.</label></div>
        <button className="report-download" type="submit" disabled={busy || !confirmed || !reference.trim() || target.trim().toLowerCase() !== confirmationTarget.trim().toLowerCase() || ports.length < 1 || ports.length > 5}>{busy ? <><LoaderCircle size={14}/> Checking…</> : <><Radar size={14}/> Run limited TCP checks</>}</button>
      </form>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {result && <div className="network-results"><h2><Network size={14} style={{ verticalAlign: "middle" }}/> Assessment results</h2><p>Target: <strong>{result.target}</strong> · Resolved IPv4: <strong>{result.resolvedAddress}</strong></p><p>Method: {result.method} · {new Date(result.checkedAt).toLocaleString()}</p><div className="network-table-wrap"><table className="network-table"><thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead><tbody>{result.results.map((item) => <tr key={item.port}><td>{item.port}</td><td>{item.service}</td><td>{item.status}</td></tr>)}</tbody></table></div><p>{result.note}</p></div>}
      <div className="agent-disclaimer"><ShieldCheck size={12}/> This Vercel-hosted check is not Nmap and cannot establish that a host is secure or vulnerable. For a full Nmap scan, use CyberLab's Kali companion locally within the approved scope.</div>
    </section>
  </main>;
}
