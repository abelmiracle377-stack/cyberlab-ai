"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, ShieldCheck, AlertTriangle, ExternalLink, Network, Activity } from "lucide-react";

type Snapshot = { status:string; installed?:boolean; api_configured?:boolean; api_reachable?:boolean; api_url?:string; edition?:string; error?:string; note?:string; next_step?:string };
type HistoryItem = { id:number|null; timestamp:string|null; method:string; url:string; status_code:number|null; in_scope:boolean };
type MapItem = { method:string; url:string; status_code:number|null; in_scope:boolean };
type Result = { status:string; count:number; items:HistoryItem[] };

const BRIDGE = "http://127.0.0.1:8765";

export default function BurpSuitePage() {
  const [token,setToken] = useState("");
  const [bridgeReady,setBridgeReady] = useState(false);
  const [status,setStatus] = useState<Snapshot|null>(null);
  const [history,setHistory] = useState<Result|null>(null);
  const [siteMap,setSiteMap] = useState<{status:string;count:number;items:MapItem[]}|null>(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");

  useEffect(() => {
    const saved = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
    setToken(saved);
  }, []);

  async function refresh() {
    if (!token.trim()) {
      setError("Pair the Kali companion first, then return here. The pairing token is kept in this browser session.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const headers = { Authorization: "Bearer " + token.trim() };
      const health = await fetch(BRIDGE + "/health", { headers, cache: "no-store" });
      const healthData = await health.json();
      if (!health.ok) throw new Error(healthData.error || "Kali companion is not reachable.");
      setBridgeReady(true);

      const [statusResponse,historyResponse,mapResponse] = await Promise.all([
        fetch(BRIDGE + "/burp/status", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/proxy/history?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/site-map?limit=50", { headers, cache: "no-store" })
      ]);
      const [statusData,historyData,mapData] = await Promise.all([
        statusResponse.json(), historyResponse.json(), mapResponse.json()
      ]);
      if (!statusResponse.ok) throw new Error(statusData.error || "Burp status request failed.");
      if (!historyResponse.ok) throw new Error(historyData.error || "Burp proxy history request failed.");
      if (!mapResponse.ok) throw new Error(mapData.error || "Burp site map request failed.");
      setStatus(statusData);
      setHistory(historyData);
      setSiteMap(mapData);
    } catch (e) {
      setBridgeReady(false);
      setError(e instanceof Error ? e.message : "Could not read Burp connector status.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link>
      <div className="agent-brand"><ShieldCheck size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> BURP SUITE</div>
      <span className="agent-secure-label"><span/> LOCAL / READ ONLY</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">WEB SECURITY / LOCAL BURP CONNECTOR</div>
        <h1>Burp Suite workspace</h1>
        <p>Read Burp connection status, in-scope proxy history and the in-scope site map from your paired Kali workstation.</p>
      </div>
      <div className="scope-warning"><AlertTriangle size={14}/> This page is read-only. It does not send requests to targets, replay traffic, run Intruder jobs, crawl sites or start Burp scans. Only metadata that Burp marks in scope is returned.</div>
      {!token && <section className="network-results">
        <h2>Kali pairing required</h2>
        <p>Connect your local Kali companion first. The existing pairing token is saved in this browser session.</p>
        <Link href="/kali-connection" className="report-download">Open Kali Connection <ExternalLink size={13}/></Link>
      </section>}
      <div className="report-editor">
        <div className="scope-checks"><span>{bridgeReady ? "KALI BRIDGE CONNECTED" : "KALI BRIDGE NOT CHECKED"}</span><span>{status?.status ? "BURP API: " + status.status.toUpperCase() : "BURP API: NOT CHECKED"}</span></div>
        <button className="report-download" onClick={()=>void refresh()} disabled={busy||!token.trim()}>
          <RefreshCw size={14}/> {busy ? "Refreshing…" : "Refresh Burp data"}
        </button>
      </div>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {status && <section className="network-results">
        <h2><Activity size={15}/> Burp connection</h2>
        <p>REST API: <strong>{status.status}</strong> · Executable detected: {status.installed ? "Yes" : "Not detected"} · Edition: {status.edition || "Unknown"}</p>
        <p>API configured: {status.api_configured ? "Yes" : "No"} · Reachable: {status.api_reachable ? "Yes" : "No"}</p>
        {status.api_url && <p>Local API: <code>{status.api_url}</code></p>}
        {(status.error || status.note || status.next_step) && <p>{status.error || status.note || status.next_step}</p>}
      </section>}
      {history && <section className="network-results">
        <h2>Proxy HTTP history ({history.count})</h2>
        {history.status !== "connected" && <p>Montoya extension: {history.status}. Load the CyberLab Burp extension in Burp and ensure the paired Kali companion runs under the same OS user.</p>}
        {history.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>ID</th><th>Time</th><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>{history.items.map((item,i)=><tr key={item.id ?? i}><td>{item.id ?? "—"}</td><td>{item.timestamp || "—"}</td><td>{item.method}</td><td className="burp-url-cell">{item.url}</td><td>{item.status_code ?? "Pending"}</td></tr>)}</tbody></table></div> : <p>No in-scope proxy history entries were returned.</p>}
      </section>}
      {siteMap && <section className="network-results">
        <h2><Network size={15}/> Site map ({siteMap.count})</h2>
        {siteMap.status !== "connected" && <p>Montoya extension: {siteMap.status}.</p>}
        {siteMap.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>{siteMap.items.map((item,i)=><tr key={item.url + i}><td>{item.method}</td><td className="burp-url-cell">{item.url}</td><td>{item.status_code ?? "Pending"}</td></tr>)}</tbody></table></div> : <p>No in-scope site map entries were returned.</p>}
      </section>}
      <section className="network-results">
        <h2>Available now</h2>
        <ul>
          <li>Local Burp REST API reachability and configuration status.</li>
          <li>Read-only proxy history metadata, limited to 50 entries per refresh.</li>
          <li>Read-only site-map metadata, limited to 50 entries per refresh.</li>
          <li>Common credential-like query parameters are redacted before leaving Burp.</li>
        </ul>
        <h2>Not enabled yet</h2>
        <p>Repeater request replay, Intruder task execution, active scanner/crawler operations, issue export and automatic remediation remain disabled until their scope, approval and edition gates are implemented.</p>
      </section>
    </section>
  </main>;
}
