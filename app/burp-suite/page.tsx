"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, ShieldCheck, AlertTriangle, ExternalLink, Network, Activity } from "lucide-react";

type Snapshot = { status:string; installed?:boolean; api_configured?:boolean; api_reachable?:boolean; api_url?:string; edition?:string; error?:string; note?:string; next_step?:string };
type HistoryItem = { id:number|null; timestamp:string|null; method:string; url:string; status_code:number|null; in_scope:boolean };
type MapItem = { method:string; url:string; status_code:number|null; in_scope:boolean };
type IssueItem = { name:string; base_url:string; severity:string; confidence:string; in_scope:boolean };
type Result = { status:string; count:number; items:HistoryItem[] };

const BRIDGE = "http://127.0.0.1:8765";

export default function BurpSuitePage() {
  const [token,setToken] = useState("");
  const [bridgeReady,setBridgeReady] = useState(false);
  const [status,setStatus] = useState<Snapshot|null>(null);
  const [history,setHistory] = useState<Result|null>(null);
  const [siteMap,setSiteMap] = useState<{status:string;count:number;items:MapItem[]}|null>(null);
  const [issues,setIssues] = useState<{status:string;count:number;items:IssueItem[]}|null>(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  const [repeaterConfirmed,setRepeaterConfirmed] = useState(false);
  const [repeaterBusyId,setRepeaterBusyId] = useState<number|null>(null);
  const [repeaterMessage,setRepeaterMessage] = useState("");
  const [sendConfirmed,setSendConfirmed] = useState(false);
  const [sendBusyId,setSendBusyId] = useState<number|null>(null);
  const [sendResults,setSendResults] = useState<Record<number,string>>({});

  useEffect(() => {
    const saved = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
    setToken(saved);
  }, []);

  async function openInRepeater(historyId: number) {
    if (!repeaterConfirmed) {
      setRepeaterMessage("Confirm the Repeater handoff first.");
      return;
    }
    setRepeaterBusyId(historyId);
    setRepeaterMessage("");
    try {
      const response = await fetch(BRIDGE + "/burp/repeater/from-history", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ historyId, confirmOpenInRepeater: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.status || "Could not open the request in Repeater.");
      setRepeaterMessage("Request #" + historyId + " was placed in Burp Repeater. It has not been sent; review it and manually press Send in Burp.");
    } catch (e) {
      setRepeaterMessage(e instanceof Error ? e.message : "Repeater handoff failed.");
    } finally {
      setRepeaterBusyId(null);
    }
  }

  async function sendThroughBurp(historyId: number) {
    if (!sendConfirmed) { setRepeaterMessage("Confirm the in-scope replay first."); return; }
    setSendBusyId(historyId);
    try {
      const response = await fetch(BRIDGE + "/burp/send-request", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ historyId, confirmSend: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.status || "Could not replay the request.");
      setSendResults(current => ({ ...current, [historyId]: data.method + " → " + data.status_code + " · " + (data.body_length ?? 0) + " bytes" }));
    } catch (e) {
      setSendResults(current => ({ ...current, [historyId]: e instanceof Error ? e.message : "Replay failed." }));
    } finally {
      setSendBusyId(null);
    }
  }

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

      const [statusResponse,historyResponse,mapResponse,issuesResponse] = await Promise.all([
        fetch(BRIDGE + "/burp/status", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/proxy/history?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/site-map?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/issues?limit=50", { headers, cache: "no-store" })
      ]);
      const [statusData,historyData,mapData,issuesData] = await Promise.all([
        statusResponse.json(), historyResponse.json(), mapResponse.json(), issuesResponse.json()
      ]);
      if (!statusResponse.ok) throw new Error(statusData.error || "Burp status request failed.");
      if (!historyResponse.ok) throw new Error(historyData.error || "Burp proxy history request failed.");
      if (!mapResponse.ok) throw new Error(mapData.error || "Burp site map request failed.");
      if (!issuesResponse.ok) throw new Error(issuesData.error || "Burp issue retrieval failed.");
      setStatus(statusData);
      setHistory(historyData);
      setSiteMap(mapData);
      setIssues(issuesData);
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
      <div className="scope-warning"><AlertTriangle size={14}/> Reads in-scope Burp metadata. It can replay a single in-scope request through Burp only after you explicitly confirm each one; it does not run Intruder jobs, crawl sites or start Burp scans. Out-of-scope requests are refused by the connector.</div>
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
        <label><input type="checkbox" checked={repeaterConfirmed} onChange={e=>setRepeaterConfirmed(e.target.checked)}/> I confirm the selected captured request may be placed in Repeater. It will not be sent until I manually press Send in Burp.</label>
        <label><input type="checkbox" checked={sendConfirmed} onChange={e=>setSendConfirmed(e.target.checked)}/> I authorise replaying a selected in-scope request through Burp. Each replay re-sends live traffic to the in-scope target.</label>
        {repeaterMessage && <p>{repeaterMessage}</p>}
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
        {history.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>ID</th><th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Action</th></tr></thead><tbody>{history.items.map((item,i)=><tr key={item.id ?? i}><td>{item.id ?? "—"}</td><td>{item.timestamp || "—"}</td><td>{item.method}</td><td className="burp-url-cell">{item.url}</td><td>{item.status_code ?? "Pending"}</td><td><button className="report-download" disabled={item.id === null || !repeaterConfirmed || repeaterBusyId !== null} onClick={()=>item.id !== null && void openInRepeater(item.id)}>{repeaterBusyId === item.id ? "Opening…" : "Open in Repeater"}</button><button className="report-download" style={{marginLeft:6}} disabled={item.id === null || !sendConfirmed || sendBusyId !== null} onClick={()=>item.id !== null && void sendThroughBurp(item.id)}>{sendBusyId === item.id ? "Sending…" : "Replay"}</button>{item.id !== null && sendResults[item.id] && <div className="network-note" style={{marginTop:4}}>{sendResults[item.id]}</div>}</td></tr>)}</tbody></table></div> : <p>No in-scope proxy history entries were returned.</p>}
      </section>}
      {siteMap && <section className="network-results">
        <h2><Network size={15}/> Site map ({siteMap.count})</h2>
        {siteMap.status !== "connected" && <p>Montoya extension: {siteMap.status}.</p>}
        {siteMap.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>{siteMap.items.map((item,i)=><tr key={item.url + i}><td>{item.method}</td><td className="burp-url-cell">{item.url}</td><td>{item.status_code ?? "Pending"}</td></tr>)}</tbody></table></div> : <p>No in-scope site map entries were returned.</p>}
      </section>}
      {issues && <section className="network-results">
        <h2>Existing Burp audit issues ({issues.count})</h2>
        {issues.status !== "connected" && <p>Montoya issue retrieval: {issues.status}. Ensure the CyberLab Burp extension is loaded in the same OS user session.</p>}
        {issues.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>Base URL</th></tr></thead><tbody>{issues.items.map((item,i)=><tr key={item.name + item.base_url + i}><td>{item.name}</td><td>{item.severity}</td><td>{item.confidence}</td><td className="burp-url-cell">{item.base_url}</td></tr>)}</tbody></table></div> : <p>No existing in-scope Burp audit issues were returned. This does not trigger a scan.</p>}
      </section>}
      <section className="network-results">
        <h2>Available now</h2>
        <ul>
          <li>Local Burp REST API reachability and configuration status.</li>
          <li>Read-only proxy history metadata, limited to 50 entries per refresh.</li>
          <li>Read-only site-map metadata, limited to 50 entries per refresh.</li>
          <li>Existing in-scope audit issue names, severity and confidence, without raw request/response evidence.</li>
          <li>Common credential-like query parameters are redacted before leaving Burp.</li>
        </ul>
        <h2>Not enabled yet</h2>
        <p>Repeater request replay, Intruder task execution, active scanner/crawler operations, active scan creation, issue mutation, raw issue detail export and automatic remediation remain disabled until their scope, approval and edition gates are implemented.</p>
      </section>
    </section>
  </main>;
}
