"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, ShieldCheck, AlertTriangle, ExternalLink, Network, Activity } from "lucide-react";

type Snapshot = { status:string; installed?:boolean; api_configured?:boolean; api_reachable?:boolean; api_url?:string; edition?:string; error?:string; note?:string; next_step?:string };
type ExtensionSnapshot = { status:string; connector?:string; authenticated?:boolean; capabilities?:string[]; note?:string };
type HistoryItem = { id:number|null; timestamp:string|null; method:string; url:string; status_code:number|null; in_scope:boolean };
type MapItem = { method:string; url:string; status_code:number|null; in_scope:boolean };
type IssueItem = { name:string; base_url:string; severity:string; confidence:string; in_scope:boolean };
type Result = { status:string; count:number; items:HistoryItem[] };

const BRIDGE = "http://127.0.0.1:8765";

export default function BurpSuitePage() {
  const [token,setToken] = useState("");
  const [bridgeReady,setBridgeReady] = useState(false);
  const [status,setStatus] = useState<Snapshot|null>(null);
  const [extension,setExtension] = useState<ExtensionSnapshot|null>(null);
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
  const [authorizationReference,setAuthorizationReference] = useState("");
  const [intruderConfirmed,setIntruderConfirmed] = useState(false);
  const [intruderBusyId,setIntruderBusyId] = useState<number|null>(null);
  const [intruderMessage,setIntruderMessage] = useState("");
  const [scannerTarget,setScannerTarget] = useState("");
  const [scannerConfirmed,setScannerConfirmed] = useState(false);
  const [scannerBusy,setScannerBusy] = useState("");
  const [scannerMessage,setScannerMessage] = useState("");
  const [scannerTasks,setScannerTasks] = useState<{status:string;tasks:Array<{task_id:string;kind:string;target:string;request_count:number;error_count:number;issue_count:number;status_message:string}>}|null>(null);

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
    setRepeaterConfirmed(false);
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
    setSendConfirmed(false);
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


  async function openInIntruder(historyId: number) {
    if (!intruderConfirmed || authorizationReference.trim().length < 3) {
      setIntruderMessage("Confirm the handoff and enter your authorization or lab reference first.");
      return;
    }
    setIntruderBusyId(historyId);
    setIntruderConfirmed(false);
    setIntruderMessage("");
    try {
      const response = await fetch(BRIDGE + "/burp/intruder/from-history", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ historyId, confirmIntruderHandoff: true, authorizationReference: authorizationReference.trim() })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.status || "Intruder handoff failed.");
      setIntruderMessage("Request #" + historyId + " was placed in Burp Intruder. Configure payload positions and attack settings in Burp, then start it there. CyberLab has not sent payloads.");
    } catch (e) {
      setIntruderMessage(e instanceof Error ? e.message : "Intruder handoff failed.");
    } finally {
      setIntruderBusyId(null);
    }
  }

  async function startScanner(kind: "crawl" | "audit") {
    if (!scannerConfirmed || authorizationReference.trim().length < 3 || !scannerTarget.trim()) {
      setScannerMessage("Enter an in-scope target URL, authorization reference and confirm this scan.");
      return;
    }
    setScannerBusy(kind);
    setScannerConfirmed(false);
    setScannerMessage("");
    try {
      const response = await fetch(BRIDGE + "/burp/scanner/" + kind, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ targetUrl: scannerTarget.trim(), authorizationReference: authorizationReference.trim(), confirmStart: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.status || "Burp Scanner task could not start.");
      setScannerMessage("Burp " + kind + " task started: " + data.task_id + ". Burp is executing it on the paired workstation.");
      const headers = { Authorization: "Bearer " + token.trim() };
      const taskResponse = await fetch(BRIDGE + "/burp/scanner/tasks", { headers, cache: "no-store" });
      if (taskResponse.ok) setScannerTasks(await taskResponse.json());
    } catch (e) {
      setScannerMessage(e instanceof Error ? e.message : "Burp Scanner task failed to start.");
    } finally {
      setScannerBusy("");
    }
  }

  async function cancelScanner(taskId: string) {
    setScannerBusy("cancel");
    try {
      const response = await fetch(BRIDGE + "/burp/scanner/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ taskId, confirmCancel: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.status || "Could not cancel the Burp task.");
      setScannerMessage("Cancellation requested for " + taskId + ".");
      const taskResponse = await fetch(BRIDGE + "/burp/scanner/tasks", { headers: { Authorization: "Bearer " + token.trim() }, cache: "no-store" });
      if (taskResponse.ok) setScannerTasks(await taskResponse.json());
    } catch (e) {
      setScannerMessage(e instanceof Error ? e.message : "Burp task cancellation failed.");
    } finally {
      setScannerBusy("");
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

      const [statusResponse,extensionResponse,historyResponse,mapResponse,issuesResponse,tasksResponse] = await Promise.all([
        fetch(BRIDGE + "/burp/status", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/extension/status", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/proxy/history?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/site-map?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/issues?limit=50", { headers, cache: "no-store" }),
        fetch(BRIDGE + "/burp/scanner/tasks", { headers, cache: "no-store" })
      ]);
      const [statusData,extensionData,historyData,mapData,issuesData,tasksData] = await Promise.all([
        statusResponse.json(), extensionResponse.json(), historyResponse.json(), mapResponse.json(), issuesResponse.json(), tasksResponse.json()
      ]);
      if (!statusResponse.ok) throw new Error(statusData.error || "Burp REST API status request failed.");
      if (!extensionResponse.ok) throw new Error(extensionData.error || "Burp extension health request failed.");
      if (!historyResponse.ok) throw new Error(historyData.error || "Burp proxy history request failed.");
      if (!mapResponse.ok) throw new Error(mapData.error || "Burp site map request failed.");
      if (!issuesResponse.ok) throw new Error(issuesData.error || "Burp issue retrieval failed.");
      if (!tasksResponse.ok) throw new Error(tasksData.error || "Burp Scanner task retrieval failed.");
      setStatus(statusData);
      setExtension(extensionData);
      setHistory(historyData);
      setSiteMap(mapData);
      setIssues(issuesData);
      setScannerTasks(tasksData);
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
      <span className="agent-secure-label"><span/> LOCAL / APPROVAL-GATED</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">WEB SECURITY / LOCAL BURP CONNECTOR</div>
        <h1>Burp Suite workspace</h1>
        <p>Read Burp connection status, in-scope proxy history and the in-scope site map from your paired Kali workstation.</p>
      </div>
      <div className="scope-warning"><AlertTriangle size={14}/> The REST API and CyberLab Montoya extension are checked separately. Repeater handoff places a captured in-scope request in Burp without sending it. Replay resends one captured in-scope request only after confirmation. Intruder, Burp crawling and Burp Scanner are not currently integrated here.</div>
      {!token && <section className="network-results">
        <h2>Kali pairing required</h2>
        <p>Connect your local Kali companion first. The existing pairing token is saved in this browser session.</p>
        <Link href="/kali-connection" className="report-download">Open Kali Connection <ExternalLink size={13}/></Link>
      </section>}
      <div className="report-editor">
        <div className="scope-checks"><span>{bridgeReady ? "KALI BRIDGE CONNECTED" : "KALI BRIDGE NOT CHECKED"}</span><span>{status?.status ? "BURP REST API: " + status.status.toUpperCase() : "BURP REST API: NOT CHECKED"}</span><span>{extension?.status ? "MONTOYA EXTENSION: " + extension.status.toUpperCase() : "MONTOYA EXTENSION: NOT CHECKED"}</span></div>
        <button className="report-download" onClick={()=>void refresh()} disabled={busy||!token.trim()}>
          <RefreshCw size={14}/> {busy ? "Refreshing…" : "Refresh Burp data"}
        </button>
        <label><input type="checkbox" checked={repeaterConfirmed} onChange={e=>setRepeaterConfirmed(e.target.checked)}/> I confirm the selected captured request may be placed in Repeater. It will not be sent until I manually press Send in Burp.</label>
        <label><input type="checkbox" checked={sendConfirmed} onChange={e=>setSendConfirmed(e.target.checked)}/> I authorise replaying a selected in-scope request through Burp. Each replay re-sends live traffic to the in-scope target.</label>
        {repeaterMessage && <p>{repeaterMessage}</p>}
      </div>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {status && <section className="network-results">
        <h2><Activity size={15}/> Burp REST API health</h2>
        <p>REST API: <strong>{status.status}</strong> · Executable detected: {status.installed ? "Yes" : "Not detected"} · Edition: {status.edition || "Unknown"}</p>
        <p>API configured: {status.api_configured ? "Yes" : "No"} · Reachable: {status.api_reachable ? "Yes" : "No"}</p>
        {status.api_url && <p>Local API: <code>{status.api_url}</code></p>}
        {(status.error || status.note || status.next_step) && <p>{status.error || status.note || status.next_step}</p>}
      </section>}
      {extension && <section className="network-results">
        <h2><ShieldCheck size={15}/> CyberLab Montoya extension</h2>
        <p>Extension health: <strong>{extension.status}</strong> · Authenticated: {extension.authenticated ? "Yes" : "No"} · Connector: {extension.connector || "Unknown"}</p>
        <p>{extension.note || (extension.status === "not_configured" ? "Load the CyberLab Burp extension in Burp; its local token is created on first start." : "The extension health endpoint is checked independently from the Burp REST API.")}</p>
        {extension.capabilities && <p>Verified extension functions: {extension.capabilities.join(" · ")}</p>}
      </section>}
      {history && <section className="network-results">
        <h2>Proxy HTTP history ({history.count})</h2>
        {history.status !== "connected" && <p>Montoya extension: {history.status}. Load the CyberLab Burp extension in Burp and ensure the paired Kali companion runs under the same OS user.</p>}
        {history.items.length > 0 ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>ID</th><th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Action</th></tr></thead><tbody>{history.items.map((item,i)=><tr key={item.id ?? i}><td>{item.id ?? "—"}</td><td>{item.timestamp || "—"}</td><td>{item.method}</td><td className="burp-url-cell">{item.url}</td><td>{item.status_code ?? "Pending"}</td><td><button className="report-download" disabled={item.id === null || !intruderConfirmed || intruderBusyId !== null || extension?.status !== "connected" || !extension.capabilities?.includes("intruder_handoff")} onClick={()=>item.id !== null && void openInIntruder(item.id)}>{intruderBusyId === item.id ? "Opening…" : "Send to Intruder"}</button><button className="report-download" style={{marginLeft:6}} disabled={item.id === null || !repeaterConfirmed || repeaterBusyId !== null || extension?.status !== "connected"} onClick={()=>item.id !== null && void openInRepeater(item.id)}>{repeaterBusyId === item.id ? "Opening…" : "Open in Repeater"}</button><button className="report-download" style={{marginLeft:6}} disabled={item.id === null || !sendConfirmed || sendBusyId !== null || extension?.status !== "connected"} onClick={()=>item.id !== null && void sendThroughBurp(item.id)}>{sendBusyId === item.id ? "Sending…" : "Replay"}</button>{item.id !== null && sendResults[item.id] && <div className="network-note" style={{marginTop:4}}>{sendResults[item.id]}</div>}</td></tr>)}</tbody></table></div> : <p>No in-scope proxy history entries were returned.</p>}
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
        <h2>Approved Intruder and Professional Scanner controls</h2>
        <p>Enter the engagement, lab or written-authorization reference. Targets must already be included in Burp Suite scope. CyberLab never changes Burp scope automatically.</p>
        {extension?.status === "connected" && (!extension.capabilities?.includes("intruder_handoff") || !extension.capabilities?.includes("professional_scanner_crawl") || !extension.capabilities?.includes("professional_scanner_active_audit")) && <p className="network-note">The loaded Burp extension is older and does not advertise every new control. Rebuild/reinstall the latest CyberLab Burp extension JAR and restart Burp to enable missing controls.</p>}
        <label htmlFor="burp-authorization-reference">Authorization / lab reference</label>
        <input id="burp-authorization-reference" value={authorizationReference} onChange={e=>setAuthorizationReference(e.target.value)} maxLength={160} placeholder="e.g. LAB-2026-001 or approved engagement ID"/>
        <div className="network-note" style={{marginTop:10}}>
          <label><input type="checkbox" checked={intruderConfirmed} onChange={e=>setIntruderConfirmed(e.target.checked)}/> I approve placing a selected in-scope request into Burp Intruder.</label>
          {intruderMessage && <p>{intruderMessage}</p>}
        </div>
        <div style={{marginTop:18}}>
          <label htmlFor="burp-scanner-target">Scanner / crawl start URL</label>
          <input id="burp-scanner-target" value={scannerTarget} onChange={e=>setScannerTarget(e.target.value)} maxLength={2048} placeholder="https://your-authorised-target.example/"/>
          <div className="network-note" style={{marginTop:10}}>
            <label><input type="checkbox" checked={scannerConfirmed} onChange={e=>setScannerConfirmed(e.target.checked)}/> I authorise Burp to actively crawl or audit this exact target, within the existing Burp scope.</label>
          </div>
          <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:12}}>
            <button className="report-download" disabled={!scannerConfirmed || !scannerTarget.trim() || scannerBusy!=="" || extension?.status!=="connected" || !extension.capabilities?.includes("professional_scanner_crawl")} onClick={()=>void startScanner("crawl")}>{scannerBusy==="crawl"?"Starting…":"Start Professional crawl"}</button>
            <button className="report-download" disabled={!scannerConfirmed || !scannerTarget.trim() || scannerBusy!=="" || extension?.status!=="connected" || !extension.capabilities?.includes("professional_scanner_active_audit")} onClick={()=>void startScanner("audit")}>{scannerBusy==="audit"?"Starting…":"Start active audit"}</button>
          </div>
          {scannerMessage && <p className="network-note" style={{marginTop:10}}>{scannerMessage}</p>}
        </div>
        <h3 style={{marginTop:22}}>Scanner tasks on this Burp session</h3>
        {scannerTasks?.tasks?.length ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Type</th><th>Target</th><th>Requests</th><th>Errors</th><th>Issues</th><th>Status</th><th>Action</th></tr></thead><tbody>{scannerTasks.tasks.map(task=><tr key={task.task_id}><td>{task.kind}</td><td className="burp-url-cell">{task.target}</td><td>{task.request_count}</td><td>{task.error_count}</td><td>{task.issue_count}</td><td>{task.status_message || "Status not exposed by this Burp API version"}</td><td><button className="report-download" disabled={scannerBusy!==""} onClick={()=>void cancelScanner(task.task_id)}>Cancel task</button></td></tr>)}</tbody></table></div> : <p>No tracked Scanner tasks in this extension session. Refresh after starting a crawl or audit.</p>}
        <p className="agent-disclaimer">Intruder handoff opens the real Burp Intruder tab, but payload positions, payload sets and attack launch remain under analyst control in Burp. Professional crawl and audit calls start real tasks through Montoya; they require a compatible Burp Professional licence. Task tracking is held in extension memory and resets when the extension unloads.</p>
      </section>
      <section className="network-results">
        <h2>Burp capability coverage</h2>
        <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Burp function</th><th>CyberLab status</th><th>What it does here</th></tr></thead><tbody>
          <tr><td>REST API health</td><td>Live check</td><td>Checks the local Burp REST API key and loopback endpoint; does not infer edition.</td></tr>
          <tr><td>Proxy history</td><td>Integrated</td><td>Reads up to 50 in-scope entries; credential-like query values are redacted.</td></tr>
          <tr><td>Target site map</td><td>Integrated</td><td>Reads bounded in-scope URL and response metadata.</td></tr>
          <tr><td>Audit issues</td><td>Integrated</td><td>Reads existing issue name, severity, confidence and base URL metadata.</td></tr>
          <tr><td>Repeater</td><td>Integrated with approval</td><td>Places one captured in-scope request in Repeater; analyst reviews and sends it inside Burp.</td></tr>
          <tr><td>Single-request replay</td><td>Integrated with per-action approval</td><td>Resends one captured in-scope request through Burp and returns response metadata only.</td></tr>
          <tr><td>Intruder</td><td>Native handoff</td><td>CyberLab can place an approved in-scope request into Burp Intruder. Payload positions, attack settings and Start remain analyst-controlled in Burp.</td></tr>
          <tr><td>Burp Professional Scanner / crawl</td><td>Live task integration</td><td>Starts real in-scope crawl-only or active-audit tasks through Montoya, tracks request/error/issue counts and supports cancellation.</td></tr>
          <tr><td>Request/response editor, Sequencer, Decoder, Comparer, extensions</td><td>Use in Burp desktop</td><td>These native Burp tools remain available in Burp; this page does not claim to reproduce their interfaces.</td></tr>
        </tbody></table></div>
        <p>Feature availability depends on the installed Burp edition. A successful REST API or extension health check does not prove that Professional-only features are licensed or available.</p>
      </section>
    </section>
  </main>;
}
