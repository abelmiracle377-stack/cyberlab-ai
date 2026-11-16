"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, AlertTriangle, Globe, History, LoaderCircle, Send, ShieldCheck } from "lucide-react";

type HttpResult = {
  id: string; status: number; reason: string; method: string; target: string;
  durationMs: number; resolvedAddress: string; headers: { name: string; value: string }[];
  body: string; bodyBytes: number; truncated: boolean; capturedAt: string;
};

export default function WebWorkbenchPage() {
  const [url, setUrl] = useState("http://localhost:3000/");
  const [confirmationUrl, setConfirmationUrl] = useState("http://localhost:3000/");
  const [method, setMethod] = useState("GET");
  const [headersText, setHeadersText] = useState('{"Accept":"*/*"}');
  const [body, setBody] = useState("");
  const [reference, setReference] = useState("LOCAL-LAB-001");
  const [authorised, setAuthorised] = useState(false);
  const [confirmSend, setConfirmSend] = useState(false);
  const [confirmStateChange, setConfirmStateChange] = useState(false);
  const [localLabMode, setLocalLabMode] = useState(true);
  const [result, setResult] = useState<HttpResult | null>(null);
  const [history, setHistory] = useState<HttpResult[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const token = () => sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";

  async function loadHistory() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/web/history", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load request history.");
    setHistory(data.items || []);
  }

  useEffect(() => { loadHistory().catch(() => undefined); }, []);

  async function sendRequest(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setResult(null);
    try {
      const pairing = token();
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      let parsedHeaders: unknown;
      try { parsedHeaders = JSON.parse(headersText); } catch { throw new Error("Headers must be valid JSON in name/value format."); }
      if (!parsedHeaders || Array.isArray(parsedHeaders) || typeof parsedHeaders !== "object") throw new Error("Headers must be a JSON object.");
      const response = await fetch("http://127.0.0.1:8765/web/request", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: JSON.stringify({ url, confirmationUrl, method, headers: parsedHeaders, body, authorizationReference: reference, authorizationConfirmed: authorised, confirmSend, confirmStateChange, localLabMode }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Native HTTP request failed.");
      setResult(data);
      await loadHistory();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unexpected request error."); }
    finally { setBusy(false); }
  }

  const stateChanging = ["POST", "PUT", "PATCH", "DELETE"].includes(method);

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14}/> Dashboard</Link>
      <div className="agent-brand"><Globe size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> NATIVE WEB WORKBENCH</div>
      <span className="agent-secure-label"><span/> LOCAL ENGINE</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">NATIVE HTTP TESTING / 001</div>
        <h1>Web request workbench</h1>
        <p>Compose, send, inspect and replay HTTP requests using CyberLab's own local engine. No external proxy is required.</p>
      </div>
      <div className="scope-warning"><AlertTriangle size={14}/> Active requests contact the selected server. Use only an asset covered by written permission. The engine pins DNS resolution, blocks private addresses except explicit loopback lab mode, does not follow redirects, and caps request/response sizes.</div>
      <form className="report-editor" onSubmit={sendRequest}>
        <label>Target URL<input value={url} onChange={e=>setUrl(e.target.value)} required maxLength={2048} placeholder="https://your-authorised-domain.example/path"/></label>
        <label>Retype target URL to confirm hostname<input value={confirmationUrl} onChange={e=>setConfirmationUrl(e.target.value)} required maxLength={2048}/></label>
        <label>HTTP method<select value={method} onChange={e=>setMethod(e.target.value)}>{["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"].map(item=><option key={item}>{item}</option>)}</select></label>
        <label>Request headers · JSON<textarea value={headersText} onChange={e=>setHeadersText(e.target.value)} rows={4} spellCheck={false}/></label>
        <label>Request body · maximum 16 KB<textarea value={body} onChange={e=>setBody(e.target.value)} rows={5} spellCheck={false} placeholder="Optional request body for POST, PUT or PATCH"/></label>
        <label>Engagement / authorisation reference<input value={reference} onChange={e=>setReference(e.target.value)} required maxLength={160}/></label>
        <div className="scope-checks"><label><input type="checkbox" checked={localLabMode} onChange={e=>setLocalLabMode(e.target.checked)}/> Local lab mode (loopback only: localhost / 127.0.0.1 / ::1)</label></div>
        <div className="scope-checks"><label><input type="checkbox" checked={authorised} onChange={e=>setAuthorised(e.target.checked)}/> I own this target or have explicit written authorisation for this request.</label></div>
        <div className="scope-checks"><label><input type="checkbox" checked={confirmSend} onChange={e=>setConfirmSend(e.target.checked)}/> I explicitly approve sending this request to the confirmed host.</label></div>
        {stateChanging && <div className="scope-checks"><label><input type="checkbox" checked={confirmStateChange} onChange={e=>setConfirmStateChange(e.target.checked)}/> I separately confirm this {method} request may change server state and is safe within the authorised test.</label></div>}
        <button className="report-download" type="submit" disabled={busy || !authorised || !confirmSend || (stateChanging && !confirmStateChange) || !reference.trim()}>{busy?<><LoaderCircle size={14}/> Sending…</>:<><Send size={14}/> Send native HTTP request</>}</button>
      </form>
      {error && <div className="agent-error"><AlertTriangle size={14}/>{error}</div>}
      {result && <div className="network-results">
        <h2><ShieldCheck size={14}/> Response · {result.status} {result.reason}</h2>
        <p>{result.method} {result.target} · {result.durationMs} ms · pinned address {result.resolvedAddress} · {result.bodyBytes} bytes{result.truncated?" · response truncated":""}</p>
        <h3>Response headers</h3>
        <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",fontSize:11}}>{result.headers.map(h=>h.name+": "+h.value).join("\n")}</pre>
        <h3>Response body</h3>
        <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:360,overflow:"auto",fontSize:11}}>{result.body}</pre>
      </div>}
      <div className="network-results">
        <h2><History size={14}/> Recent request history</h2>
        <p>{history.length} recent entries · process memory only; cleared when the companion stops</p>
        {history.map(item=><button key={item.id} type="button" className="nav-item" style={{width:"100%",marginTop:6,textAlign:"left"}} onClick={()=>{setUrl(item.target);setConfirmationUrl(item.target);setMethod(item.method);setResult(item);setConfirmSend(false);setAuthorised(false);}}>{item.method} · {item.status} · {item.target}</button>)}
        {!history.length && <p>No requests yet. Send an approved request to populate this list.</p>}
      </div>
      <div className="agent-disclaimer"><ShieldCheck size={12}/> Phase 1 provides direct request/response testing and replay. Intercepting browser proxy, crawler, automated vulnerability checks, fuzzing and WebSocket testing are separate native components still to be built.</div>
    </section>
  </main>;
}
