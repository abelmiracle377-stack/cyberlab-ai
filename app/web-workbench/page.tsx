"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, AlertTriangle, Globe, History, LoaderCircle, Send, ShieldCheck } from "lucide-react";

type ProxyHistoryItem = { id: string; method: string; url: string; status: number; queryOmitted?: boolean; requestBodyOmitted?: boolean; responseBodyOmitted?: boolean; durationMs: number; };
type PendingIntercept = { id: string; method: string; url: string; path: string; headers: { name: string; value: string }[]; bodyLength: number; bodyOmitted: boolean; body: string; bodyEditable: boolean; createdAt: string; decisionTimeoutSeconds: number; };
type InterceptDraft = { method: string; path: string; headersText: string; body: string };
type HttpResult = {
  id: string; status: number; reason: string; method: string; target: string;
  durationMs: number; resolvedAddress: string; headers: { name: string; value: string }[];
  body: string; bodyBytes: number; truncated: boolean; capturedAt: string; responseBodyOmitted?: boolean; responseBodyLength?: number; targetQueryOmitted?: boolean;
  requestHeaders?: Record<string, string>; requestBodyOmitted?: boolean; requestBodyLength?: number;
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
  const [historyBodyOmitted, setHistoryBodyOmitted] = useState(false);
  const [historySecretsRedacted, setHistorySecretsRedacted] = useState(false);
  const [caReady, setCaReady] = useState(false);
  const [caCertificatePath, setCaCertificatePath] = useState("");
  const [caPem, setCaPem] = useState("");
  const [caConsent, setCaConsent] = useState(false);
  const [caBusy, setCaBusy] = useState(false);
  const [caError, setCaError] = useState("");
  const [proxyOrigin, setProxyOrigin] = useState("http://localhost:3000");
  const [proxyConfirmation, setProxyConfirmation] = useState("http://localhost:3000");
  const [proxyAuthorised, setProxyAuthorised] = useState(false);
  const [proxyStartConsent, setProxyStartConsent] = useState(false);
  const [proxyMutatingConsent, setProxyMutatingConsent] = useState(false);
  const [proxyInterceptConsent, setProxyInterceptConsent] = useState(false);
  const [proxyInterceptActive, setProxyInterceptActive] = useState(false);
  const [pendingIntercepts, setPendingIntercepts] = useState<PendingIntercept[]>([]);
  const [interceptDrafts, setInterceptDrafts] = useState<Record<string, InterceptDraft>>({});
  const [interceptBusyId, setInterceptBusyId] = useState("");
  const [proxyActive, setProxyActive] = useState(false);
  const [proxyActiveScope, setProxyActiveScope] = useState("");
  const [proxyMutatingActive, setProxyMutatingActive] = useState(false);
  const [proxyPort, setProxyPort] = useState(8081);
  const [proxyBusy, setProxyBusy] = useState(false);
  const [proxyError, setProxyError] = useState("");
  const [proxyHistory, setProxyHistory] = useState<ProxyHistoryItem[]>([]);

  const token = () => sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";

  async function loadHistory() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/web/history", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load request history.");
    setHistory(data.items || []);
  }

  async function loadCaStatus() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/proxy/ca/status", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not inspect local CA status.");
    setCaReady(Boolean(data.ready));
    setCaCertificatePath(data.caCertificate || "");
    if (data.ready) {
      const certificate = await fetch("http://127.0.0.1:8765/proxy/ca/certificate", { headers: { Authorization: "Bearer " + pairing } });
      const certificateData = await certificate.json();
      if (!certificate.ok) throw new Error(certificateData.error || "Could not retrieve public CA certificate.");
      setCaPem(certificateData.pem || "");
    } else setCaPem("");
  }

  async function loadProxyStatus() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/proxy/status", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not inspect proxy status.");
    setProxyActive(Boolean(data.active));
    setProxyActiveScope(data.scope || "");
    setProxyMutatingActive(Boolean(data.allowStateChangingMethods));
    setProxyInterceptActive(Boolean(data.interceptRequests));
    if (data.listenPort) setProxyPort(data.listenPort);
  }

  async function loadProxyHistory() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/proxy/history", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load proxy history.");
    setProxyHistory(data.items || []);
  }

  async function loadPendingIntercepts() {
    const pairing = token();
    if (!pairing) return;
    const response = await fetch("http://127.0.0.1:8765/proxy/intercepts", { headers: { Authorization: "Bearer " + pairing } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load pending intercepted requests.");
    const items: PendingIntercept[] = data.items || [];
    setPendingIntercepts(items);
    setInterceptDrafts(current => {
      const next = { ...current };
      for (const item of items) if (!next[item.id]) next[item.id] = {
        method: item.method, path: item.path,
        headersText: JSON.stringify(item.headers.filter(header => !["host", "content-length", "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization", "expect"].includes(header.name.toLowerCase())), null, 2), body: item.body || "",
      };
      for (const id of Object.keys(next)) if (!items.some(item => item.id === id)) delete next[id];
      return next;
    });
  }

  async function decidePendingIntercept(id: string, action: "forward" | "forward_edited" | "drop") {
    setInterceptBusyId(id); setProxyError("");
    try {
      const pairing = token();
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      let edits: { method: string; path: string; headers: { name: string; value: string }[]; body?: string } | undefined;
      if (action === "forward_edited") {
        const draft = interceptDrafts[id];
        if (!draft) throw new Error("The request editor is not ready.");
        let parsed: unknown;
        try { parsed = JSON.parse(draft.headersText); } catch { throw new Error("Edited headers must be valid JSON."); }
        if (!Array.isArray(parsed)) throw new Error("Edited headers must be a JSON array of name/value objects.");
        const pending = pendingIntercepts.find(item => item.id === id);
        edits = { method: draft.method, path: draft.path, headers: parsed, ...(pending?.bodyEditable ? { body: draft.body } : {}) };
      }
      const response = await fetch("http://127.0.0.1:8765/proxy/intercepts/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: JSON.stringify({ id, action, edits }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not apply the interception decision.");
      await loadPendingIntercepts();
    } catch (cause) { setProxyError(cause instanceof Error ? cause.message : "Unexpected interception decision error."); }
    finally { setInterceptBusyId(""); }
  }

  async function startProxy() {
    setProxyBusy(true); setProxyError("");
    try {
      const pairing = token();
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/proxy/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: JSON.stringify({ origin: proxyOrigin, confirmationOrigin: proxyConfirmation, authorizationConfirmed: proxyAuthorised, confirmStart: proxyStartConsent, authorizationReference: reference, localLabMode, listenPort: 8081, allowStateChangingMethods: proxyMutatingConsent, confirmStateChangingMethods: proxyMutatingConsent, interceptRequests: proxyInterceptConsent, confirmInterceptRequests: proxyInterceptConsent }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not start the native interception proxy.");
      setProxyActive(Boolean(data.active));
      setProxyActiveScope(data.scope || "");
      setProxyMutatingActive(Boolean(data.allowStateChangingMethods));
      setProxyInterceptActive(Boolean(data.interceptRequests));
      setProxyPort(data.listenPort || 8081);
      setProxyStartConsent(false);
      setProxyMutatingConsent(false);
      setProxyInterceptConsent(false);
      await loadProxyHistory();
      await loadPendingIntercepts();
    } catch (cause) { setProxyError(cause instanceof Error ? cause.message : "Unexpected proxy start error."); }
    finally { setProxyBusy(false); }
  }

  async function stopProxy() {
    setProxyBusy(true); setProxyError("");
    try {
      const pairing = token();
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/proxy/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not stop the native interception proxy.");
      setProxyActive(Boolean(data.active));
      setProxyActiveScope(data.scope || "");
      setProxyMutatingActive(Boolean(data.allowStateChangingMethods));
      setProxyInterceptActive(Boolean(data.interceptRequests));
      setProxyMutatingConsent(false);
      setProxyInterceptConsent(false);
      await loadPendingIntercepts();
    } catch (cause) { setProxyError(cause instanceof Error ? cause.message : "Unexpected proxy stop error."); }
    finally { setProxyBusy(false); }
  }

  async function createLocalCa() {
    setCaBusy(true); setCaError("");
    try {
      const pairing = token();
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      const response = await fetch("http://127.0.0.1:8765/proxy/ca/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: JSON.stringify({ confirmCreateLocalCA: caConsent }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not create local inspection CA.");
      setCaReady(Boolean(data.ready));
      setCaCertificatePath(data.caCertificate || "");
      await loadCaStatus();
    } catch (cause) { setCaError(cause instanceof Error ? cause.message : "Unexpected CA setup error."); }
    finally { setCaBusy(false); }
  }

  useEffect(() => { loadHistory().catch(() => undefined); loadCaStatus().catch(() => undefined); loadProxyStatus().catch(() => undefined); loadProxyHistory().catch(() => undefined); loadPendingIntercepts().catch(() => undefined); }, []);
  useEffect(() => {
    if (!proxyInterceptActive) return;
    const interval = window.setInterval(() => { loadPendingIntercepts().catch(() => undefined); }, 1000);
    return () => window.clearInterval(interval);
  }, [proxyInterceptActive]);

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
      setHistoryBodyOmitted(false);
      setHistorySecretsRedacted(false);
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
      <div className="scope-warning"><AlertTriangle size={14}/> Active requests contact the selected server. Use only an asset covered by written permission. The engine pins DNS resolution, blocks private addresses except explicit loopback lab mode, does not follow redirects, and caps request/response sizes.</div>\n      <div className="network-results">
        <h2><Globe size={14}/> CyberLab native interception proxy</h2>
        <p>{proxyActive ? "Proxy is running for " + proxyActiveScope + "." : "Proxy is stopped."} It listens only on 127.0.0.1:{proxyPort} and enforces one exact approved origin. Configure your dedicated test browser to use that address as its HTTP and HTTPS proxy after starting it.</p>
        {!proxyActive && <>
          <label>Exact origin to intercept<input value={proxyOrigin} onChange={e=>{setProxyOrigin(e.target.value);setProxyConfirmation("");}} placeholder="https://your-authorised-domain.example"/></label>
          <label>Retype exact origin<input value={proxyConfirmation} onChange={e=>setProxyConfirmation(e.target.value)} placeholder="Retype the origin exactly"/></label>
          <div className="scope-checks"><label><input type="checkbox" checked={proxyAuthorised} onChange={e=>setProxyAuthorised(e.target.checked)}/> I own this origin or have explicit written authorisation to inspect its traffic.</label></div>
          <div className="scope-checks"><label><input type="checkbox" checked={proxyStartConsent} onChange={e=>setProxyStartConsent(e.target.checked)}/> I explicitly approve starting the local proxy for this exact origin. Browser requests to this origin will be forwarded while it is running.</label></div>
          <div className="scope-checks"><label><input type="checkbox" checked={proxyMutatingConsent} onChange={e=>setProxyMutatingConsent(e.target.checked)}/> I separately approve forwarding POST, PUT, PATCH and DELETE requests. These methods are blocked unless I enable this.</label></div>
          <div className="scope-checks"><label><input type="checkbox" checked={proxyInterceptConsent} onChange={e=>setProxyInterceptConsent(e.target.checked)}/> Enable manual interception: pause each in-scope request until I explicitly choose Forward or Drop in this workbench. Requests time out and are dropped if I do not decide within 120 seconds.</label></div>
          <button className="report-download" type="button" disabled={proxyBusy || !proxyAuthorised || !proxyStartConsent || proxyOrigin !== proxyConfirmation || !reference.trim() || (proxyOrigin.startsWith("https://") && !caReady)} onClick={startProxy}>{proxyBusy ? "Starting proxy…" : "Start native interception proxy"}</button>
        </>}
        {proxyActive && <button className="report-download" type="button" disabled={proxyBusy} onClick={stopProxy}>{proxyBusy ? "Stopping proxy…" : "Stop interception proxy"}</button>}
        {proxyError && <div className="agent-error"><AlertTriangle size={14}/>{proxyError}</div>}
        <p>Current implementation: HTTP/1.1 request/response inspection and HTTPS CONNECT TLS termination with upstream certificate validation. One request per client connection; no HTTP/2, WebSockets, chunked client request bodies or client certificates. POST, PUT, PATCH and DELETE are blocked unless separately approved. Bodies are forwarded but never retained in history. Out-of-scope hosts are blocked. State-changing methods are {proxyMutatingActive ? "enabled for this session" : "blocked for this session"}. Manual interception is {proxyInterceptActive ? "enabled; requests wait for an operator decision" : "disabled"}.</p>
        {proxyInterceptActive && <>
          <h3>Requests waiting for your decision</h3>
          <button className="report-download" type="button" onClick={()=>loadPendingIntercepts().catch(cause=>setProxyError(cause instanceof Error ? cause.message : "Could not refresh pending requests."))}>Refresh pending requests</button>
          {pendingIntercepts.map(item=><div className="scope-warning" key={item.id}>
            <strong>{item.method} · {item.url}</strong>
            <p>Captured {item.createdAt}. Body: {item.bodyLength} bytes. Sensitive header values are redacted; leave the [REDACTED] placeholders unchanged to preserve the original values. Request contents remain in companion memory only while pending.</p>
            <label>Method<input value={interceptDrafts[item.id]?.method || item.method} onChange={e=>setInterceptDrafts(current=>({...current,[item.id]:{...current[item.id],method:e.target.value}}))}/></label>
            <label>Path and query<textarea rows={2} value={interceptDrafts[item.id]?.path || item.path} onChange={e=>setInterceptDrafts(current=>({...current,[item.id]:{...current[item.id],path:e.target.value}}))}/></label>
            <label>Headers · JSON array<textarea rows={5} spellCheck={false} value={interceptDrafts[item.id]?.headersText || ""} onChange={e=>setInterceptDrafts(current=>({...current,[item.id]:{...current[item.id],headersText:e.target.value}}))}/></label>
            <label>Body · UTF-8 text only<textarea rows={5} disabled={!item.bodyEditable} value={interceptDrafts[item.id]?.body ?? ""} onChange={e=>setInterceptDrafts(current=>({...current,[item.id]:{...current[item.id],body:e.target.value}}))} placeholder={item.bodyEditable ? "Request body" : "Binary body cannot be edited here; forward unchanged or drop"}/></label>
            <button className="report-download" type="button" disabled={Boolean(interceptBusyId)} onClick={()=>decidePendingIntercept(item.id,"forward")}>Forward unchanged</button>
            <button className="report-download" type="button" disabled={Boolean(interceptBusyId)} onClick={()=>decidePendingIntercept(item.id,"forward_edited")}>{interceptBusyId===item.id ? "Applying…" : "Forward edited request"}</button>
            <button className="report-download" type="button" disabled={Boolean(interceptBusyId)} onClick={()=>decidePendingIntercept(item.id,"drop")}>Drop request</button>
          </div>)}
          {!pendingIntercepts.length && <p>No requests are currently waiting.</p>}
        </>}
        <h3>Recent intercepted requests</h3>
        <button className="report-download" type="button" onClick={()=>loadProxyHistory().catch(cause=>setProxyError(cause instanceof Error ? cause.message : "Could not refresh proxy history."))}>Refresh proxy history</button>
        {proxyHistory.map(item=><p key={item.id}>{item.method} · {item.status} · {item.url}{item.queryOmitted ? " · query omitted" : ""} · {item.durationMs} ms</p>)}
        {!proxyHistory.length && <p>No proxy requests recorded in this companion session.</p>}
      </div>
      <div className="network-results">
        <h2><ShieldCheck size={14}/> HTTPS inspection certificate authority</h2>
        <p>Foundation for CyberLab's native HTTPS interception. Creating this local CA does not install or trust it automatically. You must manually import the public certificate into a dedicated test browser profile. Never distribute the CA private key.</p>
        <p>{caReady ? "Local CA is ready." : "No local inspection CA has been created."}</p>
        {caCertificatePath && <p>Public CA certificate path on Kali: <code>{caCertificatePath}</code></p>}
        {caPem && <p><a className="nav-item" href={"data:application/x-pem-file;charset=utf-8," + encodeURIComponent(caPem)} download="cyberlab-local-inspection-ca.pem">Download public CA certificate for manual browser import</a></p>}
        {!caReady && <div className="scope-checks"><label><input type="checkbox" checked={caConsent} onChange={e=>setCaConsent(e.target.checked)}/> I explicitly approve generating a local CA and understand that trusting it enables HTTPS traffic decryption for traffic routed through CyberLab.</label></div>}
        {!caReady && <button className="report-download" type="button" disabled={!caConsent || caBusy} onClick={createLocalCa}>{caBusy ? "Creating local CA…" : "Create local inspection CA"}</button>}
        {caError && <div className="agent-error"><AlertTriangle size={14}/>{caError}</div>}
        <p>Private key storage is owner-only under the Kali user's CyberLab configuration directory. Browser and operating-system trust stores are never modified by CyberLab.</p>
      </div>

      <form className="report-editor" onSubmit={sendRequest}>
        <label>Target URL<input value={url} onChange={e=>setUrl(e.target.value)} required maxLength={2048} placeholder="https://your-authorised-domain.example/path"/></label>
        <label>Retype target URL to confirm hostname<input value={confirmationUrl} onChange={e=>setConfirmationUrl(e.target.value)} required maxLength={2048}/></label>
        <label>HTTP method<select value={method} onChange={e=>setMethod(e.target.value)}>{["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"].map(item=><option key={item}>{item}</option>)}</select></label>
        <label>Request headers · JSON<textarea value={headersText} onChange={e=>setHeadersText(e.target.value)} rows={4} spellCheck={false}/></label>
        <label>Request body · maximum 16 KB<textarea value={body} onChange={e=>{setBody(e.target.value);setHistoryBodyOmitted(false);}} rows={5} spellCheck={false} placeholder="Optional request body for POST, PUT or PATCH"/></label>
        {historyBodyOmitted && <div className="scope-warning">The selected history item contained a request body. CyberLab deliberately did not store its contents; re-enter the body manually before replay.</div>}
        {historySecretsRedacted && <div className="scope-warning">Sensitive headers were redacted from history and removed from the replay draft. Re-enter any required credentials manually; they will not be recovered from history.</div>}
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
        <p>{result.method} {result.target} · {result.durationMs} ms · pinned address {result.resolvedAddress} · {result.bodyBytes} bytes{result.truncated?" · response truncated":""}{result.targetQueryOmitted?" · query omitted from history; re-enter it manually for replay":""}</p>
        <h3>Response headers</h3>
        <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",fontSize:11}}>{result.headers.map(h=>h.name+": "+h.value).join("\n")}</pre>
        <h3>Response body{result.responseBodyOmitted ? " · omitted from history" : ""}</h3>
        <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:360,overflow:"auto",fontSize:11}}>{result.body}</pre>
      </div>}
      <div className="network-results">
        <h2><History size={14}/> Recent request history</h2>
        <p>{history.length} recent entries · process memory only; cleared when the companion stops</p>
        {history.map(item=><button key={item.id} type="button" className="nav-item" style={{width:"100%",marginTop:6,textAlign:"left"}} onClick={()=>{setUrl(item.target);setConfirmationUrl(item.target);setMethod(item.method);setHeadersText(JSON.stringify(Object.fromEntries(Object.entries(item.requestHeaders || {}).filter(([, value])=>value !== "[REDACTED]")), null, 2));setBody("");setHistoryBodyOmitted(Boolean(item.requestBodyOmitted));setHistorySecretsRedacted(Object.values(item.requestHeaders || {}).includes("[REDACTED]"));setResult({...item,body:item.responseBodyOmitted?"[Response body omitted from history. Send a new approved request to inspect it.]":item.body});setConfirmSend(false);setAuthorised(false);setConfirmStateChange(false);}}>{item.method} · {item.status} · {item.target}</button>)}
        {!history.length && <p>No requests yet. Send an approved request to populate this list.</p>}
      </div>
      <div className="agent-disclaimer"><ShieldCheck size={12}/> The native request workbench supports approved request replay from in-memory history. Request and response bodies are not retained in history; sensitive request and response headers are redacted. The live response remains visible only in the current workbench session. The native crawler and limited safe active checks are available separately; intercepting browser proxy, advanced vulnerability checks, fuzzing and WebSocket testing remain in development.</div>
    </section>
  </main>;
}
