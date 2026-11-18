"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Copy, GitCompareArrows, Plus, Send, ShieldCheck, X } from "lucide-react";

type HttpResult = {
  id: string; status: number; reason: string; method: string; target: string;
  durationMs: number; resolvedAddress: string; headers: { name: string; value: string }[];
  body: string; bodyBytes: number; truncated: boolean; capturedAt: string;
};
type ParameterItem = { location: "query" | "form"; index: number; name: string; value: string; eligible: boolean; reason: string };
type MutationCase = { case: number; parameter: string; location: string; payload: string; method: string; url: string; body: string; contentType: string; sent: false };
type RequestTab = {
  id: string; name: string; url: string; confirmationUrl: string; method: string;
  headersText: string; body: string; response: HttpResult | null; error: string; busy: boolean;
};

const newRequest = (name: string): RequestTab => ({
  id: crypto.randomUUID(), name, url: "http://localhost:3000/",
  confirmationUrl: "http://localhost:3000/", method: "GET",
  headersText: '{\n  "Accept": "*/*"\n}', body: "", response: null, error: "", busy: false,
});

export default function WebRepeaterPage() {
  const [tabs, setTabs] = useState<RequestTab[]>([newRequest("Request 1")]);
  const [activeId, setActiveId] = useState(tabs[0].id);
  const [reference, setReference] = useState("LOCAL-LAB-001");
  const [authorised, setAuthorised] = useState(false);
  const [confirmStateChange, setConfirmStateChange] = useState(false);
  const [localLabMode, setLocalLabMode] = useState(true);
  const [baselineId, setBaselineId] = useState("");
  const [candidateId, setCandidateId] = useState("");
  const [parameterItems, setParameterItems] = useState<ParameterItem[]>([]);
  const [selectedParameter, setSelectedParameter] = useState("");
  const [payloadText, setPayloadText] = useState("test\nvalue");
  const [mutationCases, setMutationCases] = useState<MutationCase[]>([]);
  const [plannerBusy, setPlannerBusy] = useState(false);
  const [plannerError, setPlannerError] = useState("");
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [analysisReport, setAnalysisReport] = useState<any>(null);
  const [analysisError, setAnalysisError] = useState("");
  const [copyRequestStatus, setCopyRequestStatus] = useState("");
  const [responseHeaderFilter, setResponseHeaderFilter] = useState("");
  const [responseBodyMode, setResponseBodyMode] = useState<"raw" | "pretty">("pretty");
  const [responseCopyStatus, setResponseCopyStatus] = useState("");
  const [responseBodySearch, setResponseBodySearch] = useState("");
  const [responseBodyMatchIndex, setResponseBodyMatchIndex] = useState(0);
  const responseBodyRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    const activeMatch = responseBodyRef.current?.querySelector<HTMLElement>('mark[data-active-match="true"]');
    activeMatch?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [responseBodyMatchIndex, responseBodySearch, activeId, responseBodyMode]);

  useEffect(() => {
    const raw = sessionStorage.getItem("cyberlab.repeaterDraft");
    if (!raw) return;
    sessionStorage.removeItem("cyberlab.repeaterDraft");
    try {
      const draft = JSON.parse(raw);
      if (!draft || typeof draft.url !== "string" || typeof draft.method !== "string") return;
      const target = new URL(draft.url);
      const allowedMethods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
      if (!["http:", "https:"].includes(target.protocol) || !allowedMethods.includes(draft.method)) return;
      const headers = draft.headers && typeof draft.headers === "object" && !Array.isArray(draft.headers) ? draft.headers : {};
      const next = newRequest(typeof draft.name === "string" ? draft.name.slice(0, 80) : "From proxy history");
      next.url = target.toString();
      next.confirmationUrl = target.origin;
      next.method = draft.method;
      next.headersText = JSON.stringify(headers, null, 2);
      next.body = "";
      setTabs([next]);
      setActiveId(next.id);
      setBaselineId("");
      setCandidateId("");
    } catch {
      // Invalid session handoff data is ignored; no request is sent automatically.
    }
  }, []);

  const active = tabs.find(tab => tab.id === activeId) || tabs[0];
  const responses = tabs.filter(tab => tab.response);
  const baseline = responses.find(tab => tab.id === baselineId)?.response || null;
  const candidate = responses.find(tab => tab.id === candidateId)?.response || null;
  const comparison = useMemo(() => {
    if (!baseline || !candidate) return null;
    const headerMap = (items: HttpResult["headers"]) => Object.fromEntries(items.map(item => [item.name.toLowerCase(), item.value]));
    const a = headerMap(baseline.headers), b = headerMap(candidate.headers);
    const names = Array.from(new Set([...Object.keys(a), ...Object.keys(b)])).sort();
    return {
      statusChanged: baseline.status !== candidate.status,
      bodyChanged: baseline.body !== candidate.body,
      headers: names.filter(name => a[name] !== b[name]).map(name => ({ name, before: a[name] ?? "(absent)", after: b[name] ?? "(absent)" })),
      bodyLengthDelta: candidate.bodyBytes - baseline.bodyBytes,
    };
  }, [baseline, candidate]);

  function updateActive(patch: Partial<RequestTab>) {
    setTabs(current => current.map(tab => tab.id === activeId ? { ...tab, ...patch } : tab));
  }

  function addTab(duplicate: boolean) {
    if (tabs.length >= 5) return;
    const source = active;
    const next = newRequest("Request " + (tabs.length + 1));
    if (duplicate && source) {
      next.url = source.url; next.confirmationUrl = source.confirmationUrl;
      next.method = source.method; next.headersText = source.headersText; next.body = source.body;
    }
    setTabs(current => [...current, next]);
    setActiveId(next.id);
  }

  function closeTab(id: string) {
    if (tabs.length <= 1) return;
    const next = tabs.filter(tab => tab.id !== id);
    setTabs(next);
    if (activeId === id) setActiveId(next[0].id);
    if (baselineId === id) setBaselineId("");
    if (candidateId === id) setCandidateId("");
  }

  async function plannerCall(path: string, payload: Record<string, unknown>) {
    const pairing = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
    if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
    const response = await fetch("http://127.0.0.1:8765" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Parameter planner request failed.");
    return data;
  }

  async function inspectParameters() {
    if (!active) return;
    setPlannerBusy(true); setPlannerError(""); setMutationCases([]);
    try {
      const headers = JSON.parse(active.headersText || "{}") as Record<string, string>;
      const contentType = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1] || "";
      const data = await plannerCall("/web/parameters/inspect", {
        url: active.url, body: active.body, contentType,
      });
      const items = Array.isArray(data.items) ? data.items as ParameterItem[] : [];
      setParameterItems(items);
      setSelectedParameter(items.find(item => item.eligible) ? items.find(item => item.eligible)!.location + ":" + items.find(item => item.eligible)!.index : "");
      if (!items.length) setPlannerError("No query or URL-encoded form parameters were found.");
    } catch (cause) {
      setPlannerError(cause instanceof Error ? cause.message : "Parameter inspection failed.");
    } finally { setPlannerBusy(false); }
  }

  async function generateMutationCases() {
    if (!active || !selectedParameter) return;
    setPlannerBusy(true); setPlannerError("");
    try {
      const [location, indexText] = selectedParameter.split(":");
      const headers = JSON.parse(active.headersText || "{}") as Record<string, string>;
      const contentType = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1] || "";
      const payloads = payloadText.split("\n").filter(value => value.length > 0).slice(0, 25);
      const data = await plannerCall("/web/parameters/generate", {
        url: active.url, body: active.body, contentType, location,
        parameterIndex: Number(indexText), payloads, method: active.method,
      });
      setMutationCases(Array.isArray(data.cases) ? data.cases as MutationCase[] : []);
    } catch (cause) {
      setPlannerError(cause instanceof Error ? cause.message : "Case generation failed.");
    } finally { setPlannerBusy(false); }
  }

  function loadMutationCase(item: MutationCase) {
    if (tabs.length >= 5) { setPlannerError("Close a request tab before loading another draft."); return; }
    const next = newRequest("Parameter case " + item.case);
    next.url = item.url; next.confirmationUrl = new URL(item.url).origin;
    next.method = item.method;
    next.body = item.body;
    const headers = JSON.parse(active.headersText || "{}") as Record<string, string>;
    if (item.contentType) headers["Content-Type"] = item.contentType;
    next.headersText = JSON.stringify(headers, null, 2);
    setTabs(current => [...current, next]);
    setActiveId(next.id);
    setAuthorised(false);
    setConfirmStateChange(false);
  }

  async function analyzeResponses() {
    if (!baseline || !candidate) return;
    setAnalysisBusy(true); setAnalysisError(""); setAnalysisReport(null);
    try {
      const report = await plannerCall("/web/parameters/analyze", {
        baseline: { status: baseline.status, durationMs: baseline.durationMs, headers: baseline.headers, bodyBytes: baseline.bodyBytes, body: baseline.body.slice(0, 14000) },
        candidate: { status: candidate.status, durationMs: candidate.durationMs, headers: candidate.headers, bodyBytes: candidate.bodyBytes, body: candidate.body.slice(0, 14000) },
      });
      setAnalysisReport(report);
    } catch (cause) {
      setAnalysisError(cause instanceof Error ? cause.message : "Response analysis failed.");
    } finally { setAnalysisBusy(false); }
  }

  async function copyRequestAsCurl() {
    if (!active) return;
    try {
      const parsedHeaders: unknown = JSON.parse(active.headersText);
      if (!parsedHeaders || Array.isArray(parsedHeaders) || typeof parsedHeaders !== "object") {
        throw new Error("Headers must be a JSON object before exporting.");
      }
      const quote = (value: string) => "'" + value.split("'").join("'\"'\"'") + "'";
      const args = ["curl", "--request", quote(active.method), "--url", quote(active.url)];
      for (const [name, value] of Object.entries(parsedHeaders as Record<string, unknown>)) {
        if (typeof value !== "string") throw new Error("Every header value must be text before exporting.");
        args.push("--header", quote(name + ": " + value));
      }
      if (active.body) args.push("--data-binary", quote(active.body));
      await navigator.clipboard.writeText(args.join(" "));
      setCopyRequestStatus("cURL command copied. Review it before running; it does not carry CyberLab's approval gates.");
    } catch (cause) {
      setCopyRequestStatus(cause instanceof Error ? cause.message : "Could not copy the cURL command.");
    }
  }

  function renderSearchableBody(value: string) {
    const query = responseBodySearch.trim();
    if (!query) return value;
    const lowerValue = value.toLocaleLowerCase();
    const lowerQuery = query.toLocaleLowerCase();
    const matches: number[] = [];
    let cursor = 0;
    while (matches.length < 5000) {
      const found = lowerValue.indexOf(lowerQuery, cursor);
      if (found < 0) break;
      matches.push(found);
      cursor = found + lowerQuery.length;
    }
    if (!matches.length) return value;
    const parts = [];
    let last = 0;
    for (let index = 0; index < matches.length; index += 1) {
      const start = matches[index];
      if (start > last) parts.push(value.slice(last, start));
      parts.push(<mark key={start} data-active-match={index === responseBodyMatchIndex ? "true" : "false"} style={index === responseBodyMatchIndex ? {outline:"2px solid currentColor"} : undefined}>{value.slice(start, start + query.length)}</mark>);
      last = start + query.length;
    }
    if (last < value.length) parts.push(value.slice(last));
    return <>{parts}{matches.length === 5000 && <span> [match display capped at 5,000]</span>}</>;
  }

  async function copyResponse() {
    if (!active?.response) return;
    const response = active.response;
    const statusLine = `HTTP response ${response.status} ${response.reason}`;
    const headerLines = response.headers.map(header => header.name + ": " + header.value);
    const exportText = [statusLine, ...headerLines, "", response.body].join("\n");
    try {
      await navigator.clipboard.writeText(exportText);
      setResponseCopyStatus("Response copied to clipboard. Treat copied headers and body as potentially sensitive.");
    } catch (cause) {
      setResponseCopyStatus(cause instanceof Error ? cause.message : "Could not copy the response.");
    }
  }

  async function sendRequest() {
    if (!active) return;
    updateActive({ busy: true, error: "", response: null });
    try {
      const pairing = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!pairing) throw new Error("Connect the local Kali companion first in Kali Connection.");
      let parsedHeaders: unknown;
      try { parsedHeaders = JSON.parse(active.headersText); } catch { throw new Error("Headers must be valid JSON in name/value format."); }
      if (!parsedHeaders || Array.isArray(parsedHeaders) || typeof parsedHeaders !== "object") throw new Error("Headers must be a JSON object.");
      const stateChanging = ["POST", "PUT", "PATCH", "DELETE"].includes(active.method);
      const response = await fetch("http://127.0.0.1:8765/web/request", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + pairing },
        body: JSON.stringify({
          url: active.url, confirmationUrl: active.confirmationUrl, method: active.method,
          headers: parsedHeaders, body: active.body, authorizationReference: reference,
          authorizationConfirmed: authorised, confirmSend: true,
          confirmStateChange: stateChanging && confirmStateChange, localLabMode,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Native request failed.");
      const result = data as HttpResult;
      setTabs(current => current.map(tab => tab.id === activeId ? { ...tab, response: result, error: "", busy: false } : tab));
      setCandidateId(activeId);
      if (!baselineId) setBaselineId(activeId);
    } catch (cause) {
      updateActive({ error: cause instanceof Error ? cause.message : "Unexpected request error.", busy: false });
    }
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/web-workbench" className="agent-back"><ArrowLeft size={14}/> Web workbench</Link>
      <div className="agent-brand"><GitCompareArrows size={16}/> CYBERLAB AI <span className="agent-top-sep">/</span> NATIVE REPEATER</div>
      <span className="agent-secure-label"><span/> LOCAL ENGINE</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">NATIVE HTTP TESTING / 002</div>
        <h1>Request repeater</h1>
        <p>Prepare, edit and manually resend bounded HTTP requests through CyberLab's native local engine. Every send is explicit; no request is replayed automatically.</p>
      </div>
      <div className="scope-warning"><ShieldCheck size={14}/> Use only systems covered by written permission. The companion pins DNS, blocks private addresses outside loopback lab mode, does not follow redirects and enforces request/response limits. POST, PUT, PATCH and DELETE require separate approval.</div>
      <div className="network-results">
        <h2>Request tabs</h2>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          {tabs.map(tab=><div key={tab.id} style={{display:"flex",gap:4,alignItems:"center"}}>
            <button className="nav-item" type="button" onClick={()=>setActiveId(tab.id)} aria-pressed={activeId===tab.id}>{tab.name}{tab.response ? " · "+tab.response.status : ""}</button>
            {tabs.length>1 && <button className="nav-item" type="button" onClick={()=>closeTab(tab.id)} aria-label={"Close "+tab.name}><X size={12}/></button>}
          </div>)}
          <button className="report-download" type="button" disabled={tabs.length>=5} onClick={()=>addTab(false)}><Plus size={13}/> New</button>
          <button className="report-download" type="button" disabled={tabs.length>=5} onClick={()=>addTab(true)}><Copy size={13}/> Duplicate</button>
        </div>
        <p>{tabs.length}/5 request tabs · responses are kept in this browser session only.</p>
      </div>
      {active && <div className="report-editor">
        <label>Request name<input value={active.name} onChange={e=>updateActive({name:e.target.value})}/></label>
        <label>Target URL<input value={active.url} onChange={e=>updateActive({url:e.target.value})} maxLength={2048}/></label>
        <label>Retype target hostname<input value={active.confirmationUrl} onChange={e=>updateActive({confirmationUrl:e.target.value})} maxLength={2048}/></label>
        <label>HTTP method<select value={active.method} onChange={e=>updateActive({method:e.target.value})}>{["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"].map(item=><option key={item}>{item}</option>)}</select></label>
        <label>Headers · JSON object<textarea rows={5} spellCheck={false} value={active.headersText} onChange={e=>updateActive({headersText:e.target.value})}/></label>
        <label>Request body · maximum 16 KB<textarea rows={6} value={active.body} onChange={e=>updateActive({body:e.target.value})} placeholder="Optional request body for POST, PUT or PATCH"/></label>
        <div className="network-results">
          <h2>Parameter test planner · draft only</h2>
          <p>Inspect URL query or URL-encoded form fields. Sensitive-looking names are excluded. This planner sends no traffic.</p>
          <button className="report-download" type="button" disabled={plannerBusy} onClick={inspectParameters}>{plannerBusy ? "Working…" : "Inspect parameters"}</button>
          {parameterItems.length > 0 && <>
            <label>Parameter to mutate<select value={selectedParameter} onChange={e=>setSelectedParameter(e.target.value)}>
              {parameterItems.map(item=><option key={item.location+":"+item.index} value={item.location+":"+item.index} disabled={!item.eligible}>{item.location} · {item.name} · {item.eligible ? "eligible" : item.reason}</option>)}
            </select></label>
            <label>Test values · one per line, maximum 25<textarea rows={4} value={payloadText} onChange={e=>setPayloadText(e.target.value)} /></label>
            <button className="report-download" type="button" disabled={plannerBusy || !selectedParameter || !payloadText.trim()} onClick={generateMutationCases}>Generate unsent cases</button>
          </>}
          {plannerError && <div className="agent-error">{plannerError}</div>}
          {mutationCases.map(item=><div key={item.case} className="scope-warning">
            <strong>Case {item.case} · {item.parameter}</strong>
            <p>{item.method} · {item.location} · value: {item.payload}</p>
            <button className="report-download" type="button" disabled={tabs.length>=5} onClick={()=>loadMutationCase(item)}>Load as unsent Repeater draft</button>
          </div>)}
        </div>
        <label>Engagement / authorisation reference<input value={reference} onChange={e=>setReference(e.target.value)} maxLength={160}/></label>
        <div className="scope-checks"><label><input type="checkbox" checked={localLabMode} onChange={e=>setLocalLabMode(e.target.checked)}/> Local lab mode (loopback only)</label></div>
        <div className="scope-checks"><label><input type="checkbox" checked={authorised} onChange={e=>setAuthorised(e.target.checked)}/> I own this target or have explicit written authorisation.</label></div>
        {["POST","PUT","PATCH","DELETE"].includes(active.method) && <div className="scope-checks"><label><input type="checkbox" checked={confirmStateChange} onChange={e=>setConfirmStateChange(e.target.checked)}/> I separately approve this state-changing request.</label></div>}
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          <button className="report-download" type="button" disabled={active.busy || !authorised || !reference.trim() || (["POST","PUT","PATCH","DELETE"].includes(active.method) && !confirmStateChange)} onClick={sendRequest}>{active.busy ? "Sending…" : <><Send size={14}/> Send request</>}</button>
          <button className="report-download" type="button" onClick={copyRequestAsCurl}><Copy size={13}/> Copy as cURL</button>
        </div>
        {copyRequestStatus && <p role="status">{copyRequestStatus}</p>}
        {active.error && <div className="agent-error">{active.error}</div>}
      </div>}
      {active?.response && <div className="network-results">
        <h2>Response · {active.response.status} {active.response.reason}</h2>
        <p>{active.response.method} {active.response.target} · {active.response.durationMs} ms · {active.response.resolvedAddress} · {active.response.bodyBytes} bytes{active.response.truncated ? " · preview truncated" : ""}</p>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <button className="report-download" type="button" onClick={copyResponse}><Copy size={13}/> Copy response</button>
          {responseCopyStatus && <span role="status">{responseCopyStatus}</span>}
        </div>
        <h3>Headers · {active.response.headers.length}</h3>
        <input aria-label="Filter response headers" placeholder="Filter header names or values" value={responseHeaderFilter} onChange={event=>setResponseHeaderFilter(event.target.value)} />
        <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",fontSize:11}}>{active.response.headers.filter(header => (header.name + ": " + header.value).toLowerCase().includes(responseHeaderFilter.toLowerCase())).map(header=>header.name+": "+header.value).join("\n") || "No matching response headers."}</pre>
        <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
          <h3>Body</h3>
          <button className="report-download" type="button" onClick={()=>setResponseBodyMode(mode=>mode==="pretty" ? "raw" : "pretty")}>{responseBodyMode==="pretty" ? "Show raw" : "Pretty-print JSON"}</button>
        </div>
        {(() => {
          const contentType = active.response.headers.find(header=>header.name.toLowerCase()==="content-type")?.value || "";
          let body = active.response.body;
          if (responseBodyMode === "pretty" && /json/i.test(contentType)) {
            try { body = JSON.stringify(JSON.parse(body), null, 2); } catch { /* Keep malformed JSON visible as captured. */ }
          }
          const query = responseBodySearch.trim().toLocaleLowerCase();
          let matchCount = 0;
          if (query) {
            let cursor = 0;
            const lowerBody = body.toLocaleLowerCase();
            while (matchCount < 5001) {
              const found = lowerBody.indexOf(query, cursor);
              if (found < 0) break;
              matchCount += 1;
              cursor = found + query.length;
            }
          }
          return <>
            <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",marginBottom:8}}>
              <input aria-label="Search response body" placeholder="Find text in response body" value={responseBodySearch} onChange={event=>{setResponseBodySearch(event.target.value);setResponseBodyMatchIndex(0);}} />
              <span role="status">{query ? (matchCount > 5000 ? "5,000+ matches" : matchCount + " match(es)") : "Search captured body"}</span>
              <button className="report-download" type="button" disabled={!matchCount} onClick={()=>setResponseBodyMatchIndex(index=>(index-1+Math.min(matchCount,5000))%Math.min(matchCount,5000))}>Previous</button>
              <button className="report-download" type="button" disabled={!matchCount} onClick={()=>setResponseBodyMatchIndex(index=>(index+1)%Math.min(matchCount,5000))}>Next</button>
            </div>
            <pre ref={responseBodyRef} style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:360,overflow:"auto",fontSize:11}}>{renderSearchableBody(body)}</pre>
          </>;
        })()}
        {active.response.truncated && <p className="agent-disclaimer">Only a bounded response preview is available here; copying does not recover bytes omitted by the companion.</p>}
      </div>}
      <div className="network-results">
        <h2>Response comparison</h2>
        <p>Choose two responses captured by explicit sends to compare status, headers and body text.</p>
        <label>Baseline response<select value={baselineId} onChange={e=>setBaselineId(e.target.value)}><option value="">Select response</option>{responses.map(tab=><option key={tab.id} value={tab.id}>{tab.name} · {tab.response?.status}</option>)}</select></label>
        <label>Candidate response<select value={candidateId} onChange={e=>setCandidateId(e.target.value)}><option value="">Select response</option>{responses.map(tab=><option key={tab.id} value={tab.id}>{tab.name} · {tab.response?.status}</option>)}</select></label>
        {comparison && <>
          <p>Status: {comparison.statusChanged ? "changed" : "unchanged"} · Body: {comparison.bodyChanged ? "changed" : "unchanged"} · Body size delta: {comparison.bodyLengthDelta} bytes</p>
          <h3>Changed headers ({comparison.headers.length})</h3>
          {comparison.headers.map(item=><div key={item.name} className="scope-warning"><strong>{item.name}</strong><p>Before: {item.before}</p><p>After: {item.after}</p></div>)}
          {!comparison.headers.length && <p>No header differences detected.</p>}
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:10}}>
            <div><h3>Baseline body</h3><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:320,overflow:"auto",fontSize:11}}>{baseline?.body}</pre></div>
            <div><h3>Candidate body</h3><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxHeight:320,overflow:"auto",fontSize:11}}>{candidate?.body}</pre></div>
          </div>
        </>}
        {comparison && <button className="report-download" type="button" disabled={analysisBusy} onClick={analyzeResponses}>{analysisBusy ? "Analysing…" : "Generate offline analysis report"}</button>}
        {analysisError && <div className="agent-error">{analysisError}</div>}
        {analysisReport && <>
          <h3>Review indicators</h3>
          <p>{analysisReport.summary?.changedHeaderCount ?? 0} changed header(s) · timing delta {analysisReport.summary?.durationDeltaMs ?? 0} ms</p>
          {(analysisReport.indicators || []).map((item: {code:string;label:string;detail:string;level:string})=><div key={item.code} className="scope-warning"><strong>{item.label}</strong><p>{item.detail}</p></div>)}
          {!analysisReport.indicators?.length && <p>No differences detected in the analysed response data.</p>}
          <p className="agent-disclaimer">Offline comparison only. Bodies are hashed in memory and not returned in this report; only the first 14 KB of each displayed body preview is analysed. Differences are indicators, not proof of a vulnerability.</p>
        </>}
        {!comparison && <p>Send at least two requests, or select two saved responses, to compare them.</p>}
      </div>
      <div className="agent-disclaimer"><ShieldCheck size={12}/> Requests loaded from proxy history are drafts only. Query strings, request bodies and redacted credentials are not restored. Review the target and re-enter any required test data; every send still requires fresh explicit authorisation and confirmation. Response editing is available in the proxy interception workbench, not in the Repeater response pane. This native repeater is not full Burp Repeater parity: no raw binary editor, HTTP/2, WebSockets or automated concurrent Intruder/fuzzing. The offline parameter planner can generate bounded unsent drafts for manual review.</div>
    </section>
  </main>;
}
