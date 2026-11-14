"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, FileUp, Network, ShieldCheck, AlertTriangle } from "lucide-react";
import InvestigationLink from "@/components/investigation-link";

type Port = { protocol: string; port: number; state: string; reason?: string; service: string; product: string; version: string; method?: string; confidence?: string | null };
type Host = { index: number; status: string; addresses: { address: string; type: string }[]; hostnames: string[]; ports: Port[] };
type Result = { summary: { hosts: number; up: number; ports: number; openPorts: number; stateCounts?: Record<string, number> }; hosts: Host[]; openPorts: (Port & { host: string })[]; evidenceStatus?: string; scaninfo?: Record<string, string>[]; completion?: { finished?: Record<string, string>; hosts?: Record<string, string>; scanner?: string; version?: string; args?: string; start?: string }; note: string };

export default function NetworkAnalysisPage() {
  const [fileName, setFileName] = useState("");
  const [xml, setXml] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function chooseFile(file?: File) {
    if (!file) return;
    setError("");
    setResult(null);
    if (!file.name.toLowerCase().endsWith(".xml")) {
      setError("Choose an Nmap XML file with the .xml extension.");
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setError("File exceeds the 2 MB limit.");
      return;
    }
    setFileName(file.name);
    setXml(await file.text());
  }

  async function analyse() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/network/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ xml }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not parse report.");
      setResult(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unexpected parser error.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="agent-shell">
    <header className="agent-topbar">
      <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
      <div className="agent-brand"><Network size={16} /> CYBERLAB AI <span className="agent-top-sep">/</span> NETWORK ANALYSIS</div>
      <span className="agent-secure-label"><span /> LOCAL REPORT PARSING</span>
    </header>
    <section className="agent-main">
      <div className="agent-heading">
        <div className="agent-overline">NETWORK EVIDENCE / 002</div>
        <h1>Nmap report analyser</h1>
        <p>Upload an existing Nmap XML report to summarise hosts, port states and detected services.</p>
      </div>
      <div className="network-upload">
        <div className="network-upload-icon"><FileUp size={22} /></div>
        <h2>Import Nmap XML</h2>
        <p>Only an existing XML report is processed. CyberLab AI will not initiate a scan.</p>
        <label className="network-file">
          <input type="file" accept=".xml,application/xml,text/xml" onChange={(event) => chooseFile(event.target.files?.[0])} />
          Choose XML report
        </label>
        {fileName && <div className="network-filename">{fileName}</div>}
        <button className="network-run" onClick={analyse} disabled={!xml.trim() || busy}>{busy ? "Analysing…" : "Analyse report"}</button>
        <div className="network-limit">MAXIMUM FILE SIZE: 2 MB</div>
      </div>
      {error && <div className="agent-error"><AlertTriangle size={14} />{error}</div>}
      {result && <>
        <div className="network-metrics">
          <div><span>Hosts</span><strong>{result.summary.hosts}</strong></div>
          <div><span>Hosts up</span><strong>{result.summary.up}</strong></div>
          <div><span>Ports parsed</span><strong>{result.summary.ports}</strong></div>
          <div><span>Open ports</span><strong>{result.summary.openPorts}</strong></div>
        </div>
        <section className="network-results">
          <h2>Evidence status: {(result.evidenceStatus || "unknown").replaceAll("_", " ")}</h2><p>Port-state totals: {Object.entries(result.summary.stateCounts || {}).map(([state, count]) => `${state}: ${count}`).join(" · ") || "No state counts returned"}</p><h2>Open services</h2>
          {result.openPorts.length ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>{result.openPorts.map((port, index) => <tr key={index}><td>{port.host}</td><td>{port.port}</td><td>{port.protocol}</td><td>{port.service}</td><td>{[port.product, port.version].filter(Boolean).join(" ") || "Not reported"}</td></tr>)}</tbody></table></div> : <p>No open ports were recorded in this report.</p>}
        </section>
        <section className="network-results">
          <h2>Hosts and port states</h2>
          {result.hosts.map((host) => <details className="network-host" key={host.index}><summary>{host.addresses.map((a) => a.address).join(", ") || `Host ${host.index}`} <span>{host.status.toUpperCase()} · {host.ports.length} PORTS</span></summary><div>{host.hostnames.length > 0 && <p>Names: {host.hostnames.join(", ")}</p>}{host.ports.map((port, index) => <div className="network-port" key={index}><span>{port.port}/{port.protocol}</span><span>{port.state}{port.reason ? ` · ${port.reason}` : ""}</span><span>{port.service}{port.method ? ` · ${port.method}` : ""}</span></div>)}</div></details>)}
        </section>
        <p className="network-note"><ShieldCheck size={13} /> {result.note}</p>
        {result.completion && <section className="network-results"><h2>Scan metadata</h2><p>{result.completion.scanner || "Nmap"} {result.completion.version || ""} · {result.completion.finished?.exit || "completion status unavailable"} · {result.completion.finished?.elapsed || "elapsed time unavailable"}</p><p>{result.scaninfo?.map((item) => `${item.type}/${item.protocol}: ${item.services || item.numservices || "unspecified"}`).join(" · ")}</p></section>}
      </>}
      {result && <InvestigationLink source="network-analysis" eventType="nmap-report" title={`Nmap report: ${fileName || result.summary.hosts + " hosts"}`} severity={result.summary.openPorts > 0 ? "medium" : "informational"} details={{ fileName, summary: result.summary, openPorts: result.openPorts, hosts: result.hosts, note: result.note }} />}
      <div className="agent-disclaimer"><ShieldCheck size={12} /> Use scan reports only when the underlying assessment was authorised. Parsed service/version data is evidence, not proof of vulnerability.</div>
    </section>
  </main>;
}
