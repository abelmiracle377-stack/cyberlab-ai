"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, FileUp, Network, ShieldCheck, AlertTriangle } from "lucide-react";
import InvestigationLink from "@/components/investigation-link";

type Port = { protocol: string; port: number; state: string; reason?: string; reason_ttl?: string | null; service: string; product: string; version: string; extra_info?: string; tunnel?: string; method?: string; confidence?: string | null };
type Host = { index: number; status: string; status_reason?: string; addresses: { address: string; type: string }[]; hostnames: string[]; ports: Port[] };
type Result = { summary: { hosts: number; up: number; ports: number; openPorts: number; stateCounts?: Record<string, number> }; hosts: Host[]; openPorts: (Port & { host: string })[]; note: string; evidenceStatus?: string; scaninfo?: { type?: string; protocol?: string; numservices?: string; services?: string }[]; completion?: { finished?: Record<string, string>; hosts?: Record<string, string>; scanner?: string; version?: string; args?: string; start?: string } };

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

  function downloadReport(format: "json" | "csv") {
    if (!result) return;
    let content = "";
    let mime = "application/json";
    let extension = "json";
    if (format === "json") {
      content = JSON.stringify({ fileName, ...result }, null, 2);
    } else {
      mime = "text/csv";
      extension = "csv";
      const quote = (value: unknown) => '"' + String(value ?? "").replaceAll('"', '""') + '"';
      const rows: unknown[][] = [["host", "protocol", "port", "state", "reason", "service", "product", "version", "detection_method", "confidence"]];
      for (const host of result.hosts) {
        const address = host.addresses.map((item) => item.address).join("; ") || ("Host " + host.index);
        for (const port of host.ports) rows.push([address, port.protocol, port.port, port.state, port.reason || "", port.service, port.product, port.version, port.method || "", port.confidence || ""]);
      }
      content = rows.map((row) => row.map(quote).join(",")).join("\r\n");
    }
    const url = URL.createObjectURL(new Blob([content], { type: mime + ";charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "cyberlab-nmap-report." + extension;
    anchor.click();
    URL.revokeObjectURL(url);
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
          <div className="network-actions"><button className="network-run" onClick={() => downloadReport("json")}>Export JSON</button><button className="network-run" onClick={() => downloadReport("csv")}>Export CSV</button></div>
          <h2>Evidence status: {(result.evidenceStatus || "unknown").replaceAll("_", " ")}</h2><p>Port-state totals: {Object.entries(result.summary.stateCounts || {}).map(([state, count]) => `${state}: ${count}`).join(" · ") || "No state counts returned"}</p><p>Scanner: {result.completion?.scanner || "Not recorded"} {result.completion?.version || ""} · Finish: {result.completion?.finished?.exit || "Not recorded"}</p><p>Scan types: {(result.scaninfo || []).map((item) => `${item.type || "unknown"}/${item.protocol || "unknown"} (${item.numservices || "?"} ports)`).join(" · ") || "Not recorded"}</p><h2>Open services</h2>
          {result.openPorts.length ? <div className="network-table-wrap"><table className="network-table"><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>{result.openPorts.map((port, index) => <tr key={index}><td>{port.host}</td><td>{port.port}</td><td>{port.protocol}</td><td>{port.service}</td><td>{[port.product, port.version, port.extra_info].filter(Boolean).join(" ") || "Not reported"}{port.method ? ` · ${port.method}${port.confidence ? ` (${port.confidence})` : ""}` : ""}</td></tr>)}</tbody></table></div> : <p>No open ports were recorded in this report.</p>}
        </section>
        <section className="network-results">
          <h2>Hosts and port states</h2>
          {result.hosts.map((host) => <details className="network-host" key={host.index}><summary>{host.addresses.map((a) => a.address).join(", ") || `Host ${host.index}`} <span>{host.status.toUpperCase()} · {host.ports.length} PORTS</span></summary><div>{host.hostnames.length > 0 && <p>Names: {host.hostnames.join(", ")}</p>}{host.ports.map((port, index) => <div className="network-port" key={index}><span>{port.port}/{port.protocol}</span><span>{port.state}{port.reason ? ` · ${port.reason}` : ""}{port.reason_ttl ? ` · TTL ${port.reason_ttl}` : ""}</span><span>{port.service}{port.method ? ` · ${port.method}` : ""}</span></div>)}</div></details>)}
        </section>
        <p className="network-note"><ShieldCheck size={13} /> {result.note}</p>
      </>}
      {result && <InvestigationLink source="network-analysis" eventType="nmap-report" title={`Nmap report: ${fileName || result.summary.hosts + " hosts"}`} severity={result.summary.openPorts > 0 ? "medium" : "informational"} details={{ fileName, summary: result.summary, openPorts: result.openPorts, hosts: result.hosts, note: result.note }} />}
      <div className="agent-disclaimer"><ShieldCheck size={12} /> Use scan reports only when the underlying assessment was authorised. Parsed service/version data is evidence, not proof of vulnerability.</div>
    </section>
  </main>;
}
