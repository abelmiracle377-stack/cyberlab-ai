"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { ArrowLeft, Bot, ChevronDown, CircleAlert, LoaderCircle, Send, ShieldCheck, Sparkles } from "lucide-react";
import Link from "next/link";

type Model = { id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean };
type Message = { role: "user" | "assistant"; content: string };
type LocalScanResult = { target: string; duration_seconds: number; method: string; state_summary: { open: number; closed: number; filtered: number }; hosts: { addresses: { address: string }[]; ports: { port: number; state: string; service: string; product: string; version: string }[] }[]; note: string };

export default function AgentPage() {
  const [models, setModels] = useState<Model[]>([]);
  const [model, setModel] = useState("");
  const [agentMode, setAgentMode] = useState<"standard" | "open-weight">("open-weight");
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scanRequest, setScanRequest] = useState<{ target: string; ports: string } | null>(null);
  const [scanConfirmation, setScanConfirmation] = useState("");
  const [scanReference, setScanReference] = useState("");
  const [scanAuthorised, setScanAuthorised] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [scanResult, setScanResult] = useState<LocalScanResult | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const availableModels = agentMode === "open-weight" ? models.filter((item) => item.openWeight) : models;

  useEffect(() => {
    fetch("/api/models")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Model catalogue unavailable.");
        const catalogue: Model[] = data.models || [];
        setModels(catalogue);
        setModel((current) => {
          if (catalogue.some((item) => item.id === current && (agentMode === "standard" || item.openWeight))) return current;
          if (agentMode === "open-weight") return catalogue.find((item) => item.openWeight)?.id || "";
          return catalogue.find((item) => item.id === "openai/gpt-5.5")?.id || catalogue[0]?.id || "";
        });
      })
      .catch((cause) => setError(cause.message || "Could not load model catalogue."));
  }, []);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function runLocalScan(event: FormEvent) {
    event.preventDefault();
    if (!scanRequest || scanBusy) return;
    const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
    if (!token) {
      setScanStatus("Kali bridge is not paired in this browser session. Open Kali Connection and pair the local companion first.");
      return;
    }
    const ports: number[] = [];
    for (const part of scanRequest.ports.split(",")) {
      const value = part.trim();
      const range = value.match(/^(\d{1,5})-(\d{1,5})$/);
      if (range) {
        const start = Number(range[1]), end = Number(range[2]);
        if (end < start || end - start > 99) { setScanStatus("Each port range must be ascending and contain at most 100 ports."); return; }
        for (let port = start; port <= end; port++) ports.push(port);
      } else if (/^\d{1,5}$/.test(value)) ports.push(Number(value));
      else { setScanStatus("Enter ports as comma-separated numbers or bounded ranges."); return; }
    }
    const unique = [...new Set(ports)];
    if (!unique.length || unique.length > 100 || unique.some(port => port < 1 || port > 65535)) {
      setScanStatus("Select between 1 and 100 unique TCP ports from 1 to 65535."); return;
    }
    setScanBusy(true); setScanStatus("Submitting approved scan to the paired local Kali bridge…");
    try {
      const response = await fetch("http://127.0.0.1:8765/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({
          target: scanRequest.target,
          confirmationTarget: scanConfirmation.trim(),
          authorizationReference: scanReference.trim(),
          authorizationConfirmed: scanAuthorised,
          ports: unique,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Local Kali bridge returned HTTP ${response.status}.`);
      setScanResult(data as LocalScanResult);
      setScanStatus("Local Nmap assessment completed. Review the evidence below; this is not a vulnerability verdict.");
      setScanRequest(null);
    } catch (cause) {
      setScanStatus(cause instanceof Error ? cause.message : "Could not reach the local Kali bridge. Confirm that it is running and paired on this same computer.");
    } finally { setScanBusy(false); }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const text = prompt.trim();
    if (!text || busy) return;
    setError("");
    setScanRequest(null);
    setScanStatus("");
    setScanResult(null);
    setPrompt("");
    const scanMatch = text.match(/\b(?:nmap|scan|port\s+scan|scan\s+ports)\b[\s\S]*?\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})\b/i);
    if (scanMatch) {
      const portsMatch = text.match(/\bports?\s+([0-9,-]+(?:\s*[-,]\s*[0-9]+)*)/i);
      setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "I can prepare a bounded Nmap TCP scan on your paired local Kali machine. Before anything runs, confirm the exact target, authorisation reference and scope below. No scan has started." }]);
      setScanRequest({ target: scanMatch[1], ports: portsMatch?.[1]?.replace(/\s+/g, "") || "1-100" });
      setBusy(false);
      return;
    }
    setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "" }]);
    setBusy(true);
    try {
      const response = await fetch("/api/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: text, model, agentMode, history: messages.filter((item) => item.content.trim()).slice(-12), learningContext: (() => { try { const items = JSON.parse(localStorage.getItem("cyberlab.learning.v1") || "[]"); return Array.isArray(items) ? items.filter((item: any) => item?.status === "approved" && typeof item.content === "string").slice(0, 30).map((item: any) => ({ title: String(item.title || "Untitled").slice(0, 160), category: String(item.category || "Other").slice(0, 80), source: String(item.source || "User supplied").slice(0, 120), content: item.content.slice(0, 3000) })) : []; } catch { return []; } })() }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Agent request failed.");
      }
      if (!response.body) throw new Error("Streaming response was not available.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let output = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        output += decoder.decode(value, { stream: true });
        setMessages((current) => {
          const next = [...current];
          next[next.length - 1] = { role: "assistant", content: output };
          return next;
        });
      }
      output += decoder.decode();
      setMessages((current) => {
        const next = [...current];
        next[next.length - 1] = { role: "assistant", content: output || "The model returned an empty response." };
        return next;
      });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Unexpected agent error.";
      setError(message);
      setMessages((current) => current[current.length - 1]?.content ? current : current.slice(0, -1));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="agent-shell">
      <header className="agent-topbar">
        <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
        <div className="agent-brand"><span className="agent-brand-icon"><ShieldCheck size={16} /></span> CYBERLAB AI <span className="agent-top-sep">/</span> AGENT CONSOLE</div>
        <Link href="/learning" className="agent-secure-label">LEARNING CENTRE ↗</Link>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">RESEARCH ORCHESTRATION / 001</div>
          <h1>AI research agent</h1>
          <p>Research security questions, inspect network intelligence, analyse DNS evidence, and look up public CVE records. Open-weight research mode is selected by default.</p>
        </div>
        <div className="agent-config agent-config-stack">
          <div className="agent-mode-switch" role="group" aria-label="Agent mode">
            <button type="button" className={agentMode === "standard" ? "selected" : ""} onClick={() => { setAgentMode("standard"); if (!models.some((item) => item.id === model)) setModel(models.find((item) => item.id === "openai/gpt-5.5")?.id || models[0]?.id || "openai/gpt-5.5"); }} disabled={busy}>Standard</button>
            <button type="button" className={agentMode === "open-weight" ? "selected" : ""} onClick={() => { const first = models.find((item) => item.openWeight); setAgentMode("open-weight"); if (first) setModel(first.id); }} disabled={busy}>Open-weight research mode</button>
          </div>
          <div className="agent-model-label"><span className="agent-live-dot" /> {agentMode === "open-weight" ? "OPEN-WEIGHT MODEL ROUTING" : "MODEL ROUTING"}</div>
          <label className="agent-select-wrap">
            <span className="sr-only">Select model</span>
            <select value={model} onChange={(event) => setModel(event.target.value)} disabled={busy}>
              {availableModels.length ? availableModels.map((item) => <option value={item.id} key={item.id}>{item.name} · {item.provider}</option>) : <option value="">{agentMode === "open-weight" ? "No recognised open-weight models available" : model}</option>}
            </select>
            <ChevronDown size={13} />
          </label>
          <span className="agent-model-count">{agentMode === "open-weight" ? `${availableModels.length} OPEN-WEIGHT MODELS` : `${availableModels.length} MODELS AVAILABLE`}</span>
        </div>
        <div className="agent-chat">
          {messages.length === 0 ? (
            <div className="agent-welcome">
              <div className="agent-welcome-icon"><Bot size={25} /></div>
              <h2>What are we investigating?</h2>
              <p>The agent can research public sources, analyse passive IP/DNS intelligence and NVD CVEs. Ask “scan example.com” to prepare a local Kali Nmap scan; it will wait for your explicit scope approval.</p>
              <div className="agent-prompts">
                {["Explain what information an IP address can reveal, and its limits.", "Look up public IP intelligence for an IP address I provide.", "Analyse DNS records for example.com", "Find NVD details for CVE-2024-3094", "Help me plan a safe, authorised assessment of my own web application."].map((item) => <button key={item} onClick={() => setPrompt(item)}>{item}<span>↗</span></button>)}
              </div>
            </div>
          ) : (
            <div className="agent-messages">
              {messages.map((message, index) => <div className={`agent-message ${message.role}`} key={index}>
                <div className="agent-message-avatar">{message.role === "assistant" ? <Bot size={15} /> : "YOU"}</div>
                <div className="agent-message-body"><div className="agent-message-role">{message.role === "assistant" ? "CYBERLAB AGENT" : "YOU"}</div><div className="agent-message-content">{message.content || (busy ? <span className="agent-thinking"><LoaderCircle size={13} /> Thinking and checking available tools…</span> : "")}</div></div>
              </div>)}
              <div ref={endRef} />
            </div>
          )}
        </div>
        {scanRequest && <section className="kali-panel" style={{ marginTop: 16 }}>
          <h2>Approve local Nmap scan</h2>
          <p>Target detected from your message: <strong>{scanRequest.target}</strong>. Proposed TCP ports: <strong>{scanRequest.ports}</strong> (maximum 100). The request will run directly in your browser against the paired Kali bridge; it is not sent to the CyberLab server.</p>
          <form className="report-editor" onSubmit={runLocalScan}>
            <label>Retype exact target<input value={scanConfirmation} onChange={event => setScanConfirmation(event.target.value)} placeholder={scanRequest.target} required /></label>
            <label>Authorisation / ticket reference<input value={scanReference} onChange={event => setScanReference(event.target.value)} placeholder="Written approval or engagement reference" required maxLength={160} /></label>
            <label>TCP ports<input value={scanRequest.ports} onChange={event => setScanRequest(current => current ? { ...current, ports: event.target.value } : current)} required /></label>
            <div className="scope-checks"><label><input type="checkbox" checked={scanAuthorised} onChange={event => setScanAuthorised(event.target.checked)} /> I own this target or have explicit written permission to scan this exact target and these ports.</label></div>
            <button className="report-download" type="submit" disabled={scanBusy || !scanAuthorised || !scanReference.trim() || scanConfirmation.trim().toLowerCase() !== scanRequest.target.toLowerCase()}>{scanBusy ? "Running on Kali…" : "Confirm and run local Nmap scan"}</button>
            <button className="report-download" type="button" onClick={() => setScanRequest(null)} disabled={scanBusy}>Cancel</button>
          </form>
          {scanStatus && <p role="status">{scanStatus}</p>}
        </section>}
        {scanResult && <section className="network-results" style={{ marginTop: 16 }}><h2>Local Nmap results · {scanResult.target}</h2><p>{scanResult.duration_seconds}s · {scanResult.method}</p><p><strong>Open:</strong> {scanResult.state_summary.open} · <strong>Closed:</strong> {scanResult.state_summary.closed} · <strong>Filtered:</strong> {scanResult.state_summary.filtered}</p><div className="network-table-wrap"><table className="network-table"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Product / version</th></tr></thead><tbody>{scanResult.hosts.flatMap((host, index) => host.ports.map(port => <tr key={index + "-" + port.port}><td>{host.addresses[0]?.address || scanResult.target}</td><td>{port.port}</td><td>{port.service}</td><td>{port.state}</td><td>{[port.product, port.version].filter(Boolean).join(" ") || "—"}</td></tr>))}</tbody></table></div><p>{scanResult.note}</p></section>}
        {scanStatus && !scanRequest && !scanResult && <div className="agent-error">{scanStatus}</div>}
        {error && <div className="agent-error"><CircleAlert size={14} /><span>{error}</span></div>}
        <form className="agent-composer" onSubmit={submit}>
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Describe what you want to investigate…" rows={3} maxLength={8000} disabled={busy} />
          <div className="agent-composer-bottom"><span><ShieldCheck size={12} /> Live research + passive IP/DNS/CVE · Local Nmap requires Kali pairing and explicit approval</span><button type="submit" disabled={busy || !prompt.trim() || !model}>{busy ? <LoaderCircle size={14} className="spin" /> : <Send size={14} />} {busy ? "Working" : "Send message"}</button></div>
        </form>
        <div className="agent-disclaimer"><Sparkles size={12} /> Open-weight mode does not mean unrestricted or guaranteed uncensored output. Outputs are AI-generated and must be verified against primary evidence. Use only on systems and data you are authorised to assess.</div>
      </section>
    </main>
  );
}