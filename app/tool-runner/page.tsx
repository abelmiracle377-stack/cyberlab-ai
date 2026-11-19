"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, Play, Terminal, AlertTriangle, RefreshCw } from "lucide-react";

const BRIDGE = "http://127.0.0.1:8765";

type ToolInfo = {
  name: string; binary: string; category: string; active: boolean; installed: boolean;
  parameters: string[]; purpose: string; target_param: string | null;
};
type RunResult = {
  status: string; tool: string; exitCode?: number; argv?: string[];
  stdout?: string; stderr?: string; truncated?: boolean; note?: string;
};

export default function ToolRunnerPage() {
  const [token, setToken] = useState("");
  const [tools, setTools] = useState<ToolInfo[] | null>(null);
  const [selected, setSelected] = useState<ToolInfo | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});
  const [auth, setAuth] = useState("");
  const [targetConfirm, setTargetConfirm] = useState("");
  const [owned, setOwned] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  const [runBusy, setRunBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<RunResult | null>(null);

  useEffect(() => { setToken(sessionStorage.getItem("cyberlab.kaliBridgeToken") || ""); }, []);

  async function loadTools() {
    setError(""); setListBusy(true);
    try {
      const pairing = sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!pairing) throw new Error("Pair your local companion in Kali Connection first.");
      setToken(pairing);
      const response = await fetch(BRIDGE + "/tools/runners", { headers: { Authorization: "Bearer " + pairing }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load the tool list.");
      setTools((data.tools || []).sort((a: ToolInfo, b: ToolInfo) => a.name.localeCompare(b.name)));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Tool list request failed.");
    } finally {
      setListBusy(false);
    }
  }

  function pick(tool: ToolInfo) {
    setSelected(tool);
    setParams({});
    setAuth("");
    setTargetConfirm("");
    setResult(null);
    setError("");
  }

  async function run() {
    if (!selected) return;
    setError(""); setResult(null);
    for (const name of selected.parameters) {
      if (!(params[name] || "").trim()) { setError("Fill in the '" + name + "' parameter."); return; }
    }
    const targetValue = selected.target_param ? (params[selected.target_param] || "") : "";
    if (selected.active) {
      if (!owned) { setError("Confirm you own or are authorised to assess this target."); return; }
      if (!auth.trim()) { setError("Active tools need a written authorisation reference."); return; }
      if (targetConfirm.trim().toLowerCase() !== targetValue.trim().toLowerCase()) {
        setError("Retype the exact target to confirm authorisation."); return;
      }
    }
    setRunBusy(true);
    try {
      const parameters: Record<string, string | number> = {};
      for (const name of selected.parameters) {
        const raw = params[name].trim();
        parameters[name] = /^\d+$/.test(raw) ? Number(raw) : raw;
      }
      const response = await fetch(BRIDGE + "/tools/run", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({
          tool: selected.name, parameters, confirmRun: true,
          authorizationReference: auth.trim(), targetConfirmation: targetValue,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The companion rejected the tool run.");
      setResult(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Tool run failed.");
    } finally {
      setRunBusy(false);
    }
  }

  const grouped = (tools || []).reduce((acc: Record<string, ToolInfo[]>, tool) => {
    (acc[tool.category] = acc[tool.category] || []).push(tool);
    return acc;
  }, {});

  return (
    <main className="agent-shell">
      <header className="agent-topbar">
        <Link href="/" className="agent-back"><ArrowLeft size={14} /> Dashboard</Link>
        <div className="agent-brand"><span className="agent-brand-icon"><Terminal size={16} /></span> CYBERLAB AI <span className="agent-top-sep">/</span> TOOL RUNNER</div>
        <Link href="/kali-connection" className="agent-secure-label">KALI CONNECTION ↗</Link>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">VETTED TOOL EXECUTION / 001</div>
          <h1>Run a Kali tool</h1>
          <p>Launch a vetted security tool on your paired companion. Passive tools run after one confirmation; active tools require a written authorisation reference and an exact-target retype. Everything runs on your own 127.0.0.1 companion, never the CyberLab server.</p>
        </div>

        <div className="scope-warning"><AlertTriangle size={14} /> Only run tools against systems you own or are explicitly authorised to assess.</div>

        <button type="button" className="report-download" onClick={loadTools} disabled={listBusy}>{listBusy ? <RefreshCw size={13} className="spin" /> : <ShieldCheck size={13} />} {tools ? "Refresh tool list" : "Connect and load tools"}</button>
        {error && <div className="agent-error"><AlertTriangle size={14} /><span>{error}</span></div>}

        {tools && <div className="agent-config agent-config-stack" style={{ marginTop: 14 }}>
          {Object.keys(grouped).sort().map((category) => <div key={category}>
            <div className="agent-model-label"><span className="agent-live-dot" /> {category.toUpperCase().replace(/-/g, " ")}</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, margin: "6px 0 12px" }}>
              {grouped[category].map((tool) => <button key={tool.name} type="button"
                className={"report-download" + (selected?.name === tool.name ? " selected" : "")}
                onClick={() => pick(tool)} title={tool.purpose}
                style={{ opacity: tool.installed ? 1 : 0.55 }}>
                {tool.name}{tool.active ? " ·active" : ""}{tool.installed ? "" : " ·not installed"}
              </button>)}
            </div>
          </div>)}
        </div>}

        {selected && <section className="kali-panel" style={{ marginTop: 16 }}>
          <h2>{selected.name}</h2>
          <p>{selected.purpose}{selected.installed ? "" : " — this tool is not installed on the paired machine; the run will fail closed with an install hint."}</p>
          <form className="report-editor" onSubmit={(event) => { event.preventDefault(); void run(); }}>
            {selected.parameters.map((name) => <label key={name}>{name}{selected.target_param === name ? " (target)" : ""}
              <input value={params[name] || ""} onChange={(event) => setParams((current) => ({ ...current, [name]: event.target.value }))}
                placeholder={name === "wordlist" || name === "userlist" ? "/usr/share/wordlists/…" : name} required />
            </label>)}
            {selected.active && <>
              <label>Authorisation / engagement reference<input value={auth} onChange={(event) => setAuth(event.target.value)} placeholder="Written authorisation to assess this target" required maxLength={200} /></label>
              {selected.target_param && <label>Retype exact {selected.target_param}<input value={targetConfirm} onChange={(event) => setTargetConfirm(event.target.value)} placeholder={params[selected.target_param] || ""} required /></label>}
              <div className="scope-checks"><label><input type="checkbox" checked={owned} onChange={(event) => setOwned(event.target.checked)} /> I own this target or have explicit written permission to assess it.</label></div>
            </>}
            <button className="network-run" type="submit" disabled={runBusy}>{runBusy ? "Running on companion…" : <><Play size={13} /> Run on companion</>}</button>
          </form>
        </section>}

        {result && <section className="network-results" style={{ marginTop: 16 }}>
          <h2>{result.tool} · {result.status}{typeof result.exitCode === "number" ? " · exit " + result.exitCode : ""}</h2>
          {result.argv && <p className="network-note" style={{ overflowWrap: "anywhere" }}>Command: {result.tool} {result.argv.join(" ")}</p>}
          {result.stdout && <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 420, overflowY: "auto", fontSize: 12, padding: 12, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6 }}>{result.stdout}</pre>}
          {result.truncated && <p className="network-note">Output was truncated to the display limit.</p>}
          {result.stderr && <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 160, overflowY: "auto", fontSize: 11, padding: 10, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "#e0aaaa" }}>{result.stderr}</pre>}
          <p className="network-note">{result.note}</p>
        </section>}
      </section>
    </main>
  );
}
