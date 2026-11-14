"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Check, Search, Send, Sparkles, GitCompareArrows } from "lucide-react";
import "./models.css";

type Model = { id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean; local?: boolean; size?: number | null };
type LocalHardware = { platform: string; architecture: string; totalMemory: number | null; availableMemory: number | null };
function formatBytes(bytes: number | null | undefined) {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes <= 0) return "Unavailable";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return value.toFixed(unit >= 3 ? 1 : 0) + " " + units[unit];
}
type ConsensusResult = { model: string; answer?: string; error?: string };

export default function ModelsPage() {
  const [models, setModels] = useState<Model[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [active, setActive] = useState("");
  const [query, setQuery] = useState("");
  const [openOnly, setOpenOnly] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [prompt, setPrompt] = useState("");
  const [reply, setReply] = useState("");
  const [historyByModel, setHistoryByModel] = useState<Record<string, Array<{ role: "user" | "assistant"; content: string }>>>({});
  const [busy, setBusy] = useState(false);
  const [responseMode, setResponseMode] = useState<"single" | "comparison">("single");
  const [localStatus, setLocalStatus] = useState("Pair your Kali companion to discover local Ollama models.");
  const [localHardware, setLocalHardware] = useState<LocalHardware | null>(null);

  useEffect(() => {
    let alive = true;
    fetch("/api/models", { cache: "no-store" }).then(async (r) => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Model catalogue unavailable.");
      if (!alive) return;
      const list = (data.models || []) as Model[];
      setModels(list);
      const first = list.find((m) => m.openWeight) || list[0];
      if (first) { setSelected([first.id]); setActive(first.id); }
    }).catch((e) => { if (alive) setError(e instanceof Error ? e.message : "Could not load models."); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
    if (!token) {
      setLocalStatus("Not paired · open Kali Connection to pair this browser.");
      return;
    }
    fetch("http://127.0.0.1:8765/ollama/models", {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    }).then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Local Ollama is unavailable.");
      if (!alive) return;
      const localModels = (data.models || []).filter((item: { name?: unknown }) => typeof item.name === "string").map((item: { name: string; size?: number | null }) => ({
        id: "local:ollama:" + item.name,
        name: item.name,
        provider: "ollama (local)",
        contextLength: null,
        openWeight: true,
        local: true,
        size: item.size ?? null,
      } satisfies Model));
      setModels((current) => [...current.filter((item) => !item.local), ...localModels]);
      setLocalStatus(localModels.length ? `Connected · ${localModels.length} local models discovered` : "Ollama connected · no models installed yet.");
    }).catch((cause) => {
      if (alive) setLocalStatus(cause instanceof Error ? cause.message : "Could not reach the paired local Ollama service.");
    });
    fetch("http://127.0.0.1:8765/system", {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    }).then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Local hardware information unavailable.");
      if (!alive) return;
      const metrics = data.metrics || {};
      setLocalHardware({
        platform: String(metrics.platform || "Local host"),
        architecture: String(metrics.architecture || "Unknown architecture"),
        totalMemory: typeof metrics.memory_bytes?.MemTotal === "number" ? metrics.memory_bytes.MemTotal : null,
        availableMemory: typeof metrics.memory_bytes?.MemAvailable === "number" ? metrics.memory_bytes.MemAvailable : null,
      });
    }).catch(() => { if (alive) setLocalHardware(null); });
    return () => { alive = false; };
  }, []);

  const visible = useMemo(() => models.filter((m) =>
    (!openOnly || m.openWeight) && (m.name + " " + m.provider + " " + m.id).toLowerCase().includes(query.toLowerCase())
  ), [models, openOnly, query]);

  const activeModel = models.find((m) => m.id === active);
  const activeHistory = historyByModel[active] || [];
  const selectedModels = selected.map((id) => models.find((m) => m.id === id)).filter((m): m is Model => Boolean(m));

  function toggle(id: string) {
    setSelected((current) => {
      if (current.includes(id)) {
        const next = current.filter((x) => x !== id);
        if (active === id) setActive(next[0] || "");
        return next;
      }
      if (current.length >= 3) return current;
      setActive(id);
      return [...current, id];
    });
  }

  async function sendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!prompt.trim() || !active || busy) return;
    const submittedPrompt = prompt.trim();
    setBusy(true); setReply(""); setError(""); setResponseMode("single");
    try {
      if (activeModel?.local) {
        const token = sessionStorage.getItem("cyberlab.kaliBridgeToken");
        if (!token) throw new Error("Pair your Kali companion first to use local Ollama models.");
        const response = await fetch("http://127.0.0.1:8765/ollama/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ model: activeModel.name, prompt: submittedPrompt, history: activeHistory }),
          signal: AbortSignal.timeout(125000),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Local Ollama request failed.");
        const answer = typeof data.response === "string" ? data.response : "The local model returned an empty response.";
        setReply(answer);
        setHistoryByModel((current) => ({ ...current, [active]: [...(current[active] || []), { role: "user" as const, content: submittedPrompt }, { role: "assistant" as const, content: answer }].slice(-12) }));
        setPrompt("");
        return;
      }
      const response = await fetch("/api/agent", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: submittedPrompt, model: active, agentMode: activeModel?.openWeight ? "open-weight" : "standard", history: activeHistory }),
      });
      if (!response.ok) { const data = await response.json(); throw new Error(data.error || "Agent request failed."); }
      if (!response.body) throw new Error("Streaming response unavailable.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let output = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        output += decoder.decode(value, { stream: true });
        setReply(output);
      }
      output += decoder.decode();
      const answer = output || "The model returned an empty response.";
      setReply(answer);
      setHistoryByModel((current) => ({ ...current, [active]: [...(current[active] || []), { role: "user" as const, content: submittedPrompt }, { role: "assistant" as const, content: answer }].slice(-12) }));
      setPrompt("");
    } catch (e) { setError(e instanceof Error ? e.message : "Unexpected model error."); }
    finally { setBusy(false); }
  }

  async function compareSelectedModels() {
    const question = prompt.trim();
    if (!question || busy || selected.length < 2 || selected.length > 3) return;
    setBusy(true); setReply(""); setError(""); setResponseMode("comparison");
    try {
      const allOpenWeight = selectedModels.length === selected.length && selectedModels.every((model) => model.openWeight);
      const response = await fetch("/api/agent/consensus", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: question, models: selected, agentMode: allOpenWeight ? "open-weight" : "standard" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Multi-model comparison failed.");
      const results = (data.results || []) as ConsensusResult[];
      const sections = results.map((item) =>
        "### " + item.model + "\n" + (item.answer || "Model error: " + (item.error || "No response"))
      );
      const output = [
        "## Independent model analyses",
        ...sections,
        data.synthesis ? "## Evidence & Reporting synthesis\n" + data.synthesis : "## Synthesis unavailable\nReview the individual model responses; no consolidated synthesis was returned.",
        "> " + (data.note || "Model agreement is not independent verification."),
      ].join("\n\n");
      setReply(output);
      setPrompt("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Multi-model comparison failed.");
    } finally {
      setBusy(false);
    }
  }

  const canCompare = selected.length >= 2 && selected.length <= 3 && selectedModels.length === selected.length && selectedModels.every((model) => !model.local);

  return <main className="model-workspace">
    <header className="mw-topbar">
      <Link href="/" className="mw-back"><ArrowLeft size={15}/> CyberLab</Link>
      <div className="mw-brand"><Sparkles size={15}/> MODEL INTELLIGENCE / WORKSPACE</div>
      <span className="mw-status">LIVE CATALOGUE</span>
    </header>
    <div className="mw-layout">
      <aside className="mw-sidebar">
        <div className="mw-title"><div><small>MODEL CONTROL</small><h1>Models</h1></div><b>{models.length}</b></div>
        <label className="mw-search"><Search size={14}/><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search models…"/></label>
        <div className="mw-filter"><button className={!openOnly ? "active" : ""} onClick={() => setOpenOnly(false)}>All models</button><button className={openOnly ? "active" : ""} onClick={() => setOpenOnly(true)}>Open-weight</button></div>
        <div className="mw-label">AVAILABLE MODELS <span>MAX 3 SELECTED</span></div>
        {loading && <p className="mw-muted">Loading catalogue…</p>}
        {error && <p className="mw-error">{error}</p>}
        <div className="mw-model-list">{visible.slice(0, 180).map((m) => <button key={m.id} className={selected.includes(m.id) ? "mw-model selected" : "mw-model"} onClick={() => toggle(m.id)}>
          <span className="mw-provider">{m.provider.slice(0, 1).toUpperCase()}</span><span className="mw-model-name"><strong>{m.name}</strong><small>{m.provider} · {m.openWeight ? "Open-weight" : "Hosted"}</small></span>{selected.includes(m.id) && <Check size={14}/>}
        </button>)}</div>
        <div className="mw-local"><strong>Local Ollama</strong><span>{localStatus}</span><b>{localStatus.startsWith("Connected") || localStatus.startsWith("Ollama connected") ? "CONNECTED" : "PAIR REQUIRED"}</b>
          {localHardware && <span>Hardware: {localHardware.platform} · {localHardware.architecture}<br/>RAM: {formatBytes(localHardware.availableMemory)} available / {formatBytes(localHardware.totalMemory)} total</span>}
          {localHardware?.totalMemory && localHardware.totalMemory <= 6 * 1024 ** 3 && <span>Low-memory profile: start with the smallest installed model, keep context short and avoid loading multiple models at once. Model file size is not the same as peak runtime RAM.</span>}
        </div>
      </aside>
      <section className="mw-centre">
        <div className="mw-heading"><small>EVALUATION & DISCOVERY</small><h2>Model intelligence centre</h2><p>Compare models using sourced benchmarks and reproducible CyberLab evaluations.</p></div>
        <div className="mw-stats"><article><small>CATALOGUE MODELS</small><strong>{models.length || "—"}</strong><span>Provider catalogue</span></article><article><small>SELECTED MODELS</small><strong>{selected.length}/3</strong><span>For comparison</span></article><article><small>VERIFIED BENCHMARKS</small><strong>0</strong><span>No evaluation runs recorded</span></article></div>
        <section className="mw-panel"><div className="mw-panel-head"><div><h3>Selected model comparison</h3><p>Live provider metadata. Performance scores are not fabricated.</p></div><span>PROVIDER DATA</span></div>
          {!selected.length ? <p className="mw-muted">Select models from the left panel.</p> : <div className="mw-cards">{selected.map((id, i) => { const m = models.find((x) => x.id === id); if (!m) return null; return <article className={"mw-card tone-" + i} key={id}><small>MODEL 0{i + 1}</small><div className="mw-glyph">{m.provider.slice(0, 1).toUpperCase()}</div><h4>{m.name}</h4><p>{m.provider}</p><dl><dt>Context length</dt><dd>{m.contextLength ? m.contextLength.toLocaleString() : "Not supplied"}</dd><dt>Model type</dt><dd>{m.openWeight ? "Open-weight" : "Hosted"}</dd><dt>Benchmark score</dt><dd className="mw-unverified">Not evaluated</dd></dl><button onClick={() => setActive(id)}>{active === id ? "✓ Active chat model" : "Use in chat"}</button></article>; })}</div>}
        </section>
        <section className="mw-panel"><div className="mw-panel-head"><div><h3>Benchmark breakdown</h3><p>Evaluation categories planned for the test harness.</p></div><span className="mw-pending">NOT RUN</span></div>
          {["Reasoning","Knowledge accuracy","Coding","Mathematics","Instruction following","Long-context retrieval","Safety and tool discipline"].map((name) => <div className="mw-benchmark-row" key={name}><span>{name}</span><i/><b>—</b><small>Awaiting evaluation</small></div>)}
          <p className="mw-footnote">Scores will require a named dataset, harness version, run date and reproducible settings.</p>
        </section>
      </section>
      <aside className="mw-chat"><div className="mw-chat-head"><small>ASSISTANT PANEL</small><h2>Research chat</h2></div>
        <div className="mw-active"><i/><span><small>ACTIVE MODEL</small><strong>{activeModel?.name || "Select a model"}</strong><small>{activeModel?.id || "No model selected"}</small></span></div>
        <div className="mw-chat-body">{reply ? <pre className="mw-reply">{reply}</pre> : <div className="mw-chat-empty"><Sparkles size={24}/><h3>Research with your models</h3><p>Ask a cloud or paired local Ollama model, or compare two or three cloud models in parallel with an evidence-focused synthesis.</p></div>}</div>
        {error && <p className="mw-error">{error}</p>}
        <form className="mw-composer" onSubmit={sendMessage}><textarea rows={4} value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Ask CyberLab AI…" disabled={!active || busy}/><div><small>{responseMode === "comparison" ? "Parallel model comparison" : (activeModel?.provider || "Choose a model") + " · single-model request"}</small><button type="submit" disabled={!prompt.trim() || !active || busy}>{busy ? "…" : <Send size={15}/>}</button></div>
          <button type="button" className="mw-compare" onClick={compareSelectedModels} disabled={!prompt.trim() || !canCompare || busy}><GitCompareArrows size={14}/> Compare {selected.length} selected models</button>
          {!canCompare && <small className="mw-compare-hint">Select two or three cloud models to enable parallel comparison. Local models chat directly with Ollama.</small>}
        </form>
        <p className="mw-chat-note">Uses the CyberLab agent API and parallel consensus API. Model agreement is not independent verification.</p>
      </aside>
    </div>
  </main>;
}
