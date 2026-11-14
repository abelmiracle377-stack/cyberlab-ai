"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Check, Search, Send, Sparkles } from "lucide-react";
import "./models.css";

type Model = { id: string; name: string; provider: string; contextLength: number | null; openWeight: boolean };

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
  const [busy, setBusy] = useState(false);

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

  const visible = useMemo(() => models.filter((m) =>
    (!openOnly || m.openWeight) && (m.name + " " + m.provider + " " + m.id).toLowerCase().includes(query.toLowerCase())
  ), [models, openOnly, query]);

  const activeModel = models.find((m) => m.id === active);

  function toggle(id: string) {
    setSelected((current) => {
      if (current.includes(id)) {
        const next = current.filter((x) => x !== id);
        if (active === id) setActive(next[0] || "");
        return next;
      }
      if (current.length >= 4) return current;
      setActive(id);
      return [...current, id];
    });
  }

  async function sendMessage(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!prompt.trim() || !active || busy) return;
    setBusy(true); setReply(""); setError("");
    try {
      const response = await fetch("/api/agent", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: prompt.trim(), model: active, agentMode: activeModel?.openWeight ? "open-weight" : "standard", history: [] }),
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
      setReply(output || "The model returned an empty response.");
      setPrompt("");
    } catch (e) { setError(e instanceof Error ? e.message : "Unexpected model error."); }
    finally { setBusy(false); }
  }

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
        <div className="mw-label">AVAILABLE MODELS <span>MAX 4 SELECTED</span></div>
        {loading && <p className="mw-muted">Loading catalogue…</p>}
        {error && <p className="mw-error">{error}</p>}
        <div className="mw-model-list">{visible.slice(0, 180).map((m) => <button key={m.id} className={selected.includes(m.id) ? "mw-model selected" : "mw-model"} onClick={() => toggle(m.id)}>
          <span className="mw-provider">{m.provider.slice(0, 1).toUpperCase()}</span><span className="mw-model-name"><strong>{m.name}</strong><small>{m.provider} · {m.openWeight ? "Open-weight" : "Hosted"}</small></span>{selected.includes(m.id) && <Check size={14}/>}
        </button>)}</div>
        <div className="mw-local"><strong>Local Ollama</strong><span>Companion discovery integration pending verification</span><b>PLANNED</b></div>
      </aside>
      <section className="mw-centre">
        <div className="mw-heading"><small>EVALUATION & DISCOVERY</small><h2>Model intelligence centre</h2><p>Compare models using sourced benchmarks and reproducible CyberLab evaluations.</p></div>
        <div className="mw-stats"><article><small>CATALOGUE MODELS</small><strong>{models.length || "—"}</strong><span>Provider catalogue</span></article><article><small>SELECTED MODELS</small><strong>{selected.length}/4</strong><span>For comparison</span></article><article><small>VERIFIED BENCHMARKS</small><strong>0</strong><span>No evaluation runs recorded</span></article></div>
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
        <div className="mw-chat-body">{reply ? <p>{reply}</p> : <div className="mw-chat-empty"><Sparkles size={24}/><h3>Research with your models</h3><p>Ask a question using the selected model. Parallel multi-model execution will be enabled when the consensus endpoint is integrated.</p></div>}</div>
        {error && <p className="mw-error">{error}</p>}
        <form className="mw-composer" onSubmit={sendMessage}><textarea rows={4} value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Ask CyberLab AI…" disabled={!active || busy}/><div><small>{activeModel?.provider || "Choose a model"} · single-model request</small><button disabled={!prompt.trim() || !active || busy}>{busy ? "…" : <Send size={15}/>}</button></div></form>
        <p className="mw-chat-note">Uses the existing CyberLab agent API.</p>
      </aside>
    </div>
  </main>;
}
