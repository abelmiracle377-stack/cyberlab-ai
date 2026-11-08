"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { ArrowLeft, Bot, ChevronDown, CircleAlert, LoaderCircle, Send, ShieldCheck, Sparkles, Terminal } from "lucide-react";
import Link from "next/link";

type Model = { id: string; name: string; provider: string; contextLength: number | null };
type Message = { role: "user" | "assistant"; content: string };

export default function AgentPage() {
  const [models, setModels] = useState<Model[]>([]);
  const [model, setModel] = useState("openai/gpt-5.5");
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/models")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Model catalogue unavailable.");
        setModels(data.models || []);
        if (data.models?.length && !data.models.some((item: Model) => item.id === model)) {
          const preferred = data.models.find((item: Model) => item.id === "openai/gpt-5.5") || data.models[0];
          setModel(preferred.id);
        }
      })
      .catch((cause) => setError(cause.message || "Could not load model catalogue."));
  }, []);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const text = prompt.trim();
    if (!text || busy) return;
    setError("");
    setPrompt("");
    setMessages((current) => [...current, { role: "user", content: text }, { role: "assistant", content: "" }]);
    setBusy(true);
    try {
      const response = await fetch("/api/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: text, model, history: messages.filter((item) => item.content.trim()).slice(-12) }),
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
        <span className="agent-secure-label"><span /> SERVER-SIDE INFERENCE</span>
      </header>
      <section className="agent-main">
        <div className="agent-heading">
          <div className="agent-overline">RESEARCH ORCHESTRATION / 001</div>
          <h1>AI research agent</h1>
          <p>Ask a security question, investigate public network intelligence, or analyse DNS evidence.</p>
        </div>
        <div className="agent-config">
          <div className="agent-model-label"><span className="agent-live-dot" /> MODEL ROUTING</div>
          <label className="agent-select-wrap">
            <span className="sr-only">Select model</span>
            <select value={model} onChange={(event) => setModel(event.target.value)} disabled={busy}>
              {models.length ? models.map((item) => <option value={item.id} key={item.id}>{item.name} · {item.provider}</option>) : <option value={model}>{model}</option>}
            </select>
            <ChevronDown size={13} />
          </label>
          <span className="agent-model-count">{models.length ? `${models.length} MODELS AVAILABLE` : "CATALOGUE LOADING"}</span>
        </div>
        <div className="agent-chat">
          {messages.length === 0 ? (
            <div className="agent-welcome">
              <div className="agent-welcome-icon"><Bot size={25} /></div>
              <h2>What are we investigating?</h2>
              <p>The agent can use passive IP, reverse-DNS and DNS intelligence tools, search public CVE records, explain findings, and help structure authorised security research.</p>
              <div className="agent-prompts">
                {["Explain what information an IP address can reveal, and its limits.", "Look up public IP intelligence for 1.1.1.1", "Analyse DNS records for example.com", "Find NVD details for CVE-2024-3094", "Help me plan a safe, authorised assessment of my own web application."].map((item) => <button key={item} onClick={() => setPrompt(item)}>{item}<span>↗</span></button>)}
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
        {error && <div className="agent-error"><CircleAlert size={14} /><span>{error}</span></div>}
        <form className="agent-composer" onSubmit={submit}>
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Describe what you want to investigate…" rows={3} maxLength={8000} disabled={busy} />
          <div className="agent-composer-bottom"><span><ShieldCheck size={12} /> Passive IP/DNS/CVE tools only · No active scanning</span><button type="submit" disabled={busy || !prompt.trim()}>{busy ? <LoaderCircle size={14} className="spin" /> : <Send size={14} />} {busy ? "Working" : "Run analysis"}</button></div>
        </form>
        <div className="agent-disclaimer"><Sparkles size={12} /> Outputs are AI-generated and must be verified against primary evidence. Use only on systems and data you are authorised to assess.</div>
      </section>
    </main>
  );
}