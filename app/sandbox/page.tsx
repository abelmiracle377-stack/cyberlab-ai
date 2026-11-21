"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Play, ShieldCheck, TerminalSquare } from "lucide-react";

export default function SandboxPage() {
  const [language, setLanguage] = useState("python");
  const [source, setSource] = useState('print("Hello from CyberLab sandbox")\n');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  async function run() {
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/sandbox/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ language, source }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Sandbox execution failed.");
      setResult(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Sandbox execution failed."); }
    finally { setBusy(false); }
  }
  return <main className="min-h-screen bg-[#0d1117] px-4 py-8 text-[#e6edf3] sm:px-8"><div className="mx-auto max-w-6xl space-y-6">
    <Link href="/" className="inline-flex items-center gap-2 text-sm text-[#8b949e] hover:text-white"><ArrowLeft size={16}/> CyberLab</Link>
    <header><p className="text-xs uppercase tracking-[.2em] text-emerald-400">Independent execution environment</p><h1 className="mt-2 text-3xl font-semibold">CyberLab Sandbox</h1><p className="mt-2 max-w-3xl text-sm text-[#8b949e]">Run Python, JavaScript and shell experiments in disposable, network-isolated containers. This workspace does not require Kali Companion or CyberLab AI OS.</p></header>
    <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-2 text-sm text-emerald-300"><ShieldCheck size={17}/> Disposable container · no network · bounded resources</div><select value={language} onChange={e=>setLanguage(e.target.value)} className="rounded-lg border border-[#30363d] bg-[#0d1117] p-2 text-sm"><option value="python">Python</option><option value="javascript">JavaScript</option><option value="shell">Shell</option></select></div>
    <textarea value={source} onChange={e=>setSource(e.target.value)} spellCheck={false} rows={16} className="mt-4 w-full rounded-lg border border-[#30363d] bg-[#090d12] p-4 font-mono text-sm leading-6 text-[#e6edf3]" />
    <button onClick={run} disabled={busy || !source.trim()} className="mt-3 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50"><Play size={16}/>{busy ? "Running…" : "Run in isolated sandbox"}</button>
    {error && <p role="alert" className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">{error}</p>}
    {result && <div className="mt-4 space-y-3"><div className="flex items-center gap-2 text-sm"><TerminalSquare size={16}/> Job {result.jobId} · {result.status} · exit {result.exitCode} · {result.durationMs} ms</div><pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg bg-[#090d12] p-4 font-mono text-xs">{result.output || "(no output)"}</pre><p className="text-xs text-[#8b949e]">Isolation: {result.isolation?.memoryLimit} RAM · {result.isolation?.cpuLimit} · network {result.isolation?.network} · disposable container</p></div>}
    </section>
    <p className="text-xs text-[#8b949e]">The independent runner must be deployed and connected by the CyberLab operator. It does not yet provide persistent project files, GUI browsers, Kali tools or outbound network testing. Do not run code containing secrets.</p>
  </div></main>;
}
