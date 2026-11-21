"use client";

import { useState } from "react";
import { ArrowLeft, ArrowRight, Bug, CircleAlert, ShieldCheck, Target } from "lucide-react";

type Finding = { id: string; title: string; severity: string; url: string; detail: string; confidence: string };
type ScanResult = { status: string; summary: Record<string, number>; checks: { type: string; url: string; status?: number; parameter?: string; error?: string }[]; findings: Finding[]; limitations: string[] };
const API = "/api/kali";

export default function NativeWebScannerPage() {
  const [urls, setUrls] = useState("http://127.0.0.1:3000/");
  const [confirmationUrl, setConfirmationUrl] = useState("");
  const [reference, setReference] = useState("");
  const [maxRequests, setMaxRequests] = useState(5);
  const [delayMs, setDelayMs] = useState(500);
  const [localLabMode, setLocalLabMode] = useState(true);
  const [authorised, setAuthorised] = useState(false);
  const [approved, setApproved] = useState(false);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);

  const run = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const savedToken = token || window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!savedToken) throw new Error("Pair the local Kali companion first.");
      const targets = urls.split("\n").map(x=>x.trim()).filter(Boolean);
      if (!targets.length || targets.length > 10) throw new Error("Enter between 1 and 10 target page URLs.");
      const response = await fetch(API + "/web/active-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + savedToken },
        body: JSON.stringify({ urls: targets, confirmationUrl, authorizationReference: reference,
          authorizationConfirmed: authorised, confirmRun: approved, localLabMode, maxRequests, delayMs })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The local companion rejected the active checks.");
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to start active checks.");
    } finally { setBusy(false); }
  };

  return <main className="min-h-screen bg-transparent text-[#d7e7e1]">
    <div className="mx-auto max-w-6xl px-5 py-8">
      <a href="/web-crawler" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> WEB DISCOVERY</a>
      <nav className="mb-5 flex flex-wrap gap-3 text-xs"><a href="/ssh-audit" className="rounded border border-slate-700 px-3 py-2 text-emerald-300 hover:border-emerald-600">SSH service audit →</a><a href="/browser-workspace" className="rounded border border-slate-700 px-3 py-2 text-emerald-300 hover:border-emerald-600">Browser inspection →</a></nav>
      <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
        <div><div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><Bug size={14}/> CYBERLAB NATIVE ENGINE / ACTIVE CHECKS</div>
          <h1 className="text-3xl font-semibold tracking-tight">Safe Active Web Checks</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">CyberLab sends bounded OPTIONS preflight and GET query-reflection checks to approved pages. No forms are submitted and no exploit is executed.</p></div>
        <div className="rounded border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-[10px] tracking-wider text-amber-200">NATIVE · NON-MUTATING · APPROVAL REQUIRED</div>
      </div>
      <section className="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-xl border border-slate-800 bg-[#161B22] p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold"><Target size={15}/> TARGETS & SCOPE</h2>
          <label className="mb-1 block text-xs text-slate-400">Page URLs (one per line, maximum 10; use URLs discovered by the crawler)</label>
          <textarea value={urls} onChange={e=>setUrls(e.target.value)} rows={5} className="mb-4 w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2.5 text-sm outline-none focus:border-emerald-600"/>
          <label className="mb-1 block text-xs text-slate-400">Retype exact origin (scheme, hostname and port)</label>
          <input value={confirmationUrl} onChange={e=>setConfirmationUrl(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="http://127.0.0.1:3000/"/>
          <label className="mb-1 block text-xs text-slate-400">Engagement / written authorisation reference</label>
          <input value={reference} onChange={e=>setReference(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="e.g. LAB-2026-001"/>
          <label className="mb-1 block text-xs text-slate-400">Companion pairing token (optional if already in this session)</label>
          <input value={token} onChange={e=>setToken(e.target.value)} type="password" autoComplete="off" className="mb-4 w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="Local bridge token"/>
          <label className="flex items-start gap-2 text-xs text-slate-300"><input type="checkbox" checked={localLabMode} onChange={e=>setLocalLabMode(e.target.checked)} className="mt-0.5 accent-emerald-500"/> Local lab mode (restrict DNS resolution to loopback addresses only)</label>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#161B22] p-5">
          <h2 className="mb-4 text-sm font-semibold">REQUEST BUDGET</h2>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Maximum requests</span><b className="text-amber-200">{maxRequests}</b></label>
          <input type="range" min="1" max="10" value={maxRequests} onChange={e=>setMaxRequests(Number(e.target.value))} className="mb-5 w-full accent-amber-500"/>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Delay between requests</span><b className="text-amber-200">{delayMs} ms</b></label>
          <input type="range" min="500" max="2000" step="250" value={delayMs} onChange={e=>setDelayMs(Number(e.target.value))} className="mb-5 w-full accent-amber-500"/>
          <div className="rounded border border-slate-800 bg-[#0D1117] p-3 text-[11px] leading-5 text-slate-400">Hard limits: 10 requests, 10 URLs, 30 seconds. Tests only CORS preflight and inert query-reflection indicators. Sensitive query parameters are skipped.</div>
        </div>
      </section>
      <section className="mt-5 rounded-xl border border-amber-900/50 bg-amber-950/10 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-amber-200"><ShieldCheck size={15}/> REQUIRED APPROVAL</h2>
        <label className="mb-3 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorised} onChange={e=>setAuthorised(e.target.checked)} className="mt-0.5 accent-amber-500"/> I confirm I own these targets or have written permission to assess the exact origin above.</label>
        <label className="mb-4 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)} className="mt-0.5 accent-amber-500"/> I explicitly approve up to {maxRequests} non-mutating OPTIONS/GET test requests.</label>
        <button disabled={busy || !authorised || !approved || !reference.trim() || !confirmationUrl.trim() || !urls.trim()} onClick={run} className="inline-flex items-center gap-2 rounded bg-amber-700 px-4 py-2.5 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40">{busy ? "TESTING..." : "RUN SAFE ACTIVE CHECKS"} <ArrowRight size={14}/></button>
        {error && <p className="mt-3 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      </section>
      {result && <section className="mt-7 space-y-5">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">{Object.entries(result.summary).map(([key,value])=><div key={key} className="rounded-lg border border-slate-800 bg-[#161B22] p-4"><div className="text-[10px] uppercase tracking-wider text-slate-500">{key.replace(/[A-Z]/g," $&")}</div><div className="mt-1 text-2xl font-semibold text-amber-200">{value}</div></div>)}</div>
        <div className="rounded-xl border border-slate-800 bg-[#161B22] p-5"><h2 className="mb-3 text-sm font-semibold">FINDINGS</h2>
          {result.findings.length===0 ? <p className="text-xs text-slate-400">No indicators were identified by these limited checks.</p> : <div className="space-y-3">{result.findings.map(f=><div key={f.id} className="border-b border-slate-800/70 pb-3"><div className="flex flex-wrap items-center gap-2"><span className="rounded bg-slate-800 px-2 py-1 text-[9px] uppercase text-amber-200">{f.severity}</span><b className="text-xs">{f.title}</b></div><p className="mt-1 break-all text-[11px] text-slate-500">{f.url}</p><p className="mt-1 text-xs text-slate-400">{f.detail}</p></div>)}</div>}</div>
        <div className="rounded-xl border border-slate-800 bg-[#161B22] p-5"><h2 className="mb-3 text-sm font-semibold">CHECK LOG</h2><div className="space-y-2">{result.checks.map((c,i)=><div key={i} className="border-b border-slate-800/70 py-2 text-xs"><b className="text-emerald-300">{c.type}</b> · {c.status ?? c.error ?? "completed"} {c.parameter ? "· parameter: "+c.parameter : ""}<p className="mt-1 break-all text-slate-500">{c.url}</p></div>)}</div></div>
        <div className="rounded-xl border border-slate-800 bg-[#161B22] p-5"><h2 className="mb-3 text-sm font-semibold">LIMITATIONS</h2><ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">{result.limitations.map(item=><li key={item}>{item}</li>)}</ul></div>
      </section>}
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · SAFE ACTIVE WEB CHECKS · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
