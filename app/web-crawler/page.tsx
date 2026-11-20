"use client";

import { useState } from "react";
import { ArrowLeft, ArrowRight, CircleAlert, Globe, LockKeyhole, Radar, ShieldCheck } from "lucide-react";

type Finding = { id: string; title: string; severity: string; url: string; detail: string; confidence: string; source: string };
type PageResult = { url: string; depth: number; status: number | null; contentType?: string; bodyBytes?: number; responseSha256?: string; error?: string; linksDiscovered?: number; forms?: { action: string; method: string; fields: { name: string; type: string }[]; submitted: boolean }[] };
type CrawlResult = { status: string; summary: Record<string, number>; pages: PageResult[]; findings: Finding[]; limitations: string[]; scope: { origin: string; authorizationReference: string } };
const API = "http://127.0.0.1:8765";

export default function NativeWebCrawlerPage() {
  const [url, setUrl] = useState("http://127.0.0.1:3000/");
  const [confirmationUrl, setConfirmationUrl] = useState("");
  const [reference, setReference] = useState("");
  const [maxPages, setMaxPages] = useState(10);
  const [maxDepth, setMaxDepth] = useState(2);
  const [delayMs, setDelayMs] = useState(500);
  const [localLabMode, setLocalLabMode] = useState(true);
  const [authorised, setAuthorised] = useState(false);
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<CrawlResult | null>(null);
  const [token, setToken] = useState("");

  const run = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const savedToken = token || window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!savedToken) throw new Error("Pair the local Kali companion first. Its pairing token is not available in this browser session.");
      const response = await fetch(API + "/web/crawl", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + savedToken },
        body: JSON.stringify({ url, confirmationUrl, authorizationReference: reference,
          authorizationConfirmed: authorised, confirmRun: approved, localLabMode, maxPages, maxDepth, delayMs })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The local companion rejected the crawl.");
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to start the native crawl.");
    } finally { setBusy(false); }
  };

  return <main className="min-h-screen bg-transparent text-[#d7e7e1]">
    <div className="mx-auto max-w-6xl px-5 py-8">
      <a href="/web-workbench" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> NATIVE WEB WORKBENCH</a>
      <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
        <div><div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-emerald-400"><Radar size={14}/> CYBERLAB NATIVE ENGINE / WEB DISCOVERY</div>
          <h1 className="text-3xl font-semibold tracking-tight">Web Crawler & Baseline Audit</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">Discover same-origin pages, map forms and review baseline security headers and cookies using CyberLab's own HTTP engine.</p></div>
        <div className="rounded border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-[10px] tracking-wider text-emerald-300">NATIVE · GET ONLY · SCOPE BOUND</div>
      </div>
      <section className="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold"><Globe size={15}/> TARGET & SCOPE</h2>
          <label className="mb-1 block text-xs text-slate-400">Start URL</label>
          <input value={url} onChange={e=>setUrl(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="http://127.0.0.1:3000/"/>
          <label className="mb-1 block text-xs text-slate-400">Retype exact origin (scheme, hostname and port)</label>
          <input value={confirmationUrl} onChange={e=>setConfirmationUrl(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="http://127.0.0.1:3000/"/>
          <label className="mb-1 block text-xs text-slate-400">Engagement / written authorisation reference</label>
          <input value={reference} onChange={e=>setReference(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="e.g. LAB-2026-001"/>
          <label className="mb-1 block text-xs text-slate-400">Companion pairing token (optional if already in this session)</label>
          <input value={token} onChange={e=>setToken(e.target.value)} type="password" autoComplete="off" className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="Local bridge token"/>
          <label className="flex items-start gap-2 text-xs text-slate-300"><input type="checkbox" checked={localLabMode} onChange={e=>setLocalLabMode(e.target.checked)} className="mt-0.5 accent-emerald-500"/> Local lab mode (restrict DNS resolution to loopback addresses only)</label>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold"><LockKeyhole size={15}/> CRAWL BUDGET</h2>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Maximum pages</span><b className="text-emerald-300">{maxPages}</b></label>
          <input type="range" min="1" max="20" value={maxPages} onChange={e=>setMaxPages(Number(e.target.value))} className="mb-5 w-full accent-emerald-500"/>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Maximum link depth</span><b className="text-emerald-300">{maxDepth}</b></label>
          <input type="range" min="0" max="2" value={maxDepth} onChange={e=>setMaxDepth(Number(e.target.value))} className="mb-5 w-full accent-emerald-500"/>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Delay between requests</span><b className="text-emerald-300">{delayMs} ms</b></label>
          <input type="range" min="250" max="2000" step="250" value={delayMs} onChange={e=>setDelayMs(Number(e.target.value))} className="mb-5 w-full accent-emerald-500"/>
          <div className="rounded border border-slate-800 bg-[#07110f] p-3 text-[11px] leading-5 text-slate-400">Hard limits: 20 pages, depth 2, 45 seconds. GET only. No form submission, redirects, payloads or out-of-origin requests.</div>
        </div>
      </section>
      <section className="mt-5 rounded-xl border border-amber-900/50 bg-amber-950/10 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-amber-200"><ShieldCheck size={15}/> REQUIRED APPROVAL</h2>
        <label className="mb-3 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorised} onChange={e=>setAuthorised(e.target.checked)} className="mt-0.5 accent-emerald-500"/> I confirm I own this target or have written permission to assess the exact origin above.</label>
        <label className="mb-4 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)} className="mt-0.5 accent-emerald-500"/> I approve CyberLab sending the bounded GET requests defined by this crawl budget.</label>
        <button disabled={busy || !authorised || !approved || !reference.trim() || !url.trim() || !confirmationUrl.trim()} onClick={run} className="inline-flex items-center gap-2 rounded bg-emerald-700 px-4 py-2.5 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40">{busy ? "CRAWLING..." : "START NATIVE CRAWL"} <ArrowRight size={14}/></button>
        {error && <p className="mt-3 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      </section>
      {result && <section className="mt-7 space-y-5">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {Object.entries(result.summary).filter(([key])=>["pagesVisited","htmlPages","formsObserved","findings","requestErrors","outOfScopeLinksBlocked"].includes(key)).map(([key,value])=><div key={key} className="rounded-lg border border-slate-800 bg-[#0b1715] p-4"><div className="text-[10px] uppercase tracking-wider text-slate-500">{key.replace(/[A-Z]/g," $&")}</div><div className="mt-1 text-2xl font-semibold text-emerald-300">{value}</div></div>)}
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">DISCOVERED PAGES</h2>
          <div className="space-y-2">{result.pages.map((p,i)=><div key={p.url+i} className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/70 py-2 text-xs"><span className="min-w-0 break-all text-slate-300">{p.url}</span><span className="text-emerald-300">{p.status ?? p.error ?? "—"}</span></div>)}</div></div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">FORM INVENTORY</h2>
          {result.pages.flatMap(p=>(p.forms||[]).map((f,i)=>({page:p.url,form:f,key:p.url+"-"+i}))).length===0 ? <p className="text-xs text-slate-400">No HTML forms were found on the pages reached.</p> : <div className="space-y-3">{result.pages.flatMap(p=>(p.forms||[]).map((f,i)=>({page:p.url,form:f,key:p.url+"-"+i}))).map(item=><div key={item.key} className="border-b border-slate-800/70 pb-3"><div className="flex gap-2 text-xs"><span className="rounded bg-slate-800 px-2 py-1 text-emerald-300">{item.form.method}</span><b className="break-all">{item.form.action}</b></div><p className="mt-1 break-all text-[10px] text-slate-500">Page: {item.page}</p><p className="mt-1 text-[11px] text-slate-400">Fields: {item.form.fields.map(field=>(field.name || "(unnamed)")+" ["+field.type+"]").join(", ") || "No input fields detected"} · Not submitted</p></div>)}</div>}</div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">BASELINE FINDINGS</h2>
          {result.findings.length===0 ? <p className="text-xs text-slate-400">No baseline indicators were recorded for the pages reached.</p> : <div className="space-y-3">{result.findings.map(f=><div key={f.id} className="border-b border-slate-800/70 pb-3"><div className="flex flex-wrap items-center gap-2"><span className="rounded bg-slate-800 px-2 py-1 text-[9px] uppercase text-amber-200">{f.severity}</span><b className="text-xs">{f.title}</b></div><p className="mt-1 break-all text-[11px] text-slate-500">{f.url}</p><p className="mt-1 text-xs text-slate-400">{f.detail}</p></div>)}</div>}</div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">TEST BOUNDARIES</h2><ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">{result.limitations.map(item=><li key={item}>{item}</li>)}</ul></div>
      </section>}
      <a href="/web-scanner" className="mt-6 inline-flex items-center gap-2 rounded border border-amber-900/60 px-4 py-2 text-xs text-amber-200 hover:bg-amber-950/30">Continue to Safe Active Web Checks <ArrowRight size={14}/></a>
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · NATIVE WEB DISCOVERY · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
