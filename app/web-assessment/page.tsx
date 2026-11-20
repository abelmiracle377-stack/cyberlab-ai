"use client";

import { useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Bug, CircleAlert, ShieldCheck, Target } from "lucide-react";
import TerminalStream from "../terminal-stream";

type Finding = {
  id: string; title: string; severity: string; owasp: string; cwe: string;
  url: string; detail: string; remediation: string; confidence: string;
};
type AssessResult = {
  status: string; scope: { origin: string; authorizationReference: string };
  summary: Record<string, number | Record<string, number>>;
  checks: { type: string; url: string; status?: number; parameter?: string; error?: string }[];
  findings: Finding[]; limitations: string[];
};
const API = "http://127.0.0.1:8765";
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_CLASS: Record<string, string> = {
  critical: "bg-rose-900/40 text-rose-200 border-rose-800",
  high: "bg-orange-900/30 text-orange-200 border-orange-800",
  medium: "bg-amber-900/25 text-amber-200 border-amber-800",
  low: "bg-sky-900/25 text-sky-200 border-sky-800",
  info: "bg-slate-800 text-slate-300 border-slate-700",
};

export default function WebAssessmentPage() {
  const [urls, setUrls] = useState("http://127.0.0.1:3000/");
  const [confirmationUrl, setConfirmationUrl] = useState("");
  const [reference, setReference] = useState("");
  const [maxRequests, setMaxRequests] = useState(15);
  const [delayMs, setDelayMs] = useState(500);
  const [localLabMode, setLocalLabMode] = useState(true);
  const [authorised, setAuthorised] = useState(false);
  const [approved, setApproved] = useState(false);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AssessResult | null>(null);

  const ranked = useMemo(() => {
    if (!result) return [];
    return [...result.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  }, [result]);

  const run = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const savedToken = token || window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!savedToken) throw new Error("Pair the local Kali companion first.");
      const targets = urls.split("\n").map((x) => x.trim()).filter(Boolean);
      if (!targets.length || targets.length > 10) throw new Error("Enter between 1 and 10 target page URLs.");
      const response = await fetch(API + "/web/assessment", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + savedToken },
        body: JSON.stringify({ urls: targets, confirmationUrl, authorizationReference: reference,
          authorizationConfirmed: authorised, confirmRun: approved, localLabMode, maxRequests, delayMs }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The local companion rejected the assessment.");
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to start the assessment.");
    } finally { setBusy(false); }
  };

  const bySeverity = (result?.summary.bySeverity || {}) as Record<string, number>;

  return <main className="min-h-screen bg-transparent text-[#d7e7e1]">
    <div className="mx-auto max-w-6xl px-5 py-8">
      <a href="/web-scanner" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> ACTIVE CHECKS</a>
      <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
        <div><div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><Bug size={14}/> CYBERLAB NATIVE ENGINE / WEB ASSESSMENT</div>
          <h1 className="text-3xl font-semibold tracking-tight">Web Application Assessment</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">The bug-bounty baseline a human runs first: security-header and cookie hardening, information disclosure, sensitive-file exposure, open-redirect, SQL-error and reflected-input detection, and risky HTTP methods — each mapped to OWASP/CWE with remediation. Detection only; no exploitation.</p></div>
        <div className="rounded border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-[10px] tracking-wider text-amber-200">NATIVE · DETECTION-ONLY · APPROVAL REQUIRED</div>
      </div>
      <section className="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold"><Target size={15}/> TARGETS & SCOPE</h2>
          <label className="mb-1 block text-xs text-slate-400">Page URLs (one per line, maximum 10)</label>
          <textarea value={urls} onChange={(e) => setUrls(e.target.value)} rows={5} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600"/>
          <label className="mb-1 block text-xs text-slate-400">Retype exact origin (scheme, hostname and port)</label>
          <input value={confirmationUrl} onChange={(e) => setConfirmationUrl(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="http://127.0.0.1:3000/"/>
          <label className="mb-1 block text-xs text-slate-400">Engagement / written authorisation reference</label>
          <input value={reference} onChange={(e) => setReference(e.target.value)} className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="e.g. HID program / LAB-2026-001"/>
          <label className="mb-1 block text-xs text-slate-400">Companion pairing token (optional if already in this session)</label>
          <input value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off" className="mb-4 w-full rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600" placeholder="Local bridge token"/>
          <label className="flex items-start gap-2 text-xs text-slate-300"><input type="checkbox" checked={localLabMode} onChange={(e) => setLocalLabMode(e.target.checked)} className="mt-0.5 accent-emerald-500"/> Local lab mode (restrict DNS resolution to loopback addresses only)</label>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5">
          <h2 className="mb-4 text-sm font-semibold">REQUEST BUDGET</h2>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Maximum requests</span><b className="text-amber-200">{maxRequests}</b></label>
          <input type="range" min="1" max="25" value={maxRequests} onChange={(e) => setMaxRequests(Number(e.target.value))} className="mb-5 w-full accent-amber-500"/>
          <label className="mb-1 flex justify-between text-xs text-slate-400"><span>Delay between requests</span><b className="text-amber-200">{delayMs} ms</b></label>
          <input type="range" min="500" max="2000" step="250" value={delayMs} onChange={(e) => setDelayMs(Number(e.target.value))} className="mb-5 w-full accent-amber-500"/>
          <div className="rounded border border-slate-800 bg-[#07110f] p-3 text-[11px] leading-5 text-slate-400">Hard limits: 25 requests, 10 URLs, 45 seconds. Sensitive query parameters are skipped. Every finding is a candidate requiring manual verification.</div>
        </div>
      </section>
      <section className="mt-5 rounded-xl border border-amber-900/50 bg-amber-950/10 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-amber-200"><ShieldCheck size={15}/> REQUIRED APPROVAL</h2>
        <label className="mb-3 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorised} onChange={(e) => setAuthorised(e.target.checked)} className="mt-0.5 accent-amber-500"/> I confirm I own these targets or have written permission (a bug-bounty program scope counts) to assess the exact origin above.</label>
        <label className="mb-4 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} className="mt-0.5 accent-amber-500"/> I explicitly approve up to {maxRequests} detection-only HTTP requests.</label>
        <button disabled={busy || !authorised || !approved || !reference.trim() || !confirmationUrl.trim() || !urls.trim()} onClick={run} className="inline-flex items-center gap-2 rounded bg-amber-700 px-4 py-2.5 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40">{busy ? "ASSESSING..." : "RUN ASSESSMENT"} <ArrowRight size={14}/></button>
        {error && <p className="mt-3 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      </section>
      {result && <section className="mt-7 space-y-5">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{SEV_ORDER.map((s) => <div key={s} className="rounded-lg border border-slate-800 bg-[#0b1715] p-4"><div className="text-[10px] uppercase tracking-wider text-slate-500">{s}</div><div className="mt-1 text-2xl font-semibold text-amber-200">{bySeverity[s] ?? 0}</div></div>)}</div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">FINDINGS ({ranked.length})</h2>
          {ranked.length === 0 ? <p className="text-xs text-slate-400">No issues were detected by these checks. This does not prove the target is secure.</p> : <div className="space-y-3">{ranked.map((f) => <div key={f.id} className="border-b border-slate-800/70 pb-3"><div className="flex flex-wrap items-center gap-2"><span className={"rounded border px-2 py-0.5 text-[9px] uppercase " + (SEV_CLASS[f.severity] || SEV_CLASS.info)}>{f.severity}</span><b className="text-xs">{f.title}</b><span className="text-[10px] text-slate-500">{f.owasp} · {f.cwe} · {f.confidence} confidence</span></div><p className="mt-1 break-all text-[11px] text-slate-500">{f.url}</p><p className="mt-1 text-xs text-slate-400">{f.detail}</p><p className="mt-1 text-xs text-emerald-300/80"><b>Fix:</b> {f.remediation}</p></div>)}</div>}</div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">CHECK LOG ({result.checks.length})</h2>
          <div className="max-h-72 overflow-y-auto rounded border border-slate-800 bg-[#06100e] p-3">
            <TerminalStream lines={result.checks.map((c) => `${c.type} · ${c.status ?? c.error ?? "done"}${c.parameter ? " · param " + c.parameter : ""}  ${c.url}`)} />
          </div></div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1715] p-5"><h2 className="mb-3 text-sm font-semibold">LIMITATIONS</h2><ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">{result.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div>
      </section>}
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · WEB APPLICATION ASSESSMENT · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
