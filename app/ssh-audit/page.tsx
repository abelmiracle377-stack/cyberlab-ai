"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, Terminal, ShieldCheck, CircleAlert } from "lucide-react";

type AuditResult = {
  status: string; target?: {host:string;port:number}; banner?: string|null;
  sshAudit?: {available:boolean;exitCode?:number;output?:string;error?:string;installHint?:string};
  findings?: Array<{severity:string;title:string;evidence?:string;note?:string}>;
  limitations?: string[]; error?: string;
};

const API = "/api/kali";

export default function SshAuditPage() {
  const [host,setHost] = useState("");
  const [port,setPort] = useState("22");
  const [reference,setReference] = useState("");
  const [token,setToken] = useState("");
  const [authorised,setAuthorised] = useState(false);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  const [result,setResult] = useState<AuditResult|null>(null);

  async function run() {
    setBusy(true); setError(""); setResult(null);
    try {
      const pairing = token || window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "";
      if (!pairing) throw new Error("Pair the local Kali companion first.");
      if (!authorised) throw new Error("Confirm written authorisation before running the SSH audit.");
      const response = await fetch(API + "/ssh/audit", {
        method:"POST",
        headers:{"Content-Type":"application/json","Authorization":"Bearer "+pairing},
        body:JSON.stringify({host,port:Number(port),authorized:true,authorizationReference:reference,timeoutSeconds:5})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The Kali companion rejected the SSH audit.");
      setResult(data);
    } catch(e) { setError(e instanceof Error ? e.message : "SSH audit failed."); }
    finally { setBusy(false); }
  }

  return <main className="min-h-screen bg-transparent px-5 py-8 text-[#d7e7e1]">
    <div className="mx-auto max-w-4xl space-y-6">
      <Link href="/web-scanner" className="inline-flex items-center gap-2 text-xs text-emerald-300/70"><ArrowLeft size={14}/> SECURITY TOOLS</Link>
      <header><p className="flex items-center gap-2 text-[10px] tracking-[.24em] text-emerald-300"><Terminal size={14}/> KALI COMPANION / SSH</p><h1 className="mt-2 text-3xl font-semibold">SSH Service Audit</h1><p className="mt-2 text-sm text-slate-400">Checks the SSH identification banner and, when installed on Kali, runs ssh-audit for protocol and cryptographic configuration findings. It does not log in, guess passwords, enumerate users or collect private keys.</p></header>
      <section className="rounded-xl border border-slate-800 bg-[#161B22] p-5 space-y-4">
        <div><label className="mb-1 block text-xs text-slate-400">Single authorised host or IP</label><input value={host} onChange={e=>setHost(e.target.value)} placeholder="192.168.1.20 or server.example.com" className="w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm"/></div>
        <div className="grid gap-3 sm:grid-cols-2"><div><label className="mb-1 block text-xs text-slate-400">SSH port</label><input type="number" min="1" max="65535" value={port} onChange={e=>setPort(e.target.value)} className="w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm"/></div><div><label className="mb-1 block text-xs text-slate-400">Engagement / authorisation reference</label><input value={reference} onChange={e=>setReference(e.target.value)} placeholder="e.g. Internal audit CHG-1042" className="w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm"/></div></div>
        <div><label className="mb-1 block text-xs text-slate-400">Pairing token (optional if saved in this session)</label><input type="password" autoComplete="off" value={token} onChange={e=>setToken(e.target.value)} className="w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm" placeholder="Local Kali bridge token"/></div>
        <label className="flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorised} onChange={e=>setAuthorised(e.target.checked)} className="mt-0.5 accent-emerald-500"/> I confirm this single host and port are within my written authorisation and I approve this SSH posture audit.</label>
        <button onClick={run} disabled={busy||!host.trim()||!reference.trim()||!authorised} className="rounded bg-emerald-700 px-4 py-2.5 text-xs font-semibold disabled:opacity-40">{busy?"AUDITING…":"RUN SSH AUDIT"}</button>
        {error && <p className="flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      </section>
      {result && <section className="space-y-4 rounded-xl border border-slate-800 bg-[#161B22] p-5">
        <h2 className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck size={16}/> RESULT · {result.status.toUpperCase()}</h2>
        {result.target && <p className="text-xs text-slate-400">Target: {result.target.host}:{result.target.port}</p>}
        {result.banner && <div><p className="text-xs text-slate-500">SSH identification banner</p><code className="mt-1 block break-all rounded bg-[#0D1117] p-3 text-xs">{result.banner}</code></div>}
        {result.findings?.map((finding,i)=><div key={i} className="rounded border border-amber-900/50 p-3"><p className="text-sm font-semibold">{finding.severity.toUpperCase()} · {finding.title}</p><p className="mt-1 text-xs text-slate-400">{finding.evidence} {finding.note}</p></div>)}
        {result.sshAudit && <div><p className="text-xs font-semibold">ssh-audit tool</p>{result.sshAudit.available ? <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-[#0D1117] p-3 text-xs text-slate-300">{result.sshAudit.output || result.sshAudit.error || "No tool output."}</pre> : <p className="mt-1 text-xs text-amber-200">{result.sshAudit.installHint}</p>}</div>}
        {result.limitations?.map(item=><p key={item} className="text-xs text-slate-500">• {item}</p>)}
      </section>}
    </div>
  </main>;
}
