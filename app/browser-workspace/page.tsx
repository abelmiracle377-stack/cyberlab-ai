"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Globe, ShieldCheck, RefreshCw, Code2 } from "lucide-react";

type Snapshot = {
  capturedAt: string; page: { title?: string; url?: string; readyState?: string; nodes?: any[]; forms?: any[] };
  cookies?: any[]; network?: any[]; safety?: Record<string, boolean>;
};
const CHANNEL = "CYBERLAB_BROWSER_BRIDGE_V1";

export default function BrowserWorkspacePage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [status, setStatus] = useState("Waiting for a shared browser tab. Install the CyberLab Browser Share extension and use its popup on the target tab.");
  const [selector, setSelector] = useState("");
  const [attribute, setAttribute] = useState("class");
  const [value, setValue] = useState("");
  const [editStatus, setEditStatus] = useState("Live DOM editing is not enabled in this initial inspection release.");
  useEffect(() => {
    function receive(event: MessageEvent) {
      if (event.source !== window || event.origin !== location.origin) return;
      const message = event.data;
      if (!message || message.channel !== CHANNEL || message.direction !== "from-extension") return;
      if (message.type === "browser-snapshot") {
        setSnapshot(message.payload as Snapshot);
        setStatus("Shared tab inspected. Secret values and request/response bodies were excluded.");
      }
      if (message.type === "edit-result") setEditStatus(message.payload?.error || (message.payload?.ok ? "DOM edit applied." : "Edit not applied."));
    }
    window.addEventListener("message", receive);
    return () => window.removeEventListener("message", receive);
  }, []);
  function extensionCommand(type: string, payload?: Record<string, string>) {\n    window.postMessage({ channel: CHANNEL, direction: "to-extension", type, payload }, location.origin);\n  }\n  const page = snapshot?.page;
  return <main className="min-h-screen bg-[#0d1117] px-4 py-8 text-[#e6edf3] sm:px-8">
    <div className="mx-auto max-w-7xl space-y-6">
      <Link href="/" className="inline-flex items-center gap-2 text-sm text-[#8b949e] hover:text-white"><ArrowLeft size={16}/> CyberLab</Link>
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div><p className="text-xs uppercase tracking-[.2em] text-emerald-400">Browser security workspace</p><h1 className="mt-2 text-3xl font-semibold">Shared browser inspection</h1><p className="mt-2 max-w-3xl text-sm text-[#8b949e]">Share a tab from your browser extension to inspect its page structure, forms, cookie security attributes and network metadata. This first release is read-only.</p></div>
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300"><ShieldCheck size={16}/> Local, user-initiated share</div>
      </header>
      <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><div className="flex items-center gap-2 text-sm font-medium"><Globe size={17}/> Sharing status</div><p className="mt-2 text-sm text-[#8b949e]">{status}</p>{page && <div className="mt-3 grid gap-3 text-sm sm:grid-cols-3"><div><span className="text-xs text-[#8b949e]">Page</span><p>{page.title}</p></div><div><span className="text-xs text-[#8b949e]">Origin</span><p className="break-all">{page.url}</p></div><div><span className="text-xs text-[#8b949e]">Captured</span><p>{new Date(snapshot!.capturedAt).toLocaleString()}</p></div></div>}</section>
      <div className="grid gap-5 lg:grid-cols-2">
        <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><h2 className="flex items-center gap-2 font-semibold"><Code2 size={17}/> DOM / Elements overview</h2><p className="mt-1 text-xs text-[#8b949e]">Tag, ID, class, role and safe link metadata. Input values are never collected.</p><div className="mt-3 max-h-[440px] overflow-auto rounded-lg bg-[#0d1117] p-3 font-mono text-xs">{snapshot?.page?.nodes?.length ? snapshot.page.nodes.map((n,i)=><div key={i} className="border-b border-[#30363d]/60 py-1"><span className="text-sky-300">&lt;{n.tag}&gt;</span> {n.id && <span className="text-amber-300">#{n.id}</span>} {n.className && <span className="text-emerald-300">.{n.className}</span>} {n.role && <span className="text-[#8b949e]">role={n.role}</span>} {n.passwordField && <span className="text-amber-300">password field (value hidden)</span>} {n.text && <span className="block truncate text-[#8b949e]">{n.text}</span>}</div>) : <p className="text-[#8b949e]">No DOM snapshot received.</p>}</div></section>
        <section className="space-y-5">
          <div className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><h2 className="font-semibold">Cookies / Storage security metadata</h2><p className="mt-1 text-xs text-[#8b949e]">Cookie values are never shared. This view exposes security flags only.</p><div className="mt-3 max-h-52 overflow-auto">{snapshot?.cookies?.length ? snapshot.cookies.map((c,i)=><div key={i} className="border-b border-[#30363d] py-2 text-xs"><p className="font-medium">{c.name} <span className="text-[#8b949e]">{c.domain}{c.path}</span></p><p className="mt-1 text-[#8b949e]">{c.httpOnly ? "HttpOnly" : "Not HttpOnly"} · {c.secure ? "Secure" : "Not Secure"} · SameSite: {c.sameSite} · {c.session ? "Session" : "Persistent"}</p></div>) : <p className="text-sm text-[#8b949e]">No cookie metadata received.</p>}</div></div>
          <div className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><h2 className="font-semibold">Network activity metadata</h2><p className="mt-1 text-xs text-[#8b949e]">Request URLs have query values redacted. Bodies and cookie values are excluded.</p><div className="mt-3 max-h-52 overflow-auto">{snapshot?.network?.length ? snapshot.network.map((n,i)=><div key={i} className="border-b border-[#30363d] py-2 text-xs"><span className="mr-2 rounded bg-[#30363d] px-2 py-1">{n.kind}</span><span>{n.method || n.status || n.error}</span><p className="mt-1 break-all text-[#8b949e]">{n.url}</p></div>) : <p className="text-sm text-[#8b949e]">No network events captured during the inspection window.</p>}</div></div>
        </section>
      </div>
      <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><h2 className="font-semibold">DOM editor</h2><p className="mt-1 text-sm text-[#8b949e]">The extension's initial release captures a read-only snapshot. Live DOM edits, JavaScript console execution and network replay are deliberately not enabled yet; they require a persistent, explicit approval session and reversible change history.</p><div className="mt-3 grid gap-2 md:grid-cols-3"><input value={selector} onChange={e=>setSelector(e.target.value)} placeholder="CSS selector (e.g. #login-button)" className="rounded-lg border border-[#30363d] bg-[#0d1117] p-2 text-sm"/><select value={attribute} onChange={e=>setAttribute(e.target.value)} className="rounded-lg border border-[#30363d] bg-[#0d1117] p-2 text-sm"><option>class</option><option>title</option><option>aria-label</option><option>placeholder</option></select><input value={value} onChange={e=>setValue(e.target.value)} placeholder="New value" className="rounded-lg border border-[#30363d] bg-[#0d1117] p-2 text-sm"/></div><div className="mt-3 flex flex-wrap gap-2"><button onClick={()=>extensionCommand("edit-attribute",{selector,attribute,value})} disabled={!snapshot || !selector.trim()} className="rounded-lg bg-emerald-700 px-3 py-2 text-sm disabled:opacity-40">Apply temporary DOM edit</button><button onClick={()=>extensionCommand("undo-last-edit")} disabled={!snapshot} className="rounded-lg border border-[#30363d] px-3 py-2 text-sm disabled:opacity-40">Undo last edit</button><button onClick={()=>extensionCommand("stop-sharing")} disabled={!snapshot} className="rounded-lg border border-amber-500/40 px-3 py-2 text-sm text-amber-300 disabled:opacity-40">Stop sharing</button></div><p className="mt-2 text-xs text-amber-300">{editStatus}</p></section>
      <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4"><h2 className="font-semibold">Safety boundary</h2><p className="mt-2 text-sm text-[#8b949e]">This workspace does not collect cookie values, passwords, form values, request bodies or response bodies. It does not submit forms, send requests, exploit vulnerabilities or modify the target page. Only inspect applications you own or are explicitly authorised to test.</p></section>
    </div>
  </main>;
}
