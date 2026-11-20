"use client";

import { useEffect, useState } from "react";
import { ArrowLeft, Globe, Search, Server, Loader2, CircleAlert } from "lucide-react";

const BRIDGE = "http://127.0.0.1:8765";

type HostResult = {
  ip?: string; org?: string; isp?: string; os?: string; country?: string;
  hostnames?: string[]; ports?: number[]; service_count?: number;
  services?: { port?: number; transport?: string; product?: string; version?: string; banner?: string }[];
  vulns?: string[]; last_update?: string;
};

export default function ShodanPage() {
  const [token, setToken] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [mode, setMode] = useState<"host" | "search" | "dns" | "info">("host");
  const [ip, setIp] = useState("");
  const [query, setQuery] = useState("");
  const [hostnames, setHostnames] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    setToken(window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "");
    setApiKey(window.sessionStorage.getItem("cyberlab.shodanApiKey") || "");
  }, []);

  const call = async (path: string, body: Record<string, unknown>) => {
    setBusy(true); setError(""); setResult(null);
    try {
      if (!token.trim()) throw new Error("Enter the companion bridge token.");
      if (!apiKey.trim()) throw new Error("Enter your Shodan API key.");
      window.sessionStorage.setItem("cyberlab.kaliBridgeToken", token.trim());
      window.sessionStorage.setItem("cyberlab.shodanApiKey", apiKey.trim());
      const res = await fetch(BRIDGE + path, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ apiKey: apiKey.trim(), ...body }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Shodan request failed.");
      setResult(data);
    } catch (e) { setError(e instanceof Error ? e.message : "Request failed. Is the companion paired?"); }
    finally { setBusy(false); }
  };

  const run = () => {
    if (mode === "host") return call("/shodan/host", { ip: ip.trim() });
    if (mode === "search") return call("/shodan/search", { query: query.trim() });
    if (mode === "dns") return call("/shodan/dns", { hostnames: hostnames.trim() });
    return call("/shodan/info", {});
  };

  const host = (mode === "host" ? result : null) as HostResult | null;

  return <main className="min-h-screen bg-[#07100f] text-[#d7e7e1]">
    <div className="mx-auto max-w-5xl px-5 py-8">
      <a href="/" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> Dashboard</a>
      <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><Globe size={14}/> CYBERLAB · SHODAN OSINT</div>
      <h1 className="text-3xl font-semibold tracking-tight">Shodan Reconnaissance</h1>
      <p className="mt-2 max-w-2xl text-sm text-slate-400">Read-only internet-exposure intelligence via the official Shodan API, executed by the paired companion. Look up a host, search the index, or resolve hostnames.</p>

      <section className="mt-6 grid gap-3 sm:grid-cols-2">
        <div><label className="mb-1 block text-xs text-slate-400">Companion bridge token</label>
          <input value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off" className="w-full rounded border border-slate-700 bg-[#0b1715] px-3 py-2 text-sm outline-none focus:border-emerald-600"/></div>
        <div><label className="mb-1 block text-xs text-slate-400">Shodan API key</label>
          <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} type="password" autoComplete="off" className="w-full rounded border border-slate-700 bg-[#0b1715] px-3 py-2 text-sm outline-none focus:border-emerald-600"/></div>
      </section>

      <div className="mt-5 flex flex-wrap gap-1.5">
        {([["host", "Host lookup"], ["search", "Search"], ["dns", "DNS resolve"], ["info", "Account"]] as const).map(([m, label]) =>
          <button key={m} onClick={() => { setMode(m); setResult(null); }} className={"rounded px-3 py-1.5 text-xs " + (mode === m ? "bg-amber-700 text-white" : "border border-slate-700 text-slate-300")}>{label}</button>)}
      </div>

      <section className="mt-4 flex flex-wrap items-end gap-2">
        {mode === "host" && <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="8.8.8.8" className="flex-1 rounded border border-slate-700 bg-[#0b1715] px-3 py-2 text-sm outline-none focus:border-emerald-600"/>}
        {mode === "search" && <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder='apache country:"US" port:443' className="flex-1 rounded border border-slate-700 bg-[#0b1715] px-3 py-2 text-sm outline-none focus:border-emerald-600"/>}
        {mode === "dns" && <input value={hostnames} onChange={(e) => setHostnames(e.target.value)} placeholder="google.com,example.com" className="flex-1 rounded border border-slate-700 bg-[#0b1715] px-3 py-2 text-sm outline-none focus:border-emerald-600"/>}
        <button onClick={run} disabled={busy} className="inline-flex items-center gap-2 rounded bg-emerald-700 px-4 py-2 text-xs font-semibold text-white disabled:opacity-40">{busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>} Run</button>
      </section>
      {error && <p className="mt-3 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}

      {host && <section className="mt-6 rounded-xl border border-slate-800 bg-[#0b1715] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold"><Server size={15}/> {host.ip}</div>
        <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
          <span>Org: {host.org || "—"}</span><span>OS: {host.os || "—"}</span><span>Country: {host.country || "—"}</span>
          <span>Ports: {(host.ports || []).join(", ") || "—"}</span>
        </div>
        {(host.vulns || []).length > 0 && <div className="mt-2 text-xs text-rose-300">Vulns: {(host.vulns || []).join(", ")}</div>}
        <div className="mt-3 space-y-2">{(host.services || []).map((s, i) => <div key={i} className="rounded border border-slate-800/70 p-2 text-xs"><b className="text-emerald-300">{s.port}/{s.transport}</b> {s.product} {s.version}<pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-slate-500">{s.banner}</pre></div>)}</div>
      </section>}
      {result && mode !== "host" && <pre className="mt-6 overflow-x-auto rounded-xl border border-slate-800 bg-[#0b1715] p-4 text-[11px] text-slate-300">{JSON.stringify(result, null, 2)}</pre>}
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · SHODAN OSINT · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
