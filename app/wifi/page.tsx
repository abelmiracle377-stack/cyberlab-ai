"use client";

import { useEffect, useState } from "react";
import { ArrowLeft, Wifi, CircleAlert, ShieldCheck, RefreshCw } from "lucide-react";

const BRIDGE = "/api/kali";
const SEV: Record<string, string> = {
  critical: "text-rose-300", high: "text-orange-300", low: "text-sky-300", info: "text-slate-400",
};

// Module-level (stable identity) so text inputs keep focus across re-renders.
function Field({ value, onChange, label, ph, w }: { value: string; onChange: (v: string) => void; label: string; ph?: string; w?: string }) {
  return <div className={w || "flex-1"}>
    <label className="mb-1 block text-[11px] text-slate-500">{label}</label>
    <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} className="w-full rounded border border-slate-700 bg-[#0D1117] px-2.5 py-1.5 text-sm outline-none focus:border-emerald-600"/>
  </div>;
}
function Btn({ label, running, disabled, onClick }: { label: string; running: boolean; disabled: boolean; onClick: () => void }) {
  return <button onClick={onClick} disabled={disabled} className="rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">{running ? "…" : label}</button>;
}

export default function WifiPage() {
  const [token, setToken] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [reference, setReference] = useState("");
  const [f, setF] = useState<Record<string, string>>({
    iface: "wlan0mon", bssid: "", client: "", channel: "6", seconds: "30",
    count: "5", capturePath: "", wordlistPath: "/usr/share/wordlists/rockyou.txt", tool: "aircrack", wpsTool: "reaver",
  });
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));
  const [interfaces, setInterfaces] = useState<{ interface: string; type: string | null }[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<{ title: string; data: unknown } | null>(null);

  useEffect(() => { if (typeof window !== "undefined") setToken(window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || ""); }, []);

  const auth = () => ({ authorizationConfirmed: authorized, confirmRun: true, authorizationReference: reference.trim() });
  const gated = authorized && reference.trim().length > 0;

  async function post(path: string, body: Record<string, unknown>, label: string, title: string) {
    setBusy(label); setError("");
    try {
      if (!token.trim()) throw new Error("Enter the companion bridge token.");
      window.sessionStorage.setItem("cyberlab.kaliBridgeToken", token.trim());
      const res = await fetch(BRIDGE + path, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() }, body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed.");
      setResult({ title, data });
    } catch (e) { setError(e instanceof Error ? e.message : "Request failed. Is the companion paired?"); }
    finally { setBusy(""); }
  }

  async function loadInterfaces() {
    setBusy("iface"); setError("");
    try {
      if (!token.trim()) throw new Error("Enter the companion bridge token.");
      const res = await fetch(BRIDGE + "/wifi/interfaces", { headers: { Authorization: "Bearer " + token.trim() } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed.");
      setInterfaces(data.interfaces || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Failed to list interfaces."); }
    finally { setBusy(""); }
  }

  const card = "rounded-xl border border-slate-800 bg-[#161B22] p-4";
  const audit = (result?.data as { audit?: { findings?: { essid: string; bssid: string; severity: string; posture: string; recommendation: string }[] } })?.audit?.findings;

  return <main className="min-h-screen bg-transparent text-[#d7e7e1]">
    <div className="mx-auto max-w-5xl px-5 py-8">
      <a href="/" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> Dashboard</a>
      <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><Wifi size={14}/> CYBERLAB · AUTHORIZED WI-FI TESTING</div>
      <h1 className="text-3xl font-semibold tracking-tight">Wi-Fi Engagement Toolkit</h1>
      <p className="mt-2 max-w-2xl text-sm text-slate-400">Runs the standard Kali tools on your own adapter through the paired companion. For networks you own or are explicitly authorized to test.</p>

      <div className="mt-5"><label className="mb-1 block text-xs text-slate-400">Companion bridge token</label>
        <input value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off" className="w-full max-w-md rounded border border-slate-700 bg-[#161B22] px-3 py-2 text-sm outline-none focus:border-emerald-600"/></div>

      <section className="mt-5 rounded-xl border border-amber-900/50 bg-amber-950/10 p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-amber-200"><ShieldCheck size={15}/> Authorization (required for active operations)</div>
        <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5 accent-amber-500"/> I own, or have written authorization to test, the networks I target here.</label>
        <input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Engagement / authorization reference (e.g. LAB-2026-001)" className="mt-3 w-full max-w-md rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm outline-none focus:border-amber-600"/>
        {!gated && <p className="mt-2 text-[11px] text-slate-500">Active steps (deauth, capture, crack, WPS, auto) unlock once both are provided. Interface listing and scanning are always available.</p>}
      </section>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <div className={card}>
          <div className="flex items-center justify-between"><h2 className="text-sm font-semibold">Interfaces & monitor mode</h2>
            <button onClick={loadInterfaces} className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"><RefreshCw size={12}/> List</button></div>
          {interfaces && <div className="mt-2 space-y-1 text-xs">{interfaces.length === 0 ? <span className="text-slate-500">None found.</span> : interfaces.map((i) => <div key={i.interface} className="flex justify-between"><code className="text-emerald-300">{i.interface}</code><span className="text-slate-500">{i.type}</span></div>)}</div>}
          <div className="mt-3 flex items-end gap-2"><Field value={f.iface} onChange={(v) => set("iface", v)} label="Interface" ph="wlan0 / wlan0mon"/>
            <Btn label="Monitor on" running={busy === "mon-on"} disabled={busy !== ""} onClick={() => post("/wifi/monitor/start", { interface: f.iface }, "mon-on", "Monitor mode enabled")}/>
            <Btn label="Off" running={busy === "mon-off"} disabled={busy !== ""} onClick={() => post("/wifi/monitor/stop", { interface: f.iface }, "mon-off", "Monitor mode stopped")}/></div>
        </div>

        <div className={card}>
          <h2 className="text-sm font-semibold">Scan &amp; posture audit</h2>
          <div className="mt-3 flex items-end gap-2"><Field value={f.iface} onChange={(v) => set("iface", v)} label="Monitor interface"/><Field value={f.seconds} onChange={(v) => set("seconds", v)} label="Seconds" w="w-24"/>
            <Btn label="Scan" running={busy === "scan"} disabled={busy !== ""} onClick={() => post("/wifi/scan", { interface: f.iface, seconds: Number(f.seconds) }, "scan", "Scan & audit")}/></div>
          <p className="mt-2 text-[11px] text-slate-500">Passive — listens to beacons, sends nothing.</p>
        </div>

        <div className={card}>
          <h2 className="text-sm font-semibold">Capture handshake / PMKID</h2>
          <div className="mt-3 grid grid-cols-2 gap-2"><Field value={f.bssid} onChange={(v) => set("bssid", v)} label="Target BSSID" ph="AA:BB:CC:DD:EE:FF"/><Field value={f.channel} onChange={(v) => set("channel", v)} label="Channel"/></div>
          <div className="mt-2 flex items-end gap-2"><Field value={f.seconds} onChange={(v) => set("seconds", v)} label="Seconds" w="w-24"/>
            <Btn label="Handshake" running={busy === "hs"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/capture/handshake", { ...auth(), interface: f.iface, bssid: f.bssid, channel: f.channel, seconds: Number(f.seconds), deauth: true }, "hs", "Handshake capture")}/>
            <Btn label="PMKID" running={busy === "pmkid"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/capture/pmkid", { ...auth(), interface: f.iface, seconds: Number(f.seconds) }, "pmkid", "PMKID capture")}/></div>
          <p className="mt-2 text-[11px] text-slate-500">Handshake uses a bounded, targeted deauth to prompt reassociation.</p>
        </div>

        <div className={card}>
          <h2 className="text-sm font-semibold">Deauthentication (targeted)</h2>
          <div className="mt-3 grid grid-cols-2 gap-2"><Field value={f.bssid} onChange={(v) => set("bssid", v)} label="AP BSSID"/><Field value={f.client} onChange={(v) => set("client", v)} label="Client (optional)"/></div>
          <div className="mt-2 flex items-end gap-2"><Field value={f.count} onChange={(v) => set("count", v)} label="Packets (≤64)" w="w-28"/>
            <Btn label="Send deauth" running={busy === "deauth"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/deauth", { ...auth(), interface: f.iface, bssid: f.bssid, client: f.client || undefined, count: Number(f.count) }, "deauth", "Deauth")}/></div>
        </div>

        <div className={card}>
          <div className="flex items-center justify-between"><h2 className="text-sm font-semibold">WPA crack (dictionary)</h2>
            <a href="/wifi-crack" className="text-[11px] text-sky-300 hover:text-sky-200">Upload a capture instead →</a></div>
          <div className="mt-3 grid gap-2"><Field value={f.capturePath} onChange={(v) => set("capturePath", v)} label="Capture path on companion (.cap / .hc22000)"/><Field value={f.wordlistPath} onChange={(v) => set("wordlistPath", v)} label="Wordlist"/></div>
          <div className="mt-2 flex items-end gap-2">
            <div><label className="mb-1 block text-[11px] text-slate-500">Tool</label><select value={f.tool} onChange={(e) => set("tool", e.target.value)} className="rounded border border-slate-700 bg-[#0D1117] px-2 py-1.5 text-sm"><option value="aircrack">aircrack-ng</option><option value="hashcat">hashcat</option></select></div>
            <Btn label="Crack" running={busy === "crack"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/crack-wpa", { ...auth(), capturePath: f.capturePath, wordlistPath: f.wordlistPath, tool: f.tool }, "crack", "WPA crack")}/></div>
        </div>

        <div className={card}>
          <h2 className="text-sm font-semibold">WPS &amp; automated audit</h2>
          <div className="mt-3 flex items-end gap-2"><Field value={f.bssid} onChange={(v) => set("bssid", v)} label="BSSID"/>
            <div><label className="mb-1 block text-[11px] text-slate-500">WPS tool</label><select value={f.wpsTool} onChange={(e) => set("wpsTool", e.target.value)} className="rounded border border-slate-700 bg-[#0D1117] px-2 py-1.5 text-sm"><option value="reaver">reaver</option><option value="bully">bully</option></select></div>
            <Btn label="WPS" running={busy === "wps"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/wps", { ...auth(), interface: f.iface, bssid: f.bssid, tool: f.wpsTool }, "wps", "WPS attack")}/></div>
          <div className="mt-2"><Btn label="Auto audit (wifite)" running={busy === "auto"} disabled={busy !== "" || !gated} onClick={() => post("/wifi/auto", { ...auth(), interface: f.iface, bssid: f.bssid || undefined, wordlistPath: f.wordlistPath }, "auto", "Automated audit")}/></div>
        </div>
      </div>

      {error && <p className="mt-4 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      {result && <section className="mt-6 rounded-xl border border-slate-800 bg-[#161B22] p-4">
        <h2 className="mb-2 text-sm font-semibold">{result.title}</h2>
        {audit && <div className="space-y-1.5">{audit.map((x, i) => <div key={i} className="text-xs"><span className={"font-semibold " + (SEV[x.severity] || "text-slate-400")}>[{x.severity}]</span> <b>{x.essid}</b> <code className="text-slate-500">{x.bssid}</code> — {x.posture}. <span className="text-slate-400">{x.recommendation}</span></div>)}</div>}
        <pre className="mt-2 max-h-80 overflow-auto rounded border border-slate-800 bg-[#0D1117] p-3 text-[11px] text-slate-300">{JSON.stringify(result.data, null, 2)}</pre>
      </section>}
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · AUTHORIZED WI-FI TESTING · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
