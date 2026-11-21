"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowLeft, KeyRound, Upload, ShieldCheck, CircleAlert, Loader2, CheckCircle2, XCircle } from "lucide-react";

const BRIDGE = "/api/kali";

type CrackResult = { status: string; keyFound?: boolean; key?: string | null; tool?: string; captureName?: string; uploadedBytes?: number; note?: string; error?: string };

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] || "");
    r.onerror = () => reject(new Error("Could not read the file."));
    r.readAsDataURL(file);
  });
}

export default function WifiCrackPage() {
  const [token, setToken] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [reference, setReference] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [tool, setTool] = useState("aircrack");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<CrackResult | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (typeof window !== "undefined") setToken(window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || ""); }, []);

  const gated = authorized && reference.trim().length > 0;

  const run = async () => {
    setError(""); setResult(null);
    if (!token.trim()) { setError("Enter the companion bridge token."); return; }
    if (!file) { setError("Choose a capture file (.cap / .pcapng / .hc22000)."); return; }
    if (file.size > 10 * 1024 * 1024) { setError("Capture is too large (max 10 MB)."); return; }
    setBusy(true);
    try {
      window.sessionStorage.setItem("cyberlab.kaliBridgeToken", token.trim());
      const captureBase64 = await toBase64(file);
      const res = await fetch(BRIDGE + "/wifi/crack-upload", {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({
          authorizationConfirmed: authorized, confirmRun: true, authorizationReference: reference.trim(),
          captureBase64, captureName: file.name, wordlistPath: wordlist.trim(), tool,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Crack request failed.");
      setResult(data);
    } catch (e) { setError(e instanceof Error ? e.message : "Crack failed. Is the companion paired?"); }
    finally { setBusy(false); }
  };

  return <main className="min-h-screen bg-transparent text-[#d7e7e1]">
    <div className="mx-auto max-w-3xl px-5 py-8">
      <a href="/wifi" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> Wi-Fi Toolkit</a>
      <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><KeyRound size={14}/> CYBERLAB · OFFLINE WPA CRACK</div>
      <h1 className="text-3xl font-semibold tracking-tight">Offline WPA Capture Crack</h1>
      <p className="mt-2 max-w-2xl text-sm text-slate-400">Upload a handshake or PMKID capture and audit its passphrase strength against a wordlist, offline. The file is processed by the paired companion (aircrack-ng / hashcat) and deleted afterward — nothing is transmitted to any network.</p>

      <div className="mt-5"><label className="mb-1 block text-xs text-slate-400">Companion bridge token</label>
        <input value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off" className="w-full max-w-md rounded border border-slate-700 bg-[#161B22] px-3 py-2 text-sm outline-none focus:border-emerald-600"/></div>

      <section className="mt-5 rounded-xl border border-amber-900/50 bg-amber-950/10 p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-amber-200"><ShieldCheck size={15}/> Authorization</div>
        <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-slate-300"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5 accent-amber-500"/> This capture is from a network I own or am authorized (in writing) to test.</label>
        <input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Engagement / authorization reference" className="mt-3 w-full max-w-md rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm outline-none focus:border-amber-600"/>
      </section>

      <section className="mt-5 rounded-xl border border-slate-800 bg-[#161B22] p-5">
        <div onClick={() => fileRef.current?.click()} className="flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-slate-700 py-8 text-center hover:border-emerald-600">
          <Upload size={22} className="text-slate-500"/>
          <p className="mt-2 text-sm text-slate-300">{file ? file.name : "Click to choose a capture file"}</p>
          <p className="text-[11px] text-slate-500">{file ? `${(file.size / 1024).toFixed(0)} KB` : ".cap · .pcap · .pcapng · .hccapx · .hc22000 (max 10 MB)"}</p>
          <input ref={fileRef} type="file" accept=".cap,.pcap,.pcapng,.hccapx,.hc22000,.22000" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)}/>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
          <div><label className="mb-1 block text-xs text-slate-400">Wordlist path (on the companion)</label>
            <input value={wordlist} onChange={(e) => setWordlist(e.target.value)} className="w-full rounded border border-slate-700 bg-[#0D1117] px-3 py-2 text-sm outline-none focus:border-emerald-600"/></div>
          <div><label className="mb-1 block text-xs text-slate-400">Tool</label>
            <select value={tool} onChange={(e) => setTool(e.target.value)} className="rounded border border-slate-700 bg-[#0D1117] px-2 py-2 text-sm"><option value="aircrack">aircrack-ng</option><option value="hashcat">hashcat (.hc22000)</option></select></div>
        </div>
        <button onClick={run} disabled={busy || !gated || !file} className="mt-4 inline-flex items-center gap-2 rounded bg-amber-700 px-4 py-2.5 text-xs font-semibold text-white disabled:opacity-40">{busy ? <Loader2 size={14} className="animate-spin"/> : <KeyRound size={14}/>} {busy ? "Cracking…" : "Crack capture"}</button>
        {!gated && <p className="mt-2 text-[11px] text-slate-500">Confirm authorization above to enable cracking.</p>}
        {error && <p className="mt-3 flex items-center gap-2 text-xs text-rose-300"><CircleAlert size={14}/>{error}</p>}
      </section>

      {result && <section className={"mt-5 rounded-xl border p-5 " + (result.keyFound ? "border-rose-900 bg-rose-950/20" : "border-emerald-800 bg-emerald-950/20")}>
        <div className="flex items-center gap-2 text-sm font-semibold">{result.keyFound ? <><XCircle size={16} className="text-rose-300"/> Passphrase recovered — weak</> : <><CheckCircle2 size={16} className="text-emerald-300"/> Not in wordlist</>}</div>
        {result.keyFound && <p className="mt-2 text-sm">Key: <code className="rounded bg-black/40 px-2 py-0.5 text-rose-200">{result.key}</code></p>}
        <p className="mt-2 text-xs text-slate-400">{result.note}</p>
        <p className="mt-1 text-[11px] text-slate-500">{result.captureName} · {result.tool} · {result.uploadedBytes ? (result.uploadedBytes / 1024).toFixed(0) + " KB" : ""}</p>
      </section>}
      <p className="mt-8 text-[10px] tracking-wide text-slate-600">CYBERLAB AI · OFFLINE WPA AUDIT · LOCAL COMPANION EXECUTION</p>
    </div>
  </main>;
}
