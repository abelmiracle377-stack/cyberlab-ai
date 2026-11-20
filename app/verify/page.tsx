"use client";

import { useEffect, useRef, useState } from "react";
import { BadgeCheck, ShieldX, Search, Loader2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type VerifiedCert = { code: string; track_id: string; percent: number; issued_at: string; serial: string };
const TRACK_NAMES: Record<string, string> = {
  "web-appsec": "Web Application Security",
  "soc-analyst": "SOC Analyst Fundamentals",
  "ctf-lab": "Capture The Flag: Vulnerable Shop",
  "attack-defense": "Attack Techniques & Defense",
};

export default function VerifyPage() {
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [serial, setSerial] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [cert, setCert] = useState<VerifiedCert | null>(null);
  const [error, setError] = useState("");

  const verify = async (value: string) => {
    const s = value.trim().toUpperCase();
    if (!s) return;
    setBusy(true); setError(""); setDone(false); setCert(null);
    try {
      const { data, error } = await getSupabase().rpc("verify_certificate", { p_serial: s });
      if (error) throw new Error(error.message);
      const row = Array.isArray(data) ? data[0] : data;
      setCert(row ?? null);
    } catch (e) { setError(e instanceof Error ? e.message : "Verification failed."); }
    finally { setBusy(false); setDone(true); }
  };

  useEffect(() => {
    if (typeof window === "undefined") return;
    const q = new URLSearchParams(window.location.search).get("serial");
    if (q) { setSerial(q); void verify(q); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <main className="min-h-screen bg-[#07100f] text-[#d7e7e1]">
    <div className="mx-auto max-w-xl px-5 py-12">
      <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><BadgeCheck size={14}/> CYBERLAB ACADEMY</div>
      <h1 className="text-2xl font-semibold tracking-tight">Verify a certificate</h1>
      <p className="mt-2 text-sm text-slate-400">Enter a certificate serial (e.g. CCWT-7F3A9C2D) to confirm it was issued by CyberLab Academy.</p>
      <form onSubmit={(e) => { e.preventDefault(); void verify(serial); }} className="mt-5 flex gap-2">
        <input value={serial} onChange={(e) => setSerial(e.target.value)} placeholder="CODE-XXXXXXXX" className="flex-1 rounded border border-slate-700 bg-[#06100e] px-3 py-2.5 text-sm outline-none focus:border-emerald-600"/>
        <button type="submit" disabled={busy || !serial.trim()} className="inline-flex items-center gap-2 rounded bg-emerald-700 px-4 py-2.5 text-xs font-semibold text-white disabled:opacity-40">{busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>} Verify</button>
      </form>
      {error && <p className="mt-4 text-xs text-rose-300">{error}</p>}
      {done && !error && (cert
        ? <div className="mt-6 rounded-xl border border-emerald-800 bg-emerald-950/30 p-5">
            <div className="flex items-center gap-2 text-emerald-200"><BadgeCheck size={18}/> <span className="font-semibold">Valid certificate</span></div>
            <dl className="mt-3 space-y-1 text-sm">
              <div className="flex gap-2"><dt className="w-24 text-slate-500">Credential</dt><dd>{cert.code}</dd></div>
              <div className="flex gap-2"><dt className="w-24 text-slate-500">Track</dt><dd>{TRACK_NAMES[cert.track_id] || cert.track_id}</dd></div>
              <div className="flex gap-2"><dt className="w-24 text-slate-500">Score</dt><dd>{cert.percent}%</dd></div>
              <div className="flex gap-2"><dt className="w-24 text-slate-500">Issued</dt><dd>{new Date(cert.issued_at).toLocaleDateString()}</dd></div>
              <div className="flex gap-2"><dt className="w-24 text-slate-500">Serial</dt><dd><code className="text-emerald-300">{cert.serial}</code></dd></div>
            </dl>
            <a href={"/certificate/" + encodeURIComponent(cert.serial)} className="mt-4 inline-block text-xs text-emerald-300 hover:text-emerald-200">View printable certificate →</a>
          </div>
        : <div className="mt-6 rounded-xl border border-rose-900 bg-rose-950/20 p-5 text-rose-200"><div className="flex items-center gap-2"><ShieldX size={18}/> <span className="font-semibold">No certificate found</span></div><p className="mt-1 text-sm text-rose-300/80">No certificate matches that serial.</p></div>)}
      <a href="/academy" className="mt-8 inline-block text-xs text-emerald-300/70 hover:text-emerald-200">← CyberLab Academy</a>
    </div>
  </main>;
}
