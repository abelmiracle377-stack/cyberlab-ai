"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { Award, Printer, ShieldX, Loader2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type Cert = { code: string; track_id: string; percent: number; issued_at: string; serial: string };
const TRACK_NAMES: Record<string, string> = {
  "web-appsec": "Web Application Security",
  "soc-analyst": "SOC Analyst Fundamentals",
  "ctf-lab": "Capture The Flag: Vulnerable Shop",
};
const CRED_NAMES: Record<string, string> = {
  CCWT: "CyberLab Certified Web Tester",
  CCSA: "CyberLab Certified SOC Analyst",
  CCCP: "CyberLab Certified CTF Player",
};

export default function CertificatePage() {
  const params = useParams();
  const serial = String(params.serial || "").toUpperCase();
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [cert, setCert] = useState<Cert | null>(null);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const { data, error } = await getSupabase().rpc("verify_certificate", { p_serial: serial });
        if (error) throw new Error(error.message);
        setCert((Array.isArray(data) ? data[0] : data) ?? null);
      } catch (e) { setError(e instanceof Error ? e.message : "Lookup failed."); }
      finally { setDone(true); }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serial]);

  if (!done) return <main className="flex min-h-screen items-center justify-center bg-[#07100f] text-[#d7e7e1]"><Loader2 className="animate-spin"/></main>;

  if (!cert) return <main className="flex min-h-screen items-center justify-center bg-[#07100f] text-[#d7e7e1]"><div className="text-center"><ShieldX className="mx-auto mb-2"/><p className="text-sm text-rose-300">{error || "No certificate matches that serial."}</p><a href="/verify" className="mt-3 inline-block text-xs text-emerald-300">Verify another →</a></div></main>;

  const cred = CRED_NAMES[cert.code] || cert.code;
  const track = TRACK_NAMES[cert.track_id] || cert.track_id;
  const issued = new Date(cert.issued_at).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });

  return <main className="min-h-screen bg-[#0a1412] px-4 py-8 text-[#d7e7e1] print:bg-white print:py-0">
    <div className="mx-auto max-w-3xl">
      <div className="mb-4 flex justify-end gap-2 print:hidden">
        <button onClick={() => window.print()} className="inline-flex items-center gap-2 rounded bg-emerald-700 px-4 py-2 text-xs font-semibold text-white"><Printer size={14}/> Print / Save as PDF</button>
        <a href="/academy" className="rounded border border-slate-700 px-4 py-2 text-xs text-slate-300">Academy</a>
      </div>
      <div id="cert" className="relative overflow-hidden rounded-2xl border-[6px] border-double border-emerald-800 bg-[#0b1715] p-10 text-center print:border-emerald-700 print:bg-white print:text-black">
        <div className="pointer-events-none absolute inset-0 opacity-[0.04] [background:repeating-linear-gradient(45deg,#10b981_0,#10b981_1px,transparent_1px,transparent_12px)]"/>
        <div className="relative">
          <div className="flex items-center justify-center gap-2 text-emerald-400 print:text-emerald-700"><Award size={22}/><span className="text-[11px] font-semibold tracking-[.3em]">CYBERLAB ACADEMY</span></div>
          <p className="mt-8 text-xs uppercase tracking-[.25em] text-slate-500">Certificate of Achievement</p>
          <h1 className="mt-4 text-3xl font-bold text-slate-100 print:text-black">{cred}</h1>
          <p className="mt-1 text-sm text-slate-400 print:text-slate-700">{cert.code}</p>
          <p className="mx-auto mt-6 max-w-lg text-sm text-slate-400 print:text-slate-700">has been awarded upon completion of the <b className="text-slate-200 print:text-black">{track}</b> track and passing the certification exam.</p>
          <div className="mt-8 flex items-center justify-center gap-10 text-sm">
            <div><div className="text-2xl font-semibold text-emerald-400 print:text-emerald-700">{cert.percent}%</div><div className="text-[10px] uppercase tracking-wider text-slate-500">Exam score</div></div>
            <div><div className="text-lg font-medium text-slate-200 print:text-black">{issued}</div><div className="text-[10px] uppercase tracking-wider text-slate-500">Date issued</div></div>
          </div>
          <div className="mt-10 border-t border-slate-800 pt-4 print:border-slate-300">
            <p className="font-mono text-sm text-emerald-300 print:text-emerald-700">{cert.serial}</p>
            <p className="mt-1 text-[10px] text-slate-500">Verify at cyberlab.ai/verify?serial={cert.serial}</p>
          </div>
        </div>
      </div>
    </div>
    <style>{`@media print{@page{margin:1cm}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}`}</style>
  </main>;
}
