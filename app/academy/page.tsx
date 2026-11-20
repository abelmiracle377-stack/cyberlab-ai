"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ArrowLeft, GraduationCap, PlayCircle, CheckCircle2, Circle, Award, ExternalLink, Loader2, Trophy, Terminal } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type Task = { id: string; title: string; instructions: string; hint?: string; videoUrl?: string; requiresAnswer: boolean };
type Room = { id: string; title: string; summary: string; difficulty: string; tool?: string; toolHref?: string; videoUrl?: string; lab?: boolean; resources?: { title: string; url: string }[]; tasks: Task[] };
type LabChallenge = { id: string; title: string; technique: string; pathHint: string };
type LabInfo = { status: string; baseUrl: string | null; challenges: LabChallenge[] };
type Cert = { code: string; title: string; passPercent: number; exam: { id: string; prompt: string; options: { id: string; text: string }[] }[] };
type Track = { id: string; title: string; summary: string; level: string; rooms: Room[]; certification: Cert | null };
type IssuedCert = { track_id: string; code: string; serial: string; percent: number; issued_at: string };

async function api(path: string, init?: RequestInit) {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}
function embed(url?: string): string | null {
  if (!url) return null;
  const m = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/shorts\/)([\w-]{11})/);
  return m ? "https://www.youtube.com/embed/" + m[1] : null;
}
const DIFF: Record<string, string> = {
  intro: "text-sky-300", easy: "text-emerald-300", medium: "text-amber-300", hard: "text-rose-300",
};
// Client-safe request presets for the in-browser Attack Console (no flags here).
const CTF_PRESETS: { id: string; title: string; path: string; query: string; cookie?: string; jwt?: boolean }[] = [
  { id: "recon", title: "robots.txt", path: "/robots.txt", query: "" },
  { id: "dotenv", title: ".env", path: "/.env", query: "" },
  { id: "git", title: ".git", path: "/.git/config", query: "" },
  { id: "header", title: "X-Flag header", path: "/api/status", query: "" },
  { id: "sqli", title: "SQLi", path: "/product", query: "id=1'" },
  { id: "idor", title: "IDOR", path: "/api/orders", query: "id=1000" },
  { id: "traversal", title: "Traversal", path: "/download", query: "file=../../secret/flag.txt" },
  { id: "authbypass", title: "Auth bypass", path: "/admin", query: "", cookie: "role=admin" },
  { id: "jwt", title: "JWT none", path: "/api/profile", query: "", jwt: true },
  { id: "ssrf", title: "SSRF", path: "/fetch", query: "url=http://169.254.169.254/latest/meta-data/" },
];

export default function AcademyPage() {
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [authChecked, setAuthChecked] = useState(false);
  const [me, setMe] = useState<string | null>(null);
  const [tracks, setTracks] = useState<Track[]>([]);
  const [completed, setCompleted] = useState<Set<string>>(new Set());
  const [certs, setCerts] = useState<IssuedCert[]>([]);
  const [trackId, setTrackId] = useState<string | null>(null);
  const [roomId, setRoomId] = useState<string | null>(null);
  const [exam, setExam] = useState(false);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [flag, setFlag] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [examResult, setExamResult] = useState<{ passed: boolean; percent: number } | null>(null);
  const [lab, setLab] = useState<LabInfo | null>(null);
  const [labBusy, setLabBusy] = useState(false);
  const [scoreboard, setScoreboard] = useState<{ display_name: string; flags: number; last_capture: string }[] | null>(null);
  const [conPath, setConPath] = useState("/");
  const [conQuery, setConQuery] = useState("");
  const [conCookie, setConCookie] = useState("");
  const [conAuth, setConAuth] = useState("");
  const [conResp, setConResp] = useState<{ status: number; headers: Record<string, string>; body: string } | null>(null);
  const [conBusy, setConBusy] = useState(false);

  async function sendConsole() {
    setConBusy(true); setError("");
    try {
      const headers: Record<string, string> = {};
      if (conCookie.trim()) headers["Cookie"] = conCookie.trim();
      if (conAuth.trim()) headers["Authorization"] = conAuth.trim();
      const data = await api("/api/academy/lab/target", {
        method: "POST",
        body: JSON.stringify({ method: "GET", path: conPath, query: conQuery, headers }),
      });
      setConResp(data);
    } catch (e) { setError(e instanceof Error ? e.message : "Target request failed."); }
    finally { setConBusy(false); }
  }
  function buildAdminJwt() {
    const b64url = (o: object) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    setConAuth("Bearer " + b64url({ alg: "none", typ: "JWT" }) + "." + b64url({ role: "admin" }) + ".");
  }

  const loadScoreboard = useCallback(async () => {
    try {
      const { data, error } = await getSupabase().rpc("ctf_scoreboard", { p_limit: 50 });
      if (error) throw new Error(error.message);
      setScoreboard(data ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load scoreboard."); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const BRIDGE = "http://127.0.0.1:8765";
  async function labAction(action: "start" | "stop") {
    setError(""); setLabBusy(true);
    try {
      const token = typeof window !== "undefined" ? window.sessionStorage.getItem("cyberlab.kaliBridgeToken") || "" : "";
      if (!token) throw new Error("Pair the local Kali companion first (the lab runs on your machine).");
      const res = await fetch(`${BRIDGE}/academy/lab/${action}`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token }, body: "{}",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "The companion rejected the lab request.");
      setLab(action === "stop" ? null : data);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not reach the companion."); }
    finally { setLabBusy(false); }
  }

  const load = useCallback(async () => {
    const [c, p, cert] = await Promise.all([
      api("/api/academy/content"),
      api("/api/academy/progress").catch(() => ({ completed: [] })),
      api("/api/academy/certificate").catch(() => ({ certificates: [] })),
    ]);
    setTracks(c.tracks || []);
    setCompleted(new Set(p.completed || []));
    setCerts(cert.certificates || []);
  }, []);

  useEffect(() => {
    (async () => {
      const { data: { user } } = await getSupabase().auth.getUser();
      setMe(user?.id ?? null); setAuthChecked(true);
      if (user) await load().catch((e) => setError(e instanceof Error ? e.message : "Load failed."));
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const track = useMemo(() => tracks.find((t) => t.id === trackId) || null, [tracks, trackId]);
  const room = useMemo(() => track?.rooms.find((r) => r.id === roomId) || null, [track, roomId]);
  const progressOf = useCallback((t: Track) => {
    const all = t.rooms.flatMap((r) => r.tasks);
    const done = all.filter((x) => completed.has(x.id)).length;
    return { done, total: all.length, percent: all.length ? Math.round((done / all.length) * 100) : 0, complete: all.length > 0 && done === all.length };
  }, [completed]);

  async function complete(task: Task) {
    setError("");
    try {
      const data = await api("/api/academy/progress", { method: "POST", body: JSON.stringify({ taskId: task.id, answer: flag[task.id] || "" }) });
      if (data.completed) { setCompleted((prev) => new Set(prev).add(task.id)); setFlag((f) => ({ ...f, [task.id]: "" })); }
      else setError(data.error || "Incorrect — try again.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save progress."); }
  }

  async function submitExam() {
    if (!track?.certification) return;
    setError(""); setExamResult(null);
    try {
      const data = await api("/api/academy/certificate", { method: "POST", body: JSON.stringify({ trackId: track.id, answers }) });
      setExamResult({ passed: !!data.passed, percent: data.result?.percent ?? 0 });
      if (data.passed) { await load(); }
    } catch (e) { setError(e instanceof Error ? e.message : "Could not submit exam."); }
  }

  if (!authChecked) return <main className="flex min-h-screen items-center justify-center bg-[#07100f] text-[#d7e7e1]"><Loader2 className="animate-spin" /></main>;
  if (!me) return <main className="flex min-h-screen items-center justify-center bg-[#07100f] text-[#d7e7e1]"><div className="text-center"><GraduationCap className="mx-auto mb-3" /><h1 className="text-xl font-semibold">CyberLab Academy</h1><p className="mt-2 text-sm text-slate-400">Sign in to track progress and earn certifications.</p><a href="/login" className="mt-4 inline-block rounded bg-emerald-700 px-4 py-2 text-xs font-semibold text-white">Sign in</a></div></main>;

  const wrap = (inner: ReactNode) => <main className="min-h-screen bg-[#07100f] text-[#d7e7e1]"><div className="mx-auto max-w-5xl px-5 py-8">{inner}</div></main>;

  // Exam view
  if (exam && track?.certification) {
    const cert = track.certification;
    return wrap(<>
      <button onClick={() => { setExam(false); setExamResult(null); }} className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> {track.title}</button>
      <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><Award size={14}/> CERTIFICATION EXAM</div>
      <h1 className="text-2xl font-semibold">{cert.title} <span className="text-slate-500">({cert.code})</span></h1>
      <p className="mt-1 text-sm text-slate-400">Pass mark {cert.passPercent}%. Grading is server-side.</p>
      <div className="mt-6 space-y-5">
        {cert.exam.map((q, i) => <div key={q.id} className="rounded-xl border border-slate-800 bg-[#0b1715] p-4">
          <p className="mb-3 text-sm font-medium">{i + 1}. {q.prompt}</p>
          <div className="space-y-2">{q.options.map((o) => <label key={o.id} className="flex items-center gap-2 text-sm text-slate-300"><input type="radio" name={q.id} checked={answers[q.id] === o.id} onChange={() => setAnswers((a) => ({ ...a, [q.id]: o.id }))} className="accent-emerald-500"/> {o.text}</label>)}</div>
        </div>)}
      </div>
      {examResult && <div className={"mt-5 rounded-lg border p-4 text-sm " + (examResult.passed ? "border-emerald-800 bg-emerald-950/30 text-emerald-200" : "border-rose-900 bg-rose-950/20 text-rose-200")}>{examResult.passed ? `Passed with ${examResult.percent}% — certificate issued.` : `Scored ${examResult.percent}%. ${cert.passPercent}% needed — review the rooms and retry.`}</div>}
      {error && <p className="mt-3 text-xs text-rose-300">{error}</p>}
      <button onClick={submitExam} disabled={Object.keys(answers).length < cert.exam.length} className="mt-5 inline-flex items-center gap-2 rounded bg-amber-700 px-4 py-2.5 text-xs font-semibold text-white disabled:opacity-40">Submit exam</button>
    </>);
  }

  // Room view
  if (room && track) {
    return wrap(<>
      <button onClick={() => setRoomId(null)} className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> {track.title}</button>
      <div className={"mb-2 text-[10px] uppercase tracking-[.2em] " + (DIFF[room.difficulty] || "text-slate-400")}>{room.difficulty} room</div>
      <h1 className="text-2xl font-semibold">{room.title}</h1>
      <p className="mt-1 max-w-2xl text-sm text-slate-400">{room.summary}</p>
      {room.tool && room.toolHref && <a href={room.toolHref} className="mt-3 inline-flex items-center gap-2 rounded border border-emerald-800 bg-emerald-950/30 px-3 py-1.5 text-xs text-emerald-200">Open tool: {room.tool} <ExternalLink size={12}/></a>}
      {room.lab && <div className="mt-4 rounded-xl border border-amber-900/50 bg-amber-950/10 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm font-semibold text-amber-200">Hands-on lab target</div>
          <div className="flex gap-2">
            <button onClick={() => labAction("start")} disabled={labBusy} className="rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">{labBusy ? "…" : lab ? "Restart lab" : "Start lab"}</button>
            {lab && <button onClick={() => labAction("stop")} disabled={labBusy} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300">Stop</button>}
          </div>
        </div>
        <p className="mt-2 text-xs text-slate-400">Runs a deliberately vulnerable target on your own machine (loopback only) via the paired companion. Attack it to capture each flag, then submit the flags below.</p>
        {lab?.baseUrl && <>
          <p className="mt-2 text-xs text-emerald-200">Target: <code className="rounded bg-black/30 px-1.5 py-0.5">{lab.baseUrl}</code> — point the assessment tool or your browser/repeater here.</p>
          <div className="mt-3 space-y-1.5">{lab.challenges.map((c) => <div key={c.id} className="text-[11px] text-slate-400"><b className="text-slate-300">{c.title}</b> — {c.technique} <code className="text-slate-500">{c.pathHint}</code></div>)}</div>
        </>}
      </div>}
      {room.lab && <div className="mt-4 rounded-xl border border-sky-900/50 bg-sky-950/10 p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-sky-200"><Terminal size={15}/> Attack Console — practice in-browser (no setup)</div>
        <p className="mt-1 text-xs text-slate-400">The vulnerable target is hosted in the app. Craft a request below, send it, and read the flag from the response — then submit it in the task. No companion needed.</p>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {CTF_PRESETS.map((p) => <button key={p.id} onClick={() => { setConPath(p.path); setConQuery(p.query); if (p.cookie) setConCookie(p.cookie); if (p.jwt) buildAdminJwt(); }} className="rounded border border-slate-700 px-2 py-1 text-[10px] text-slate-300 hover:border-sky-600">{p.title}</button>)}
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-[auto_1fr]">
          <div className="flex items-center rounded border border-slate-700 bg-[#06100e] px-2 text-xs text-slate-500">GET</div>
          <input value={conPath} onChange={(e) => setConPath(e.target.value)} placeholder="/path" className="rounded border border-slate-700 bg-[#06100e] px-3 py-2 text-sm outline-none focus:border-sky-600"/>
          <label className="self-center text-[11px] text-slate-500">query</label>
          <input value={conQuery} onChange={(e) => setConQuery(e.target.value)} placeholder="id=1'" className="rounded border border-slate-700 bg-[#06100e] px-3 py-2 text-sm outline-none focus:border-sky-600"/>
          <label className="self-center text-[11px] text-slate-500">Cookie</label>
          <input value={conCookie} onChange={(e) => setConCookie(e.target.value)} placeholder="role=admin" className="rounded border border-slate-700 bg-[#06100e] px-3 py-2 text-sm outline-none focus:border-sky-600"/>
          <label className="self-center text-[11px] text-slate-500">Authorization</label>
          <input value={conAuth} onChange={(e) => setConAuth(e.target.value)} placeholder="Bearer …" className="rounded border border-slate-700 bg-[#06100e] px-3 py-2 text-sm outline-none focus:border-sky-600"/>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          <button onClick={sendConsole} disabled={conBusy} className="rounded bg-sky-700 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">{conBusy ? "Sending…" : "Send request"}</button>
          <button onClick={() => setConCookie("role=admin")} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300">Forge admin cookie</button>
          <button onClick={buildAdminJwt} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300">Build alg:none JWT</button>
        </div>
        {conResp && <div className="mt-3 rounded-lg border border-slate-800 bg-[#06100e] p-3 font-mono text-[11px]">
          <div className={conResp.status < 400 ? "text-emerald-300" : "text-amber-300"}>HTTP {conResp.status}</div>
          {Object.entries(conResp.headers).map(([k, val]) => <div key={k} className="text-slate-500">{k}: {val}</div>)}
          <pre className="mt-2 whitespace-pre-wrap break-all text-slate-300">{conResp.body}</pre>
        </div>}
      </div>}
      {embed(room.videoUrl) && <div className="mt-5 aspect-video w-full overflow-hidden rounded-xl border border-slate-800"><iframe className="h-full w-full" src={embed(room.videoUrl)!} title="Lesson video" allowFullScreen/></div>}
      {room.resources && room.resources.length > 0 && <div className="mt-4 flex flex-wrap gap-2">{room.resources.map((r) => <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded border border-slate-800 px-2.5 py-1 text-[11px] text-slate-300 hover:border-slate-600">{r.title} <ExternalLink size={11}/></a>)}</div>}
      <div className="mt-6 space-y-3">
        {room.tasks.map((task, i) => {
          const done = completed.has(task.id);
          return <div key={task.id} className="rounded-xl border border-slate-800 bg-[#0b1715] p-4">
            <div className="flex items-start gap-3">
              {done ? <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-400" size={18}/> : <Circle className="mt-0.5 shrink-0 text-slate-600" size={18}/>}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">Task {i + 1}: {task.title}</p>
                <p className="mt-1 text-sm text-slate-400">{task.instructions}</p>
                {!embed(room.videoUrl) && task.videoUrl && <a href={task.videoUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1 text-xs text-sky-300"><PlayCircle size={13}/> Open video</a>}
                {!done && <div className="mt-3">
                  {task.requiresAnswer ? <div className="flex flex-wrap gap-2">
                    <input value={flag[task.id] || ""} onChange={(e) => setFlag((f) => ({ ...f, [task.id]: e.target.value }))} placeholder="Your answer" className="rounded border border-slate-700 bg-[#06100e] px-3 py-1.5 text-sm outline-none focus:border-emerald-600"/>
                    <button onClick={() => complete(task)} className="rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white">Submit</button>
                    {task.hint && <span className="self-center text-[11px] text-slate-500">Hint: {task.hint}</span>}
                  </div> : <button onClick={() => complete(task)} className="rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white">Mark complete</button>}
                </div>}
              </div>
            </div>
          </div>;
        })}
      </div>
      {error && <p className="mt-3 text-xs text-rose-300">{error}</p>}
    </>);
  }

  // Track view (rooms list)
  if (track) {
    const prog = progressOf(track);
    const issued = certs.find((c) => c.track_id === track.id);
    return wrap(<>
      <button onClick={() => setTrackId(null)} className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> All tracks</button>
      <h1 className="text-2xl font-semibold">{track.title}</h1>
      <p className="mt-1 max-w-2xl text-sm text-slate-400">{track.summary}</p>
      <div className="mt-4 h-2 w-full max-w-md overflow-hidden rounded-full bg-slate-800"><div className="h-full bg-emerald-500" style={{ width: prog.percent + "%" }}/></div>
      <p className="mt-1 text-xs text-slate-500">{prog.done}/{prog.total} tasks · {prog.percent}%</p>
      {track.id === "ctf-lab" && <div className="mt-4">
        <button onClick={() => { if (scoreboard) setScoreboard(null); else loadScoreboard(); }} className="inline-flex items-center gap-2 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-500"><Trophy size={13}/> {scoreboard ? "Hide scoreboard" : "Scoreboard"}</button>
        {scoreboard && <div className="mt-3 overflow-hidden rounded-xl border border-slate-800 bg-[#0b1715]">
          {scoreboard.length === 0 ? <p className="p-4 text-xs text-slate-400">No flags captured yet. Be the first.</p>
            : <table className="w-full text-sm"><thead><tr className="border-b border-slate-800 text-left text-[10px] uppercase tracking-wider text-slate-500"><th className="px-4 py-2">#</th><th className="px-4 py-2">Player</th><th className="px-4 py-2 text-right">Flags</th></tr></thead>
              <tbody>{scoreboard.map((row, i) => <tr key={i} className="border-b border-slate-800/60"><td className="px-4 py-2 text-slate-500">{i + 1}</td><td className="px-4 py-2">{row.display_name}</td><td className="px-4 py-2 text-right font-semibold text-amber-200">{row.flags}/10</td></tr>)}</tbody></table>}
        </div>}
      </div>}
      <div className="mt-6 space-y-3">
        {track.rooms.map((r) => {
          const rp = r.tasks.filter((t) => completed.has(t.id)).length;
          return <button key={r.id} onClick={() => setRoomId(r.id)} className="flex w-full items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0b1715] p-4 text-left hover:border-slate-600">
            <div><div className={"text-[10px] uppercase tracking-wider " + (DIFF[r.difficulty] || "text-slate-400")}>{r.difficulty}</div><p className="mt-0.5 text-sm font-medium">{r.title}</p><p className="text-xs text-slate-500">{r.summary}</p></div>
            <div className="shrink-0 text-right text-xs text-slate-400">{rp}/{r.tasks.length}{rp === r.tasks.length && <CheckCircle2 className="ml-auto mt-1 text-emerald-400" size={16}/>}</div>
          </button>;
        })}
      </div>
      {track.certification && <div className="mt-6 rounded-xl border border-amber-900/50 bg-amber-950/10 p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-amber-200"><Award size={16}/> {track.certification.title} ({track.certification.code})</div>
        {issued ? <p className="mt-2 text-sm text-emerald-200">Certified · serial <code className="text-emerald-300">{issued.serial}</code> · {issued.percent}%</p>
          : prog.complete ? <button onClick={() => { setExam(true); setAnswers({}); }} className="mt-3 rounded bg-amber-700 px-4 py-2 text-xs font-semibold text-white">Take certification exam</button>
          : <p className="mt-2 text-xs text-slate-400">Finish every room to unlock the exam ({prog.percent}% done).</p>}
      </div>}
    </>);
  }

  // Tracks home
  return wrap(<>
    <a href="/" className="mb-6 inline-flex items-center gap-2 text-xs text-emerald-300/70 hover:text-emerald-200"><ArrowLeft size={14}/> Dashboard</a>
    <div className="mb-2 flex items-center gap-2 text-[10px] tracking-[.24em] text-amber-300"><GraduationCap size={14}/> CYBERLAB ACADEMY</div>
    <h1 className="text-3xl font-semibold tracking-tight">Learn by doing</h1>
    <p className="mt-2 max-w-2xl text-sm text-slate-400">Hack The Box / TryHackMe-style tracks that teach real skills on CyberLab's own tools — with videos, hands-on rooms, flag answers, and certifications you can earn.</p>
    {certs.length > 0 && <div className="mt-5 flex flex-wrap items-center gap-2">{certs.map((c) => <a key={c.serial} href={"/verify?serial=" + encodeURIComponent(c.serial)} className="inline-flex items-center gap-1 rounded border border-emerald-800 bg-emerald-950/30 px-2.5 py-1 text-xs text-emerald-200 hover:border-emerald-600"><Award size={12}/> {c.code} · {c.serial}</a>)}<a href="/verify" className="text-xs text-emerald-300/70 hover:text-emerald-200">Verify a certificate →</a></div>}
    <div className="mt-6 grid gap-4 md:grid-cols-2">
      {tracks.map((t) => {
        const p = progressOf(t);
        return <button key={t.id} onClick={() => { setTrackId(t.id); setRoomId(null); }} className="rounded-xl border border-slate-800 bg-[#0b1715] p-5 text-left hover:border-slate-600">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">{t.level} · {t.rooms.length} rooms</div>
          <h2 className="mt-1 text-lg font-semibold">{t.title}</h2>
          <p className="mt-1 text-sm text-slate-400">{t.summary}</p>
          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-800"><div className="h-full bg-emerald-500" style={{ width: p.percent + "%" }}/></div>
          <p className="mt-1 text-[11px] text-slate-500">{p.percent}% complete{t.certification ? ` · ${t.certification.code}` : ""}</p>
        </button>;
      })}
    </div>
    {error && <p className="mt-4 text-xs text-rose-300">{error}</p>}
  </>);
}
