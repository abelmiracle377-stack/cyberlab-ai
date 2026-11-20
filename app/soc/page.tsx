"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ShieldAlert, Activity, Play, RefreshCw, AlertTriangle, Loader2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import {
  ALERT_STATUSES, isDestructive, groupIncidents, computeMetrics,
  type Severity, type SocMetrics,
} from "@/lib/soc";

type Alert = {
  id: string; alert_key: string; rule: string; title: string; severity: Severity; score: number;
  mitre: { tactic?: string; technique_id?: string; technique?: string };
  description: string; entities: Record<string, unknown>; event_count: number;
  recommended_actions: { action: string; rationale?: string; params?: Record<string, unknown> }[];
  source: string; status: string; assignee: string | null; last_seen: string; created_at?: string; updated_at?: string;
};
type ActionRow = { id: string; action: string; status: string; created_at: string };
type NoteRow = { id: string; body: string; created_at: string };

const BRIDGE = "http://127.0.0.1:8765";
const TOKEN_KEY = "cyberlab.kaliBridgeToken";
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

async function api(path: string, init?: RequestInit) {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}
function fmtTime(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export default function SocPage() {
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [me, setMe] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<SocMetrics | null>(null);
  const [active, setActive] = useState<Alert | null>(null);
  const [actions, setActions] = useState<ActionRow[]>([]);
  const [notes, setNotes] = useState<NoteRow[]>([]);
  const [noteDraft, setNoteDraft] = useState("");
  const [view, setView] = useState<"alerts" | "incidents">("alerts");
  const [query, setQuery] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [cycleInfo, setCycleInfo] = useState("");

  const loadAlerts = useCallback(async () => {
    try {
      const [a, m] = await Promise.all([api("/api/soc/alerts"), api("/api/soc/metrics").catch(() => null)]);
      setAlerts(a.alerts || []);
      if (m?.metrics) setMetrics(m.metrics);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load alerts."); }
  }, []);

  useEffect(() => {
    (async () => {
      const { data: { user } } = await getSupabase().auth.getUser();
      setMe(user?.id ?? null);
      setAuthChecked(true);
      if (typeof window !== "undefined") setToken(sessionStorage.getItem(TOKEN_KEY) || "");
      if (user) await loadAlerts();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!me) return;
    const channel = getSupabase()
      .channel("soc-" + me)
      .on("postgres_changes", { event: "*", schema: "public", table: "soc_alerts", filter: `owner=eq.${me}` },
        () => { void loadAlerts(); })
      .subscribe();
    return () => { void getSupabase().removeChannel(channel); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me]);

  // Fall back to client-side metrics if the metrics endpoint is unavailable.
  const liveMetrics = useMemo(() => metrics ?? computeMetrics(alerts), [metrics, alerts]);
  const incidents = useMemo(() => groupIncidents(alerts), [alerts]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter((a) =>
      a.title.toLowerCase().includes(q) || a.rule.toLowerCase().includes(q) ||
      (a.mitre?.technique_id || "").toLowerCase().includes(q) ||
      JSON.stringify(a.entities).toLowerCase().includes(q));
  }, [alerts, query]);

  async function runCompanionCycle(dryRun: boolean) {
    setError(""); setCycleInfo("");
    if (!token.trim()) { setError("Enter the companion bridge token (from the Kali connection page)."); return; }
    setBusy(dryRun ? "cycle" : "cycle-live");
    try {
      sessionStorage.setItem(TOKEN_KEY, token.trim());
      const res = await fetch(BRIDGE + "/soc/run-cycle", {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.trim() },
        body: JSON.stringify({ fromTelemetry: true, dryRun }),
      });
      const report = await res.json();
      if (!res.ok) throw new Error(report.error || "Companion cycle failed.");
      if ((report.alerts || []).length) {
        await api("/api/soc/alerts", { method: "POST", body: JSON.stringify({ alerts: report.alerts, source: "companion" }) });
      }
      setCycleInfo(`${report.events_collected} events · ${report.alert_count} alerts · ${report.escalations?.length ?? 0} escalations` +
        (dryRun ? " (dry run)" : ` · ${report.actions_taken?.length ?? 0} actions taken`));
      await loadAlerts();
    } catch (e) { setError(e instanceof Error ? e.message : "Companion cycle failed. Is the companion paired?"); }
    finally { setBusy(""); }
  }

  async function openAlert(alert: Alert) {
    setActive(alert); setActions([]); setNotes([]); setNoteDraft("");
    try {
      const [ac, nt] = await Promise.all([
        api("/api/soc/actions?alertId=" + encodeURIComponent(alert.id)),
        api("/api/soc/notes?alertId=" + encodeURIComponent(alert.id)).catch(() => ({ notes: [] })),
      ]);
      setActions(ac.actions || []); setNotes(nt.notes || []);
    } catch { /* fresh alert */ }
  }

  async function setStatus(alert: Alert, status: string) {
    try {
      await api("/api/soc/alerts", { method: "PATCH", body: JSON.stringify({ id: alert.id, status }) });
      setActive({ ...alert, status });
      await loadAlerts();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update status."); }
  }

  async function toggleAssign(alert: Alert) {
    const next = alert.assignee === me ? null : "me";
    try {
      const data = await api("/api/soc/alerts", { method: "PATCH", body: JSON.stringify({ id: alert.id, assignee: next }) });
      setActive({ ...alert, assignee: data.alert?.assignee ?? (next === "me" ? me : null) });
      await loadAlerts();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update assignment."); }
  }

  async function addNote(alert: Alert) {
    const body = noteDraft.trim();
    if (!body) return;
    try {
      const data = await api("/api/soc/notes", { method: "POST", body: JSON.stringify({ alertId: alert.id, body }) });
      setNotes((prev) => [...prev, data.note]); setNoteDraft("");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save note."); }
  }

  async function approveAction(alert: Alert, action: string, params: Record<string, unknown> | undefined) {
    try {
      const data = await api("/api/soc/actions", {
        method: "POST",
        body: JSON.stringify({ alertId: alert.id, action, params: params || {}, status: isDestructive(action) ? "approved" : "executed" }),
      });
      setActions((prev) => [...prev, data.action]);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not record action."); }
  }

  if (!authChecked) return <main className="soc-shell"><Loader2 className="spin" /> Loading CyberSOC…</main>;
  if (!me) return (
    <main className="soc-shell"><div className="chat-card"><ShieldAlert size={28} /><h1>CyberSOC</h1>
      <p>Sign in to monitor incidents and response.</p><a className="network-run" href="/login">Sign in</a></div></main>
  );

  const timeline: { kind: "action" | "note"; at: string; text: string }[] = active ? [
    ...actions.map((a) => ({ kind: "action" as const, at: a.created_at, text: `${a.action} — ${a.status}` })),
    ...notes.map((n) => ({ kind: "note" as const, at: n.created_at, text: n.body })),
  ].sort((a, b) => Date.parse(a.at) - Date.parse(b.at)) : [];

  return (
    <main className="soc-layout">
      <header className="soc-top">
        <div className="soc-title"><ShieldAlert size={18} /> CyberSOC
          <span className="soc-sub">Autonomous detection &amp; response · CyberLab AI</span></div>
        <div className="soc-kpis">
          <div className={"soc-kpi" + (liveMetrics.open_critical ? " alarm" : "")}>
            <span className="soc-kpi-val">{liveMetrics.open_critical}</span><span className="soc-kpi-label">Crit open</span></div>
          <div className="soc-kpi"><span className="soc-kpi-val">{liveMetrics.open_high}</span><span className="soc-kpi-label">High open</span></div>
          <div className="soc-kpi"><span className="soc-kpi-val">{liveMetrics.open}</span><span className="soc-kpi-label">Open</span></div>
          <div className="soc-kpi"><span className="soc-kpi-val">{incidents.length}</span><span className="soc-kpi-label">Incidents</span></div>
          <div className="soc-kpi"><span className="soc-kpi-val">{Math.round(liveMetrics.resolved_rate * 100)}%</span><span className="soc-kpi-label">Resolved</span></div>
          <div className="soc-kpi"><span className="soc-kpi-val">{fmtDuration(liveMetrics.mttr_seconds)}</span><span className="soc-kpi-label">MTTR</span></div>
        </div>
      </header>

      <section className="soc-controls">
        <div className="soc-tabs">
          <button className={"soc-tab" + (view === "alerts" ? " on" : "")} onClick={() => setView("alerts")}>Alerts</button>
          <button className={"soc-tab" + (view === "incidents" ? " on" : "")} onClick={() => setView("incidents")}>Incidents</button>
        </div>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by title, rule, technique, entity…" />
        <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Companion token" style={{ maxWidth: 170 }} />
        <button className="soc-btn primary" disabled={busy === "cycle"} onClick={() => runCompanionCycle(true)}>
          {busy === "cycle" ? <Loader2 size={13} className="spin" /> : <Play size={13} />} Run (dry)</button>
        <button className="soc-btn" disabled={busy === "cycle-live"} onClick={() => runCompanionCycle(false)}
          title="Lets authorized safe actions run on the companion">
          {busy === "cycle-live" ? <Loader2 size={13} className="spin" /> : <Activity size={13} />} Run live</button>
        <button className="soc-btn" onClick={() => loadAlerts()} aria-label="Refresh"><RefreshCw size={14} /></button>
        {cycleInfo && <span className="soc-cycle-info">{cycleInfo}</span>}
      </section>
      {error && <div className="soc-error"><AlertTriangle size={14} /> {error}</div>}

      <div className="soc-body">
        <div className="soc-list">
          {view === "alerts" ? (
            filtered.length === 0
              ? <div className="soc-empty">No alerts match. Run a companion cycle to pull live telemetry, or push events from Splunk / Wazuh.</div>
              : filtered.map((a) => (
                <button key={a.id} className={"soc-row" + (active?.id === a.id ? " active" : "")} onClick={() => openAlert(a)}>
                  <span className={"soc-row-accent sev-accent-" + a.severity} />
                  <span className="soc-row-body">
                    <span className="soc-row-title">{a.title}</span>
                    <span className="soc-row-meta">
                      <span>{a.mitre?.technique_id || a.rule}</span><span>{a.status}</span>
                      <span>{a.source}</span>{a.assignee === me && <span>· mine</span>}
                    </span>
                  </span>
                  <span className="soc-row-right">
                    <span className={"soc-sevtag sevtag-" + a.severity}>{a.severity}</span>
                    <span className="soc-score">{a.score}</span>
                  </span>
                </button>
              ))
          ) : (
            incidents.length === 0
              ? <div className="soc-empty">No correlated incidents. Related alerts sharing a host, source IP or user are grouped here.</div>
              : incidents.map((inc) => (
                <div key={inc.id} className="soc-row" style={{ cursor: "default" }}>
                  <span className={"soc-row-accent sev-accent-" + inc.severity} />
                  <span className="soc-row-body">
                    <span className="soc-row-title">{inc.title}</span>
                    <span className="soc-row-meta">
                      <span>{inc.alert_count} alerts</span><span>{inc.open_count} open</span>
                      {Object.entries(inc.entities).slice(0, 2).map(([k, v]) => <span key={k}>{k}={v}</span>)}
                    </span>
                  </span>
                  <span className="soc-row-right">
                    <span className={"soc-sevtag sevtag-" + inc.severity}>{inc.severity}</span>
                    <span className="soc-score">{inc.score}</span>
                  </span>
                </div>
              ))
          )}
        </div>

        <div className="soc-detail">
          {!active ? <div className="soc-empty">Select an alert to triage, assign and respond.</div> : (
            <>
              <div className="soc-detail-head">
                <h2>{active.title}</h2>
                <div className="soc-detail-meta">
                  <span className={"soc-sevtag sevtag-" + active.severity}>{active.severity}</span>
                  {active.mitre?.technique_id && <span className="soc-chip">{active.mitre.technique_id} {active.mitre.technique}</span>}
                  {active.mitre?.tactic && <span className="soc-chip">{active.mitre.tactic}</span>}
                  <span className="soc-chip">score {active.score}</span>
                  <span className="soc-chip">{active.event_count} events</span>
                  <button className="soc-mini" onClick={() => toggleAssign(active)}>
                    {active.assignee === me ? "Unassign" : "Assign to me"}</button>
                </div>
              </div>
              <p className="soc-desc">{active.description}</p>
              <div className="soc-kv"><span>Entities</span><code>{JSON.stringify(active.entities)}</code></div>
              <div className="soc-kv"><span>First seen</span><code>{fmtTime(active.created_at) || "—"}</code></div>

              <div className="soc-section-label">Status</div>
              <div className="soc-status-row">
                {ALERT_STATUSES.map((s) => (
                  <button key={s} className={"soc-status" + (active.status === s ? " on" : "")} onClick={() => setStatus(active, s)}>{s.replace("_", " ")}</button>
                ))}
              </div>

              <div className="soc-section-label">Recommended response</div>
              {active.recommended_actions.length === 0 && <div className="soc-empty" style={{ padding: "4px 0" }}>No automated response for this rule.</div>}
              {active.recommended_actions.map((ra, i) => (
                <div className="soc-action" key={i}>
                  <div>
                    <strong>{ra.action.replace(/_/g, " ")}</strong>{isDestructive(ra.action) && <span className="soc-destructive">needs authorization</span>}
                    {ra.rationale && <div className="soc-action-why">{ra.rationale}</div>}
                  </div>
                  <button className="soc-mini" onClick={() => approveAction(active, ra.action, ra.params)}>
                    {isDestructive(ra.action) ? "Authorize" : "Mark done"}</button>
                </div>
              ))}

              <div className="soc-section-label">Investigation timeline</div>
              {timeline.length === 0 && <div className="soc-empty" style={{ padding: "4px 0" }}>No actions or notes yet.</div>}
              {timeline.map((t, i) => (
                <div className={t.kind === "note" ? "soc-note" : "soc-logrow"} key={i}>
                  {t.text}<time>{fmtTime(t.at)}</time>
                </div>
              ))}
              <div className="soc-note-compose">
                <input value={noteDraft} onChange={(e) => setNoteDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") addNote(active); }} placeholder="Add an investigation note…" />
                <button className="soc-mini" onClick={() => addNote(active)}>Add</button>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
