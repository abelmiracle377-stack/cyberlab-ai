"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldAlert, Activity, Play, RefreshCw, AlertTriangle, Loader2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import { ALERT_STATUSES, isDestructive, summarizeBySeverity, type Severity } from "@/lib/soc";

type Alert = {
  id: string; alert_key: string; rule: string; title: string; severity: Severity; score: number;
  mitre: { tactic?: string; technique_id?: string; technique?: string };
  description: string; entities: Record<string, unknown>; event_count: number;
  recommended_actions: { action: string; rationale?: string; params?: Record<string, unknown> }[];
  source: string; status: string; last_seen: string;
};
type ActionRow = { id: string; action: string; status: string; created_at: string };

const BRIDGE = "http://127.0.0.1:8765";
const TOKEN_KEY = "cyberlab.kaliBridgeToken";

async function api(path: string, init?: RequestInit) {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

export default function SocPage() {
  const supabaseRef = useRef<ReturnType<typeof createClient> | null>(null);
  const getSupabase = () => (supabaseRef.current ??= createClient());
  const [me, setMe] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [active, setActive] = useState<Alert | null>(null);
  const [actions, setActions] = useState<ActionRow[]>([]);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [cycleInfo, setCycleInfo] = useState("");

  const loadAlerts = useCallback(async () => {
    try {
      const data = await api("/api/soc/alerts");
      setAlerts(data.alerts || []);
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
    setActive(alert); setActions([]);
    try { const data = await api("/api/soc/actions?alertId=" + encodeURIComponent(alert.id)); setActions(data.actions || []); }
    catch { /* no actions yet */ }
  }

  async function setStatus(alert: Alert, status: string) {
    try {
      await api("/api/soc/alerts", { method: "PATCH", body: JSON.stringify({ id: alert.id, status }) });
      setActive({ ...alert, status });
      await loadAlerts();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update status."); }
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

  const counts = summarizeBySeverity(alerts);

  return (
    <main className="soc-layout">
      <header className="soc-top">
        <div className="soc-title"><ShieldAlert size={18} /> CyberSOC <span className="soc-sub">autonomous SOC · powered by CyberLab AI</span></div>
        <div className="soc-counts">
          {(["critical", "high", "medium", "low", "informational"] as Severity[]).map((s) =>
            <span key={s} className={"soc-chip soc-sev-" + s}>{counts[s]} {s}</span>)}
        </div>
      </header>

      <section className="soc-controls">
        <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Companion bridge token" />
        <button className="network-run" disabled={busy === "cycle"} onClick={() => runCompanionCycle(true)}>
          {busy === "cycle" ? <Loader2 size={14} className="spin" /> : <Play size={14} />} Run cycle (dry)</button>
        <button className="network-run alt" disabled={busy === "cycle-live"} onClick={() => runCompanionCycle(false)}
          title="Lets authorized safe actions run on the companion">
          {busy === "cycle-live" ? <Loader2 size={14} className="spin" /> : <Activity size={14} />} Run live</button>
        <button className="icon-button" onClick={() => loadAlerts()} aria-label="Refresh"><RefreshCw size={15} /></button>
        {cycleInfo && <span className="soc-cycle-info">{cycleInfo}</span>}
      </section>
      {error && <div className="soc-error"><AlertTriangle size={14} /> {error}</div>}

      <div className="soc-body">
        <div className="soc-list">
          {alerts.length === 0 && <div className="soc-empty">No alerts yet. Run a companion cycle to pull live telemetry, or push events from Splunk/Wazuh.</div>}
          {alerts.map((a) => (
            <button key={a.id} className={"soc-row" + (active?.id === a.id ? " active" : "")} onClick={() => openAlert(a)}>
              <span className={"soc-dot soc-sev-" + a.severity} />
              <span className="soc-row-main">
                <span className="soc-row-title">{a.title}</span>
                <span className="soc-row-meta">{a.mitre?.technique_id || a.rule} · {a.status} · {a.source}</span>
              </span>
              <span className="soc-score">{a.score}</span>
            </button>
          ))}
        </div>

        <div className="soc-detail">
          {!active ? <div className="soc-empty">Select an alert to triage and respond.</div> : (
            <>
              <div className={"soc-detail-head soc-sev-border-" + active.severity}>
                <h2>{active.title}</h2>
                <div className="soc-detail-meta">
                  <span className={"soc-chip soc-sev-" + active.severity}>{active.severity}</span>
                  {active.mitre?.technique_id && <span className="soc-chip">{active.mitre.technique_id} {active.mitre.technique}</span>}
                  <span className="soc-chip">score {active.score}</span>
                </div>
              </div>
              <p className="soc-desc">{active.description}</p>
              <div className="soc-kv"><span>Entities</span><code>{JSON.stringify(active.entities)}</code></div>

              <div className="soc-section-label">Status</div>
              <div className="soc-status-row">
                {ALERT_STATUSES.map((s) => (
                  <button key={s} className={"soc-status" + (active.status === s ? " on" : "")} onClick={() => setStatus(active, s)}>{s}</button>
                ))}
              </div>

              <div className="soc-section-label">Recommended response</div>
              {active.recommended_actions.map((ra, i) => (
                <div className="soc-action" key={i}>
                  <div>
                    <strong>{ra.action}</strong>{isDestructive(ra.action) && <span className="soc-destructive">needs authorization</span>}
                    {ra.rationale && <div className="soc-action-why">{ra.rationale}</div>}
                  </div>
                  <button className="chat-mini" onClick={() => approveAction(active, ra.action, ra.params)}>
                    {isDestructive(ra.action) ? "Authorize" : "Mark done"}</button>
                </div>
              ))}

              {actions.length > 0 && <>
                <div className="soc-section-label">Action log</div>
                {actions.map((ac) => <div className="soc-logrow" key={ac.id}>{ac.action} — {ac.status}</div>)}
              </>}
            </>
          )}
        </div>
      </div>
    </main>
  );
}
