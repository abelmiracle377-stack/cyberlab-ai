// Pure, dependency-free helpers for the CyberSOC web dashboard and API.
// Kept import-free so it compiles and unit-tests standalone (CI node --test).

export const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export const ALERT_STATUSES = [
  "new", "acknowledged", "investigating", "contained", "resolved", "false_positive",
] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export const ACTION_STATUSES = ["pending", "approved", "executed", "failed", "declined"] as const;
export type ActionStatus = (typeof ACTION_STATUSES)[number];

export const CASE_STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

export function isCaseStatus(value: unknown): value is CaseStatus {
  return typeof value === "string" && (CASE_STATUSES as readonly string[]).includes(value);
}

// Actions that change a system and need explicit human authorization.
export const DESTRUCTIVE_ACTIONS = new Set([
  "block_ip", "isolate_host", "kill_process", "reset_credentials", "restrict_firewall", "enforce_mfa",
]);

export function severityRank(severity: string): number {
  const idx = (SEVERITY_ORDER as readonly string[]).indexOf(severity);
  return idx < 0 ? 0 : idx;
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITY_ORDER as readonly string[]).includes(value);
}

export function isAlertStatus(value: unknown): value is AlertStatus {
  return typeof value === "string" && (ALERT_STATUSES as readonly string[]).includes(value);
}

export function isActionStatus(value: unknown): value is ActionStatus {
  return typeof value === "string" && (ACTION_STATUSES as readonly string[]).includes(value);
}

export function isDestructive(action: unknown): boolean {
  return typeof action === "string" && DESTRUCTIVE_ACTIONS.has(action);
}

function clampStr(value: unknown, max: number): string {
  return typeof value === "string" ? value.slice(0, max) : "";
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

export type IngestAlert = {
  alert_key: string; rule: string; title: string; severity: Severity; score: number;
  mitre: Record<string, unknown>; description: string; entities: Record<string, unknown>;
  event_count: number; first_seen: string; last_seen: string;
  recommended_actions: unknown[]; source: string;
};

// Validate and clamp one engine alert into a row safe to store. Returns null if
// the alert is missing the fields we require.
export function normalizeIngestAlert(raw: unknown, source = "companion"): IngestAlert | null {
  const a = asObject(raw);
  const alertKey = clampStr(a.id ?? a.alert_key, 64);
  const rule = clampStr(a.rule, 80);
  const title = clampStr(a.title, 300);
  if (!alertKey || !rule || !title) return null;
  const severity: Severity = isSeverity(a.severity) ? a.severity : "medium";
  const scoreNum = typeof a.score === "number" && Number.isFinite(a.score)
    ? Math.max(0, Math.min(100, Math.round(a.score))) : severityRank(severity) * 20;
  const eventCount = typeof a.event_count === "number" && a.event_count >= 0
    ? Math.min(100000, Math.round(a.event_count)) : 0;
  const actions = Array.isArray(a.recommended_actions) ? a.recommended_actions.slice(0, 20) : [];
  return {
    alert_key: alertKey, rule, title, severity, score: scoreNum,
    mitre: asObject(a.mitre), description: clampStr(a.description, 2000),
    entities: asObject(a.entities), event_count: eventCount,
    first_seen: clampStr(a.first_seen, 40), last_seen: clampStr(a.last_seen, 40),
    recommended_actions: actions, source: clampStr(source, 40) || "companion",
  };
}

export function summarizeBySeverity(alerts: { severity: string }[]): Record<Severity, number> {
  const counts = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>;
  for (const alert of alerts) if (isSeverity(alert.severity)) counts[alert.severity] += 1;
  return counts;
}

const OPEN_STATUSES = new Set(["new", "acknowledged", "investigating", "contained"]);

export type MetricAlert = { severity: string; status: string; created_at?: string; updated_at?: string };
export type SocMetrics = {
  total: number; open: number; resolved: number; false_positive: number;
  open_critical: number; open_high: number;
  by_severity: Record<Severity, number>; by_status: Record<AlertStatus, number>;
  resolved_rate: number; mttr_seconds: number | null;
};

// Operational KPIs over a set of alerts (open load, resolved rate, mean time to
// resolve). MTTR uses the span from created_at to updated_at on resolved alerts.
export function computeMetrics(alerts: MetricAlert[]): SocMetrics {
  const by_severity = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>;
  const by_status = {
    new: 0, acknowledged: 0, investigating: 0, contained: 0, resolved: 0, false_positive: 0,
  } as Record<AlertStatus, number>;
  let open = 0, resolved = 0, falsePositive = 0, openCritical = 0, openHigh = 0;
  let resolveSum = 0, resolveCount = 0;

  for (const alert of alerts) {
    if (isSeverity(alert.severity)) by_severity[alert.severity] += 1;
    if (isAlertStatus(alert.status)) by_status[alert.status] += 1;
    const isOpen = OPEN_STATUSES.has(alert.status);
    if (isOpen) open += 1;
    if (alert.status === "resolved") resolved += 1;
    if (alert.status === "false_positive") falsePositive += 1;
    if (isOpen && alert.severity === "critical") openCritical += 1;
    if (isOpen && alert.severity === "high") openHigh += 1;
    if (alert.status === "resolved" && alert.created_at && alert.updated_at) {
      const span = (Date.parse(alert.updated_at) - Date.parse(alert.created_at)) / 1000;
      if (Number.isFinite(span) && span >= 0) { resolveSum += span; resolveCount += 1; }
    }
  }
  const total = alerts.length;
  return {
    total, open, resolved, false_positive: falsePositive,
    open_critical: openCritical, open_high: openHigh,
    by_severity, by_status,
    resolved_rate: total ? Math.round((resolved / total) * 100) / 100 : 0,
    mttr_seconds: resolveCount ? Math.round(resolveSum / resolveCount) : null,
  };
}

export type CaseMember = { severity: string; status: string; score?: number };
export type CaseRollup = {
  severity: Severity; score: number; total: number; open: number;
  by_severity: Record<Severity, number>;
};

// Derive a case's headline figures from its member alerts: highest severity,
// summed score, and how many members are still open. Keeps a case honest —
// it is exactly as severe as its worst live alert.
export function summarizeCase(members: CaseMember[]): CaseRollup {
  const by_severity = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>;
  let severity: Severity = "informational";
  let score = 0, open = 0;
  for (const m of members) {
    if (isSeverity(m.severity)) {
      by_severity[m.severity] += 1;
      if (severityRank(m.severity) > severityRank(severity)) severity = m.severity;
    }
    score += typeof m.score === "number" ? m.score : 0;
    if (OPEN_STATUSES.has(m.status)) open += 1;
  }
  return { severity, score, total: members.length, open, by_severity };
}

const PIVOT_ENTITIES = ["host", "src_ip", "user"] as const;

export type IncidentAlert = {
  id: string; title: string; severity: string; score: number; status: string;
  entities?: Record<string, unknown>; mitre?: { tactic?: string };
};
export type Incident = {
  id: string; title: string; severity: Severity; score: number;
  alert_count: number; alert_ids: string[]; open_count: number;
  entities: Record<string, string>; tactics: string[];
};

// Cluster alerts that share a pivot entity (host / src_ip / user) into incidents,
// mirroring the companion's union-find grouping so the web view matches the engine.
export function groupIncidents(alerts: IncidentAlert[]): Incident[] {
  const parent = alerts.map((_, i) => i);
  const find = (i: number): number => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  const union = (a: number, b: number) => { const ra = find(a), rb = find(b); if (ra !== rb) parent[ra] = rb; };

  const seen = new Map<string, number>();
  alerts.forEach((alert, i) => {
    for (const key of PIVOT_ENTITIES) {
      const raw = alert.entities?.[key];
      if (raw === undefined || raw === null || raw === "") continue;
      const token = `${key}:${String(raw)}`;
      const prev = seen.get(token);
      if (prev === undefined) seen.set(token, i); else union(prev, i);
    }
  });

  const groups = new Map<number, number[]>();
  alerts.forEach((_, i) => { const r = find(i); (groups.get(r) ?? groups.set(r, []).get(r)!).push(i); });

  const incidents: Incident[] = [];
  for (const members of groups.values()) {
    const rows = members.map((i) => alerts[i]);
    const top = rows.reduce((a, b) => (severityRank(b.severity) > severityRank(a.severity) ? b : a));
    const entities: Record<string, string> = {};
    const tactics = new Set<string>();
    let openCount = 0;
    for (const r of rows) {
      for (const key of PIVOT_ENTITIES) { const v = r.entities?.[key]; if (v) entities[key] = String(v); }
      if (r.mitre?.tactic) tactics.add(r.mitre.tactic);
      if (OPEN_STATUSES.has(r.status)) openCount += 1;
    }
    incidents.push({
      id: "inc-" + rows.map((r) => r.id).sort().join("-").slice(0, 60),
      title: top.title,
      severity: isSeverity(top.severity) ? top.severity : "informational",
      score: rows.reduce((sum, r) => sum + (r.score || 0), 0),
      alert_count: rows.length,
      alert_ids: rows.map((r) => r.id),
      open_count: openCount,
      entities, tactics: [...tactics],
    });
  }
  incidents.sort((a, b) => b.score - a.score || b.alert_count - a.alert_count);
  return incidents;
}

const SEVERITY_SCORE: Record<Severity, number> = {
  informational: 10, low: 30, medium: 55, high: 78, critical: 95,
};

export type Suppression = {
  rule?: string | null; host?: string | null; src_ip?: string | null; user?: string | null;
  action?: "drop" | "cap"; max_severity?: string | null; expires?: string | null;
};
export type SuppressibleAlert = {
  rule: string; severity: string; score?: number; entities?: Record<string, unknown>;
  [k: string]: unknown;
};

export function matchesSuppression(alert: SuppressibleAlert, rule: Suppression): boolean {
  if (rule.rule && rule.rule !== alert.rule) return false;
  const entities = alert.entities || {};
  for (const key of ["host", "src_ip", "user"] as const) {
    const want = rule[key];
    if (want && String(want) !== String(entities[key] ?? "")) return false;
  }
  return Boolean(rule.rule || rule.host || rule.src_ip || rule.user);
}

// Drop or down-rank alerts matching an active operator suppression, mirroring
// the companion engine so web ingest and the headless runner tune identically.
export function applySuppressions<T extends SuppressibleAlert>(
  alerts: T[], suppressions: Suppression[], now?: string,
): { kept: T[]; suppressed: number } {
  const active = (suppressions || []).filter((s) => !(s.expires && now && String(s.expires) < String(now)));
  if (active.length === 0) return { kept: [...alerts], suppressed: 0 };
  const kept: T[] = [];
  let suppressed = 0;
  for (const alert of alerts) {
    const rule = active.find((s) => matchesSuppression(alert, s));
    if (!rule) { kept.push(alert); continue; }
    if (rule.action === "cap" && isSeverity(rule.max_severity)) {
      if (severityRank(alert.severity) > severityRank(rule.max_severity)) {
        kept.push({ ...alert, severity: rule.max_severity, score: SEVERITY_SCORE[rule.max_severity], suppressed: "capped" });
      } else {
        kept.push(alert);
      }
    } else {
      suppressed += 1; // dropped
    }
  }
  return { kept, suppressed };
}
