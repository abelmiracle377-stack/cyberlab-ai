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
