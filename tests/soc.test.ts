import { test } from "node:test";
import assert from "node:assert/strict";
import {
  severityRank, isSeverity, isAlertStatus, isDestructive,
  normalizeIngestAlert, summarizeBySeverity, computeMetrics, groupIncidents,
} from "../lib/soc";

test("severity rank and guards", () => {
  assert.equal(severityRank("critical") > severityRank("low"), true);
  assert.equal(severityRank("bogus"), 0);
  assert.equal(isSeverity("high"), true);
  assert.equal(isSeverity("spicy"), false);
  assert.equal(isAlertStatus("investigating"), true);
  assert.equal(isAlertStatus("nope"), false);
});

test("destructive action detection", () => {
  assert.equal(isDestructive("kill_process"), true);
  assert.equal(isDestructive("capture_evidence"), false);
});

test("normalize a valid engine alert", () => {
  const engineAlert = {
    id: "abc123", rule: "suspicious_listening_port", title: "Suspicious listener on port 4444",
    severity: "critical", score: 95, mitre: { technique_id: "T1571" },
    description: "nc listening", entities: { host: "h", port: 4444 },
    event_count: 1, first_seen: "t0", last_seen: "t1",
    recommended_actions: [{ action: "kill_process" }],
  };
  const row = normalizeIngestAlert(engineAlert, "companion");
  assert.ok(row);
  assert.equal(row.alert_key, "abc123");
  assert.equal(row.severity, "critical");
  assert.equal(row.score, 95);
  assert.equal(row.mitre.technique_id, "T1571");
  assert.equal(row.source, "companion");
});

test("normalize clamps and defaults bad fields", () => {
  const row = normalizeIngestAlert({
    id: "k", rule: "r", title: "t", severity: "nonsense", score: 9999,
    event_count: -5, recommended_actions: "not-an-array",
  });
  assert.ok(row);
  assert.equal(row.severity, "medium"); // invalid -> default
  assert.equal(row.score, 100);         // clamped
  assert.equal(row.event_count, 0);     // negative -> 0
  assert.deepEqual(row.recommended_actions, []);
});

test("normalize rejects alerts missing required fields", () => {
  assert.equal(normalizeIngestAlert({ rule: "r", title: "t" }), null); // no id
  assert.equal(normalizeIngestAlert({ id: "k", title: "t" }), null);   // no rule
  assert.equal(normalizeIngestAlert("not an object"), null);
});

test("compute metrics: open load, resolved rate and MTTR", () => {
  const metrics = computeMetrics([
    { severity: "critical", status: "new" },
    { severity: "high", status: "investigating" },
    { severity: "medium", status: "resolved",
      created_at: "2026-11-20T00:00:00Z", updated_at: "2026-11-20T01:00:00Z" },
    { severity: "low", status: "false_positive" },
  ]);
  assert.equal(metrics.total, 4);
  assert.equal(metrics.open, 2);           // new + investigating
  assert.equal(metrics.resolved, 1);
  assert.equal(metrics.false_positive, 1);
  assert.equal(metrics.open_critical, 1);
  assert.equal(metrics.open_high, 1);
  assert.equal(metrics.resolved_rate, 0.25);
  assert.equal(metrics.mttr_seconds, 3600); // one hour
  assert.equal(metrics.by_status.resolved, 1);
});

test("metrics MTTR is null with no resolved alerts", () => {
  const metrics = computeMetrics([{ severity: "high", status: "new" }]);
  assert.equal(metrics.mttr_seconds, null);
  assert.equal(metrics.resolved_rate, 0);
});

test("group incidents: alerts sharing a host cluster together", () => {
  const incidents = groupIncidents([
    { id: "a1", title: "Brute force", severity: "medium", score: 40, status: "new", entities: { host: "web-1", src_ip: "10.0.0.5" } },
    { id: "a2", title: "Privileged login", severity: "high", score: 70, status: "new", entities: { host: "web-1" } },
    { id: "a3", title: "Port scan", severity: "low", score: 20, status: "new", entities: { host: "db-9" } },
  ]);
  assert.equal(incidents.length, 2);
  const big = incidents[0];
  assert.equal(big.alert_count, 2);            // a1 + a2 share web-1
  assert.equal(big.severity, "high");          // rolled up to highest
  assert.equal(big.score, 110);                // summed
  assert.equal(big.entities.host, "web-1");
});

test("group incidents: ranked by score, unrelated stay separate", () => {
  const incidents = groupIncidents([
    { id: "a1", title: "Low", severity: "low", score: 10, status: "resolved", entities: { host: "h1" } },
    { id: "a2", title: "Crit", severity: "critical", score: 95, status: "new", entities: { host: "h2" } },
  ]);
  assert.equal(incidents.length, 2);
  assert.equal(incidents[0].title, "Crit");
  assert.equal(incidents[0].open_count, 1);
  assert.equal(incidents[1].open_count, 0);
});

test("summarize by severity", () => {
  const counts = summarizeBySeverity([
    { severity: "critical" }, { severity: "critical" }, { severity: "high" }, { severity: "bogus" },
  ]);
  assert.equal(counts.critical, 2);
  assert.equal(counts.high, 1);
  assert.equal(counts.low, 0);
});
