import { test } from "node:test";
import assert from "node:assert/strict";
import {
  severityRank, isSeverity, isAlertStatus, isDestructive,
  normalizeIngestAlert, summarizeBySeverity,
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

test("summarize by severity", () => {
  const counts = summarizeBySeverity([
    { severity: "critical" }, { severity: "critical" }, { severity: "high" }, { severity: "bogus" },
  ]);
  assert.equal(counts.critical, 2);
  assert.equal(counts.high, 1);
  assert.equal(counts.low, 0);
});
