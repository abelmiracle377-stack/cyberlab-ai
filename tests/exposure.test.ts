import { test } from "node:test";
import assert from "node:assert/strict";
import { assessExposure, exposureAlerts } from "../lib/exposure";

test("risky ports are flagged by severity", () => {
  const findings = assessExposure({ ip: "1.2.3.4", ports: [23, 3389, 80] });
  const byTitle = Object.fromEntries(findings.map((f) => [f.title, f.severity]));
  assert.equal(byTitle["Telnet exposed on port 23"], "critical");
  assert.equal(byTitle["RDP exposed on port 3389"], "high");
  // port 80 is not inherently risky -> no finding for it
  assert.ok(!findings.some((f) => f.port === 80));
});

test("known CVEs become high-severity findings", () => {
  const findings = assessExposure({ ip: "1.2.3.4", ports: [443], vulns: ["CVE-2021-44228"] });
  const cve = findings.find((f) => f.cve === "CVE-2021-44228");
  assert.ok(cve);
  assert.equal(cve.severity, "high");
});

test("benign exposure records an informational surface note", () => {
  const findings = assessExposure({ ip: "1.2.3.4", ports: [80, 443] });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "informational");
});

test("no ports, no findings", () => {
  assert.deepEqual(assessExposure({ ip: "1.2.3.4", ports: [] }), []);
});

test("exposureAlerts map to the ingest shape with shodan source", () => {
  const alerts = exposureAlerts({ ip: "9.9.9.9", org: "Acme", ports: [3306], vulns: ["CVE-2020-0001"] });
  assert.equal(alerts.length, 2);
  for (const a of alerts) {
    assert.equal(a.source, "shodan");
    assert.equal(a.rule, "external_exposure");
    assert.ok(typeof a.id === "string" && (a.id as string).startsWith("exposure:"));
    assert.ok(a.entities && (a.entities as { host: string }).host === "9.9.9.9");
  }
  const cveAlert = alerts.find((a) => (a.entities as { cve?: string }).cve === "CVE-2020-0001");
  assert.equal((cveAlert!.mitre as { technique_id: string }).technique_id, "T1190");
});
