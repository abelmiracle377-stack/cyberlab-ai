# CyberSOC — CyberLab AI's Security Operations Center

CyberSOC lets CyberLab AI do what a SOC analyst does: watch for incidents,
triage them, and respond. It works two ways, and both are real — no simulation:

1. **Analyst companion** — alongside an existing SIEM (Splunk, Wazuh). CyberLab AI
   forwards findings into the SIEM and pulls the SIEM's data back, triaging it.
2. **Its own SOC ("CyberSOC")** — an autonomous monitor controlled by CyberLab AI
   that needs no human to operate, while a human can run it as a tool, review
   every cycle, or widen its policy to let it act more aggressively.

It ships **standalone** (a downloadable loop that runs on a host or the CyberLab
OS VM) and **integrated into the web app** (dashboard + API).

## The detection engine (`kali-companion/soc_engine.py`)

Deterministic correlation of normalized events into ranked alerts. Each alert
carries a severity, a 0–100 score, a MITRE ATT&CK mapping, the entities
involved, and concrete recommended response actions. Current rules:

| Rule | MITRE | Severity |
|------|-------|----------|
| Brute-force login (N failures from a source) | T1110 | medium/high (public source bumps) |
| Successful login after repeated failures | T1110 | critical |
| Implant/C2 listener port (4444, 31337, …) | T1571 | critical |
| Exposed sensitive service (Telnet/RDP/SMB/DB/Docker API…) | T1133 | medium–critical |
| Privileged login from an external address | T1078.003 | high |
| Port scan (many ports from one source) | T1046 | medium/high |
| Known-bad indicator (operator IOC: IP/domain/hash) | T1071 | critical |
| SIEM pass-through (Splunk/Wazuh alerts) | from source | mapped |

`events_from_telemetry()` folds the companion's own read-only telemetry
(listening sockets, logins, failed logins) into events. `POST /soc/analyze`
analyzes supplied events and/or live host telemetry.

**Incident correlation.** `group_incidents()` clusters alerts that share a pivot
entity — host, source IP or user — into a single incident using union-find, the
way an analyst groups "all the noise from one box." Each incident rolls up the
highest severity, the summed score, the combined ATT&CK tactics, the entities,
and the merged recommended actions, ranked by score. `analyze()` returns both the
ranked `alerts` and the correlated `incidents`.

**Threat intel (IOCs).** Pass `config["indicators"] = {ips, domains, hashes}` —
the operator's own indicator list, exported from whatever feed they use; nothing
is fetched. Any event whose source/destination IP, domain, or file hash matches
raises a critical alert with a block/isolate response. Matching is
case-insensitive for domains and hashes.

**Detection tuning (suppression).** `config["suppressions"]` lets an analyst tune
out known-good noise without disabling a whole rule. Each entry selects on any of
`rule`, `host`, `src_ip`, `user` and either drops the alert (`action: "drop"`,
the default) or caps it to a ceiling (`action: "cap"`, `max_severity`). Entries
with an `expires` in the past are ignored, and an entry with no selector is
refused (it would mute everything). `analyze()` applies them after ranking and
reports `suppressed_count`.

## SIEM connectors (companion)

- **Splunk** (`splunk_connector.py`): send events to a HEC, and run REST searches
  (Bearer auth) normalized into SOC events. `POST /soc/splunk/send`, `/soc/splunk/search`.
- **Wazuh** (`wazuh_connector.py`): authenticate to the Wazuh API, list agents,
  and search the Wazuh Indexer for alerts (rule.level → severity, MITRE carried).
  `POST /soc/wazuh/agents`, `/soc/wazuh/alerts`.

Both use real HTTP with an injectable network call (tests never touch the
network). TLS verification is on by default; self-signed on-prem can opt into
`insecure`.

## Autonomous runner (`cybersoc.py`)

One cycle = collect events → `soc_engine.analyze` → act:

- **Safe actions run automatically** when authorized (evidence collection,
  packet capture, telemetry, triage, reviews).
- **Destructive actions are escalated, not executed**, unless the operator
  explicitly adds them to the policy's `allowed_actions` (block IP, isolate host,
  kill process, reset credentials, firewall changes, enforce MFA).
- High/critical alerts are always escalated for human review.

This is the safety model: autonomous by default for safe work, human‑in‑the‑loop
for anything that changes a system — and the operator can widen the policy to let
CyberSOC act on its own. `POST /soc/run-cycle` runs a cycle (dry‑run by default;
set `dryRun=false` to let authorized actions run). A failing source never stops a
cycle; its error is reported.

### Standalone

```
python3 kali-companion/cybersoc.py            # continuous loop (60s)
python3 kali-companion/cybersoc.py --once --json
```

It prints a one‑line summary per cycle and lists escalations. It is part of the
companion, so it travels with the Kali companion and the CyberLab OS VM.

## Web app

Apply, in order after the earlier migrations: `202611200003_cybersoc.sql`,
`202611200004_cybersoc_notes.sql`, `202611200005_cybersoc_tuning.sql`,
`202611200006_cybersoc_cases.sql`. These create `soc_alerts`, `soc_actions`,
`soc_notes`, `soc_suppressions` and `soc_cases` with owner-scoped Row-Level
Security and Realtime on alerts; the later ones add `soc_alerts.assignee` and
`soc_alerts.case_id`.

- **External exposure (Shodan)** — the console's **Exposure** control takes a
  list of asset IPs, queries Shodan through the paired companion (read-only
  OSINT), and turns the results into alerts: risky internet-facing services
  (Telnet, RDP, SMB, databases, Docker API, …) and Shodan-reported CVEs, mapped
  to ATT&CK T1133 / T1190. They ingest via the normal pipeline (`source:
  shodan`), so external attack-surface findings correlate into incidents and
  cases alongside host telemetry. Logic in `lib/exposure.ts`
  (`tests/exposure.test.ts`).
- **Console** `/soc` (linked under **CyberSOC** in the sidebar) — a dense,
  restrained SOC console, not a demo. A KPI strip shows critical/high open load,
  total open, correlated incident count, resolved rate, and mean time to resolve
  (MTTR). Two views: **Alerts** (severity-accented rows with a filter across
  title, rule, technique and entities) and **Incidents** (the correlated
  clusters). The detail panel carries MITRE tactic/technique, entities, first-seen
  time, status triage (new → acknowledged → investigating → contained → resolved /
  false positive), **assign-to-me**, the recommended response actions (destructive
  ones badged "needs authorization"), and an **investigation timeline** that
  interleaves response actions with free-text analyst notes. The palette is a
  muted enterprise severity scheme (no neon). "Run (dry)" calls the paired
  companion's `/soc/run-cycle` over the loopback bridge and persists the alerts;
  "Run live" lets the companion's authorized safe actions run. Alerts update live
  via a Supabase Realtime subscription.
- **Cases** — an investigation that spans several alerts. "Open case" on an
  incident groups its alerts into one case with a shared severity roll-up (as
  severe as its worst live alert), status lifecycle
  (open → investigating → contained → resolved → closed), assignee, member list,
  and a **consolidated timeline** merging the actions and notes of every member
  alert. Backed by `soc_cases` + `soc_alerts.case_id`.
- **API** `/api/soc/alerts` (list / ingest-by-key / update status / assign),
  `/api/soc/actions` (record / approve / update outcome), `/api/soc/metrics`
  (operational KPIs), `/api/soc/notes` (list / add investigation notes),
  `/api/soc/suppressions` (list / add / delete tuning rules), and
  `/api/soc/cases` (list / detail with roll-up + timeline / create / update /
  attach-detach alerts / delete). Ingest upserts by
  `alert_key`, preserves an alert's triage status across re-ingests, and
  **applies the operator's active suppressions at ingest** — tuned-out noise is
  never stored and capped alerts persist at the reduced severity. Pure logic —
  severity ranking, metrics, incident correlation and suppression — lives in
  `lib/soc.ts` (unit-tested in `tests/soc.test.ts`), mirroring the companion
  engine so the browser matches the headless runner. The console's **Mute rule
  here** button scopes a drop suppression to the alert's rule and host/IP.

So the same CyberSOC runs headless (standalone), on the companion, and in the
browser — and a human can review every alert, change its status, and authorize
or decline each response action.
