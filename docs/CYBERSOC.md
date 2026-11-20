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
| SIEM pass-through (Splunk/Wazuh alerts) | from source | mapped |

`events_from_telemetry()` folds the companion's own read-only telemetry
(listening sockets, logins, failed logins) into events. `POST /soc/analyze`
analyzes supplied events and/or live host telemetry.

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

Apply `supabase/migrations/202611200003_cybersoc.sql` (after the earlier
migrations) to create `soc_alerts` and `soc_actions` with Row-Level Security
(owner-scoped) and Realtime on alerts.

- **Dashboard** `/soc` (linked under **CyberSOC** in the sidebar): live alert
  list coloured by severity with a severity summary, an alert detail panel
  (MITRE, entities, description), status triage
  (new → acknowledged → investigating → contained → resolved / false positive),
  the recommended response actions (destructive ones badged "needs
  authorization"), and an action log. "Run cycle (dry)" calls the paired
  companion's `/soc/run-cycle` over the loopback bridge, persists the resulting
  alerts, and shows them; "Run live" lets the companion's authorized safe
  actions run. Alerts update live via a Supabase Realtime subscription.
- **API** `/api/soc/alerts` (list / ingest-by-key / update status) and
  `/api/soc/actions` (record / approve / update outcome). Ingest upserts by
  `alert_key` and preserves an alert's triage status across re-ingests. Pure
  validation lives in `lib/soc.ts` (unit-tested in `tests/soc.test.ts`).

So the same CyberSOC runs headless (standalone), on the companion, and in the
browser — and a human can review every alert, change its status, and authorize
or decline each response action.
