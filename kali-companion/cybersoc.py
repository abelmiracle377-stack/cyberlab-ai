"""CyberSOC: the autonomous SOC loop, powered and controlled by CyberLab-AI.

One cycle = collect events from every source, run the detection engine, then act:
safe response actions the operator has authorized run automatically, and
everything destructive or high-severity is escalated for human review. A human
can run it as a tool, review each cycle, or widen the policy to let it act more
autonomously — nothing destructive runs unless the operator explicitly allows it.

This module is pure/injectable (collectors, responder, clock) and fully tested.
Run it standalone with `python3 cybersoc.py` for a continuous monitor loop.
"""
from __future__ import annotations

import argparse
import json
import time

import soc_engine

SEVERITY_ORDER = soc_engine.SEVERITY_ORDER

# Actions that change a system and therefore need explicit operator authorization.
DESTRUCTIVE_ACTIONS = {
    "block_ip", "isolate_host", "kill_process", "reset_credentials",
    "restrict_firewall", "enforce_mfa",
}
# Safe, read-only / evidence / review actions the SOC may run on its own.
SAFE_AUTO_ACTIONS = {
    "capture_evidence", "capture_pcap", "collect_telemetry", "triage",
    "review_accounts", "review_service", "review_exposure", "verify_access",
}


def default_policy() -> dict:
    return {
        "auto_response": True,
        "auto_response_min_severity": "high",
        "escalate_min_severity": "high",
        "allowed_actions": set(SAFE_AUTO_ACTIONS),
    }


def run_cycle(collectors, responder=None, policy: dict | None = None,
              config: dict | None = None, clock=time.time) -> dict:
    """Run one monitor→detect→respond cycle and return a structured report."""
    merged = {**default_policy(), **(policy or {})}
    allowed = set(merged["allowed_actions"])
    auto_idx = SEVERITY_ORDER.index(merged["auto_response_min_severity"])
    escalate_idx = SEVERITY_ORDER.index(merged["escalate_min_severity"])

    events: list = []
    source_errors: list = []
    for collector in collectors:
        try:
            produced = collector() or []
            if isinstance(produced, list):
                events.extend(produced)
        except Exception as exc:  # a failing source must not stop the cycle
            source_errors.append(str(exc)[:200])

    analysis = soc_engine.analyze(events, config)

    actions_taken: list = []
    escalations: list = []
    for alert in analysis["alerts"]:
        severity_idx = SEVERITY_ORDER.index(alert["severity"])
        eligible = merged["auto_response"] and severity_idx >= auto_idx
        for action in alert["recommended_actions"]:
            name = action.get("action", "")
            if eligible and name in allowed and responder is not None:
                try:
                    result = responder({**action, "alert_id": alert["id"], "severity": alert["severity"]})
                    actions_taken.append({"alert_id": alert["id"], "action": name, "result": result})
                except Exception as exc:
                    escalations.append({"alert_id": alert["id"], "reason": "action_failed",
                                        "action": name, "error": str(exc)[:200]})
        pending = sorted({a.get("action") for a in alert["recommended_actions"] if a.get("action") not in allowed})
        if severity_idx >= escalate_idx or pending:
            escalations.append({"alert_id": alert["id"], "severity": alert["severity"],
                                "title": alert["title"], "reason": "needs_human_review",
                                "pending_actions": pending})

    return {
        "timestamp": _iso(clock()),
        "events_collected": len(events),
        "source_errors": source_errors,
        "alert_count": analysis["alert_count"],
        "by_severity": analysis["by_severity"],
        "highest_severity": analysis["highest_severity"],
        "alerts": analysis["alerts"],
        "actions_taken": actions_taken,
        "escalations": escalations,
        "autonomous": merged["auto_response"],
        "note": "Autonomous cycle: safe authorized actions ran; destructive or high-severity items are escalated for review.",
    }


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def summarize(report: dict) -> str:
    """One-line human/AI-readable summary of a cycle."""
    counts = report["by_severity"]
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts.get(s)]
    return ("[%s] %d events · %d alerts (%s) · %d actions · %d escalations" % (
        report["timestamp"], report["events_collected"], report["alert_count"],
        ", ".join(parts) or "none", len(report["actions_taken"]), len(report["escalations"])))


def telemetry_collector(host: str = "local"):
    """A collector that turns this host's live read-only telemetry into events."""
    import host_telemetry

    def collect():
        security = host_telemetry.collect_security_telemetry()
        system = host_telemetry.collect_system_telemetry()
        return soc_engine.events_from_telemetry(security, system, host)

    return collect


def build_default_responder():
    """A conservative responder: performs safe evidence collection, logs the rest."""
    import host_telemetry

    def respond(action: dict) -> dict:
        name = action.get("action", "")
        if name in ("collect_telemetry", "capture_evidence"):
            snapshot = host_telemetry.collect_security_telemetry()
            return {"status": "collected", "listening_sockets": len(snapshot.get("listening_sockets", []))}
        return {"status": "logged", "action": name, "params": action.get("params", {})}

    return respond


def main(argv=None) -> int:  # pragma: no cover - CLI loop
    parser = argparse.ArgumentParser(description="CyberSOC autonomous monitor (CyberLab AI).")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between cycles.")
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit.")
    parser.add_argument("--json", action="store_true", help="Print full JSON reports.")
    parser.add_argument("--host", default="local", help="Host label for events.")
    args = parser.parse_args(argv)

    collectors = [telemetry_collector(args.host)]
    responder = build_default_responder()
    print("CyberSOC starting — autonomous monitoring (safe actions only unless policy widened).")
    while True:
        report = run_cycle(collectors, responder=responder)
        print(json.dumps(report) if args.json else summarize(report))
        for escalation in report["escalations"]:
            print("  ESCALATE:", escalation.get("title", escalation.get("alert_id")),
                  "->", escalation.get("pending_actions") or escalation.get("reason"))
        if args.once:
            return 0
        time.sleep(max(5, args.interval))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
