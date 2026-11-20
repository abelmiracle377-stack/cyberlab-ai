"""CyberSOC detection and triage engine.

Turns a batch of normalized security events into correlated alerts with a
severity score, MITRE ATT&CK mapping, the entities involved, and concrete
recommended response actions. This is the analyst "brain": it is what lets
CyberLab-AI decide, from telemetry and SIEM events, what is an incident and what
to do about it. Everything here is pure and deterministic, so it is fully
unit-tested; nothing is simulated — real events in, real alerts out.

Normalized event shape (all keys optional except `type`):
    {"source", "type", "timestamp", "host", "user", "src_ip", "dst_ip",
     "port", "process", "message", "details"}
Event types the rules understand: auth_failure, auth_success, listening_socket,
network_connection, process, siem_alert.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
SEVERITY_SCORE = {"informational": 10, "low": 30, "medium": 55, "high": 78, "critical": 95}

# Ports strongly associated with implants / C2 / handlers.
IMPLANT_PORTS = {1337, 4444, 4445, 5554, 5555, 6666, 9001, 12345, 31337, 1234, 2222}
# Sensitive services that should not be world-exposed; value is the base severity.
SENSITIVE_SERVICES = {
    23: ("Telnet", "high"), 21: ("FTP", "medium"), 3389: ("RDP", "high"),
    5900: ("VNC", "high"), 445: ("SMB", "high"), 139: ("NetBIOS", "medium"),
    3306: ("MySQL", "medium"), 5432: ("PostgreSQL", "medium"), 6379: ("Redis", "high"),
    9200: ("Elasticsearch", "high"), 27017: ("MongoDB", "high"), 11211: ("Memcached", "high"),
    1433: ("MSSQL", "medium"), 2375: ("Docker API", "critical"), 5984: ("CouchDB", "high"),
}
PRIVILEGED_USERS = {"root", "administrator", "admin", "sa", "superuser"}
DEFAULT_CONFIG = {"brute_force_threshold": 5, "port_scan_threshold": 15}


def _is_public_ip(value) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _severity_at_least(base: str, floor: str) -> str:
    return base if SEVERITY_ORDER.index(base) >= SEVERITY_ORDER.index(floor) else floor


def _bump(severity: str, steps: int) -> str:
    idx = min(len(SEVERITY_ORDER) - 1, max(0, SEVERITY_ORDER.index(severity) + steps))
    return SEVERITY_ORDER[idx]


def _alert_id(rule: str, entities: dict) -> str:
    parts = rule + "|" + "|".join(str(entities.get(k, "")) for k in sorted(entities))
    return hashlib.sha1(parts.encode("utf-8")).hexdigest()[:16]


def _window(events: list) -> tuple:
    stamps = sorted(str(e.get("timestamp", "")) for e in events if e.get("timestamp"))
    return (stamps[0] if stamps else "", stamps[-1] if stamps else "")


def _make_alert(rule, title, severity, mitre, description, entities, events, actions) -> dict:
    first, last = _window(events)
    return {
        "id": _alert_id(rule, entities), "rule": rule, "title": title,
        "severity": severity, "score": SEVERITY_SCORE[severity], "mitre": mitre,
        "description": description, "entities": entities, "event_count": len(events),
        "first_seen": first, "last_seen": last, "recommended_actions": actions, "status": "new",
    }


def _rule_brute_force(events, config) -> list:
    groups = defaultdict(list)
    for e in events:
        if e.get("type") == "auth_failure":
            groups[(e.get("host", ""), e.get("src_ip", ""))].append(e)
    alerts = []
    for (host, src_ip), group in groups.items():
        if len(group) < config["brute_force_threshold"]:
            continue
        severity = "high" if len(group) >= config["brute_force_threshold"] * 3 else "medium"
        if _is_public_ip(src_ip):
            severity = _bump(severity, 1)
        users = sorted({e.get("user") for e in group if e.get("user")})
        alerts.append(_make_alert(
            "brute_force_login",
            "Brute-force login attempts against " + (host or "host"),
            severity,
            {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
            "%d failed logins from %s%s." % (len(group), src_ip or "unknown",
                                             " targeting " + ", ".join(users) if users else ""),
            {"host": host, "src_ip": src_ip},
            group,
            [
                {"action": "block_ip", "tool": None, "params": {"ip": src_ip},
                 "rationale": "Stop the source from continuing the attack."},
                {"action": "review_accounts", "tool": None, "params": {"users": users},
                 "rationale": "Check the targeted accounts for lockout or compromise."},
                {"action": "capture_evidence", "tool": None, "params": {"host": host},
                 "rationale": "Preserve auth logs for the incident record."},
            ],
        ))
    return alerts


def _rule_successful_after_failures(events, config) -> list:
    fails = defaultdict(int)
    for e in events:
        if e.get("type") == "auth_failure":
            fails[(e.get("host", ""), e.get("user", ""), e.get("src_ip", ""))] += 1
    alerts = []
    for e in events:
        if e.get("type") != "auth_success":
            continue
        key = (e.get("host", ""), e.get("user", ""), e.get("src_ip", ""))
        if fails.get(key, 0) >= config["brute_force_threshold"]:
            alerts.append(_make_alert(
                "successful_login_after_failures",
                "Successful login after repeated failures",
                "critical",
                {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
                "%s signed in to %s from %s after %d failures — possible account takeover." % (
                    e.get("user", "user"), e.get("host", "host"), e.get("src_ip", "unknown"), fails[key]),
                {"host": e.get("host", ""), "user": e.get("user", ""), "src_ip": e.get("src_ip", "")},
                [e],
                [
                    {"action": "isolate_host", "tool": None, "params": {"host": e.get("host", "")},
                     "rationale": "Contain a potentially compromised host."},
                    {"action": "reset_credentials", "tool": None, "params": {"user": e.get("user", "")},
                     "rationale": "Revoke access gained by the attacker."},
                    {"action": "capture_evidence", "tool": None, "params": {"host": e.get("host", "")},
                     "rationale": "Preserve the session and auth trail."},
                ],
            ))
    return alerts


def _rule_implant_port(events, config) -> list:
    alerts = []
    for e in events:
        if e.get("type") != "listening_socket":
            continue
        port = e.get("port")
        if port in IMPLANT_PORTS:
            alerts.append(_make_alert(
                "suspicious_listening_port",
                "Suspicious listener on port %s" % port,
                "critical",
                {"tactic": "Command and Control", "technique_id": "T1571", "technique": "Non-Standard Port"},
                "A process is listening on %s (commonly an implant/C2 handler port) on %s." % (
                    port, e.get("host", "host")),
                {"host": e.get("host", ""), "port": port, "process": e.get("process", "")},
                [e],
                [
                    {"action": "kill_process", "tool": None, "params": {"process": e.get("process", ""), "port": port},
                     "rationale": "Terminate the suspicious listener."},
                    {"action": "isolate_host", "tool": None, "params": {"host": e.get("host", "")},
                     "rationale": "Prevent C2 communication."},
                    {"action": "capture_pcap", "tool": None, "params": {"host": e.get("host", ""), "port": port},
                     "rationale": "Record traffic to/from the handler for analysis."},
                ],
            ))
    return alerts


def _rule_exposed_service(events, config) -> list:
    alerts = []
    for e in events:
        if e.get("type") != "listening_socket":
            continue
        port = e.get("port")
        spec = SENSITIVE_SERVICES.get(port)
        address = str(e.get("details", {}).get("address", e.get("dst_ip", "")))
        world_facing = address in ("0.0.0.0", "::", "*") or _is_public_ip(address)
        if spec and world_facing:
            name, base = spec
            alerts.append(_make_alert(
                "exposed_sensitive_service",
                "%s exposed to all interfaces" % name,
                base,
                {"tactic": "Initial Access", "technique_id": "T1133", "technique": "External Remote Services"},
                "%s (port %s) is listening on %s on %s and may be reachable externally." % (
                    name, port, address or "0.0.0.0", e.get("host", "host")),
                {"host": e.get("host", ""), "port": port},
                [e],
                [
                    {"action": "restrict_firewall", "tool": None, "params": {"port": port},
                     "rationale": "Limit %s to trusted networks or a VPN." % name},
                    {"action": "review_service", "tool": None, "params": {"port": port, "service": name},
                     "rationale": "Confirm the service is intended to be exposed."},
                ],
            ))
    return alerts


def _rule_privileged_login(events, config) -> list:
    alerts = []
    for e in events:
        if e.get("type") != "auth_success":
            continue
        user = str(e.get("user", "")).lower()
        if user in PRIVILEGED_USERS and _is_public_ip(e.get("src_ip")):
            alerts.append(_make_alert(
                "privileged_external_login",
                "Privileged login from an external address",
                "high",
                {"tactic": "Defense Evasion", "technique_id": "T1078.003", "technique": "Valid Accounts: Local Accounts"},
                "%s signed in to %s from the external address %s." % (
                    user, e.get("host", "host"), e.get("src_ip", "")),
                {"host": e.get("host", ""), "user": user, "src_ip": e.get("src_ip", "")},
                [e],
                [
                    {"action": "verify_access", "tool": None, "params": {"user": user, "src_ip": e.get("src_ip", "")},
                     "rationale": "Confirm the administrator initiated this session."},
                    {"action": "enforce_mfa", "tool": None, "params": {"user": user},
                     "rationale": "Require multi-factor for privileged accounts."},
                ],
            ))
    return alerts


def _rule_port_scan(events, config) -> list:
    ports_by_src = defaultdict(set)
    sample = {}
    for e in events:
        if e.get("type") == "network_connection" and e.get("src_ip") and e.get("dst_port") is not None:
            ports_by_src[(e.get("host", ""), e.get("src_ip"))].add(e.get("dst_port"))
            sample.setdefault((e.get("host", ""), e.get("src_ip")), e)
    alerts = []
    for (host, src_ip), ports in ports_by_src.items():
        if len(ports) >= config["port_scan_threshold"]:
            alerts.append(_make_alert(
                "port_scan",
                "Port scan from %s" % src_ip,
                "medium" if not _is_public_ip(src_ip) else "high",
                {"tactic": "Discovery", "technique_id": "T1046", "technique": "Network Service Discovery"},
                "%s touched %d distinct ports on %s — consistent with a port scan." % (
                    src_ip, len(ports), host or "host"),
                {"host": host, "src_ip": src_ip},
                [sample[(host, src_ip)]],
                [
                    {"action": "block_ip", "tool": None, "params": {"ip": src_ip},
                     "rationale": "Stop reconnaissance from this source."},
                    {"action": "review_exposure", "tool": None, "params": {"host": host},
                     "rationale": "Check which scanned ports are actually open."},
                ],
            ))
    return alerts


def _rule_siem_passthrough(events, config) -> list:
    alerts = []
    for e in events:
        if e.get("type") != "siem_alert":
            continue
        severity = e.get("severity") if e.get("severity") in SEVERITY_ORDER else "medium"
        alerts.append(_make_alert(
            "siem_alert",
            str(e.get("message") or "SIEM alert")[:160],
            severity,
            e.get("details", {}).get("mitre", {"tactic": "", "technique_id": "", "technique": ""}),
            str(e.get("message") or "Alert forwarded from " + str(e.get("source", "SIEM")))[:500],
            {"host": e.get("host", ""), "src_ip": e.get("src_ip", ""), "source": e.get("source", "")},
            [e],
            [{"action": "triage", "tool": None, "params": {}, "rationale": "Review the upstream SIEM detection."}],
        ))
    return alerts


RULES = [
    _rule_brute_force, _rule_successful_after_failures, _rule_implant_port,
    _rule_exposed_service, _rule_privileged_login, _rule_port_scan, _rule_siem_passthrough,
]


def events_from_telemetry(security: dict | None, system: dict | None, host: str = "local") -> list:
    """Convert companion telemetry into normalized SOC events the rules understand."""
    events = []
    security = security or {}
    system = system or {}
    collected = security.get("collected_at", "") or system.get("collected_at", "")
    for sock in security.get("listening_sockets", []):
        if sock.get("listening"):
            events.append({
                "source": "companion-telemetry", "type": "listening_socket", "host": host,
                "port": sock.get("port"), "timestamp": collected,
                "details": {"address": sock.get("address", ""), "protocol": sock.get("protocol", "")},
            })
    for login in system.get("recent_logins", []):
        events.append({
            "source": "companion-telemetry", "type": "auth_success", "host": host,
            "user": login.get("user", ""), "src_ip": login.get("from", "") or None, "timestamp": collected,
        })
    for failed in system.get("failed_logins", []):
        events.append({
            "source": "companion-telemetry", "type": "auth_failure", "host": host,
            "user": failed.get("user", ""), "src_ip": failed.get("from", "") or None, "timestamp": collected,
        })
    return events


def analyze(events: list, config: dict | None = None) -> dict:
    """Run every detection rule over the events and return ranked alerts."""
    if not isinstance(events, list):
        raise ValueError("events must be a list of normalized event objects.")
    settings = {**DEFAULT_CONFIG, **(config or {})}
    alerts: dict[str, dict] = {}
    for rule in RULES:
        for alert in rule(events, settings):
            # De-duplicate by stable id; keep the higher-severity instance.
            existing = alerts.get(alert["id"])
            if not existing or alert["score"] > existing["score"]:
                alerts[alert["id"]] = alert
    ranked = sorted(alerts.values(), key=lambda a: (-a["score"], a["rule"]))
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    for alert in ranked:
        by_severity[alert["severity"]] += 1
    return {
        "alerts": ranked, "alert_count": len(ranked),
        "events_analyzed": len(events), "by_severity": by_severity,
        "highest_severity": ranked[0]["severity"] if ranked else "none",
        "note": "Deterministic correlation of the supplied events; no telemetry is fabricated.",
    }
