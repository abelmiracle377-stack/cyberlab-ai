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


def _indicator_sets(config) -> dict:
    """Normalize the operator-supplied threat-intel indicators into lookup sets."""
    raw = config.get("indicators") or {}
    ips = {str(v).strip() for v in (raw.get("ips") or []) if str(v).strip()}
    domains = {str(v).strip().lower() for v in (raw.get("domains") or []) if str(v).strip()}
    hashes = {str(v).strip().lower() for v in (raw.get("hashes") or []) if str(v).strip()}
    return {"ips": ips, "domains": domains, "hashes": hashes}


def _rule_known_indicator(events, config) -> list:
    """Match events against operator-supplied threat-intel indicators (IOCs).

    The operator provides their own indicator list (e.g. exported from a feed);
    nothing is fetched or invented. A hit is a critical alert — a known-bad IP,
    domain or file hash seen on the estate is high-confidence by definition.
    """
    ioc = _indicator_sets(config)
    if not (ioc["ips"] or ioc["domains"] or ioc["hashes"]):
        return []
    grouped: dict[str, dict] = {}
    for e in events:
        details = e.get("details") or {}
        candidates = []  # (indicator_value, indicator_type, matched)
        for key in ("src_ip", "dst_ip"):
            val = str(e.get(key) or "").strip()
            if val and val in ioc["ips"]:
                candidates.append((val, "ip"))
        domain = str(e.get("domain") or details.get("domain") or "").strip().lower()
        if domain and domain in ioc["domains"]:
            candidates.append((domain, "domain"))
        file_hash = str(details.get("hash") or details.get("sha256") or details.get("md5") or "").strip().lower()
        if file_hash and file_hash in ioc["hashes"]:
            candidates.append((file_hash, "hash"))
        for value, itype in candidates:
            entities = {
                "indicator": value, "indicator_type": itype,
                "host": e.get("host", ""), "src_ip": e.get("src_ip", ""),
            }
            key = _alert_id("known_indicator", entities)
            actions = [{"action": "isolate_host", "tool": None, "params": {"host": e.get("host", "")},
                        "rationale": "Contain the host that touched a known-bad indicator."}]
            if itype == "ip":
                actions.insert(0, {"action": "block_ip", "tool": None, "params": {"ip": value},
                                   "rationale": "Block the known-malicious address at the perimeter."})
            grouped.setdefault(key, {"value": value, "itype": itype, "entities": entities,
                                     "events": [], "actions": actions})
            grouped[key]["events"].append(e)
    alerts = []
    for g in grouped.values():
        label = {"ip": "address", "domain": "domain", "hash": "file hash"}[g["itype"]]
        alerts.append(_make_alert(
            "known_indicator",
            f"Known-bad {label} observed: {g['value']}"[:160],
            "critical",
            {"tactic": "command-and-control", "technique_id": "T1071", "technique": "Application Layer Protocol"},
            f"Traffic or activity matched a threat-intel indicator ({g['itype']}={g['value']}). "
            "This indicator was supplied by the operator's intel set.",
            g["entities"], g["events"], g["actions"],
        ))
    return alerts


RULES = [
    _rule_brute_force, _rule_successful_after_failures, _rule_implant_port,
    _rule_exposed_service, _rule_privileged_login, _rule_port_scan,
    _rule_known_indicator, _rule_siem_passthrough,
]


def _suppression_matches(alert: dict, rule: dict) -> bool:
    """A suppression matches when every field it specifies matches the alert."""
    if rule.get("rule") and rule["rule"] != alert.get("rule"):
        return False
    entities = alert.get("entities") or {}
    for key in ("host", "src_ip", "user"):
        want = rule.get(key)
        if want and str(want) != str(entities.get(key, "")):
            return False
    # A suppression with no selective field at all is ignored (too broad).
    return any(rule.get(k) for k in ("rule", "host", "src_ip", "user"))


def apply_suppressions(alerts: list, suppressions: list, now: str | None = None) -> tuple:
    """Drop or down-rank alerts that match an active operator suppression.

    Suppression shape: {rule?, host?, src_ip?, user?, action: "drop"|"cap",
    max_severity?, expires?}. This is how an analyst tunes out known-good noise
    without disabling a whole rule. Expired suppressions (expires < now) are
    skipped. Returns (kept_alerts, suppressed_count).
    """
    active = []
    for s in suppressions or []:
        if not isinstance(s, dict):
            continue
        exp = s.get("expires")
        if exp and now and str(exp) < str(now):
            continue
        active.append(s)
    if not active:
        return list(alerts), 0

    kept, suppressed = [], 0
    for alert in alerts:
        rule = next((s for s in active if _suppression_matches(alert, s)), None)
        if rule is None:
            kept.append(alert)
            continue
        if rule.get("action") == "cap" and rule.get("max_severity") in SEVERITY_ORDER:
            capped = dict(alert)
            if SEVERITY_ORDER.index(alert["severity"]) > SEVERITY_ORDER.index(rule["max_severity"]):
                capped["severity"] = rule["max_severity"]
                capped["score"] = SEVERITY_SCORE[rule["max_severity"]]
                capped["suppressed"] = "capped"
            kept.append(capped)
        else:
            suppressed += 1  # dropped
    return kept, suppressed


# Entity keys that, when shared, link two alerts into the same incident.
_PIVOT_ENTITIES = ("host", "src_ip", "user")


def group_incidents(alerts: list) -> list:
    """Cluster alerts that share a host, source IP or user into incidents.

    An incident rolls up the member alerts: the highest severity/score, every
    ATT&CK tactic in the chain, the combined entities, and a de-duplicated set of
    recommended actions. This is how analysts actually work — on the related
    whole, not each alert in isolation.
    """
    if not alerts:
        return []
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        parent[find(a)] = find(b)

    # Link alerts sharing any pivot entity value.
    seen: dict = {}
    for index, alert in enumerate(alerts):
        entities = alert.get("entities", {}) or {}
        for key in _PIVOT_ENTITIES:
            value = entities.get(key)
            if value in (None, "", "*"):
                continue
            token = key + "=" + str(value)
            if token in seen:
                union(index, seen[token])
            else:
                seen[token] = index

    clusters: dict = defaultdict(list)
    for index in range(len(alerts)):
        clusters[find(index)].append(alerts[index])

    incidents = []
    for members in clusters.values():
        top = max(members, key=lambda a: a.get("score", 0))
        tactics, entities, actions, alert_ids = [], {}, {}, []
        for member in members:
            alert_ids.append(member.get("id"))
            tactic = (member.get("mitre", {}) or {}).get("tactic")
            if tactic and tactic not in tactics:
                tactics.append(tactic)
            for key, value in (member.get("entities", {}) or {}).items():
                if value not in (None, "", "*"):
                    entities.setdefault(key, value)
            for action in member.get("recommended_actions", []):
                actions.setdefault(action.get("action"), action)
        incident_id = hashlib.sha1("|".join(sorted(str(a) for a in alert_ids)).encode()).hexdigest()[:16]
        incidents.append({
            "id": incident_id, "title": top.get("title", "Incident"),
            "severity": top.get("severity", "medium"), "score": top.get("score", 0),
            "alert_count": len(members), "alert_ids": alert_ids,
            "tactics": tactics, "entities": entities,
            "recommended_actions": list(actions.values()),
            "first_seen": min((m.get("first_seen", "") for m in members if m.get("first_seen")), default=""),
            "last_seen": max((m.get("last_seen", "") for m in members if m.get("last_seen")), default=""),
        })
    return sorted(incidents, key=lambda i: (-i["score"], -i["alert_count"]))


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
    ranked, suppressed_count = apply_suppressions(
        ranked, settings.get("suppressions", []), settings.get("now"))
    # Capping may change scores; re-sort so ranking stays truthful.
    ranked = sorted(ranked, key=lambda a: (-a["score"], a["rule"]))
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    for alert in ranked:
        by_severity[alert["severity"]] += 1
    incidents = group_incidents(ranked)
    return {
        "alerts": ranked, "alert_count": len(ranked),
        "incidents": incidents, "incident_count": len(incidents),
        "events_analyzed": len(events), "by_severity": by_severity,
        "suppressed_count": suppressed_count,
        "highest_severity": ranked[0]["severity"] if ranked else "none",
        "note": "Deterministic correlation of the supplied events; no telemetry is fabricated.",
    }
