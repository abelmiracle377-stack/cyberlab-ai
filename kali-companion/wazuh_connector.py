"""Wazuh connector: authenticate to the Wazuh API, list agents, and pull alerts
from the Wazuh Indexer, normalized as SOC events.

Lets CyberLab-AI act as a Wazuh companion. Real HTTP (urllib) with an injectable
network call so tests never touch the network. TLS verification is on by default;
self-signed deployments can opt into `insecure=True`.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.request

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def _request(method: str, url: str, headers: dict, body=None, timeout: int = 30,
             insecure: bool = False, opener=None) -> tuple:
    data = body.encode("utf-8") if isinstance(body, str) else body
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    if opener is not None:
        response = opener(request, timeout=timeout)
    else:  # pragma: no cover - exercised only against a live Wazuh
        context = ssl._create_unverified_context() if insecure else None
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
    status = getattr(response, "status", None) or response.getcode()
    raw = response.read()
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return status, text


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")


def api_login(base_url: str, user: str, password: str, timeout: int = 30,
              insecure: bool = False, opener=None) -> str:
    """Authenticate to the Wazuh API (default port 55000) and return a JWT."""
    if not base_url or not user or not password:
        raise ValueError("Wazuh API URL, user and password are required.")
    url = base_url.rstrip("/") + "/security/user/authenticate"
    status, text = _request("POST", url, {"Authorization": _basic(user, password)},
                            None, timeout, insecure, opener)
    if status not in (200, 201):
        raise ValueError("Wazuh authentication failed (HTTP %s)." % status)
    token = (json.loads(text).get("data") or {}).get("token")
    if not token:
        raise ValueError("Wazuh authentication response did not contain a token.")
    return token


def list_agents(base_url: str, token: str, timeout: int = 30,
                insecure: bool = False, opener=None) -> dict:
    """List Wazuh agents and their connection status."""
    url = base_url.rstrip("/") + "/agents?select=id,name,ip,status,os.name,version&limit=500"
    status, text = _request("GET", url, {"Authorization": "Bearer " + token},
                            None, timeout, insecure, opener)
    if status != 200:
        return {"ok": False, "status": status, "error": text[:500], "agents": []}
    items = ((json.loads(text).get("data") or {}).get("affected_items")) or []
    agents = [{
        "id": a.get("id", ""), "name": a.get("name", ""), "ip": a.get("ip", ""),
        "status": a.get("status", ""), "os": (a.get("os") or {}).get("name", ""),
        "version": a.get("version", ""),
    } for a in items]
    active = sum(1 for a in agents if a["status"] == "active")
    return {"ok": True, "status": status, "agent_count": len(agents),
            "active": active, "agents": agents}


def _level_to_severity(level) -> str:
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "medium"
    if value >= 12:
        return "critical"
    if value >= 8:
        return "high"
    if value >= 5:
        return "medium"
    if value >= 1:
        return "low"
    return "informational"


def normalize_wazuh_alerts(hits: list) -> list:
    """Map Wazuh Indexer alert documents to normalized SOC events."""
    events = []
    for hit in hits:
        doc = hit.get("_source", hit) if isinstance(hit, dict) else {}
        rule = doc.get("rule", {}) or {}
        agent = doc.get("agent", {}) or {}
        payload = doc.get("data", {}) or {}
        mitre = rule.get("mitre", {}) or {}
        technique_ids = mitre.get("id", []) or []
        techniques = mitre.get("technique", []) or []
        events.append({
            "source": "wazuh", "type": "siem_alert", "timestamp": doc.get("timestamp", ""),
            "host": agent.get("name", ""), "src_ip": payload.get("srcip") or None,
            "dst_ip": payload.get("dstip") or None,
            "severity": _level_to_severity(rule.get("level")),
            "message": rule.get("description", ""),
            "details": {
                "rule_id": rule.get("id", ""), "level": rule.get("level"),
                "groups": rule.get("groups", []),
                "mitre": {
                    "tactic": (mitre.get("tactic", []) or [""])[0],
                    "technique_id": technique_ids[0] if technique_ids else "",
                    "technique": techniques[0] if techniques else "",
                },
            },
        })
    return events


def search_alerts(indexer_url: str, user: str, password: str, query: dict | None = None,
                  size: int = 50, index: str = "wazuh-alerts-*", timeout: int = 30,
                  insecure: bool = False, opener=None) -> dict:
    """Search the Wazuh Indexer for recent alerts and normalize them."""
    if not indexer_url or not user or not password:
        raise ValueError("Wazuh Indexer URL, user and password are required.")
    if not 1 <= int(size) <= 1000:
        raise ValueError("size must be between 1 and 1000.")
    url = indexer_url.rstrip("/") + "/" + index + "/_search"
    body = {"size": int(size), "sort": [{"timestamp": {"order": "desc"}}],
            "query": query or {"match_all": {}}}
    status, text = _request("POST", url, {"Authorization": _basic(user, password),
                                          "Content-Type": "application/json"},
                            json.dumps(body), timeout, insecure, opener)
    if status != 200:
        return {"ok": False, "status": status, "error": text[:500], "events": []}
    hits = (((json.loads(text).get("hits") or {}).get("hits")) or [])
    events = normalize_wazuh_alerts(hits)
    return {"ok": True, "status": status, "result_count": len(hits), "events": events}
