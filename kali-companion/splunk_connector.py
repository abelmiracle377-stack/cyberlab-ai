"""Splunk connector: send events to HEC and run searches over the REST API.

Lets CyberLab-AI act as a Splunk companion — forwarding the companion's findings
into Splunk, and pulling Splunk search results back as normalized SOC events for
the detection engine. Real HTTP (urllib); the network call is injectable so tests
never touch the network. TLS verification is on by default; on-prem self-signed
Splunk can opt into `insecure=True`.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from urllib.parse import urlencode


def _request(method: str, url: str, headers: dict, body=None, timeout: int = 30,
             insecure: bool = False, opener=None) -> tuple:
    data = body.encode("utf-8") if isinstance(body, str) else body
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    if opener is not None:
        response = opener(request, timeout=timeout)
    else:  # pragma: no cover - exercised only against a live Splunk
        context = ssl._create_unverified_context() if insecure else None
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
    status = getattr(response, "status", None) or response.getcode()
    raw = response.read()
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return status, text


def send_hec_event(hec_url: str, token: str, event, index: str | None = None,
                   sourcetype: str = "cyberlab:soc", timeout: int = 30,
                   insecure: bool = False, opener=None) -> dict:
    """POST one event to a Splunk HTTP Event Collector."""
    if not hec_url or not token:
        raise ValueError("A HEC URL and token are required.")
    url = hec_url.rstrip("/")
    if not url.endswith("/services/collector/event") and not url.endswith("/services/collector"):
        url = url + "/services/collector/event"
    payload = {"event": event, "sourcetype": sourcetype}
    if index:
        payload["index"] = index
    status, text = _request("POST", url, {"Authorization": "Splunk " + token,
                                          "Content-Type": "application/json"},
                            json.dumps(payload), timeout, insecure, opener)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = {"raw": text[:500]}
    ok = status == 200 and parsed.get("code", 0) == 0
    return {"ok": ok, "status": status, "response": parsed}


def normalize_splunk_results(rows: list) -> list:
    """Map Splunk result rows to normalized SOC events."""
    events = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        events.append({
            "source": "splunk", "type": row.get("event_type", "siem_alert"),
            "timestamp": row.get("_time", ""), "host": row.get("host", ""),
            "user": row.get("user") or row.get("user_name"),
            "src_ip": row.get("src_ip") or row.get("src"),
            "dst_ip": row.get("dest_ip") or row.get("dest"),
            "port": _as_int(row.get("dest_port") or row.get("port")),
            "dst_port": _as_int(row.get("dest_port")),
            "message": row.get("_raw") or row.get("message") or row.get("signature"),
            "severity": row.get("severity") if row.get("severity") in
                        ("informational", "low", "medium", "high", "critical") else None,
            "details": {"sourcetype": row.get("sourcetype", ""), "source": row.get("source", "")},
        })
    return events


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def search(base_url: str, token: str, spl_query: str, earliest: str = "-24h",
           latest: str = "now", max_count: int = 100, timeout: int = 60,
           insecure: bool = False, opener=None) -> dict:
    """Run a Splunk search via the REST export endpoint and normalize the rows."""
    if not base_url or not token:
        raise ValueError("A Splunk base URL and token are required.")
    if not isinstance(spl_query, str) or not spl_query.strip():
        raise ValueError("Provide an SPL search query.")
    if not 1 <= int(max_count) <= 10000:
        raise ValueError("max_count must be between 1 and 10000.")
    query = spl_query.strip()
    if not query.lower().startswith(("search ", "|")):
        query = "search " + query
    url = base_url.rstrip("/") + "/services/search/jobs/export"
    form = urlencode({"search": query, "output_mode": "json", "earliest_time": earliest,
                      "latest_time": latest, "count": str(int(max_count))})
    status, text = _request("POST", url, {"Authorization": "Bearer " + token,
                                          "Content-Type": "application/x-www-form-urlencoded"},
                            form, timeout, insecure, opener)
    if status != 200:
        return {"ok": False, "status": status, "error": text[:500], "events": []}
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            rows.append(obj["result"])
    events = normalize_splunk_results(rows)
    return {"ok": True, "status": status, "result_count": len(rows), "events": events}
