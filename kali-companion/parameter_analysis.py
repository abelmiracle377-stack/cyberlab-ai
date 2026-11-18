"""Offline comparison of explicitly captured HTTP responses.

The analyser never performs network I/O and never returns response bodies.
It emits review indicators, not vulnerability verdicts.
"""
from __future__ import annotations

import hashlib
import re

MAX_BODY_CHARS = 65536
MAX_HEADERS = 100
SENSITIVE_HEADER_HINTS = ("authorization", "cookie", "set-cookie", "token", "secret", "api-key", "apikey")


def _response(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} response must be an object.")
    status = value.get("status")
    duration = value.get("durationMs")
    body = value.get("body", "")
    headers = value.get("headers", [])
    body_bytes = value.get("bodyBytes", len(body.encode("utf-8")) if isinstance(body, str) else 0)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise ValueError(f"{label} status must be an HTTP status code.")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 0 <= duration <= 300000:
        raise ValueError(f"{label} durationMs must be between 0 and 300000.")
    if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
        raise ValueError(f"{label} body must be text no longer than 64 KB.")
    if not isinstance(body_bytes, int) or isinstance(body_bytes, bool) or not 0 <= body_bytes <= 10_000_000:
        raise ValueError(f"{label} bodyBytes must be between 0 and 10000000.")
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise ValueError(f"{label} headers must be a list of at most 100 entries.")
    clean_headers = {}
    for item in headers:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            raise ValueError(f"{label} headers must contain name/value text entries.")
        name = item["name"].strip().lower()
        if not name or len(name) > 128 or len(item["value"]) > 4096 or any(ord(ch) < 32 and ch != "\t" for ch in name):
            raise ValueError(f"{label} contains an invalid header.")
        clean_headers[name] = "[REDACTED]" if any(hint in name for hint in SENSITIVE_HEADER_HINTS) else item["value"][:4096]
    return {"status": status, "durationMs": float(duration), "body": body,
            "bodyBytes": body_bytes, "headers": clean_headers}


def compare_responses(baseline: object, candidate: object) -> dict:
    """Compare two already-captured responses without retaining or returning bodies."""
    before = _response(baseline, "Baseline")
    after = _response(candidate, "Candidate")
    body_before = hashlib.sha256(before["body"].encode("utf-8")).hexdigest()
    body_after = hashlib.sha256(after["body"].encode("utf-8")).hexdigest()
    names = sorted(set(before["headers"]) | set(after["headers"]))
    changed_headers = [
        {"name": name, "before": before["headers"].get(name, "(absent)"),
         "after": after["headers"].get(name, "(absent)")}
        for name in names if before["headers"].get(name) != after["headers"].get(name)
    ]
    status_changed = before["status"] != after["status"]
    body_changed = body_before != body_after
    size_delta = after["bodyBytes"] - before["bodyBytes"]
    duration_delta = round(after["durationMs"] - before["durationMs"], 1)
    indicators = []
    if status_changed:
        indicators.append({"code": "status_changed", "label": "HTTP status changed",
                           "detail": f'{before["status"]} → {after["status"]}', "level": "review"})
    if body_changed:
        indicators.append({"code": "body_changed", "label": "Response body changed",
                           "detail": "SHA-256 digest differs; body content is not included in this report.", "level": "review"})
    if size_delta:
        indicators.append({"code": "body_size_changed", "label": "Response size changed",
                           "detail": f"{size_delta:+d} bytes", "level": "info"})
    if duration_delta >= 500:
        indicators.append({"code": "response_slower", "label": "Candidate response was slower",
                           "detail": f"{duration_delta:+.1f} ms", "level": "review"})
    elif duration_delta <= -500:
        indicators.append({"code": "response_faster", "label": "Candidate response was faster",
                           "detail": f"{duration_delta:+.1f} ms", "level": "info"})
    if changed_headers:
        indicators.append({"code": "headers_changed", "label": "Response headers changed",
                           "detail": f"{len(changed_headers)} header value(s) differ.", "level": "info"})
    return {
        "status": "analysed",
        "summary": {
            "statusChanged": status_changed, "bodyChanged": body_changed,
            "bodyLengthDelta": size_delta, "durationDeltaMs": duration_delta,
            "changedHeaderCount": len(changed_headers),
        },
        "headers": changed_headers,
        "indicators": indicators,
        "digests": {"baselineBodySha256": body_before, "candidateBodySha256": body_after},
        "limitations": [
            "Indicators describe response differences only; they do not establish exploitability or causation.",
            "Timing is affected by network and server variability; repeat measurements before drawing conclusions.",
            "Response bodies are hashed in memory and are not included in this report.",
        ],
    }
