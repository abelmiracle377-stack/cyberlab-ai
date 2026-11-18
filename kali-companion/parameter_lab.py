"""Bounded, offline parameter mutation planner for the native HTTP workbench.

This module generates request drafts only. It never opens sockets or sends traffic.
Each case mutates exactly one selected parameter and is intended for explicit,
individually approved review in the native Repeater.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_PARAMETERS = 50
MAX_PAYLOADS = 25
MAX_CASES = 25
MAX_VALUE_LENGTH = 512
SENSITIVE_HINTS = ("token", "key", "auth", "password", "secret", "session",
                   "credential", "signature", "jwt", "csrf", "nonce", "code")


@dataclass(frozen=True)
class Parameter:
    location: str
    index: int
    name: str
    value: str
    eligible: bool
    reason: str = ""


def _pairs(value: str) -> list[tuple[str, str]]:
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("Parameter source must be text no longer than 8 KB.")
    pairs = parse_qsl(value, keep_blank_values=True, max_num_fields=MAX_PARAMETERS)
    if len(pairs) > MAX_PARAMETERS:
        raise ValueError("At most 50 parameters can be inspected.")
    return pairs


def inspect_parameters(url: str, body: str = "", content_type: str = "") -> dict:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Enter a valid HTTP(S) URL.")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Target must be an HTTP(S) URL without credentials or fragments.")
    query_pairs = _pairs(parsed.query)
    form_pairs: list[tuple[str, str]] = []
    if body:
        if "application/x-www-form-urlencoded" not in content_type.lower():
            raise ValueError("Only URL-encoded form bodies can be inspected.")
        form_pairs = _pairs(body)
    items = []
    for location, pairs in (("query", query_pairs), ("form", form_pairs)):
        for index, (name, value) in enumerate(pairs):
            sensitive = any(hint in name.lower() for hint in SENSITIVE_HINTS)
            items.append({
                "location": location, "index": index, "name": name[:128],
                "value": value[:MAX_VALUE_LENGTH], "eligible": not sensitive,
                "reason": "Sensitive-looking parameter is excluded." if sensitive else "",
            })
    return {"items": items, "count": len(items), "eligibleCount": sum(x["eligible"] for x in items)}


def generate_cases(url: str, body: str, content_type: str, location: str,
                   parameter_index: int, payloads: list[str], method: str = "GET") -> dict:
    inventory = inspect_parameters(url, body, content_type)
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Choose a supported HTTP method.")
    method = method.upper()
    if location not in {"query", "form"}:
        raise ValueError("Choose query or form parameter location.")
    if location == "form" and method not in {"POST", "PUT", "PATCH"}:
        raise ValueError("URL-encoded form mutations require POST, PUT or PATCH.")
    selected = [item for item in inventory["items"]
                if item["location"] == location and item["index"] == parameter_index]
    if not selected:
        raise ValueError("Selected parameter does not exist.")
    parameter = selected[0]
    if not parameter["eligible"]:
        raise ValueError("Sensitive-looking parameters cannot be mutated.")
    if not isinstance(payloads, list) or not 1 <= len(payloads) <= MAX_PAYLOADS:
        raise ValueError("Supply between 1 and 25 payload values.")
    clean_payloads = []
    for payload in payloads:
        if not isinstance(payload, str) or len(payload) > MAX_VALUE_LENGTH or any(ord(ch) < 32 for ch in payload):
            raise ValueError("Payloads must be plain text of at most 512 characters without controls.")
        clean_payloads.append(payload)
    parsed = urlsplit(url)
    original_query = _pairs(parsed.query)
    original_form = _pairs(body) if body else []
    cases = []
    for number, payload in enumerate(clean_payloads, 1):
        query = list(original_query)
        form = list(original_form)
        target = query if location == "query" else form
        target[parameter_index] = (target[parameter_index][0], payload)
        mutated_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                  urlencode(query, doseq=True), ""))
        mutated_body = urlencode(form, doseq=True) if form else ""
        cases.append({
            "case": number, "parameter": parameter["name"], "location": location,
            "payload": payload, "method": method,
            "url": mutated_url, "body": mutated_body,
            "contentType": "application/x-www-form-urlencoded" if location == "form" else "",
            "sent": False,
        })
    return {"cases": cases, "count": len(cases), "sent": False,
            "notice": "Drafts only. Review scope and approve each request separately in Repeater."}
