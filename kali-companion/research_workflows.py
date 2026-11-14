"""Fixed, bounded passive research actions for the local CyberLab bridge.

No shell execution, target probing, credential handling, or package installation.
"""
from __future__ import annotations

import ipaddress
import json
import re

from cyberlab import cve_search, dns_lookup, domain_osint, ip_intelligence

MAX_OUTPUT_BYTES = 512_000
ACTIONS = {"dns", "domain", "ip", "cve"}


def run_research_action(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    action = data.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError("Choose one supported research action: dns, domain, ip or cve.")

    if action in {"dns", "domain"}:
        value = data.get("value")
        if not isinstance(value, str) or len(value) > 253:
            raise ValueError("Enter one public domain name (maximum 253 characters).")
        result = dns_lookup(value, timeout=8) if action == "dns" else domain_osint(value, timeout=8)
    elif action == "ip":
        value = data.get("value")
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError("Enter one public IP address.")
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("Enter a valid public IPv4 or IPv6 address.") from exc
        if not address.is_global:
            raise ValueError("Only public global IP addresses are accepted.")
        result = ip_intelligence(str(address), timeout=8)
    else:
        value = data.get("value")
        if not isinstance(value, str) or len(value.strip()) < 2 or len(value.strip()) > 120:
            raise ValueError("Enter a CVE keyword, product, vendor or version (2–120 characters).")
        limit = data.get("limit", 10)
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Result limit must be an integer from 1 to 20.")
        result = cve_search(value, limit=limit, timeout=8)

    encoded = json.dumps(result, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("Research response exceeded the 512 KB output limit; narrow the query.")
    return {"status": "completed", "action": action, "result": result,
            "execution": "passive_public_source_lookup",
            "note": "This action queried public registration, DNS, certificate-transparency or vulnerability data only. It did not scan, exploit, authenticate to or modify a target."}
