"""Evidence-led correlation of observed services with public CVE references.

Search results are leads, never proof that the observed host is vulnerable.
No target is contacted by this module; NVD lookups are public passive research.
"""
from __future__ import annotations

import json
import re
from cyberlab import cve_search

MAX_ITEMS = 40
MAX_QUERIES = 3
MAX_CVES_PER_QUERY = 10
MAX_TEXT = 240


def _text(value, limit=MAX_TEXT):
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", value).strip()[:limit]


def _query_for(row):
    product = _text(row.get("product"), 100)
    version = _text(row.get("version"), 60)
    service = _text(row.get("service"), 40)
    if product and version:
        return (product + " " + version)[:120]
    if product:
        return product[:120]
    # Service names alone are too broad to support useful CVE correlation.
    return None


def _normalise_rows(scan_result, service_result):
    rows = []
    target = ""
    if isinstance(scan_result, dict):
        target = _text(scan_result.get("target"), 253)
        source_rows = scan_result.get("open_ports", [])
        if isinstance(source_rows, list):
            for item in source_rows[:MAX_ITEMS]:
                if isinstance(item, dict) and item.get("state", "open") == "open":
                    rows.append({
                        "source": "nmap", "host": _text(item.get("host") or target, 253),
                        "port": item.get("port"), "protocol": _text(item.get("protocol") or "tcp", 8),
                        "state": "open", "service": _text(item.get("service"), 40),
                        "product": _text(item.get("product"), 100), "version": _text(item.get("version"), 60),
                        "banner": "", "tls": None,
                    })
    if isinstance(service_result, dict):
        target = target or _text(service_result.get("target"), 253)
        source_rows = service_result.get("services", [])
        if isinstance(source_rows, list):
            for item in source_rows[:MAX_ITEMS]:
                if isinstance(item, dict) and item.get("state") == "open":
                    rows.append({
                        "source": "service_identification", "host": target,
                        "port": item.get("port"), "protocol": "tcp", "state": "open",
                        "service": _text(item.get("service"), 40), "product": "",
                        "version": "", "banner": _text(item.get("banner"), MAX_TEXT),
                        "tls": item.get("tls") if isinstance(item.get("tls"), dict) else None,
                    })
    clean = []
    seen = set()
    for row in rows:
        port = row["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            continue
        key = (row["source"], row["host"], port, row["service"], row["product"], row["version"])
        if key not in seen:
            seen.add(key)
            clean.append(row)
    return target, clean[:MAX_ITEMS]


def build_service_report(scan_result=None, service_result=None, lookup=cve_search):
    if scan_result is not None and not isinstance(scan_result, dict):
        raise ValueError("Nmap evidence must be a JSON object.")
    if service_result is not None and not isinstance(service_result, dict):
        raise ValueError("Service evidence must be a JSON object.")
    target, observations = _normalise_rows(scan_result, service_result)
    queries = list(dict.fromkeys(q for row in observations if (q := _query_for(row))))
    queries = queries[:MAX_QUERIES]
    references = []
    lookup_errors = []
    for query in queries:
        try:
            result = lookup(query, limit=MAX_CVES_PER_QUERY, timeout=8)
            if not isinstance(result, dict) or not isinstance(result.get("results", []), list):
                raise ValueError("NVD returned an unexpected response.")
            for item in result.get("results", [])[:MAX_CVES_PER_QUERY]:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                references.append({
                    "query": query, "id": _text(item.get("id"), 30),
                    "published": _text(item.get("published"), 40),
                    "cvss": item.get("cvss") if isinstance(item.get("cvss"), (int, float)) else None,
                    "severity": _text(item.get("severity"), 20),
                    "description": _text(item.get("description"), 500),
                    "status": "unverified_reference_candidate",
                })
        except Exception as exc:
            lookup_errors.append({"query": query, "error": _text(str(exc), 180)})
    # Deduplicate CVEs while retaining the search terms that surfaced them.
    unique = {}
    for item in references:
        key = item["id"]
        if key not in unique:
            unique[key] = item
        else:
            unique[key]["query"] += "; " + item["query"]
    return {
        "status": "completed",
        "target": target or "Not recorded in supplied evidence",
        "observations": observations,
        "observation_confidence": "high for the fact that the local probe observed an open TCP port; service/banner/version accuracy depends on the remote response",
        "cve_reference_candidates": list(unique.values())[:30],
        "lookup_errors": lookup_errors,
        "queries_performed": queries,
        "findings": [],
        "limitations": [
            "An open port or service banner is not, by itself, evidence of a vulnerability.",
            "NVD keyword matches are unverified reference candidates, not proof of product, version, affected configuration or exploitability.",
            "No authenticated checks, exploit attempts, configuration review or patch-state verification were performed.",
            "TLS certificate metadata and protocol banners may be incomplete, spoofed, hidden or affected by proxies.",
            "Only up to three product/version queries and ten NVD records per query are considered.",
        ],
        "recommended_next_steps": [
            "Verify the exact vendor, product, full version and deployment context from an authorised asset owner.",
            "Compare candidate CVE affected-version ranges and configurations against the verified asset inventory.",
            "Use vendor advisories and official patch records to confirm remediation status.",
            "Prioritise safe configuration review and vendor-supported checks before any active validation.",
        ],
        "source": "NIST National Vulnerability Database keyword search",
        "note": "Evidence correlation only. No vulnerability is declared by this report.",
    }


def validate_report_payload(data):
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    scan = data.get("scanResult")
    services = data.get("serviceResult")
    if scan is None and services is None:
        raise ValueError("Provide at least one Nmap or service-identification evidence result.")
    if scan is not None and not isinstance(scan, dict):
        raise ValueError("Nmap evidence must be a JSON object.")
    if services is not None and not isinstance(services, dict):
        raise ValueError("Service evidence must be a JSON object.")
    if len(json.dumps({"scanResult": scan, "serviceResult": services}, ensure_ascii=False)) > 60000:
        raise ValueError("Evidence payload exceeds the 60 KB limit.")
    return scan, services
