"""Shodan connector: OSINT host and search lookups over the official API.

Lets CyberLab-AI query Shodan (https://www.shodan.io) for internet-exposure
reconnaissance — host details, search results, DNS resolution and account info —
using the operator's own API key. This is read-only OSINT against Shodan's public
index; it performs no scanning or interaction with any target itself. Real HTTP
(urllib); the network call is injectable so tests never touch the network.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from urllib.parse import urlencode

API_BASE = "https://api.shodan.io"


def _get(url: str, timeout: int = 30, opener=None) -> tuple:
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    if opener is not None:
        response = opener(request, timeout=timeout)
    else:  # pragma: no cover - exercised only against the live API
        response = urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context())
    status = getattr(response, "status", None) or response.getcode()
    raw = response.read()
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return status, text


def _call(path: str, api_key: str, params: dict | None = None, timeout: int = 30, opener=None) -> dict:
    if not api_key:
        raise ValueError("A Shodan API key is required.")
    query = dict(params or {})
    query["key"] = api_key
    url = f"{API_BASE}{path}?{urlencode(query)}"
    status, text = _get(url, timeout=timeout, opener=opener)
    try:
        data = json.loads(text) if text else {}
    except json.JSONDecodeError:
        data = {"raw": text[:2000]}
    if status >= 400:
        raise RuntimeError(f"Shodan API error {status}: {data.get('error', text[:200])}")
    return data


def api_info(api_key: str, timeout: int = 30, opener=None) -> dict:
    """Account/plan info and remaining query credits."""
    return _call("/api-info", api_key, timeout=timeout, opener=opener)


def host_lookup(ip: str, api_key: str, history: bool = False, timeout: int = 30, opener=None) -> dict:
    """All services Shodan has observed on one IP."""
    if not ip:
        raise ValueError("An IP address is required.")
    return _call(f"/shodan/host/{ip}", api_key, {"history": "true" if history else "false"}, timeout, opener)


def search(query: str, api_key: str, page: int = 1, timeout: int = 30, opener=None) -> dict:
    """Search the Shodan index (consumes query credits)."""
    if not query:
        raise ValueError("A search query is required.")
    return _call("/shodan/host/search", api_key, {"query": query, "page": max(1, int(page))}, timeout, opener)


def dns_resolve(hostnames, api_key: str, timeout: int = 30, opener=None) -> dict:
    """Resolve hostnames to IPs via Shodan DNS."""
    names = hostnames if isinstance(hostnames, str) else ",".join(hostnames)
    if not names:
        raise ValueError("At least one hostname is required.")
    return _call("/dns/resolve", api_key, {"hostnames": names}, timeout, opener)


def normalize_host(result: dict) -> dict:
    """Compact a host result into the fields an analyst reads first."""
    data = result.get("data") or []
    ports = sorted({item.get("port") for item in data if item.get("port") is not None})
    services = [{
        "port": item.get("port"),
        "transport": item.get("transport"),
        "product": item.get("product"),
        "version": item.get("version"),
        "banner": (item.get("data") or "")[:160],
    } for item in data]
    vulns = result.get("vulns") or []
    return {
        "ip": result.get("ip_str") or result.get("ip"),
        "org": result.get("org"),
        "isp": result.get("isp"),
        "os": result.get("os"),
        "country": result.get("country_name"),
        "hostnames": result.get("hostnames") or [],
        "ports": ports,
        "service_count": len(services),
        "services": services,
        "vulns": sorted(vulns),
        "last_update": result.get("last_update"),
    }


def normalize_search(result: dict, limit: int = 50) -> dict:
    """Compact search matches to ip/port/org/product for quick triage."""
    matches = result.get("matches") or []
    rows = [{
        "ip": m.get("ip_str"),
        "port": m.get("port"),
        "org": m.get("org"),
        "product": m.get("product"),
        "hostnames": m.get("hostnames") or [],
        "location": (m.get("location") or {}).get("country_name"),
    } for m in matches[:limit]]
    return {"total": result.get("total", len(rows)), "count": len(rows), "matches": rows}
