"""Read-only, loopback-only Burp Suite REST API health connector.

The API key is stored locally and is never returned to callers or model context.
This module does not start scans, alter scope, or send requests to target systems.
"""
from __future__ import annotations

import os
import socket
import shutil
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import json

CONFIG_DIR = Path.home() / ".config" / "cyberlab"
DEFAULT_API_URL = "http://127.0.0.1:1337"
DEFAULT_TIMEOUT_SECONDS = 2.0


def _loopback_base_url(value: str) -> str:
    """Accept only an HTTP(S) URL bound to a loopback address."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Burp REST API must use http or https.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Burp REST API URL must not contain credentials, query, or fragment.")
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "::1"}:
        try:
            if not ipaddress_is_loopback(host):
                raise ValueError("Burp REST API must bind to loopback only.")
        except ValueError:
            raise
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Burp REST API port is invalid.")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def ipaddress_is_loopback(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _load_api_key() -> str | None:
    configured = os.environ.get("CYBERLAB_BURP_API_KEY", "").strip()
    if configured:
        return configured
    key_file = Path(os.environ.get(
        "CYBERLAB_BURP_API_KEY_FILE",
        str(CONFIG_DIR / "burp-api-key"),
    )).expanduser()
    try:
        key = key_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return key or None


def inspect_burp_status(
    api_url: str | None = None,
    api_key: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Return a safe Burp connection snapshot without disclosing secrets."""
    executable = shutil.which("burpsuite")
    raw_url = api_url or os.environ.get("CYBERLAB_BURP_API_URL", DEFAULT_API_URL)
    try:
        base_url = _loopback_base_url(raw_url)
    except (TypeError, ValueError):
        return {
            "status": "invalid_configuration",
            "installed": bool(executable),
            "executable_available": bool(executable),
            "api_configured": False,
            "edition": "unknown",
            "capabilities": {"rest_api_health": False, "proxy_history": "not_implemented",
                             "site_map": "not_implemented", "scanner": "not_implemented"},
            "error": "Burp API URL is invalid; configure a loopback-only HTTP(S) address.",
        }

    key = api_key if api_key is not None else _load_api_key()
    if not key:
        return {
            "status": "not_configured",
            "installed": bool(executable),
            "executable_available": bool(executable),
            "api_configured": False,
            "api_url": base_url,
            "edition": "unknown",
            "capabilities": {"rest_api_health": False, "proxy_history": "not_implemented",
                             "site_map": "not_implemented", "scanner": "not_implemented"},
            "next_step": "Enable Burp Suite's REST API on loopback, create an API key, and store it in ~/.config/cyberlab/burp-api-key with file permissions 600.",
        }

    if not isinstance(key, str) or len(key) > 512 or any(ch in key for ch in "\r\n"):
        return {
            "status": "invalid_configuration",
            "installed": bool(executable),
            "executable_available": bool(executable),
            "api_configured": False,
            "edition": "unknown",
            "capabilities": {"rest_api_health": False, "proxy_history": "not_implemented",
                             "site_map": "not_implemented", "scanner": "not_implemented"},
            "error": "Burp API key format is invalid.",
        }

    endpoint = base_url + "/" + quote(key, safe="")
    request = Request(endpoint, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=max(0.2, min(float(timeout), 5.0))) as response:
            code = getattr(response, "status", 200)
            if 200 <= code < 300:
                return {
                    "status": "connected",
                    "installed": bool(executable),
                    "executable_available": bool(executable),
                    "api_configured": True,
                    "api_reachable": True,
                    "api_url": base_url,
                    "edition": "unknown",
                    "capabilities": {"rest_api_health": True, "proxy_history": "not_implemented",
                                     "site_map": "not_implemented", "scanner": "not_implemented"},
                    "note": "Burp REST API is reachable. Edition and operational feature support have not yet been verified.",
                }
            return {
                "status": "api_error",
                "installed": bool(executable),
                "executable_available": bool(executable),
                "api_configured": True,
                "api_reachable": True,
                "api_url": base_url,
                "edition": "unknown",
                "error": "Burp REST API returned HTTP " + str(code) + ".",
            }
    except HTTPError as exc:
        status = "authentication_failed" if exc.code in {401, 403} else "api_error"
        return {
            "status": status,
            "installed": bool(executable),
            "executable_available": bool(executable),
            "api_configured": True,
            "api_reachable": True,
            "api_url": base_url,
            "edition": "unknown",
            "error": "Burp REST API returned HTTP " + str(exc.code) + ".",
        }
    except (URLError, TimeoutError, socket.timeout, OSError):
        return {
            "status": "unavailable",
            "installed": bool(executable),
            "executable_available": bool(executable),
            "api_configured": True,
            "api_reachable": False,
            "api_url": base_url,
            "edition": "unknown",
            "error": "Burp REST API is not reachable on the configured loopback address.",
        }


EXTENSION_TOKEN_FILE = Path.home() / ".config" / "cyberlab" / "burp-extension-token"
EXTENSION_HEALTH_URL = "http://127.0.0.1:8766/v1/health"


def inspect_burp_extension_status(opener=None) -> dict:
    opener = opener or urlopen
    """Check the authenticated local Montoya extension independently of Burp REST API."""
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "connector": "montoya"}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "connector": "montoya"}
    request = Request(EXTENSION_HEALTH_URL, headers={"Accept": "application/json", "Authorization": "Bearer " + token}, method="GET")
    try:
        with opener(request, timeout=2.5) as response:
            if getattr(response, "status", 200) != 200:
                return {"status": "api_error", "connector": "montoya"}
            payload = json.loads(response.read(8192).decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "ok" or payload.get("connector") != "montoya":
            return {"status": "invalid_response", "connector": "montoya"}
        return {"status": "connected", "connector": "montoya", "authenticated": True,
                "capabilities": ["proxy_history", "site_map", "audit_issues", "repeater_handoff", "confirmed_single_request_replay"],
                "note": "The local CyberLab Burp extension is reachable. This is separate from the Burp REST API health check."}
    except HTTPError as exc:
        return {"status": "authentication_failed" if exc.code in {401, 403} else "api_error", "connector": "montoya"}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "connector": "montoya"}

EXTENSION_HISTORY_URL = "http://127.0.0.1:8766/v1/proxy/history"


def inspect_burp_proxy_history(limit: int = 50) -> dict:
    """Read redacted, in-scope proxy-history metadata from the local Montoya extension."""
    try:
        bounded_limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        bounded_limit = 50
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "items": [], "count": 0}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "items": [], "count": 0}
    request = Request(
        EXTENSION_HISTORY_URL + "?limit=" + str(bounded_limit),
        headers={"Accept": "application/json", "Authorization": "Bearer " + token},
        method="GET",
    )
    try:
        with urlopen(request, timeout=2.5) as response:
            if getattr(response, "status", 200) != 200:
                return {"status": "api_error", "items": [], "count": 0}
            payload = json.loads(response.read(256 * 1024).decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            return {"status": "invalid_response", "items": [], "count": 0}
        items = payload["items"][:bounded_limit]
        safe_items = []
        for item in items:
            if not isinstance(item, dict) or item.get("in_scope") is not True:
                continue
            url = item.get("url")
            method = item.get("method")
            if not isinstance(url, str) or not isinstance(method, str):
                continue
            safe_items.append({
                "id": item.get("id") if isinstance(item.get("id"), int) else None,
                "timestamp": item.get("timestamp") if isinstance(item.get("timestamp"), str) else None,
                "method": method[:20],
                "url": url[:2048],
                "status_code": item.get("status_code") if isinstance(item.get("status_code"), int) else None,
                "in_scope": True,
            })
        return {"status": "connected", "items": safe_items, "count": len(safe_items)}
    except HTTPError as exc:
        return {"status": "authentication_failed" if exc.code in {401, 403} else "api_error",
                "items": [], "count": 0}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "items": [], "count": 0}


EXTENSION_SITE_MAP_URL = "http://127.0.0.1:8766/v1/site-map"


def inspect_burp_site_map(limit: int = 50) -> dict:
    """Read bounded, redacted, in-scope site-map metadata from the local Montoya extension."""
    try:
        bounded_limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        bounded_limit = 50
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "items": [], "count": 0}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "items": [], "count": 0}
    request = Request(
        EXTENSION_SITE_MAP_URL + "?limit=" + str(bounded_limit),
        headers={"Accept": "application/json", "Authorization": "Bearer " + token},
        method="GET",
    )
    try:
        with urlopen(request, timeout=2.5) as response:
            if getattr(response, "status", 200) != 200:
                return {"status": "api_error", "items": [], "count": 0}
            payload = json.loads(response.read(256 * 1024).decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            return {"status": "invalid_response", "items": [], "count": 0}
        safe_items = []
        for item in payload["items"][:bounded_limit]:
            if not isinstance(item, dict) or item.get("in_scope") is not True:
                continue
            url = item.get("url")
            method = item.get("method")
            if not isinstance(url, str) or not isinstance(method, str):
                continue
            safe_items.append({
                "method": method[:20],
                "url": url[:2048],
                "status_code": item.get("status_code") if isinstance(item.get("status_code"), int) else None,
                "in_scope": True,
            })
        return {"status": "connected", "items": safe_items, "count": len(safe_items)}
    except HTTPError as exc:
        return {"status": "authentication_failed" if exc.code in {401, 403} else "api_error",
                "items": [], "count": 0}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "items": [], "count": 0}



EXTENSION_ISSUES_URL = "http://127.0.0.1:8766/v1/issues"


def inspect_burp_issues(limit: int = 50) -> dict:
    """Read bounded severity metadata for existing in-scope Burp audit issues."""
    try:
        bounded_limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        bounded_limit = 50
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "items": [], "count": 0}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "items": [], "count": 0}
    request = Request(
        EXTENSION_ISSUES_URL + "?limit=" + str(bounded_limit),
        headers={"Accept": "application/json", "Authorization": "Bearer " + token},
        method="GET",
    )
    try:
        with urlopen(request, timeout=2.5) as response:
            if getattr(response, "status", 200) != 200:
                return {"status": "api_error", "items": [], "count": 0}
            payload = json.loads(response.read(128 * 1024).decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            return {"status": "invalid_response", "items": [], "count": 0}
        safe_items = []
        for item in payload["items"][:bounded_limit]:
            if not isinstance(item, dict) or item.get("in_scope") is not True:
                continue
            name = item.get("name")
            base_url = item.get("base_url")
            severity = item.get("severity")
            confidence = item.get("confidence")
            if not all(isinstance(value, str) for value in (name, base_url, severity, confidence)):
                continue
            safe_items.append({
                "name": name[:200],
                "base_url": base_url[:2048],
                "severity": severity[:40],
                "confidence": confidence[:40],
                "in_scope": True,
            })
        return {"status": "connected", "items": safe_items, "count": len(safe_items)}
    except HTTPError as exc:
        return {"status": "authentication_failed" if exc.code in {401, 403} else "api_error",
                "items": [], "count": 0}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "items": [], "count": 0}


EXTENSION_REPEATER_URL = "http://127.0.0.1:8766/v1/repeater/from-history"
EXTENSION_SEND_URL = "http://127.0.0.1:8766/v1/send-request"


def send_in_scope_request(history_id: int, confirmed: bool = False, opener=urlopen) -> dict:
    """Replay one explicitly confirmed in-scope proxy-history request through Burp.

    Returns bounded response metadata (status code, body length, MIME type). The
    extension refuses out-of-scope requests; no request or response body is read.
    """
    if isinstance(history_id, bool) or not isinstance(history_id, int) or history_id < 1:
        return {"status": "invalid_request", "request_sent": False}
    if confirmed is not True:
        return {"status": "confirmation_required", "request_sent": False}
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "request_sent": False}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "request_sent": False}
    request = Request(
        EXTENSION_SEND_URL + "?id=" + str(history_id) + "&confirm=true",
        data=b"",
        headers={"Accept": "application/json", "Authorization": "Bearer " + token},
        method="POST",
    )
    try:
        with opener(request, timeout=15) as response:
            payload = json.loads(response.read(8192).decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "sent":
            return {"status": "invalid_response", "request_sent": False}
        return {
            "status": "sent", "request_sent": True, "history_id": history_id,
            "method": str(payload.get("method", "")),
            "status_code": payload.get("status_code"),
            "mime_type": str(payload.get("mime_type", "")),
            "body_length": payload.get("body_length"),
            "note": "Replayed one in-scope request through Burp. Review the response in Burp; only metadata is returned here.",
        }
    except HTTPError as exc:
        return {"status": "out_of_scope" if exc.code == 403 else (
            "authentication_failed" if exc.code == 401 else "api_error"),
            "request_sent": False}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "request_sent": False}


def open_burp_history_in_repeater(history_id: int, confirmed: bool = False) -> dict:
    """Place one in-scope captured request into Repeater; this does not send it."""
    if isinstance(history_id, bool) or not isinstance(history_id, int) or history_id < 1:
        return {"status": "invalid_request", "request_sent": False}
    if confirmed is not True:
        return {"status": "confirmation_required", "request_sent": False}
    try:
        token = EXTENSION_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"status": "not_configured", "request_sent": False}
    if not token or len(token) > 256 or any(ch in token for ch in "\r\n"):
        return {"status": "invalid_configuration", "request_sent": False}
    request = Request(
        EXTENSION_REPEATER_URL + "?id=" + str(history_id) + "&confirm=true",
        data=b"",
        headers={"Accept": "application/json", "Authorization": "Bearer " + token},
        method="POST",
    )
    try:
        with urlopen(request, timeout=2.5) as response:
            payload = json.loads(response.read(8192).decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "opened_in_repeater":
            return {"status": "invalid_response", "request_sent": False}
        return {"status": "opened_in_repeater", "history_id": history_id, "request_sent": False}
    except HTTPError as exc:
        return {"status": "out_of_scope" if exc.code == 403 else (
            "authentication_failed" if exc.code in {401, 403} else "api_error"),
            "request_sent": False}
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError, UnicodeDecodeError):
        return {"status": "unavailable", "request_sent": False}
