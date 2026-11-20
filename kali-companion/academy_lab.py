"""CyberLab Academy CTF lab — a bundled, deliberately vulnerable target.

A small, self-contained web app the learner attacks on loopback to capture real
flags, Hack-The-Box style. The vulnerabilities are real but the target is a
sandbox you run locally (127.0.0.1 only), so nothing external is touched. Each
challenge yields a flag only by performing the technique (reading robots.txt and
following the hidden path, pulling an exposed .env or .git, inspecting a response
header, or triggering an error-based SQL message).

`build_response` is a pure function (method, path, query) -> (status, headers,
body) so every challenge is unit-tested offline; `start_lab` wraps it in a
loopback http.server on demand.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG_RECON = "CYBERLAB{recon_robots_txt}"
FLAG_ENV = "CYBERLAB{dotenv_secrets_exposed}"
FLAG_GIT = "CYBERLAB{git_source_leak}"
FLAG_HEADER = "CYBERLAB{response_header_leak}"
FLAG_SQLI = "CYBERLAB{error_based_sqli}"
FLAG_IDOR = "CYBERLAB{idor_order_access}"
FLAG_TRAVERSAL = "CYBERLAB{path_traversal_secret}"
FLAG_AUTHBYPASS = "CYBERLAB{cookie_role_forgery}"
FLAG_JWT = "CYBERLAB{jwt_alg_none}"
FLAG_SSRF = "CYBERLAB{ssrf_internal_metadata}"

HIDDEN_PATH = "/flag-7a1c"

# Challenge catalogue surfaced to the learner (no flags here). Tiered by difficulty.
CHALLENGES = [
    {"id": "recon", "tier": 1, "points": 10, "title": "Robots recon",
     "technique": "Read /robots.txt and follow the disallowed path.", "pathHint": "/robots.txt"},
    {"id": "dotenv", "tier": 1, "points": 10, "title": "Exposed .env",
     "technique": "The environment file is web-served and leaks secrets.", "pathHint": "/.env"},
    {"id": "git", "tier": 1, "points": 10, "title": "Exposed .git",
     "technique": "The version-control folder is downloadable.", "pathHint": "/.git/config"},
    {"id": "header", "tier": 1, "points": 10, "title": "Leaky response header",
     "technique": "Inspect the response headers of the status endpoint.", "pathHint": "/api/status"},
    {"id": "sqli", "tier": 2, "points": 20, "title": "Error-based SQL injection",
     "technique": "Break the product query with a single quote.", "pathHint": "/product?id=1"},
    {"id": "idor", "tier": 2, "points": 20, "title": "IDOR on orders",
     "technique": "Your order is id 1001. Change the id to read another user's order.", "pathHint": "/api/orders?id=1001"},
    {"id": "traversal", "tier": 2, "points": 20, "title": "Path traversal",
     "technique": "The download endpoint builds a file path from input. Traverse up to the secret flag file.", "pathHint": "/download?file=report.txt"},
    {"id": "authbypass", "tier": 3, "points": 30, "title": "Cookie auth bypass",
     "technique": "The admin area trusts a client-set role cookie. Forge Cookie: role=admin.", "pathHint": "/admin"},
    {"id": "jwt", "tier": 3, "points": 30, "title": "JWT alg:none",
     "technique": "The profile API accepts an unsigned token. Send a Bearer JWT with alg 'none' and role 'admin'.", "pathHint": "/api/profile"},
    {"id": "ssrf", "tier": 3, "points": 30, "title": "SSRF to internal metadata",
     "technique": "The fetch endpoint will request a URL you supply. Point it at the internal metadata service.", "pathHint": "/fetch?url=https://example.com"},
]

_BASE_HTML = (
    "<!doctype html><html><head><title>CyberLab Vulnerable Shop</title></head>"
    "<body><h1>CyberLab Vulnerable Shop</h1>"
    "<p>A deliberately insecure training target. Find the flags.</p>"
    "<!-- hint: check /robots.txt, /.env, /.git/config, /api/status headers, and /product?id= -->"
    "<ul><li><a href='/product?id=1'>Product 1</a></li></ul></body></html>"
)


def _text(status, body, extra=None):
    headers = [("Content-Type", "text/plain; charset=utf-8")]
    if extra:
        headers.extend(extra)
    return status, headers, body


def _decode_jwt(token: str) -> tuple:
    """Decode a JWT header and payload (no signature verification — that's the point)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, None

        def seg(part):
            part += "=" * (-len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(part.encode()))
        return seg(parts[0]), seg(parts[1])
    except Exception:
        return None, None


def build_response(method: str, path: str, query: str = "", headers: dict | None = None) -> tuple:
    """Pure request handler for the lab. Returns (status, headers, body)."""
    path = path or "/"
    hdr = {k.lower(): v for k, v in (headers or {}).items()}
    if method not in ("GET", "HEAD"):
        return _text(405, "Method Not Allowed")

    if path == "/":
        # Intentionally omits security headers so the assessment tool flags them.
        return 200, [("Content-Type", "text/html; charset=utf-8")], _BASE_HTML
    if path == "/robots.txt":
        return _text(200, "User-agent: *\nDisallow: %s\n" % HIDDEN_PATH)
    if path == HIDDEN_PATH:
        return _text(200, "Nice recon. Flag: %s\n" % FLAG_RECON)
    if path == "/.env":
        return _text(200, "APP_ENV=production\nAPP_DEBUG=false\nDB_PASSWORD=hunter2\nFLAG=%s\n" % FLAG_ENV)
    if path == "/.git/HEAD":
        return _text(200, "ref: refs/heads/main\n")
    if path == "/.git/config":
        return _text(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                          "\turl = git@example.com:shop.git\n# flag: %s\n" % FLAG_GIT)
    if path == "/api/status":
        return 200, [("Content-Type", "application/json"), ("X-Flag", FLAG_HEADER)], json.dumps({"status": "ok"})
    if path == "/product":
        ident = (parse_qs(query).get("id", [""])[0])
        if "'" in ident or '"' in ident:
            return _text(500, "SQL error: You have an error in your SQL syntax near '%s'. "
                              "Debug flag: %s\n" % (ident[:40], FLAG_SQLI))
        return 200, [("Content-Type", "text/html; charset=utf-8")], (
            "<html><body><h2>Product %s</h2><p>In stock.</p></body></html>" % (ident[:20] or "1"))

    # Tier 2 — IDOR: order 1001 is "yours"; any other existing id leaks another user's order.
    if path == "/api/orders":
        oid = parse_qs(query).get("id", ["1001"])[0]
        if oid == "1001":
            return 200, [("Content-Type", "application/json")], json.dumps({"id": 1001, "owner": "you", "item": "Mug", "total": 12})
        if oid == "1000":
            return 200, [("Content-Type", "application/json")], json.dumps({"id": 1000, "owner": "victim", "item": "Laptop", "flag": FLAG_IDOR})
        return _text(404, "No such order")

    # Tier 2 — Path traversal: a filename that climbs out of the docs folder reaches the secret.
    if path == "/download":
        fname = parse_qs(query).get("file", [""])[0]
        if ".." in fname and "flag" in fname.lower():
            return _text(200, "Secret file contents. Flag: %s\n" % FLAG_TRAVERSAL)
        if fname:
            return _text(200, "Report: quarterly figures for %s\n" % fname[:40])
        return _text(400, "Provide a file parameter, e.g. ?file=report.txt")

    # Tier 3 — Auth bypass: the admin area trusts a client-set role cookie.
    if path == "/admin":
        cookie = str(hdr.get("cookie", ""))
        if "role=admin" in cookie.replace(" ", ""):
            return _text(200, "Admin dashboard. Flag: %s\n" % FLAG_AUTHBYPASS)
        return _text(403, "Forbidden: admin role required.")

    # Tier 3 — JWT alg:none: the API accepts an unsigned admin token.
    if path == "/api/profile":
        auth = str(hdr.get("authorization", ""))
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        head, payload = _decode_jwt(token)
        if head and payload and str(head.get("alg", "")).lower() == "none" and (
                payload.get("role") == "admin" or payload.get("admin") is True):
            return 200, [("Content-Type", "application/json")], json.dumps({"role": "admin", "flag": FLAG_JWT})
        return _text(401, "Unauthorized: valid admin token required.")

    # Tier 3 — SSRF: the fetcher would request a user-supplied URL; internal targets leak metadata.
    # The lab does NOT actually perform any request — it recognises the internal target and returns the lesson flag.
    if path == "/fetch":
        target = parse_qs(query).get("url", [""])[0].lower()
        internal = ("169.254.169.254", "127.0.0.1", "localhost", "metadata.internal", "::1")
        if target and any(host in target for host in internal):
            return _text(200, "Internal metadata response (simulated). Flag: %s\n" % FLAG_SSRF)
        if target:
            return _text(200, "Fetched external URL (allowed).")
        return _text(400, "Provide a url parameter.")
    return _text(404, "Not Found")


def flags() -> dict:
    """The authoritative flag answers (used by tests and grading parity)."""
    return {"recon": FLAG_RECON, "dotenv": FLAG_ENV, "git": FLAG_GIT, "header": FLAG_HEADER,
            "sqli": FLAG_SQLI, "idor": FLAG_IDOR, "traversal": FLAG_TRAVERSAL,
            "authbypass": FLAG_AUTHBYPASS, "jwt": FLAG_JWT, "ssrf": FLAG_SSRF}


class _LabHandler(BaseHTTPRequestHandler):
    def _serve(self):
        parts = urlsplit(self.path)
        status, headers, body = build_response(self.command, parts.path, parts.query, dict(self.headers.items()))
        data = body.encode("utf-8")
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve()

    def log_message(self, *_args):  # silence default logging
        return


_server = None
_server_thread = None
_lock = threading.Lock()
DEFAULT_PORT = 8787


def start_lab(port: int = DEFAULT_PORT) -> dict:
    """Start the loopback lab server (idempotent). Returns base URL + challenges."""
    global _server, _server_thread
    with _lock:
        if _server is None:
            _server = ThreadingHTTPServer(("127.0.0.1", port), _LabHandler)
            _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
            _server_thread.start()
        bound = _server.server_address[1]
    return {"status": "running", "baseUrl": "http://127.0.0.1:%d/" % bound,
            "port": bound, "challenges": CHALLENGES,
            "note": "Loopback-only training target. Capture each flag and submit it in the Academy."}


def stop_lab() -> dict:
    global _server, _server_thread
    with _lock:
        if _server is not None:
            _server.shutdown()
            _server.server_close()
            _server = None
            _server_thread = None
    return {"status": "stopped"}


def lab_status() -> dict:
    with _lock:
        running = _server is not None
        port = _server.server_address[1] if running else None
    return {"status": "running" if running else "stopped",
            "baseUrl": "http://127.0.0.1:%d/" % port if running else None,
            "challenges": CHALLENGES}
