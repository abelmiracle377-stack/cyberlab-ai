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

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG_RECON = "CYBERLAB{recon_robots_txt}"
FLAG_ENV = "CYBERLAB{dotenv_secrets_exposed}"
FLAG_GIT = "CYBERLAB{git_source_leak}"
FLAG_HEADER = "CYBERLAB{response_header_leak}"
FLAG_SQLI = "CYBERLAB{error_based_sqli}"

HIDDEN_PATH = "/flag-7a1c"

# Challenge catalogue surfaced to the learner (no flags here).
CHALLENGES = [
    {"id": "recon", "title": "Robots recon", "technique": "Read /robots.txt and follow the disallowed path.",
     "pathHint": "/robots.txt"},
    {"id": "dotenv", "title": "Exposed .env", "technique": "The environment file is web-served and leaks secrets.",
     "pathHint": "/.env"},
    {"id": "git", "title": "Exposed .git", "technique": "The version-control folder is downloadable.",
     "pathHint": "/.git/config"},
    {"id": "header", "title": "Leaky response header", "technique": "Inspect the response headers of the status endpoint.",
     "pathHint": "/api/status"},
    {"id": "sqli", "title": "Error-based SQL injection", "technique": "Break the product query with a single quote.",
     "pathHint": "/product?id=1"},
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


def build_response(method: str, path: str, query: str = "") -> tuple:
    """Pure request handler for the lab. Returns (status, headers, body)."""
    path = path or "/"
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
    return _text(404, "Not Found")


def flags() -> dict:
    """The authoritative flag answers (used by tests and grading parity)."""
    return {"recon": FLAG_RECON, "dotenv": FLAG_ENV, "git": FLAG_GIT, "header": FLAG_HEADER, "sqli": FLAG_SQLI}


class _LabHandler(BaseHTTPRequestHandler):
    def _serve(self):
        parts = urlsplit(self.path)
        status, headers, body = build_response(self.command, parts.path, parts.query)
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
