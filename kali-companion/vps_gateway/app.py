"""Per-operator CyberLab VPS gateway.

Run behind a TLS reverse proxy. This service never activates device sensors:
a companion must obtain and maintain explicit OS/browser permission locally.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import shutil
import sys
import secrets
import sqlite3
import time
import threading
import uuid
from collections import deque
from pathlib import Path
from typing import Optional, Literal

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, ConfigDict

DB_PATH = Path(os.environ.get("CYBERLAB_GATEWAY_DB", "/var/lib/cyberlab-gateway/registry.sqlite3"))
DATA_DIR = Path(os.environ.get("CYBERLAB_GATEWAY_FILES", "/var/lib/cyberlab-gateway/files"))
OWNER_TOKEN = os.environ.get("CYBERLAB_OWNER_TOKEN", "")
PAIR_TTL = 600
MAX_UPLOAD = 25 * 1024 * 1024
PAIRING_ATTEMPT_LIMIT = 30
PAIRING_WINDOW_SECONDS = 15 * 60
_PAIRING_ATTEMPTS = deque()
_PAIRING_ATTEMPTS_LOCK = threading.Lock()


def enforce_pairing_rate_limit() -> None:
    """Bound short-code guesses per gateway process; deploy behind a firewall/WAF too."""
    now = time.monotonic()
    with _PAIRING_ATTEMPTS_LOCK:
        while _PAIRING_ATTEMPTS and now - _PAIRING_ATTEMPTS[0] >= PAIRING_WINDOW_SECONDS:
            _PAIRING_ATTEMPTS.popleft()
        if len(_PAIRING_ATTEMPTS) >= PAIRING_ATTEMPT_LIMIT:
            raise HTTPException(429, "Too many pairing attempts. Wait before trying again.")
        _PAIRING_ATTEMPTS.append(now)
app = FastAPI(title="CyberLab Personal VPS Gateway", version="0.1.0")


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS pairing (
      code_hash TEXT PRIMARY KEY, device_name TEXT NOT NULL, platform TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL,
      token_hash TEXT NOT NULL, permissions TEXT NOT NULL,
      created_at INTEGER NOT NULL, last_seen INTEGER, revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY, device_id TEXT NOT NULL, name TEXT NOT NULL,
      media_type TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
      created_at INTEGER NOT NULL, FOREIGN KEY(device_id) REFERENCES devices(id)
    );
    CREATE TABLE IF NOT EXISTS shares (
      token_hash TEXT PRIMARY KEY, file_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
      FOREIGN KEY(file_id) REFERENCES files(id)
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, device_id TEXT, event_type TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
    );
    """)
    con.executescript("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, device_role TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL, approval_reference TEXT NOT NULL, status TEXT NOT NULL, lease_token_hash TEXT, lease_expires_at INTEGER, result TEXT, error TEXT, result_sha256 TEXT, evidence_record_hash TEXT, previous_evidence_hash TEXT, created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, expires_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS jobs_device_status_idx ON jobs(device_id,status,created_at); CREATE TABLE IF NOT EXISTS relay_evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT UNIQUE NOT NULL, device_id TEXT NOT NULL, action TEXT NOT NULL, approval_reference TEXT NOT NULL, status TEXT NOT NULL, result_sha256 TEXT NOT NULL, previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL, created_at INTEGER NOT NULL);")
    job_columns = {row[1] for row in con.execute("PRAGMA table_info(jobs)")}
    for column in ("result_sha256", "evidence_record_hash", "previous_evidence_hash"):
        if column not in job_columns:
            con.execute("ALTER TABLE jobs ADD COLUMN " + column + " TEXT")
    return con


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def log_event(con, device_id: Optional[str], event_type: str, detail: str = "") -> None:
    """Append an audit event within the caller's open transaction."""
    con.execute(
        "INSERT INTO events(id,device_id,event_type,detail,created_at) VALUES(?,?,?,?,?)",
        (str(uuid.uuid4()), device_id, str(event_type)[:40], str(detail)[:200], int(time.time())),
    )


def owner_auth(authorization: Optional[str] = Header(default=None)):
    if not OWNER_TOKEN:
        raise HTTPException(503, "Gateway owner token is not configured.")
    supplied = authorization[7:] if isinstance(authorization, str) and authorization.startswith("Bearer ") else ""
    if not supplied or len(supplied) > 512 or not hmac.compare_digest(supplied, OWNER_TOKEN):
        raise HTTPException(401, "Owner authentication required.")
    return True


def device_auth(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Device authentication required.")
    token = authorization[7:]
    if not 32 <= len(token) <= 512:
        raise HTTPException(401, "Device token is invalid or revoked.")
    con = db()
    row = con.execute("SELECT * FROM devices WHERE token_hash=?", (digest(token),)).fetchone()
    con.close()
    if not row or row["revoked"]:
        raise HTTPException(401, "Device token is invalid or revoked.")
    return dict(row)


class PairRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=80)
    platform: str = Field(min_length=1, max_length=40)


class AcceptPairing(BaseModel):
    code: str = Field(min_length=6, max_length=12)
    participant_label: str = Field(min_length=1, max_length=80)
    terms_accepted: bool
    permissions: dict[str, bool]


@app.get("/consent", response_class=HTMLResponse)
def consent_page():
    consent_file = Path(__file__).with_name("consent.html")
    if not consent_file.is_file():
        raise HTTPException(404, "Device consent page is unavailable.")
    return HTMLResponse(consent_file.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberlab-personal-vps-gateway"}


@app.get("/v1/owner/diagnostics", dependencies=[Depends(owner_auth)])
def owner_diagnostics():
    """Return limited host compatibility facts to the authenticated VPS owner."""
    try:
        distro = platform.freedesktop_os_release()
        os_name = distro.get("PRETTY_NAME") or distro.get("ID") or platform.system()
    except (AttributeError, OSError):
        os_name = platform.system()
    memory_bytes = None
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as meminfo:
            for line in meminfo:
                if line.startswith("MemAvailable:"):
                    memory_bytes = int(line.split()[1]) * 1024
                    break
    except (OSError, ValueError, IndexError):
        pass
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(DATA_DIR)
    python_ok = sys.version_info >= (3, 10)
    linux_ok = platform.system() == "Linux"
    memory_ok = memory_bytes is not None and memory_bytes >= 1536 * 1024 * 1024
    disk_ok = disk.free >= 2 * 1024 * 1024 * 1024
    checks = [
        {"name": "Operating system", "status": "pass" if linux_ok else "fail",
         "detail": os_name, "required": "Linux"},
        {"name": "Python", "status": "pass" if python_ok else "fail",
         "detail": platform.python_version(), "required": "3.10 or newer"},
        {"name": "Available memory", "status": "pass" if memory_ok else "warning",
         "detail_bytes": memory_bytes, "required_bytes": 1536 * 1024 * 1024},
        {"name": "Free storage", "status": "pass" if disk_ok else "warning",
         "detail_bytes": disk.free, "required_bytes": 2 * 1024 * 1024 * 1024},
    ]
    compatible = linux_ok and python_ok
    return {
        "status": "compatible" if compatible else "incompatible",
        "checks": checks,
        "gateway": "healthy",
        "notes": [
            "Memory and disk checks are advisory; workload and retention needs may require more.",
            "Only the authenticated owner can retrieve these diagnostics.",
            "Hostname, IP addresses, usernames and environment variables are not disclosed.",
        ],
    }


@app.post("/v1/pairing", dependencies=[Depends(owner_auth)])
def create_pairing(body: PairRequest):
    code = str(secrets.randbelow(90000000) + 10000000)
    now = int(time.time())
    con = db()
    con.execute("DELETE FROM pairing WHERE expires_at < ?", (now,))
    con.execute("INSERT INTO pairing VALUES (?, ?, ?, ?)",
                (digest(code), body.device_name, body.platform, now + PAIR_TTL))
    con.commit()
    con.close()
    return {"pairing_code": code, "expires_in_seconds": PAIR_TTL,
            "notice": "Share this one-time code only with the intended device owner."}


@app.post("/v1/pairing/accept")
def accept_pairing(body: AcceptPairing):
    enforce_pairing_rate_limit()
    if not body.terms_accepted:
        raise HTTPException(403, "The participant must accept the disclosed terms.")
    if not body.permissions or not any(body.permissions.values()):
        raise HTTPException(400, "At least one explicitly granted permission is required.")
    allowed = {"microphone", "camera", "screen_capture", "location", "file_upload", "job_execution"}
    if set(body.permissions) - allowed:
        raise HTTPException(400, "Unknown permission requested.")
    now = int(time.time())
    con = db()
    pairing = con.execute("SELECT * FROM pairing WHERE code_hash=? AND expires_at>=?",
                         (digest(body.code), now)).fetchone()
    if not pairing:
        con.close()
        raise HTTPException(404, "Pairing code is invalid or expired.")
    device_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
    con.execute("DELETE FROM pairing WHERE code_hash=?", (digest(body.code),))
    con.execute("INSERT INTO devices(id,name,platform,token_hash,permissions,created_at,last_seen,revoked) VALUES(?,?,?,?,?,?,?,0)",
                (device_id, body.participant_label, pairing["platform"], digest(token),
                 json.dumps(body.permissions), now, now))
    log_event(con, device_id, "device_paired",
              body.participant_label + " · " + ",".join(sorted(k for k, v in body.permissions.items() if v)))
    con.commit()
    con.close()
    return {"device_id": device_id, "device_token": token,
            "permissions": body.permissions,
            "message": "Store the device token securely; it is shown only once."}


@app.get("/v1/devices", dependencies=[Depends(owner_auth)])
def list_devices():
    con = db()
    rows = con.execute("SELECT id,name,platform,permissions,created_at,last_seen,revoked FROM devices ORDER BY created_at DESC").fetchall()
    con.close()
    now = int(time.time())
    return {"devices": [{
        "device_id": r["id"], "name": r["name"], "platform": r["platform"],
        "permissions": json.loads(r["permissions"]), "created_at": r["created_at"],
        "last_seen": r["last_seen"], "status": "revoked" if r["revoked"] else
        ("online" if r["last_seen"] and now-r["last_seen"] <= 90 else "offline")
    } for r in rows]}


@app.get("/v1/audit", dependencies=[Depends(owner_auth)])
def list_audit(device_id: Optional[str] = None, limit: int = 100):
    """Owner-only audit log of device pairing, file and revocation events."""
    if not 1 <= limit <= 1000:
        raise HTTPException(400, "limit must be between 1 and 1000.")
    con = db()
    if device_id:
        rows = con.execute(
            "SELECT id,device_id,event_type,detail,created_at FROM events WHERE device_id=? ORDER BY created_at DESC, id DESC LIMIT ?",
            (device_id, limit)).fetchall()
    else:
        rows = con.execute(
            "SELECT id,device_id,event_type,detail,created_at FROM events ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,)).fetchall()
    con.close()
    return {"events": [{"id": r["id"], "device_id": r["device_id"], "event_type": r["event_type"],
                        "detail": r["detail"], "created_at": r["created_at"]} for r in rows],
            "count": len(rows),
            "note": "Owner-only audit trail. It records event metadata only, never file contents, tokens or sensor data."}


@app.post("/v1/devices/{device_id}/revoke", dependencies=[Depends(owner_auth)])
def revoke_device(device_id: str):
    con = db()
    cur = con.execute("UPDATE devices SET revoked=1 WHERE id=?", (device_id,))
    if cur.rowcount:
        log_event(con, device_id, "device_revoked", "")
    con.commit()
    con.close()
    if not cur.rowcount:
        raise HTTPException(404, "Device not found.")
    return {"device_id": device_id, "status": "revoked"}


@app.post("/v1/heartbeat")
def heartbeat(device=Depends(device_auth)):
    con = db()
    con.execute("UPDATE devices SET last_seen=? WHERE id=?", (int(time.time()), device["id"]))
    con.commit()
    con.close()
    return {"device_id": device["id"], "status": "online", "server_time": int(time.time())}


@app.post("/v1/files", status_code=201)
async def upload_file(upload: UploadFile = File(...), device=Depends(device_auth)):
    permissions = json.loads(device["permissions"])
    if not permissions.get("file_upload"):
        raise HTTPException(403, "This device has not granted file-upload permission.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    file_id = str(uuid.uuid4())
    safe_name = Path(upload.filename or "upload.bin").name[:180]
    destination = DATA_DIR / (file_id + ".bin")
    size = 0
    try:
        with destination.open("xb") as output:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, "File exceeds the 25 MB upload limit.")
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()
    con = db()
    con.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?)",
                (file_id, device["id"], safe_name,
                 upload.content_type or "application/octet-stream",
                 str(destination), size, int(time.time())))
    log_event(con, device["id"], "file_uploaded", safe_name + " (" + str(size) + " bytes)")
    con.commit()
    con.close()
    return {"file_id": file_id, "name": safe_name, "size": size,
            "status": "stored", "preview_endpoint": f"/v1/files/{file_id}"}


@app.get("/v1/files/{file_id}")
def get_device_file(file_id: str, device=Depends(device_auth)):
    con = db()
    row = con.execute(
        "SELECT id,name,media_type,path FROM files WHERE id=? AND device_id=?",
        (file_id, device["id"])
    ).fetchone()
    con.close()
    if not row or not Path(row["path"]).is_file():
        raise HTTPException(404, "File not found.")
    if not json.loads(device["permissions"]).get("file_upload"):
        raise HTTPException(403, "File access was not granted for this device.")
    preview_types = {
        "image/jpeg", "image/png", "image/webp", "image/gif",
        "audio/mpeg", "audio/wav", "audio/ogg", "audio/webm",
        "video/mp4", "video/webm", "application/pdf", "text/plain"
    }
    disposition = "inline" if row["media_type"] in preview_types else "attachment"
    return FileResponse(
        row["path"], media_type=row["media_type"], filename=row["name"],
        content_disposition_type=disposition,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    )


@app.get("/v1/files")
def list_files(device=Depends(device_auth)):
    if not json.loads(device["permissions"]).get("file_upload"):
        raise HTTPException(403, "File access was not granted for this device.")
    con = db()
    rows = con.execute("SELECT id,name,media_type,size,created_at FROM files WHERE device_id=? ORDER BY created_at DESC",
                       (device["id"],)).fetchall()
    con.close()
    return {"files": [dict(file_id=r["id"], name=r["name"], media_type=r["media_type"],
                           size=r["size"], created_at=r["created_at"]) for r in rows]}


@app.post("/v1/files/{file_id}/share", dependencies=[Depends(owner_auth)])
def create_share(file_id: str, expires_in: int = 3600):
    if not 60 <= expires_in <= 86400:
        raise HTTPException(400, "Share expiry must be between 60 and 86400 seconds.")
    con = db()
    exists = con.execute("SELECT id, device_id FROM files WHERE id=?", (file_id,)).fetchone()
    if not exists:
        con.close()
        raise HTTPException(404, "File not found.")
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO shares VALUES(?,?,?)", (digest(token), file_id, int(time.time()) + expires_in))
    log_event(con, exists["device_id"], "file_shared", file_id + " · expires in " + str(expires_in) + "s")
    con.commit()
    con.close()
    return {"share_token": token, "expires_in_seconds": expires_in,
            "share_path": f"/v1/shared/{token}"}


@app.get("/v1/shared/{token}")
def view_shared_file(token: str):
    con = db()
    row = con.execute("""SELECT f.* FROM shares s JOIN files f ON f.id=s.file_id
                         WHERE s.token_hash=? AND s.expires_at>=?""",
                      (digest(token), int(time.time()))).fetchone()
    con.close()
    if not row or not Path(row["path"]).is_file():
        raise HTTPException(404, "Share link is invalid, expired or unavailable.")
    preview_types = {
        "image/jpeg", "image/png", "image/webp", "image/gif",
        "audio/mpeg", "audio/wav", "audio/ogg", "audio/webm",
        "video/mp4", "video/webm", "application/pdf", "text/plain"
    }
    disposition = "inline" if row["media_type"] in preview_types else "attachment"
    return FileResponse(
        row["path"], media_type=row["media_type"], filename=row["name"],
        content_disposition_type=disposition,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    )

class RelayJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=1, max_length=80)
    action: Literal["desktop.browser.inspect", "kali.health", "kali.tools.inventory", "kali.ollama.models", "kali.ollama.chat", "kali.tool.run", "kali.bridge.request"]
    payload: dict = Field(default_factory=dict)
    approval_reference: str = Field(min_length=3, max_length=160)
    operator_approved: bool


class RelayJobResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_token: str = Field(min_length=32, max_length=256)
    status: str = Field(pattern="^(completed|failed)$")
    result: dict = Field(default_factory=dict)
    error: str = Field(default="", max_length=1000)


def validate_relay_payload(action, payload, approval_reference, approved):
    if not approved:
        raise HTTPException(403, "Explicit operator approval is required.")
    if action == "desktop.browser.inspect":
        if set(payload) != {"url", "allowed_origins"}:
            raise HTTPException(400, "Browser inspection accepts only url and allowed_origins.")
        from urllib.parse import urlsplit
        url = payload.get("url")
        origins = payload.get("allowed_origins")
        if not isinstance(url, str) or len(url) > 2048:
            raise HTTPException(400, "A target URL is required.")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(400, "Only HTTPS targets without embedded credentials are accepted.")
        origin = "https://" + parsed.netloc.lower()
        if not isinstance(origins, list) or not 1 <= len(origins) <= 10 or origin not in origins or any(not isinstance(x, str) or len(x) > 300 for x in origins):
            raise HTTPException(400, "Exact target origin must be in the approved-origin list.")
        return "desktop-browser"
    if action == "kali.bridge.request":
        from urllib.parse import urlsplit, parse_qs
        if set(payload) - {"method", "path", "body"} or not {"method", "path"} <= set(payload):
            raise HTTPException(400, "Bridge request accepts method, path and optional JSON body.")
        method, path = payload.get("method"), payload.get("path")
        if method not in {"GET", "POST"} or not isinstance(path, str) or len(path) > 240:
            raise HTTPException(400, "Only bounded GET and POST bridge requests are supported.")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/") or ".." in parsed.path.split("/"):
            raise HTTPException(400, "Bridge path must be a local absolute path, not a URL.")
        get_paths = {
            "/", "/health", "/system", "/identity", "/capabilities", "/ollama/health", "/ollama/models",
            "/solidity/compiler", "/solidity/tests/status", "/wallet/status", "/tools/runners",
            "/telemetry/security", "/telemetry/system", "/forensics/devices", "/tools", "/burp/status",
            "/burp/extension/status", "/burp/scanner/tasks", "/burp/site-map",
            "/network/interfaces", "/academy/lab/status", "/wifi/interfaces", 
            "/proxy/ca/status", "/proxy/ca/certificate", "/proxy/status", 
            
            "/evidence/case/ledger/verify",
        }
        post_paths = {
            "/plan", "/research", "/services",   
              "/scan",  
             "/forensics/inspect", "/forensics/partitions", "/forensics/fsstat",
               
              
              
             "/web/crawl",  
            "/web/parameters/inspect", "/web/parameters/generate",  "/proxy/ca/create",
            
            "/ollama/chat", "/solidity/compile", "/solidity/project/compile",
            "/solidity/tests/run", "/wallet/recovery-assess", 
            
             
               
            "/academy/lab/start", "/academy/lab/stop",   
             "/wifi/scan", "/wifi/audit", "/wifi/monitor/start", "/wifi/monitor/stop",
            "/wifi/deauth", "/wifi/wps",
            "/wifi/auto", "/tools/run", "/ssh/audit",
        }
        allowed = parsed.path in (get_paths if method == "GET" else post_paths)
        if parsed.path.startswith("/forensics/jobs/") and method == "GET":
            allowed = bool(__import__("re").fullmatch(r"/forensics/jobs/[a-f0-9]{32}", parsed.path))
        if not allowed:
            raise HTTPException(404, "Kali bridge route is not in the relay allowlist.")
        query = parse_qs(parsed.query)
        if query and (set(query) != {"limit"} or len(query["limit"]) != 1 or not query["limit"][0].isdigit()):
            raise HTTPException(400, "Only a numeric limit query parameter is supported.")
        body = payload.get("body")
        if method == "GET" and body is not None:
            raise HTTPException(400, "GET bridge requests cannot include a body.")
        if method == "POST" and not isinstance(body, dict):
            raise HTTPException(400, "POST bridge requests require a JSON object body.")
        if len(json.dumps(body or {}).encode("utf-8")) > 32768:
            raise HTTPException(413, "Bridge request body exceeds 32 KB.")
        return "kali"
    if action == "kali.ollama.chat":
        if set(payload) != {"model", "prompt"}:
            raise HTTPException(400, "Local Ollama chat accepts only model and prompt.")
        model = payload.get("model")
        prompt = payload.get("prompt")
        if not isinstance(model, str) or not 1 <= len(model) <= 160 or any(ch.isspace() for ch in model):
            raise HTTPException(400, "Provide an installed local Ollama model tag.")
        if not isinstance(prompt, str) or not 1 <= len(prompt.strip()) <= 12000:
            raise HTTPException(400, "Local model prompt must contain 1–12,000 characters.")
        return "kali"
    if action == "kali.tool.run":
        required = {"tool", "parameters", "confirmRun", "authorizationReference", "targetConfirmation", "timeoutSeconds"}
        if set(payload) != required or payload.get("confirmRun") is not True:
            raise HTTPException(400, "Kali tool job requires complete explicit confirmation.")
        if payload.get("authorizationReference") != approval_reference:
            raise HTTPException(400, "Tool approval reference mismatch.")
        if not isinstance(payload.get("tool"), str) or not isinstance(payload.get("parameters"), dict):
            raise HTTPException(400, "Tool name and parameters must be typed.")
        if not isinstance(payload.get("targetConfirmation"), str) or not payload["targetConfirmation"] or len(payload["targetConfirmation"]) > 253:
            raise HTTPException(400, "Exact target confirmation is required.")
        if type(payload.get("timeoutSeconds")) is not int or not 1 <= payload["timeoutSeconds"] <= 120:
            raise HTTPException(400, "Timeout must be between 1 and 120 seconds.")
    elif payload:
        raise HTTPException(400, "Read-only action does not accept a payload.")
    return "kali"


@app.post("/v1/jobs", dependencies=[Depends(owner_auth)], status_code=202)
def create_relay_job(body: RelayJobCreate):
    expected_platform = validate_relay_payload(body.action, body.payload, body.approval_reference, body.operator_approved)
    con = db()
    device = con.execute("SELECT id,platform,revoked,permissions FROM devices WHERE id=?", (body.device_id,)).fetchone()
    if not device or device["revoked"]:
        con.close()
        raise HTTPException(404, "Paired execution device not found or revoked.")
    if device["platform"].lower() != expected_platform:
        con.close()
        raise HTTPException(409, "Selected paired device has the wrong execution role. Pair its platform as kali or desktop-browser.")
    if not json.loads(device["permissions"]).get("job_execution"):
        con.close()
        raise HTTPException(403, "Device has not granted job_execution permission.")
    now = int(time.time())
    job_id = str(uuid.uuid4())
    con.execute("INSERT INTO jobs(id,device_id,device_role,action,payload,approval_reference,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (job_id, body.device_id, expected_platform, body.action, json.dumps(body.payload), body.approval_reference, "queued", now, now + 900))
    log_event(con, body.device_id, "job_queued", body.action + " · " + body.approval_reference)
    con.commit()
    con.close()
    return {"job_id": job_id, "status": "queued", "device_id": body.device_id, "action": body.action, "expires_in_seconds": 900}


@app.get("/v1/jobs/next")
def claim_relay_job(device=Depends(device_auth)):
    if not json.loads(device["permissions"]).get("job_execution"):
        raise HTTPException(403, "Device has not granted job_execution permission.")
    now = int(time.time())
    con = db()
    con.execute("BEGIN IMMEDIATE")
    con.execute("UPDATE devices SET last_seen=? WHERE id=?", (now, device["id"]))
    con.execute("UPDATE jobs SET status='queued',lease_token_hash=NULL,lease_expires_at=NULL,started_at=NULL WHERE device_id=? AND status='running' AND lease_expires_at<? AND expires_at>=?", (device["id"], now, now))
    con.execute("UPDATE jobs SET status='expired',finished_at=? WHERE device_id=? AND status='queued' AND expires_at<?", (now, device["id"], now))
    row = con.execute("SELECT * FROM jobs WHERE device_id=? AND status='queued' AND expires_at>=? ORDER BY created_at,id LIMIT 1", (device["id"], now)).fetchone()
    if not row:
        con.commit()
        con.close()
        return {"job": None, "status": "idle", "server_time": now}
    lease = secrets.token_urlsafe(48)
    con.execute("UPDATE jobs SET status='running',lease_token_hash=?,lease_expires_at=?,started_at=? WHERE id=? AND status='queued'", (digest(lease), now + 180, now, row["id"]))
    log_event(con, device["id"], "job_claimed", row["action"])
    con.commit()
    con.close()
    return {"job": {"job_id": row["id"], "action": row["action"], "payload": json.loads(row["payload"]), "approval_reference": row["approval_reference"], "lease_token": lease, "lease_expires_at": now + 180}}



def verify_relay_evidence_chain(con=None):
    own_connection = con is None
    connection = con or db()
    rows = connection.execute("SELECT relay_evidence.*, jobs.result AS job_result FROM relay_evidence LEFT JOIN jobs ON jobs.id=relay_evidence.job_id ORDER BY relay_evidence.id ASC").fetchall()
    previous = "GENESIS"
    errors = []
    for row in rows:
        record = {
            "job_id": row["job_id"],
            "device_id": row["device_id"],
            "action": row["action"],
            "approval_reference": row["approval_reference"],
            "status": row["status"],
            "result_sha256": row["result_sha256"],
            "previous_hash": row["previous_hash"],
            "created_at": row["created_at"],
        }
        expected = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        actual_result_hash = hashlib.sha256((row["job_result"] or "").encode("utf-8")).hexdigest()
        if actual_result_hash != row["result_sha256"]:
            errors.append("Evidence record " + str(row["id"]) + " result digest does not match the stored job result.")
        if row["previous_hash"] != previous:
            errors.append("Evidence record " + str(row["id"]) + " has a broken previous-hash link.")
        if row["record_hash"] != expected:
            errors.append("Evidence record " + str(row["id"]) + " hash does not match its contents.")
        previous = row["record_hash"]
    if own_connection:
        connection.close()
    return {
        "status": "verified" if rows and not errors else ("empty" if not rows else "failed"),
        "verified": bool(rows) and not errors,
        "record_count": len(rows),
        "final_record_hash": previous if rows else None,
        "errors": errors,
        "note": "Hash chaining detects changes to stored records but is not a digital signature or protection against a privileged gateway/database administrator.",
    }


@app.post("/v1/jobs/{job_id}/result")
def submit_relay_result(job_id: str, body: RelayJobResult, device=Depends(device_auth)):
    if not json.loads(device["permissions"]).get("job_execution"):
        raise HTTPException(403, "Device has not granted job_execution permission.")
    encoded = json.dumps(body.result, ensure_ascii=False)
    encoded_bytes = encoded.encode("utf-8")
    if len(encoded_bytes) > 65536:
        raise HTTPException(413, "Job result exceeds 64 KB.")
    result_hash = hashlib.sha256(encoded_bytes).hexdigest()
    now = int(time.time())
    con = db()
    con.execute("BEGIN IMMEDIATE")
    row = con.execute("SELECT * FROM jobs WHERE id=? AND device_id=?", (job_id, device["id"])).fetchone()
    if not row or row["status"] != "running":
        con.close()
        raise HTTPException(404, "Active job not found for this device.")
    if not row["lease_expires_at"] or row["lease_expires_at"] < now:
        con.close()
        raise HTTPException(409, "Job lease expired.")
    if not row["lease_token_hash"] or not hmac.compare_digest(row["lease_token_hash"], digest(body.lease_token)):
        con.close()
        raise HTTPException(401, "Job lease token is invalid.")
    previous_row = con.execute("SELECT record_hash FROM relay_evidence ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous_row["record_hash"] if previous_row else "GENESIS"
    record = {
        "job_id": job_id,
        "device_id": device["id"],
        "action": row["action"],
        "approval_reference": row["approval_reference"],
        "status": body.status,
        "result_sha256": result_hash,
        "previous_hash": previous_hash,
        "created_at": now,
    }
    record_hash = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    con.execute("INSERT INTO relay_evidence(job_id,device_id,action,approval_reference,status,result_sha256,previous_hash,record_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (job_id, device["id"], row["action"], row["approval_reference"], body.status, result_hash, previous_hash, record_hash, now))
    con.execute("UPDATE jobs SET status=?,result=?,error=?,result_sha256=?,previous_evidence_hash=?,evidence_record_hash=?,finished_at=? WHERE id=?",
                (body.status, encoded, body.error, result_hash, previous_hash, record_hash, now, job_id))
    log_event(con, device["id"], "job_" + body.status, row["action"] + " · evidence " + record_hash[:16])
    con.commit()
    con.close()
    return {"job_id": job_id, "status": body.status, "accepted": True,
            "result_sha256": result_hash, "evidence_record_hash": record_hash,
            "previous_evidence_hash": previous_hash}


@app.get("/v1/evidence/verify", dependencies=[Depends(owner_auth)])
def verify_relay_evidence():
    con = db()
    result = verify_relay_evidence_chain(con)
    con.close()
    return result


@app.get("/v1/jobs", dependencies=[Depends(owner_auth)])
def list_relay_jobs(device_id: Optional[str] = None, limit: int = 100):
    if not 1 <= limit <= 250:
        raise HTTPException(400, "limit must be between 1 and 250.")
    con = db()
    if device_id:
        rows = con.execute("SELECT * FROM jobs WHERE device_id=? ORDER BY created_at DESC LIMIT ?", (device_id, limit)).fetchall()
    else:
        rows = con.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    chain = verify_relay_evidence_chain(con)
    con.close()
    return {"evidence_chain": chain, "jobs": [{"job_id": r["id"], "device_id": r["device_id"], "action": r["action"], "status": r["status"], "approval_reference": r["approval_reference"], "result": json.loads(r["result"]) if r["result"] else None, "error": r["error"], "result_sha256": r["result_sha256"], "evidence_record_hash": r["evidence_record_hash"], "previous_evidence_hash": r["previous_evidence_hash"], "created_at": r["created_at"], "started_at": r["started_at"], "finished_at": r["finished_at"]} for r in rows]}


@app.post("/v1/jobs/{job_id}/cancel", dependencies=[Depends(owner_auth)])
def cancel_relay_job(job_id: str):
    con = db()
    row = con.execute("SELECT device_id,status,action FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(404, "Job not found.")
    if row["status"] != "queued":
        con.close()
        raise HTTPException(409, "Only queued jobs can be cancelled. An already-running local action cannot be interrupted by the relay.")
    now = int(time.time())
    con.execute("UPDATE jobs SET status='cancelled',finished_at=? WHERE id=?", (now, job_id))
    log_event(con, row["device_id"], "job_cancelled", row["action"])
    con.commit()
    con.close()
    return {"job_id": job_id, "status": "cancelled"}
