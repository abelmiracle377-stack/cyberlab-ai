"""Per-operator CyberLab VPS gateway.

Run behind a TLS reverse proxy. This service never activates device sensors:
a companion must obtain and maintain explicit OS/browser permission locally.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

DB_PATH = Path(os.environ.get("CYBERLAB_GATEWAY_DB", "/var/lib/cyberlab-gateway/registry.sqlite3"))
DATA_DIR = Path(os.environ.get("CYBERLAB_GATEWAY_FILES", "/var/lib/cyberlab-gateway/files"))
OWNER_TOKEN = os.environ.get("CYBERLAB_OWNER_TOKEN", "")
PAIR_TTL = 600
MAX_UPLOAD = 25 * 1024 * 1024
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
    """)
    return con


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def owner_auth(authorization: Optional[str] = Header(default=None)):
    if not OWNER_TOKEN:
        raise HTTPException(503, "Gateway owner token is not configured.")
    if authorization != "Bearer " + OWNER_TOKEN:
        raise HTTPException(401, "Owner authentication required.")
    return True


def device_auth(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Device authentication required.")
    token = authorization[7:]
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


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberlab-personal-vps-gateway"}


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
    if not body.terms_accepted:
        raise HTTPException(403, "The participant must accept the disclosed terms.")
    if not body.permissions or not any(body.permissions.values()):
        raise HTTPException(400, "At least one explicitly granted permission is required.")
    allowed = {"microphone", "camera", "screen_capture", "location", "file_upload"}
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


@app.post("/v1/devices/{device_id}/revoke", dependencies=[Depends(owner_auth)])
def revoke_device(device_id: str):
    con = db()
    cur = con.execute("UPDATE devices SET revoked=1 WHERE id=?", (device_id,))
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
    exists = con.execute("SELECT id FROM files WHERE id=?", (file_id,)).fetchone()
    if not exists:
        con.close()
        raise HTTPException(404, "File not found.")
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO shares VALUES(?,?,?)", (digest(token), file_id, int(time.time()) + expires_in))
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
