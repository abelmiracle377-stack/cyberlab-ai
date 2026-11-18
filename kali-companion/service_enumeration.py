"""Bounded, non-authenticating TCP service identification for authorised targets."""
from __future__ import annotations

import socket
import ssl
import time

ALLOWED_PORTS = {21, 22, 25, 80, 110, 143, 443, 445, 587, 993, 995, 8080, 8443}
MAX_PORTS = 8
CONNECT_TIMEOUT = 2.0
TOTAL_TIMEOUT = 20.0
READ_LIMIT = 4096
BANNER_LIMIT = 512


def _clean(data: bytes) -> str:
    text = data[:BANNER_LIMIT].decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() or ch in "\r\n\t" else " " for ch in text).strip()


def _read_bounded(sock: socket.socket, limit: int = READ_LIMIT) -> bytes:
    chunks = bytearray()
    sock.settimeout(0.5)
    while len(chunks) < limit:
        try:
            part = sock.recv(min(1024, limit - len(chunks)))
        except (socket.timeout, OSError):
            break
        if not part:
            break
        chunks.extend(part)
        if b"\r\n\r\n" in chunks or b"\n\n" in chunks:
            break
    return bytes(chunks)


def _probe_one(target: str, port: int) -> dict:
    row = {"port": port, "state": "unknown", "service": "unknown", "banner": None, "tls": None, "error": None}
    try:
        with socket.create_connection((target, port), timeout=CONNECT_TIMEOUT) as connection:
            row["state"] = "open"
            connection.settimeout(0.5)
            if port in {443, 993, 995, 8443}:
                row["service"] = "tls"
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(connection, server_hostname=target) as secured:
                        cert = secured.getpeercert()
                        row["tls"] = {
                            "version": secured.version(),
                            "cipher": secured.cipher()[0] if secured.cipher() else None,
                            "subject": cert.get("subject", []),
                            "issuer": cert.get("issuer", []),
                            "not_after": cert.get("notAfter"),
                            "san": cert.get("subjectAltName", [])[:30],
                        }
                        row["banner"] = _clean(_read_bounded(secured))
                except (ssl.SSLError, OSError, ValueError) as exc:
                    row["error"] = "TLS metadata unavailable: " + str(exc)[:180]
            else:
                if port == 80 or port == 8080:
                    row["service"] = "http"
                    connection.sendall(("HEAD / HTTP/1.0\r\nHost: " + target + "\r\nConnection: close\r\n\r\n").encode("ascii", errors="ignore"))
                elif port == 21:
                    row["service"] = "ftp"
                elif port == 22:
                    row["service"] = "ssh"
                elif port in {25, 587}:
                    row["service"] = "smtp"
                elif port == 110:
                    row["service"] = "pop3"
                elif port == 143:
                    row["service"] = "imap"
                elif port == 445:
                    row["service"] = "smb"
                row["banner"] = _clean(_read_bounded(connection))
    except (ConnectionRefusedError, TimeoutError, socket.timeout):
        row["state"] = "closed_or_filtered"
    except OSError as exc:
        row["state"] = "error"
        row["error"] = str(exc)[:180]
    return row


def enumerate_services(target: str, ports: list[int]) -> dict:
    if not isinstance(target, str) or not target or len(target) > 253:
        raise ValueError("Provide one validated IP address or hostname.")
    if not isinstance(ports, list) or not ports or len(ports) > MAX_PORTS:
        raise ValueError("Select between 1 and 8 supported service ports.")
    if any(type(port) is not int or port not in ALLOWED_PORTS for port in ports):
        raise ValueError("Only the reviewed common service ports are supported.")
    if len(set(ports)) != len(ports):
        raise ValueError("Duplicate service ports are not accepted.")
    started = time.monotonic()
    results = []
    for port in ports:
        if time.monotonic() - started >= TOTAL_TIMEOUT:
            results.append({"port": port, "state": "not_checked", "service": "unknown", "banner": None, "tls": None, "error": "Overall time limit reached."})
            continue
        results.append(_probe_one(target, port))
    return {
        "status": "completed",
        "target": target,
        "ports_checked": ports,
        "duration_seconds": round(time.monotonic() - started, 2),
        "services": results,
        "note": "Non-authenticating TCP connection and minimal protocol identification only. HTTP uses HEAD; TLS reads certificate metadata; no credentials, exploit payloads, brute force, file transfer or state-changing requests are used. closed_or_filtered is intentionally inconclusive.",
    }
