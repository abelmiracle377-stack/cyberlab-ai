"""CyberLab-managed local CA for explicitly enabled HTTPS inspection.

The CA is generated only on an explicit operator action. Its private key is
kept owner-readable under ~/.config/cyberlab/proxy-ca; trust installation is
always manual. No system/browser trust stores are modified.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import stat
import subprocess
import threading
from pathlib import Path

CONFIG_ROOT = Path.home() / ".config" / "cyberlab"
CA_DIR = CONFIG_ROOT / "proxy-ca"
CA_KEY = CA_DIR / "ca-key.pem"
CA_CERT = CA_DIR / "ca-cert.pem"
LEAF_DIR = CA_DIR / "hosts"
_HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)
_LOCK = threading.RLock()


def _secure_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("Certificate storage must not be a symbolic link.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("Certificate storage is not a directory.")
    os.chmod(path, 0o700)


def _openssl() -> str:
    binary = shutil.which("openssl")
    if not binary:
        raise RuntimeError("OpenSSL is required for local HTTPS inspection. Install the openssl package.")
    return binary


def _run(args: list[str], timeout: int = 30) -> None:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("OpenSSL operation timed out.") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace")[-500:]
        raise RuntimeError("OpenSSL operation failed: " + detail)


def ca_status() -> dict:
    with _LOCK:
        ready = False
        if (CA_KEY.is_file() and not CA_KEY.is_symlink() and CA_CERT.is_file()
                and not CA_CERT.is_symlink() and CA_DIR.is_dir() and not CA_DIR.is_symlink()):
            key_stat = os.stat(CA_KEY, follow_symlinks=False)
            directory_stat = os.stat(CA_DIR, follow_symlinks=False)
            key_mode = stat.S_IMODE(key_stat.st_mode)
            directory_mode = stat.S_IMODE(directory_stat.st_mode)
            current_uid = os.geteuid() if hasattr(os, "geteuid") else key_stat.st_uid
            ready = (key_mode == 0o600 and directory_mode == 0o700
                     and key_stat.st_uid == current_uid and directory_stat.st_uid == current_uid)
        return {
            "ready": ready,
            "caCertificate": str(CA_CERT) if ready else None,
            "privateKeyStored": ready,
            "privateKeyPermissions": "owner-only (0600)" if ready else "not verified",
            "trustInstallation": "manual; CyberLab never modifies operating-system or browser trust stores",
            "storage": str(CA_DIR),
        }


def ca_certificate_pem() -> dict:
    """Return only the public root certificate for manual browser import."""
    with _LOCK:
        if not ca_status()["ready"]:
            raise ValueError("Local inspection CA is missing or its private-key permissions are unsafe.")
        with CA_CERT.open("r", encoding="ascii") as certificate_file:
            pem = certificate_file.read(65537)
        if len(pem) > 65536 or "-----BEGIN CERTIFICATE-----" not in pem:
            raise ValueError("Local CA certificate file is invalid or exceeds the size limit.")
        return {"filename": "cyberlab-local-inspection-ca.pem", "pem": pem,
                "trustInstallation": "manual; import only into a dedicated test browser profile"}


def create_local_ca() -> dict:
    """Create the local root CA once; never overwrite an existing key."""
    with _LOCK:
        _secure_directory(CONFIG_ROOT)
        _secure_directory(CA_DIR)
        if CA_KEY.exists() or CA_CERT.exists():
            if CA_KEY.is_file() and CA_CERT.is_file() and not CA_KEY.is_symlink() and not CA_CERT.is_symlink():
                return ca_status()
            raise ValueError("Incomplete or unsafe CA files exist. Refusing to overwrite them.")
        binary = _openssl()
        key_tmp = CA_DIR / ".ca-key.pending"
        cert_tmp = CA_DIR / ".ca-cert.pending"
        try:
            _run([binary, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key_tmp)])
            os.chmod(key_tmp, 0o600)
            _run([binary, "req", "-x509", "-new", "-key", str(key_tmp), "-sha256", "-days", "3650",
                  "-subj", "/CN=CyberLab AI Local Inspection CA",
                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                  "-addext", "subjectKeyIdentifier=hash", "-out", str(cert_tmp)])
            os.chmod(cert_tmp, 0o644)
            os.replace(key_tmp, CA_KEY)
            os.replace(cert_tmp, CA_CERT)
            os.chmod(CA_KEY, 0o600)
            os.chmod(CA_CERT, 0o644)
        finally:
            for path in (key_tmp, cert_tmp):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        return ca_status()


def _normalise_host(host: str) -> tuple[str, str]:
    if not isinstance(host, str) or not host or len(host) > 253 or host != host.strip():
        raise ValueError("Enter one valid DNS hostname or IP address.")
    value = host.rstrip(".").lower()
    if not value or "*" in value or "/" in value or "@" in value or "?" in value or "#" in value:
        raise ValueError("Wildcards, URL paths and malformed hostnames are not accepted.")
    try:
        address = ipaddress.ip_address(value.strip("[]"))
        return address.compressed, "IP"
    except ValueError:
        if ":" in value or not _HOST_RE.fullmatch(value) or ".." in value:
            raise ValueError("Enter a valid DNS hostname or IP address.")
        return value, "DNS"


def issue_host_certificate(host: str) -> dict:
    """Issue a short-lived server certificate for one exact host (no wildcards)."""
    name, kind = _normalise_host(host)
    with _LOCK:
        if not ca_status()["ready"]:
            raise ValueError("Create the local inspection CA first; no certificate will be issued without it.")
        _secure_directory(LEAF_DIR)
        fingerprint = hashlib.sha256(name.encode("ascii")).hexdigest()
        host_dir = LEAF_DIR / fingerprint
        _secure_directory(host_dir)
        key_path, cert_path = host_dir / "key.pem", host_dir / "cert.pem"
        if key_path.exists() or cert_path.exists():
            if key_path.is_file() and cert_path.is_file() and not key_path.is_symlink() and not cert_path.is_symlink():
                return {"host": name, "certificate": str(cert_path), "privateKey": str(key_path), "reused": True}
            raise ValueError("Incomplete or unsafe host certificate files exist. Refusing to overwrite them.")
        binary = _openssl()
        csr = host_dir / ".request.pending"
        ext = host_dir / ".extensions.pending"
        key_tmp = host_dir / ".key.pending"
        cert_tmp = host_dir / ".cert.pending"
        san = ("IP:" if kind == "IP" else "DNS:") + name
        try:
            _run([binary, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key_tmp),
                  "-out", str(csr), "-subj", "/CN=" + name], timeout=45)
            os.chmod(key_tmp, 0o600)
            ext.write_text("basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\nsubjectAltName=" + san + "\\n", encoding="ascii")
            os.chmod(ext, 0o600)
            serial = "0x" + os.urandom(16).hex()
            _run([binary, "x509", "-req", "-in", str(csr), "-CA", str(CA_CERT), "-CAkey", str(CA_KEY),
                  "-set_serial", serial, "-sha256", "-days", "30", "-extfile", str(ext), "-out", str(cert_tmp)])
            os.chmod(cert_tmp, 0o644)
            os.replace(key_tmp, key_path)
            os.replace(cert_tmp, cert_path)
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
        finally:
            for path in (csr, ext, key_tmp, cert_tmp):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        return {"host": name, "certificate": str(cert_path), "privateKey": str(key_path), "reused": False}
