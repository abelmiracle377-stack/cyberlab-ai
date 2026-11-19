#!/usr/bin/env python3
"""CyberLab local Kali bridge. Loopback-only, paired, explicitly authorised Nmap TCP checks."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from forensics import get_image_job, inspect_image_filesystem, inspect_image_partitions, list_block_devices, start_foremost_recovery, start_image_acquisition, list_deleted_files, recover_deleted_file
from filesystem_analysis import inspect_partition_filesystem
from tool_catalog import inspect_tool_catalog
from burp_connector import inspect_burp_status, inspect_burp_proxy_history, inspect_burp_site_map, inspect_burp_issues, open_burp_history_in_repeater
from network_capture import list_capture_interfaces, capture_packets
from web_testing import execute_request, request_history
from web_crawler import run_crawl
from web_active_scan import run_active_scan
from parameter_lab import inspect_parameters, generate_cases
from parameter_analysis import compare_responses
from proxy_certificates import ca_status, ca_certificate_pem, create_local_ca
from intercept_proxy import PROXY, decide_intercept, pending_intercepts, pending_response_intercepts, decide_response_intercept, proxy_history, websocket_frame_history, pending_websocket_frames, decide_websocket_frame
import base64
import wallet_recovery
import wallet_cracking
import kali_tools
from task_planner import plan_task
from research_workflows import run_research_action
from service_enumeration import enumerate_services
from evidence_analysis import build_service_report, validate_report_payload
from artifact_analysis import build_artifact_report, validate_artifact_payload
from case_management import build_case_report, validate_case_payload, verify_audit_ledger
from case_export import export_case_bundle, verify_case_archive
from bridge_security import load_or_create_pairing_token

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY = 8192
MAX_OLLAMA_BODY = 65536
MAX_SOLIDITY_BODY = 120000
MAX_SOLIDITY_SOURCE = 100000
MAX_SOLIDITY_OUTPUT = 2_000_000
MAX_SOLIDITY_PROJECT_BODY = 700000
SOLIDITY_RUNTIME = 30
SOLIDITY_TEST_BODY = 700000
SOLIDITY_TEST_RUNTIME = 120
SOLIDITY_TEST_OUTPUT = 262144
OLLAMA_URL = "http://127.0.0.1:11434"
solidity_lock = threading.Lock()
solidity_test_lock = threading.Lock()
MAX_PORTS = 100
MAX_RUNTIME = 55
ALLOWED_ORIGINS = {"https://cyberlab-ai.vercel.app", "http://localhost:3000", "http://127.0.0.1:3000"} | {origin.strip().rstrip("/") for origin in os.environ.get("CYBERLAB_ALLOWED_ORIGINS", "").split(",") if origin.strip()}
CONFIG_DIR = Path.home() / ".config" / "cyberlab"
TOKEN_FILE = CONFIG_DIR / "bridge-token"
scan_lock = threading.Lock()
research_lock = threading.Lock()
service_lock = threading.Lock()
evidence_lock = threading.Lock()
artifact_lock = threading.Lock()
case_lock = threading.Lock()
case_export_lock = threading.Lock()
network_capture_lock = threading.Lock()
web_request_lock = threading.Lock()
web_crawl_lock = threading.Lock()
web_active_scan_lock = threading.Lock()
proxy_ca_lock = threading.Lock()
proxy_control_lock = threading.Lock()


def load_token() -> str:
    return load_or_create_pairing_token(CONFIG_DIR, TOKEN_FILE)


def valid_target(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or any(ch in value for ch in "/\\:@?#"):
        raise ValueError("Enter a single IP address or hostname, not a URL or network range.")
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Loopback, link-local, multicast and reserved targets are blocked.")
        return str(ip)
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("Enter a valid fully-qualified domain name or IP address.")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(value, None, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError as exc:
        raise ValueError("Target could not be resolved to IPv4.") from exc
    if not addresses or len(addresses) > 4:
        raise ValueError("Domain must resolve to between one and four IPv4 addresses. For larger/CDN domains, use an explicitly authorised single IP.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Resolved target includes loopback, link-local, multicast or reserved addresses.")
    return value


def parse_report(xml_text: str) -> dict:
    """Parse Nmap XML with the same evidence fields as the CLI/browser parser."""
    raw = xml_text.encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds the 2 MB limit.")
    if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):
        raise ValueError("DOCTYPE and entity declarations are not accepted.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("Invalid Nmap XML: " + str(exc)) from exc
    if root.tag != "nmaprun":
        raise ValueError("XML root element is not nmaprun.")
    hosts = []
    for index, host in enumerate(root.findall("host"), 1):
        status = host.find("status")
        addresses = [{"address": n.get("addr", ""), "type": n.get("addrtype", "unknown")} for n in host.findall("address")]
        hostnames = [{"name": n.get("name", ""), "type": n.get("type", "unknown")} for n in host.findall("./hostnames/hostname") if n.get("name")]
        ports = []
        for node in host.findall("./ports/port"):
            state, service = node.find("state"), node.find("service")
            try:
                number = int(node.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= number <= 65535:
                continue
            ports.append({
                "protocol": node.get("protocol", "unknown"), "port": number,
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "reason": state.get("reason", "") if state is not None else "",
                "reason_ttl": state.get("reason_ttl") if state is not None else None,
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra_info": service.get("extrainfo", "") if service is not None else "",
                "tunnel": service.get("tunnel", "") if service is not None else "",
                "method": service.get("method", "") if service is not None else "",
                "confidence": service.get("conf") if service is not None else None,
            })
        hosts.append({
            "index": index, "status": status.get("state", "unknown") if status is not None else "unknown",
            "status_reason": status.get("reason", "") if status is not None else "",
            "addresses": addresses, "hostnames": hostnames, "ports": ports,
        })
    all_ports = [port for host in hosts for port in host["ports"]]
    states = ("open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown")
    scaninfo = [{"type": n.get("type", ""), "protocol": n.get("protocol", ""),
                 "numservices": n.get("numservices", ""), "services": n.get("services", "")}
                for n in root.findall("./scaninfo")]
    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    host_stats = runstats.find("hosts") if runstats is not None else None
    completion = {
        "finished": finished.attrib if finished is not None else {},
        "hosts": host_stats.attrib if host_stats is not None else {},
        "scanner": root.get("scanner", ""), "version": root.get("version", ""),
        "args": root.get("args", ""), "start": root.get("start", ""),
    }
    open_ports = [
        {"host": host["addresses"][0]["address"] if host["addresses"] else f"Host {host['index']}", **port}
        for host in hosts for port in host["ports"] if port["state"] == "open"
    ]
    state_counts = {state: sum(1 for port in all_ports if port["state"] == state) for state in states}
    evidence_status = "completed" if completion["finished"].get("exit") == "success" else ("partial" if hosts or completion["finished"] else "no_port_evidence")
    return {
        "hosts": hosts, "open_ports": open_ports, "state_summary": state_counts,
        "summary": {"hosts": len(hosts), "up": sum(1 for host in hosts if host["status"] == "up"),
                    "ports": len(all_ports), "open_ports": len(open_ports), "state_counts": state_counts},
        "scaninfo": scaninfo, "completion": completion, "evidence_status": evidence_status,
    }

def system_snapshot() -> dict:
    """Return bounded, non-sensitive host health metrics; never process args or user data."""
    memory = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                memory[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        memory = {}
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        uptime_seconds = None
    try:
        process_count = sum(1 for entry in Path("/proc").iterdir() if entry.name.isdigit())
    except OSError:
        process_count = None
    disk = shutil.disk_usage("/")
    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "platform": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "uptime_seconds": round(uptime_seconds) if uptime_seconds is not None else None,
        "load_average_1_5_15": load_average,
        "memory_bytes": memory,
        "disk_root_bytes": {"total": disk.total, "used": disk.used, "free": disk.free},
        "process_count": process_count,
        "nmap_available": bool(shutil.which("nmap")),
        "tcpdump_available": bool(shutil.which("tcpdump")),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Local host health summary only; no usernames, process names, command lines, files or network payloads are collected.",
    }


def ollama_request(path: str, payload: dict | None = None, timeout: int = 12) -> dict:
    """Talk only to the fixed Ollama loopback service; callers cannot supply a host or URL."""
    if path not in {"/api/tags", "/api/chat"}:
        raise ValueError("Unsupported local model operation.")
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        OLLAMA_URL + path,
        data=body,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Local model response exceeded the 2 MB limit.")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Local model service returned an invalid response.")
        return result
    except urllib.error.URLError as exc:
        raise ConnectionError("Ollama is unavailable at 127.0.0.1:11434. Start Ollama locally and try again.") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Ollama returned invalid JSON.") from exc



def ollama_models() -> list[dict]:
    result = ollama_request("/api/tags")
    models = result.get("models", [])
    if not isinstance(models, list):
        raise ValueError("Ollama model catalogue is malformed.")
    return [
        {"name": str(item.get("name", "")), "size": item.get("size"), "modified_at": item.get("modified_at")}
        for item in models if isinstance(item, dict) and item.get("name")
    ][:100]



def ollama_chat(model: str, prompt: str, history: list | None = None) -> dict:
    model = model.strip()
    prompt = prompt.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model):
        raise ValueError("Choose a valid model name from your local Ollama catalogue.")
    if not prompt or len(prompt) > 12000:
        raise ValueError("Prompt must contain between 1 and 12,000 characters.")
    available = {item["name"] for item in ollama_models()}
    if model not in available:
        raise ValueError("Selected model is not installed in local Ollama.")
    # Bound the aggregate conversation, not just each message, so the JSON body
    # remains comfortably below MAX_OLLAMA_BODY even with a full history.
    messages = []
    history_budget = 32000
    if isinstance(history, list):
        for item in history[-12:]:
            if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"}:
                continue
            content = item.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            remaining = history_budget - sum(len(message["content"]) for message in messages)
            if remaining <= 0:
                break
            bounded = content[:min(4000, remaining)]
            messages.append({"role": item["role"], "content": bounded})
    messages.append({"role": "user", "content": prompt})
    result = ollama_request("/api/chat", {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"num_predict": 4096},
    }, timeout=120)
    message = result.get("message", {})
    content = message.get("content", "") if isinstance(message, dict) else ""
    if not isinstance(content, str):
        raise ValueError("Local model returned an invalid message.")
    return {"model": model, "response": content[:50000], "done": bool(result.get("done", False))}



def wallet_tool_status() -> dict:
    """Report which local password-recovery tools are available; installs nothing."""
    return {
        "hashcat": {"installed": bool(shutil.which("hashcat")), "executable": shutil.which("hashcat")},
        "john": {"installed": bool(shutil.which("john")), "executable": shutil.which("john")},
        "supportedFormats": ["ethereum-keystore-v3", "bitcoin-core-wallet.dat"],
        "derivation": ["bip44-legacy", "bip84-segwit", "bip44-ethereum"],
        "note": "Hash extraction and HD address derivation run locally with no tool. Password recovery requires a locally installed hashcat or John; the companion never downloads cracking tools.",
    }


def wallet_extract_hash(data: dict) -> dict:
    """Extract a hashcat/John-ready hash from an owned wallet backup."""
    kind = str(data.get("kind", "")).lower()
    if kind in {"keystore", "ethereum-keystore-v3"}:
        keystore = data.get("keystoreJson")
        if not isinstance(keystore, str) or not keystore.strip():
            raise ValueError("Provide the keystore JSON in 'keystoreJson'.")
        return wallet_recovery.extract_keystore_hash(keystore)
    if kind in {"wallet.dat", "bitcoin-core-wallet.dat", "walletdat"}:
        encoded = data.get("walletDatBase64")
        if not isinstance(encoded, str) or not encoded.strip():
            raise ValueError("Provide the wallet.dat bytes as base64 in 'walletDatBase64'.")
        try:
            blob = base64.b64decode(encoded, validate=True)
        except ValueError as exc:  # binascii.Error subclasses ValueError
            raise ValueError("walletDatBase64 is not valid base64.") from exc
        if not 16 <= len(blob) <= 4_000_000:
            raise ValueError("wallet.dat payload is outside the accepted size range.")
        return wallet_recovery.extract_wallet_dat_hash(blob)
    raise ValueError("Unknown wallet kind. Use 'keystore' or 'wallet.dat'.")


def wallet_derive(data: dict) -> dict:
    """Derive owned-wallet addresses from a mnemonic the operator supplies locally."""
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("Provide the recovery mnemonic in 'mnemonic'.")
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    template = str(data.get("template", "bip44-ethereum"))
    count = data.get("count", 5)
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("count must be an integer.")
    seed = wallet_recovery.mnemonic_to_seed(mnemonic, passphrase)
    accounts = wallet_recovery.derive_accounts(seed, template, count)
    return {"template": template, "count": len(accounts), "accounts": accounts,
            "note": "Derived locally from the supplied mnemonic. Private keys and the mnemonic never leave this machine."}


def wallet_crack(data: dict) -> dict:
    """Run a locally installed hashcat/John against an extracted wallet hash."""
    tool = str(data.get("tool", "hashcat")).lower()
    hash_value = data.get("hash")
    wordlist = data.get("wordlist")
    confirmed = data.get("confirmRun") is True
    if not isinstance(hash_value, str) or not isinstance(wordlist, str):
        raise ValueError("Provide 'hash' and 'wordlist' (a path on this machine).")
    timeout = data.get("timeoutSeconds", wallet_cracking.DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError("timeoutSeconds must be an integer.")
    if tool == "john":
        return wallet_cracking.run_john(hash_value, wordlist, confirmed=confirmed, timeout=timeout)
    mode = data.get("hashcatMode")
    if not isinstance(mode, int) or isinstance(mode, bool):
        raise ValueError("hashcatMode is required for hashcat (for example 11300, 15700 or 16300).")
    return wallet_cracking.run_hashcat(hash_value, mode, wordlist, confirmed=confirmed, timeout=timeout)


def run_kali_tool(data: dict) -> dict:
    """Run one registered Kali tool with validation, consent and authorisation."""
    name = str(data.get("tool", ""))
    params = data.get("parameters")
    if not isinstance(params, dict):
        raise ValueError("Provide a 'parameters' object for the tool.")
    timeout = data.get("timeoutSeconds", kali_tools.DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError("timeoutSeconds must be an integer.")
    return kali_tools.run_tool(
        name, params,
        confirmed=data.get("confirmRun") is True,
        authorization_reference=str(data.get("authorizationReference", "")),
        target_confirmation=str(data.get("targetConfirmation", "")),
        timeout=timeout,
    )


def environment_capabilities() -> dict:
    """Read-only discovery for CyberLab OS; never installs or starts runtimes."""
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass

    runtimes = {
        "docker": {"installed": bool(shutil.which("docker")), "executable": shutil.which("docker")},
        "podman": {"installed": bool(shutil.which("podman")), "executable": shutil.which("podman")},
        "qemu": {"installed": bool(shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-aarch64")), "executable": shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-aarch64")},
        "libvirt": {"installed": bool(shutil.which("virsh")), "executable": shutil.which("virsh")},
        "virtualbox": {"installed": bool(shutil.which("VBoxManage")), "executable": shutil.which("VBoxManage")},
    }
    return {
        "platform": platform.system(),
        "distribution": os_release.get("PRETTY_NAME") or platform.platform(),
        "distribution_id": os_release.get("ID", "").lower(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count(),
        "hardware_virtualization_device": Path("/dev/kvm").exists(),
        "wsl": bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP")),
        "runtimes": runtimes,
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Read-only capability discovery. No packages were installed, no containers or virtual machines were started, and no host commands were executed.",
    }



def solidity_compiler_status() -> dict:
    """Discover only the fixed PATH-resolved solc executable; never install or accept a path."""
    executable = shutil.which("solc")
    if not executable:
        return {"available": False, "compiler": "solc", "version": None, "message": "solc is not installed or not on PATH. Install a trusted, pinned Solidity compiler manually; the bridge never downloads or installs toolchains."}
    try:
        completed = subprocess.run(
            [executable, "--version"], capture_output=True, text=True,
            timeout=5, check=False, env={"PATH": os.environ.get("PATH", "")},
        )
        if completed.returncode != 0:
            return {"available": False, "compiler": "solc", "version": None, "message": "The installed solc executable did not report a version."}
        match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", completed.stdout)
        if not match:
            return {"available": False, "compiler": "solc", "version": None, "message": "Could not parse the installed solc version."}
        return {"available": True, "compiler": "solc", "version": match.group(1), "message": "Local compiler detected. Compilation runs on this machine."}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "compiler": "solc", "version": None, "message": "The installed solc executable could not be queried."}




def _validate_solidity_project(files: object, dependency_lock: object) -> tuple[dict[str, str], list[str]]:
    """Validate an in-memory multi-file project and its operator-pinned local dependency manifest."""
    import hashlib
    import posixpath

    if not isinstance(files, list) or not 1 <= len(files) <= 100:
        raise ValueError("Provide 1–100 Solidity project files.")
    sources: dict[str, str] = {}
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "content"}:
            raise ValueError("Each project file must contain only path and content.")
        path, content = item["path"], item["content"]
        if not isinstance(path, str) or not isinstance(content, str):
            raise ValueError("Project paths and file contents must be text.")
        valid_source = bool(re.fullmatch(r"(?:src|test)/[A-Za-z0-9_.-]+\.sol", path))
        valid_dependency = bool(re.fullmatch(r"lib/openzeppelin-contracts/contracts/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.sol", path))
        if not (valid_source or valid_dependency) or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("Only flat src/*.sol, test/*.sol and nested OpenZeppelin contracts paths are accepted.")
        if path in sources:
            raise ValueError("Duplicate project paths are not accepted.")
        size = len(content.encode("utf-8"))
        if not content.strip() or size > 100000:
            raise ValueError("Each project file must contain 1–100,000 UTF-8 bytes.")
        total += size
        if total > 500000:
            raise ValueError("Combined Solidity project exceeds 500,000 UTF-8 bytes.")
        sources[path] = content
    if not any(path.startswith("src/") for path in sources):
        raise ValueError("Include at least one src/*.sol contract.")

    if not isinstance(dependency_lock, list) or len(dependency_lock) > 1:
        raise ValueError("Dependency lock must contain at most one reviewed package; only @openzeppelin/contracts is supported.")
    remappings: list[str] = []
    locked_paths: set[str] = set()
    for dependency in dependency_lock:
        if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "source", "commit", "files"}:
            raise ValueError("Each dependency lock entry must contain name, version, source, commit and files.")
        if dependency["name"] != "@openzeppelin/contracts" or remappings:
            raise ValueError("Only one @openzeppelin/contracts package lock is supported in this stage.")
        if not isinstance(dependency["version"], str) or not re.fullmatch(r"5\.\d+\.\d+", dependency["version"]):
            raise ValueError("OpenZeppelin Contracts must use an exact 5.x.y version.")
        if dependency["source"] != "https://github.com/OpenZeppelin/openzeppelin-contracts":
            raise ValueError("OpenZeppelin dependency source must be its canonical GitHub repository.")
        if not isinstance(dependency["commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", dependency["commit"]):
            raise ValueError("OpenZeppelin dependency lock must include a full 40-character lowercase commit.")
        entries = dependency["files"]
        if not isinstance(entries, list) or not entries:
            raise ValueError("OpenZeppelin dependency lock must include SHA-256 entries for every dependency source file.")
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                raise ValueError("Dependency file lock entries must contain only path and sha256.")
            path, digest = entry["path"], entry["sha256"]
            if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("Dependency file paths and SHA-256 digests are invalid.")
            if not path.startswith("lib/openzeppelin-contracts/contracts/") or path in locked_paths:
                raise ValueError("Dependency file path is outside the approved package root or duplicated.")
            if path not in sources:
                raise ValueError("A locked dependency file is missing from the supplied project: " + path)
            actual = hashlib.sha256(sources[path].encode("utf-8")).hexdigest()
            if not hmac.compare_digest(actual, digest):
                raise ValueError("Dependency integrity check failed for " + path)
            locked_paths.add(path)
        remappings.append("@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/")
    supplied_dependency_paths = {path for path in sources if path.startswith("lib/")}
    if supplied_dependency_paths != locked_paths:
        raise ValueError("Every supplied dependency source must be covered by the dependency lock; no unpinned library files are accepted.")

    import_pattern = re.compile(r"\bimport\s+(?:(?:[^'\";]*?)\s+from\s+)?['\"]([^'\"]+)['\"]\s*;")
    for importer, content in sources.items():
        for imported in import_pattern.findall(content):
            if imported.startswith("@openzeppelin/contracts/"):
                resolved = "lib/openzeppelin-contracts/contracts/" + imported[len("@openzeppelin/contracts/"):]
            elif imported.startswith("./") or imported.startswith("../"):
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(importer), imported))
                if resolved.startswith("../") or resolved.startswith("/") or resolved not in sources:
                    raise ValueError("Relative import does not resolve to a supplied project file: " + imported)
                if importer.startswith("lib/") and not resolved.startswith("lib/openzeppelin-contracts/contracts/"):
                    raise ValueError("OpenZeppelin dependency imports must remain inside the pinned package root.")
            else:
                raise ValueError("Unsupported import path. Use project-relative imports or the pinned @openzeppelin/contracts package.")
            if resolved not in sources:
                raise ValueError("Import does not resolve to a supplied, locked source file: " + imported)
    return sources, remappings



def compile_solidity_project(files: object, dependency_lock: object = None, expected_version: str = "") -> dict:
    """Compile a bounded multi-file project with explicit local source and SHA-256-locked OpenZeppelin inputs."""
    sources, remappings = _validate_solidity_project(files, dependency_lock if dependency_lock is not None else [])
    if expected_version and not re.fullmatch(r"\d+\.\d+\.\d+", expected_version):
        raise ValueError("Expected compiler version must use the exact x.y.z format.")
    status = solidity_compiler_status()
    if not status["available"]:
        raise FileNotFoundError(status["message"])
    if expected_version and status["version"] != expected_version:
        raise RuntimeError("Compiler version mismatch: expected " + expected_version + ", found " + status["version"] + ".")
    if not solidity_lock.acquire(blocking=False):
        raise BlockingIOError("A local Solidity compilation is already running.")
    try:
        standard_input = {
            "language": "Solidity",
            "sources": {path: {"content": content} for path, content in sources.items()},
            "settings": {
                "remappings": remappings,
                "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
            },
        }
        payload = json.dumps(standard_input, separators=(",", ":")).encode("utf-8")
        command = [shutil.which("solc"), "--standard-json"]
        kwargs = {
            "input": payload, "capture_output": True, "timeout": SOLIDITY_RUNTIME,
            "check": False, "env": {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
        }
        if os.name == "posix":
            try:
                import resource
                def limit_process():
                    resource.setrlimit(resource.RLIMIT_CPU, (SOLIDITY_RUNTIME, SOLIDITY_RUNTIME + 2))
                    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SOLIDITY_OUTPUT, MAX_SOLIDITY_OUTPUT))
                    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
                kwargs["preexec_fn"] = limit_process
            except (ImportError, AttributeError, OSError, ValueError):
                pass
        completed = subprocess.run(command, **kwargs)
        raw = completed.stdout
        if len(raw) > MAX_SOLIDITY_OUTPUT or len(completed.stderr) > 16000:
            raise RuntimeError("Compiler output exceeded the configured safety limit.")
        if completed.returncode not in (0, 1) or not raw.strip():
            raise RuntimeError("solc failed to return standard JSON output: " + completed.stderr.decode("utf-8", "replace")[:1000])
        try:
            output = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("solc returned invalid or truncated standard JSON output.") from exc
        diagnostics = []
        for item in output.get("errors", [])[:200]:
            if not isinstance(item, dict):
                continue
            location = item.get("sourceLocation") or {}
            diagnostics.append({
                "severity": item.get("severity", "info"),
                "code": str(item.get("errorCode", ""))[:32],
                "message": str(item.get("formattedMessage") or item.get("message") or "")[:4000],
                "file": str(location.get("file", ""))[:160],
                "line": location.get("start"),
            })
        contracts = []
        for file_name, entries in output.get("contracts", {}).items():
            if not isinstance(entries, dict):
                continue
            for name, artifact in entries.items():
                contracts.append({
                    "file": str(file_name)[:160], "name": str(name)[:128],
                    "abi": artifact.get("abi", []),
                    "bytecode": (artifact.get("evm") or {}).get("bytecode", {}).get("object", "")[:500000],
                })
        errors = sum(1 for item in diagnostics if item["severity"] == "error")
        return {
            "status": "failed" if errors or completed.returncode else "compiled",
            "compiler": "solc", "version": status["version"],
            "diagnostics": diagnostics, "contracts": contracts,
            "source_files": len(sources), "dependency_packages": len(dependency_lock or []),
            "note": "Compilation is local and uses only the supplied in-memory files. OpenZeppelin file integrity is checked against the supplied SHA-256 lock entries; repository/commit provenance must be independently verified by the operator. No network fetch, package install, deployment or signing occurs. Compilation is not a security audit or test run.",
        }
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Solidity project compilation exceeded the 30-second limit.") from exc
    finally:
        solidity_lock.release()



def compile_solidity(source: str, expected_version: str = "") -> dict:
    """Backward-compatible single-file, import-free compiler entry point."""
    if not isinstance(source, str) or not source.strip() or len(source.encode("utf-8")) > MAX_SOLIDITY_SOURCE:
        raise ValueError("Provide Solidity source between 1 and 100,000 UTF-8 bytes.")
    if re.search(r"\bimport\b", source):
        raise ValueError("Imports are not supported in the single-file compiler endpoint; use the locked multi-file project endpoint.")
    result = compile_solidity_project(
        [{"path": "src/Contract.sol", "content": source}], [], expected_version
    )
    result["note"] = "Single-file local compilation; imports are not supported by this compatibility endpoint. " + result["note"]
    return result



def solidity_test_runner_status() -> dict:
    """Fail-closed discovery for rootless, preloaded, digest-pinned Foundry."""
    executable = shutil.which("podman")
    image = os.environ.get("CYBERLAB_FOUNDRY_IMAGE", "").strip()
    pinned = bool(re.fullmatch(r"[A-Za-z0-9._/:+-]+@sha256:[a-f0-9]{64}", image))
    if not executable:
        return {"available": False, "message": "Rootless Podman is required; Docker and direct host execution are not accepted."}
    if not pinned:
        return {"available": False, "message": "Configure CYBERLAB_FOUNDRY_IMAGE with a locally preloaded trusted image pinned by sha256 digest. No image is pulled."}
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home())}
    try:
        rootless = subprocess.run([executable, "info", "--format", "{{.Host.Security.Rootless}}"], capture_output=True, text=True, timeout=8, check=False, env=env)
        if rootless.returncode or rootless.stdout.strip().lower() != "true":
            return {"available": False, "message": "Podman is not confirmed rootless; execution is disabled."}
        present = subprocess.run([executable, "image", "exists", image], capture_output=True, text=True, timeout=8, check=False, env=env)
        if present.returncode:
            return {"available": False, "message": "The configured digest-pinned Foundry image is not present locally. Load it manually; no pull is attempted."}
        return {"available": True, "runtime": "rootless Podman", "image": image, "message": "Local rootless Podman and digest-pinned image are ready for offline tests."}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "message": "Could not verify rootless Podman and the local image."}



def _validate_solidity_test_files(files: object, dependency_lock: object = None) -> tuple[list[dict], list[str]]:
    if not isinstance(files, list) or not 2 <= len(files) <= 100:
        raise ValueError("Provide 2–100 project files, including a contract and a Foundry test.")
    seen, has_source, has_test = set(), False, False
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "content"}:
            raise ValueError("Each project file must contain only path and content.")
        path = item["path"]
        if not isinstance(path, str):
            raise ValueError("Every Solidity file needs a text path.")
        if path in seen:
            raise ValueError("Duplicate project paths are not accepted.")
        seen.add(path)
        has_source = has_source or bool(re.fullmatch(r"src/[A-Za-z0-9_.-]+\.sol", path))
        has_test = has_test or bool(re.fullmatch(r"test/[A-Za-z0-9_.-]+\.t\.sol", path))
    if not has_source or not has_test:
        raise ValueError("Include at least one src/*.sol contract and one test/*.t.sol test.")
    sources, remappings = _validate_solidity_project(files, dependency_lock if dependency_lock is not None else [])
    return [{"path": path, "content": content} for path, content in sources.items()], remappings


def run_solidity_tests(files: object, dependency_lock: object = None) -> dict:
    """Run Foundry only in a preloaded rootless Podman sandbox; never on host."""
    project_files, remappings = _validate_solidity_test_files(files, dependency_lock)
    status = solidity_test_runner_status()
    if not status["available"]:
        raise FileNotFoundError(status["message"])
    if not solidity_test_lock.acquire(blocking=False):
        raise BlockingIOError("A local Solidity test run is already active.")
    try:
        executable = shutil.which("podman")
        image = os.environ["CYBERLAB_FOUNDRY_IMAGE"].strip()
        with tempfile.TemporaryDirectory(prefix="cyberlab-solidity-") as workspace:
            root = Path(workspace)
            for item in project_files:
                destination = root / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(item["content"], encoding="utf-8")
            foundry_config = (
                '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
                'cache_path = "cache"\nlibs = ["lib"]\nauto_detect_solc = true\noptimizer = false\n'
                'remappings = ' + json.dumps(remappings) + '\n'
            )
            (root / "foundry.toml").write_text(foundry_config, encoding="utf-8")
            command = [
                executable, "run", "--rm", "--pull=never", "--network=none",
                "--memory=1g", "--cpus=1", "--pids-limit=64", "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
                "--security-opt=no-new-privileges", "--cap-drop=all", "--userns=keep-id",
                "--volume", workspace + ":/workspace:rw", "--workdir", "/workspace",
                image, "forge", "test", "--offline", "--json",
            ]
            stdout_path, stderr_path = root / "runner.stdout", root / "runner.stderr"
            def limit_runner():
                try:
                    import resource
                    resource.setrlimit(resource.RLIMIT_CPU, (SOLIDITY_TEST_RUNTIME, SOLIDITY_TEST_RUNTIME + 2))
                    resource.setrlimit(resource.RLIMIT_FSIZE, (SOLIDITY_TEST_OUTPUT, SOLIDITY_TEST_OUTPUT))
                    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
                except (ImportError, AttributeError, OSError, ValueError):
                    pass
            try:
                with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
                    completed = subprocess.run(
                        command, stdout=out, stderr=err, timeout=SOLIDITY_TEST_RUNTIME,
                        check=False, env={"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home()), "LANG": "C.UTF-8"},
                        preexec_fn=limit_runner if os.name == "posix" else None,
                    )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError("Solidity tests exceeded the 120-second limit.") from exc
            stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
            if len(stdout) > SOLIDITY_TEST_OUTPUT or len(stderr) > SOLIDITY_TEST_OUTPUT:
                raise RuntimeError("Test runner output exceeded the 256 KB limit.")
            if completed.returncode not in (0, 1) or not stdout.strip():
                raise RuntimeError("Sandboxed Foundry runner failed: " + stderr.decode("utf-8", "replace")[:1200])
            try:
                result = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("Foundry returned invalid or truncated JSON test results.") from exc
            if not isinstance(result, dict):
                raise RuntimeError("Foundry returned an unexpected test result shape.")
            return {
                "status": "passed" if completed.returncode == 0 else "failed",
                "exit_code": completed.returncode, "result": result,
                "stderr": stderr.decode("utf-8", "replace")[:8000],
                "sandbox": "rootless Podman; no network; 1 GiB memory; 1 CPU; 64 processes; read-only image filesystem",
                "note": "A passing test suite is not a security audit or proof of correctness.",
            }
    finally:
        solidity_test_lock.release()



class Handler(BaseHTTPRequestHandler):
    server_version = "CyberLabKaliBridge/1.0"

    def log_message(self, fmt, *args):
        print("[bridge] " + (fmt % args))

    def send_json(self, status: int, payload: dict, origin: str | None = None):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def authorised(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.server.bridge_token
        return hmac.compare_digest(supplied, expected)

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if not (path in {"/health", "/system", "/capabilities", "/ollama/health", "/ollama/models", "/solidity/compiler", "/solidity/tests/status", "/wallet/status", "/tools/runners", "/forensics/devices", "/tools", "/burp/status", "/burp/proxy/history", "/burp/site-map", "/burp/issues", "/network/interfaces", "/web/history", "/proxy/ca/status", "/proxy/ca/certificate", "/proxy/status", "/proxy/history", "/proxy/intercepts", "/proxy/response-intercepts", "/proxy/websocket-frames", "/proxy/websocket-intercepts", "/evidence/case/ledger/verify"} or re.fullmatch(r"/forensics/jobs/[a-f0-9]{32}", path)):
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Pairing token required."}, origin)
        if path == "/capabilities":
            return self.send_json(200, {"status": "ok", "capabilities": environment_capabilities()}, origin)
        if path == "/solidity/compiler":
            return self.send_json(200, solidity_compiler_status(), origin)
        if path == "/solidity/tests/status":
            return self.send_json(200, solidity_test_runner_status(), origin)
        if path == "/wallet/status":
            return self.send_json(200, wallet_tool_status(), origin)
        if path == "/tools/runners":
            return self.send_json(200, kali_tools.list_tools(), origin)
        if path == "/ollama/health":
            try:
                models = ollama_models()
                return self.send_json(200, {"status": "available", "endpoint": OLLAMA_URL, "model_count": len(models)}, origin)
            except (ConnectionError, ValueError) as exc:
                return self.send_json(503, {"status": "unavailable", "error": str(exc)}, origin)
        if path == "/ollama/models":
            try:
                return self.send_json(200, {"models": ollama_models()}, origin)
            except (ConnectionError, ValueError) as exc:
                return self.send_json(503, {"error": str(exc)}, origin)
        if path == "/tools":
            return self.send_json(200, inspect_tool_catalog(), origin)
        if path == "/proxy/ca/status":
            return self.send_json(200, ca_status(), origin)
        if path == "/proxy/ca/certificate":
            try:
                return self.send_json(200, ca_certificate_pem(), origin)
            except ValueError as exc:
                return self.send_json(400, {"error": str(exc)}, origin)
        if path == "/proxy/status":
            return self.send_json(200, PROXY.status(), origin)
        if path == "/proxy/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, proxy_history(limit), origin)
        if path == "/proxy/intercepts":
            return self.send_json(200, pending_intercepts(), origin)
        if path == "/proxy/response-intercepts":
            return self.send_json(200, pending_response_intercepts(), origin)
        if path == "/proxy/websocket-frames":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except (TypeError, ValueError):
                limit = 100
            return self.send_json(200, websocket_frame_history(limit), origin)
        if path == "/proxy/websocket-intercepts":
            return self.send_json(200, pending_websocket_frames(), origin)
        if path == "/network/interfaces":
            return self.send_json(200, list_capture_interfaces(), origin)
        if path == "/web/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["20"])[0])
            except (TypeError, ValueError):
                limit = 20
            return self.send_json(200, request_history(limit), origin)
        if path == "/burp/status":
            return self.send_json(200, inspect_burp_status(), origin)
        if path == "/burp/proxy/history":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_proxy_history(limit), origin)
        if path == "/burp/site-map":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_site_map(limit), origin)
        if path == "/burp/issues":
            query = parse_qs(urlparse(self.path).query)
            try:
                limit = int(query.get("limit", ["50"])[0])
            except (TypeError, ValueError):
                limit = 50
            return self.send_json(200, inspect_burp_issues(limit), origin)
        if path == "/evidence/case/ledger/verify":
            return self.send_json(200, verify_audit_ledger(), origin)
        if path == "/forensics/devices":
            try:
                return self.send_json(200, list_block_devices(), origin)
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                return self.send_json(400, {"error": str(exc)}, origin)
        if path.startswith("/forensics/jobs/"):
            job = get_image_job(path.rsplit("/", 1)[-1])
            return self.send_json(200 if job else 404, job or {"error": "Unknown or expired acquisition job."}, origin)
        if path == "/system":
            return self.send_json(200, {"status": "ok", "metrics": system_snapshot()}, origin)
        self.send_json(200, {"status": "connected", "agent": "CyberLab Kali Bridge", "nmap": bool(shutil.which("nmap"))}, origin)

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if path not in {"/plan", "/research", "/services", "/evidence/report", "/evidence/artifacts", "/evidence/case", "/evidence/case/export", "/evidence/case/verify", "/scan", "/forensics/image", "/forensics/foremost", "/forensics/inspect", "/forensics/partitions", "/forensics/fsstat", "/forensics/deleted-list", "/forensics/recover-file", "/burp/repeater/from-history", "/network/capture", "/web/request", "/web/crawl", "/web/active-scan", "/web/parameters/inspect", "/web/parameters/generate", "/web/parameters/analyze", "/proxy/ca/create", "/proxy/start", "/proxy/stop", "/proxy/intercepts/decision", "/proxy/response-intercepts/decision", "/proxy/websocket-intercepts/decision", "/ollama/chat", "/solidity/compile", "/solidity/project/compile", "/solidity/tests/run", "/wallet/extract-hash", "/wallet/derive", "/wallet/crack", "/tools/run"}:
            return self.send_json(404, {"error": "Not found."}, origin)
        if not self.authorised():
            return self.send_json(401, {"error": "Invalid pairing token."}, origin)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body_limit = (
                MAX_OLLAMA_BODY if path == "/ollama/chat" else
                MAX_SOLIDITY_PROJECT_BODY if path in {"/solidity/project/compile", "/solidity/tests/run"} else
                MAX_SOLIDITY_BODY if path == "/solidity/compile" else
                600000 if path == "/evidence/case/export" else
                131072 if path in {"/proxy/intercepts/decision", "/proxy/websocket-intercepts/decision"} else
                8192 if path == "/evidence/case/verify" else
                131072 if path == "/evidence/case" else
                65536 if path in {"/evidence/report", "/evidence/artifacts"} else
                4_200_000 if path == "/wallet/extract-hash" else
                4096 if path in {"/wallet/derive", "/wallet/crack", "/forensics/deleted-list", "/forensics/recover-file"} else
                8192 if path == "/tools/run" else
                32768 if path in {"/web/request", "/web/crawl", "/web/active-scan", "/web/parameters/inspect", "/web/parameters/generate", "/web/parameters/analyze"} else MAX_BODY
            )
            if length < 2 or length > body_limit:
                raise ValueError("Request body is missing or too large.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/ollama/chat":
                result = ollama_chat(str(data.get("model", "")), str(data.get("prompt", "")), data.get("history"))
                return self.send_json(200, result, origin)
            if path == "/solidity/compile":
                result = compile_solidity(data.get("source"), str(data.get("expectedCompilerVersion", "")))
                return self.send_json(200, result, origin)
            if path == "/solidity/project/compile":
                result = compile_solidity_project(data.get("files"), data.get("dependencyLock", []), str(data.get("expectedCompilerVersion", "")))
                return self.send_json(200, result, origin)
            if path == "/solidity/tests/run":
                result = run_solidity_tests(data.get("files"), data.get("dependencyLock", []))
                return self.send_json(200, result, origin)
            if path == "/wallet/extract-hash":
                return self.send_json(200, wallet_extract_hash(data), origin)
            if path == "/wallet/derive":
                return self.send_json(200, wallet_derive(data), origin)
            if path == "/wallet/crack":
                return self.send_json(200, wallet_crack(data), origin)
            if path == "/tools/run":
                return self.send_json(200, run_kali_tool(data), origin)
            if path == "/proxy/intercepts/decision":
                try:
                    return self.send_json(200, decide_intercept(data.get("id", ""), data.get("action", ""), data.get("edits")), origin)
                except ValueError as exc:
                    return self.send_json(409, {"error": str(exc)}, origin)
            if path == "/proxy/response-intercepts/decision":
                try:
                    return self.send_json(200, decide_response_intercept(data.get("id", ""), data.get("action", ""), data.get("edits")), origin)
                except ValueError as exc:
                    return self.send_json(409, {"error": str(exc)}, origin)
            if path == "/proxy/websocket-intercepts/decision":
                try:
                    return self.send_json(200, decide_websocket_frame(
                        data.get("id", ""), data.get("action", ""), data.get("payload")), origin)
                except ValueError as exc:
                    return self.send_json(409, {"error": str(exc)}, origin)
            if path == "/proxy/start":
                if not proxy_control_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A proxy control operation is already running."}, origin)
                try:
                    return self.send_json(201, PROXY.start(data), origin)
                finally:
                    proxy_control_lock.release()
            if path == "/proxy/stop":
                return self.send_json(200, PROXY.stop(), origin)
            if path == "/proxy/ca/create":
                if data.get("confirmCreateLocalCA") is not True:
                    return self.send_json(400, {"error": "Explicitly confirm creation of a local CA whose certificate must be manually trusted by the operator."}, origin)
                if not proxy_ca_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "Local inspection CA creation is already running."}, origin)
                try:
                    return self.send_json(201, create_local_ca(), origin)
                finally:
                    proxy_ca_lock.release()
            if path == "/web/active-scan":
                if not web_active_scan_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native active web check is already running."}, origin)
                try:
                    result = run_active_scan(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_active_scan_lock.release()
            if path == "/web/crawl":
                if not web_crawl_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native web crawl is already running."}, origin)
                try:
                    result = run_crawl(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_crawl_lock.release()
            if path == "/web/parameters/inspect":
                result = inspect_parameters(
                    str(data.get("url", "")), str(data.get("body", "")),
                    str(data.get("contentType", "")),
                )
                return self.send_json(200, result, origin)
            if path == "/web/parameters/generate":
                result = generate_cases(
                    str(data.get("url", "")), str(data.get("body", "")),
                    str(data.get("contentType", "")), data.get("location"),
                    data.get("parameterIndex"), data.get("payloads"),
                    data.get("method", "GET"),
                )
                return self.send_json(200, result, origin)
            if path == "/web/parameters/analyze":
                result = compare_responses(data.get("baseline"), data.get("candidate"))
                return self.send_json(200, result, origin)
            if path == "/web/request":
                if not web_request_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native HTTP request is already running."}, origin)
                try:
                    result = execute_request(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_request_lock.release()
            if path == "/network/capture":
                if not network_capture_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A packet capture is already running."}, origin)
                try:
                    result = capture_packets(
                        interface=data.get("interface"),
                        confirmation_interface=data.get("confirmationInterface"),
                        authorization_confirmed=data.get("authorizationConfirmed") is True,
                        authorization_reference=data.get("authorizationReference"),
                        duration_seconds=data.get("durationSeconds", 10),
                        packet_limit=data.get("packetLimit", 500),
                        filter_name=data.get("filter", "ssh"),
                    )
                    status_code = 200 if result.get("status") == "completed" else (503 if result.get("status") == "unavailable" else 502)
                    return self.send_json(status_code, result, origin)
                finally:
                    network_capture_lock.release()
            if path == "/burp/repeater/from-history":
                if data.get("confirmOpenInRepeater") is not True:
                    return self.send_json(400, {"status": "confirmation_required", "request_sent": False}, origin)
                history_id = data.get("historyId")
                if isinstance(history_id, bool) or not isinstance(history_id, int):
                    return self.send_json(400, {"status": "invalid_request", "request_sent": False}, origin)
                result = open_burp_history_in_repeater(history_id, confirmed=True)
                status_code = 200 if result.get("status") == "opened_in_repeater" else 400
                return self.send_json(status_code, result, origin)
            if path == "/plan":
                return self.send_json(200, plan_task(data.get("prompt", "")), origin)
            if path == "/research":
                if not research_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A passive research request is already running."}, origin)
                try:
                    return self.send_json(200, run_research_action(data), origin)
                finally:
                    research_lock.release()
            if path == "/evidence/case/verify":
                return self.send_json(200, verify_case_archive(data.get("caseId")), origin)
            if path == "/evidence/case/export":
                case_report = data.get("caseReport")
                if not case_export_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A case export is already being written."}, origin)
                try:
                    return self.send_json(200, export_case_bundle(case_report), origin)
                finally:
                    case_export_lock.release()
            if path == "/evidence/case":
                service_evidence, artifact_evidence = validate_case_payload(data)
                if not case_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A case report is already being written."}, origin)
                try:
                    report = build_case_report(service_evidence, artifact_evidence)
                    return self.send_json(201, report, origin)
                finally:
                    case_lock.release()
            if path == "/evidence/artifacts":
                triage_evidence, recovery_evidence = validate_artifact_payload(data)
                if not artifact_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "An artifact analysis request is already running."}, origin)
                try:
                    report = build_artifact_report(triage_evidence, recovery_evidence)
                    return self.send_json(200, report, origin)
                finally:
                    artifact_lock.release()
            if path == "/evidence/report":
                scan_evidence, service_evidence = validate_report_payload(data)
                if not evidence_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "An evidence analysis request is already running."}, origin)
                try:
                    report = build_service_report(scan_evidence, service_evidence)
                    return self.send_json(200, report, origin)
                finally:
                    evidence_lock.release()
            if path == "/services":
                target_value = data.get("target")
                if not isinstance(target_value, str):
                    raise ValueError("Enter one IP address or hostname.")
                target = valid_target(target_value)
                confirmation = data.get("confirmationTarget")
                reference = data.get("authorizationReference")
                if (data.get("authorizationConfirmed") is not True or not isinstance(confirmation, str)
                        or confirmation.strip().lower().rstrip(".") != target_value.strip().lower().rstrip(".")
                        or not isinstance(reference, str) or not reference.strip() or len(reference) > 160):
                    raise ValueError("Confirm ownership or written permission, provide an approval reference and retype the exact target.")
                if not service_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A service-identification request is already running."}, origin)
                try:
                    result = enumerate_services(target, data.get("ports"))
                    return self.send_json(200, result, origin)
                finally:
                    service_lock.release()
            if path == "/forensics/fsstat":
                result = inspect_partition_filesystem(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                    data.get("startSector"),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/partitions":
                result = inspect_image_partitions(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/inspect":
                result = inspect_image_filesystem(
                    str(data.get("imageJobId", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(200, result, origin)
            if path == "/forensics/foremost":
                result = start_foremost_recovery(
                    str(data.get("imageJobId", "")),
                    str(data.get("outputDirectory", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(202, result, origin)
            if path == "/forensics/deleted-list":
                offset = data.get("offset", 0)
                if not isinstance(offset, int) or isinstance(offset, bool):
                    raise ValueError("offset must be an integer.")
                limit = data.get("limit", 1000)
                if not isinstance(limit, int) or isinstance(limit, bool):
                    raise ValueError("limit must be an integer.")
                result = list_deleted_files(str(data.get("imageJobId", "")), str(data.get("confirmationImage", "")), offset=offset, limit=limit)
                return self.send_json(200, result, origin)
            if path == "/forensics/recover-file":
                offset = data.get("offset", 0)
                if not isinstance(offset, int) or isinstance(offset, bool):
                    raise ValueError("offset must be an integer.")
                result = recover_deleted_file(
                    str(data.get("imageJobId", "")), str(data.get("confirmationImage", "")),
                    str(data.get("inode", "")), str(data.get("outputDirectory", "")),
                    offset=offset, filename=str(data.get("filename", "")))
                return self.send_json(201, result, origin)
            if path == "/forensics/image":
                result = start_image_acquisition(
                    str(data.get("source", "")),
                    str(data.get("destinationDirectory", "")),
                    str(data.get("filename", "")),
                    str(data.get("confirmationSource", "")),
                )
                return self.send_json(202, result, origin)
            target = valid_target(str(data.get("target", "")))
            confirmation = str(data.get("confirmationTarget", "")).strip().lower().rstrip(".")
            reference = str(data.get("authorizationReference", "")).strip()
            if data.get("authorizationConfirmed") is not True or confirmation != str(data.get("target", "")).strip().lower().rstrip(".") or not reference or len(reference) > 160:
                raise ValueError("Confirm ownership or written permission, provide an approval reference and retype the exact target.")
            ports_raw = data.get("ports", [])
            if not isinstance(ports_raw, list) or not ports_raw or len(ports_raw) > MAX_PORTS or any(type(p) is not int or not 1 <= p <= 65535 for p in ports_raw):
                raise ValueError("Select between 1 and 100 unique TCP ports in the range 1–65535.")
            ports = sorted(set(ports_raw))
            if len(ports) != len(ports_raw):
                raise ValueError("Duplicate ports are not accepted.")
            if not shutil.which("nmap"):
                return self.send_json(503, {"error": "Nmap is not installed. Install it with: sudo apt install nmap"}, origin)
            if not scan_lock.acquire(blocking=False):
                return self.send_json(409, {"error": "A local assessment is already running."}, origin)
            try:
                command = [
                    "nmap", "-n", "-sT", "-sV", "--version-light", "--reason", "-T2",
                    "--max-retries", "1", "--host-timeout", "45s",
                    "-p", ",".join(map(str, ports)), "-oX", "-", target,
                ]
                started = time.time()
                completed = subprocess.run(command, capture_output=True, text=True, timeout=MAX_RUNTIME, check=False)
                if completed.returncode not in (0, 1) or not completed.stdout.strip():
                    raise RuntimeError((completed.stderr or "Nmap did not return a report.")[:700])
                report = parse_report(completed.stdout)
                return self.send_json(200, {
                    "status": "completed",
                    "target": target,
                    "ports_checked": ports,
                    "duration_seconds": round(time.time() - started, 1),
                    "method": "Nmap TCP connect scan with light service version detection",
                    **report,
                    "note": "Nmap reports selected TCP ports as open, closed or filtered when determinable. Filtered means a firewall or network control prevented a definitive result. This is not a vulnerability verdict. No NSE scripts, exploit checks, credentials, evasion or denial-of-service options are used. Assess only systems explicitly in scope.",
                }, origin)
            finally:
                scan_lock.release()
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)}, origin)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"error": "Assessment exceeded the 55-second time limit."}, origin)
        except Exception as exc:
            self.send_json(502, {"error": str(exc)[:700]}, origin)


def main():
    parser = argparse.ArgumentParser(description="CyberLab local Kali bridge (loopback only).")
    parser.add_argument("--host", default=HOST, choices=[HOST], help="Must remain bound to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")
    token = load_token()
    if not shutil.which("nmap"):
        print("Nmap not found. Install with: sudo apt update && sudo apt install -y nmap")
    print("\nCyberLab Kali Bridge is ready.")
    print("Listening only on http://127.0.0.1:" + str(args.port))
    print("Pairing token (keep private; enter it in your CyberLab dashboard):\n" + token)
    print("\nPress Ctrl+C to stop the bridge.\n")
    server = ThreadingHTTPServer((HOST, args.port), Handler)
    server.bridge_token = token
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberLab Kali Bridge...")
    finally:
        PROXY.stop()
        server.server_close()


if __name__ == "__main__":
    main()
