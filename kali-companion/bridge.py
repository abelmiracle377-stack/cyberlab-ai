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

from forensics import get_image_job, inspect_image_filesystem, inspect_image_partitions, list_block_devices, start_foremost_recovery, start_image_acquisition, list_deleted_files, recover_deleted_file, recover_all_deleted_files, start_photorec_recovery
from filesystem_analysis import inspect_partition_filesystem
from tool_catalog import inspect_tool_catalog
from burp_connector import inspect_burp_status, inspect_burp_proxy_history, inspect_burp_site_map, inspect_burp_issues, open_burp_history_in_repeater, send_in_scope_request
from network_capture import list_capture_interfaces, capture_packets
from web_testing import execute_request, request_history
from web_crawler import run_crawl
from web_active_scan import run_active_scan
from web_assessment import run_assessment
import academy_lab
import shodan_connector
import wifi_assessment
import wifi_authorized
from parameter_lab import inspect_parameters, generate_cases
from parameter_analysis import compare_responses
from proxy_certificates import ca_status, ca_certificate_pem, create_local_ca
from intercept_proxy import PROXY, decide_intercept, pending_intercepts, pending_response_intercepts, decide_response_intercept, proxy_history, websocket_frame_history, pending_websocket_frames, decide_websocket_frame
import base64
import wallet_recovery
import wallet_cracking
import seed_solver
import balance_check
import kali_tools
import host_telemetry
import soc_engine
import cybersoc
import splunk_connector
import wazuh_connector
import pcap_analysis
import plist_forensics
import sqlite_forensics
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
web_assessment_lock = threading.Lock()
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



def _read_os_release() -> dict:
    data = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def _read_cyberlab_os_marker() -> dict | None:
    """Return the CyberLab AI OS marker fields, or None when not a CyberLab OS VM."""
    try:
        text = Path("/etc/cyberlab-ai-os-release").read_text(encoding="utf-8")
    except OSError:
        return None
    marker = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            marker[key.strip()] = value.strip().strip('"').strip("'")
    return marker if marker.get("CYBERLAB_OS") == "1" else None


def detect_companion_type(os_release: dict, cyberlab_marker: dict | None) -> dict:
    """Classify the host the companion runs on (pure function; easy to test)."""
    if cyberlab_marker:
        return {
            "companion_type": "cyberlab-os",
            "label": "CyberLab AI OS VM companion",
            "edition": cyberlab_marker.get("EDITION", "") or cyberlab_marker.get("VERSION_ID", ""),
            "distribution": cyberlab_marker.get("NAME", "CyberLab AI OS"),
        }
    distro_id = (os_release.get("ID", "") or "").lower()
    id_like = (os_release.get("ID_LIKE", "") or "").lower()
    if distro_id == "kali" or "kali" in id_like:
        return {"companion_type": "kali", "label": "Kali Linux companion", "edition": "",
                "distribution": os_release.get("PRETTY_NAME", "Kali Linux")}
    return {"companion_type": "linux", "label": "Linux companion", "edition": "",
            "distribution": os_release.get("PRETTY_NAME", "Linux")}


def companion_identity() -> dict:
    """Self-identify the companion so the dashboard can label and offer each VM type."""
    identity = detect_companion_type(_read_os_release(), _read_cyberlab_os_marker())
    runners = kali_tools.list_tools()["tools"]
    identity.update({
        "agent": "CyberLab Companion Bridge",
        "architecture": platform.machine(),
        "tool_count": len(runners),
        "tools_installed": sum(1 for tool in runners if tool["installed"]),
        "note": "Companion identity only. Hostname, IP addresses, usernames and environment variables are not disclosed.",
    })
    return identity


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
    if kind in {"metamask", "metamask-vault"}:
        vault = data.get("vaultJson")
        if not isinstance(vault, str) or not vault.strip():
            raise ValueError("Provide the MetaMask vault JSON in 'vaultJson'.")
        return wallet_recovery.extract_metamask_hash(vault)
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
    raise ValueError("Unknown wallet kind. Use 'keystore', 'wallet.dat' or 'metamask'.")


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
    response = {"template": template, "count": len(accounts), "accounts": accounts,
                "note": "Derived locally from the supplied mnemonic. Private keys and the mnemonic never leave this machine."}
    electrum = wallet_recovery.electrum_seed_type(mnemonic)
    if electrum:
        if electrum in wallet_recovery.ELECTRUM_SUPPORTED:
            response["warning"] = ("This is an Electrum " + electrum + " seed, not a BIP39 seed. The "
                                   "addresses above (BIP39/BIP44) will not match your Electrum wallet. "
                                   "Use 'Derive as Electrum wallet' (/wallet/electrum-derive) for the correct addresses.")
        else:
            response["warning"] = ("This is an Electrum " + electrum + " seed, which uses a 2FA cosigner "
                                   "and cannot be recovered from the seed alone. Recover it in the Electrum client.")
    elif wallet_recovery.is_old_electrum_seed(mnemonic):
        response["warning"] = ("This looks like an Electrum old (pre-2016) seed, not BIP39. If the "
                               "addresses above don't match your wallet, use 'Derive as Electrum wallet' "
                               "(/wallet/electrum-derive) for the correct legacy addresses.")
    return response


def wallet_electrum_derive(data: dict) -> dict:
    """Derive the correct addresses for an Electrum v2 standard or segwit seed."""
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("Provide the Electrum recovery phrase in 'mnemonic'.")
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    count = data.get("count", 5)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 100:
        raise ValueError("count must be an integer between 1 and 100.")
    include_change = data.get("includeChange", True) is not False
    if wallet_recovery.electrum_seed_type(mnemonic):
        result = wallet_recovery.derive_electrum_accounts(
            mnemonic, passphrase, count=count, include_change=include_change)
    elif wallet_recovery.is_old_electrum_seed(mnemonic):
        # Old Electrum seeds predate passphrases; the passphrase is not used.
        result = wallet_recovery.derive_old_electrum_accounts(
            mnemonic, count=count, include_change=include_change)
    else:
        raise ValueError("Not a recognised Electrum seed (v2 standard/segwit, or old/pre-2016).")
    result["note"] = "Derived locally from the Electrum seed. Keys and the seed never leave this machine."
    return result


def wallet_solve_seed(data: dict) -> dict:
    """Reconstruct a mnemonic that is missing words or out of order.

    Loads the operator's own SHA-256-verified BIP-39 english.txt and searches
    offline for checksum-valid phrases, narrowing to a known address if given.
    """
    wordlist_path = data.get("wordlistPath")
    if not isinstance(wordlist_path, str) or not wordlist_path.strip():
        raise ValueError("Provide 'wordlistPath' (the path to your BIP-39 english.txt on this machine).")
    try:
        wordlist = wallet_recovery.load_wordlist(Path(wordlist_path).expanduser())
    except FileNotFoundError:
        raise ValueError("Wordlist file not found at the supplied path.")

    mode = str(data.get("mode", "missing"))
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    match_address = data.get("matchAddress")
    if match_address is not None and (not isinstance(match_address, str) or len(match_address) > 120):
        raise ValueError("matchAddress must be a string address.")
    templates = data.get("templates")
    if templates is not None:
        if not isinstance(templates, list) or not all(isinstance(t, str) for t in templates):
            raise ValueError("templates must be a list of account-template names.")
        unknown = [t for t in templates if t not in wallet_recovery.ACCOUNT_TEMPLATES]
        if unknown:
            raise ValueError("Unknown account template(s): " + ", ".join(unknown))
    gap = data.get("addressGap", 5)
    if not isinstance(gap, int) or isinstance(gap, bool) or not 1 <= gap <= 50:
        raise ValueError("addressGap must be an integer between 1 and 50.")
    max_results = data.get("maxResults", seed_solver.DEFAULT_MAX_RESULTS)
    if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= 2000:
        raise ValueError("maxResults must be an integer between 1 and 2000.")
    time_budget = data.get("timeBudgetSeconds", seed_solver.DEFAULT_TIME_BUDGET)
    if not isinstance(time_budget, (int, float)) or isinstance(time_budget, bool) or not 1 <= time_budget <= 600:
        raise ValueError("timeBudgetSeconds must be between 1 and 600.")
    common = dict(match_address=match_address, templates=templates, address_gap=gap,
                  passphrase=passphrase, max_results=max_results, time_budget=time_budget)

    if mode == "scramble":
        words = data.get("words") or data.get("phrase")
        if isinstance(words, str):
            words = words.split()
        if not isinstance(words, list) or not words:
            raise ValueError("Provide the known words in 'words' (any order).")
        max_permutations = data.get("maxPermutations", 400_000)
        if not isinstance(max_permutations, int) or isinstance(max_permutations, bool) or not 1 <= max_permutations <= 5_000_000:
            raise ValueError("maxPermutations must be an integer between 1 and 5,000,000.")
        result = seed_solver.solve_scrambled_order(words, wordlist, max_permutations=max_permutations, **common)
    else:
        phrase = data.get("phrase") or data.get("words")
        if isinstance(phrase, list):
            phrase = " ".join(str(token) for token in phrase)
        if not isinstance(phrase, str) or not phrase.strip():
            raise ValueError("Provide the partial 'phrase', marking each missing word with ? or _.")
        result = seed_solver.solve_missing_words(phrase, wordlist, **common)
    result["mode"] = mode
    return result


def wallet_check_balances(data: dict) -> dict:
    """Opt-in, read-only on-chain balance lookup for derived addresses.

    Either pass 'accounts' (address + coin, no keys) or a 'mnemonic' plus
    'templates' and 'count' to derive and then check. Requires confirmNetwork
    because it is the only wallet step that reaches the network; only public
    addresses are sent, never a key, seed or mnemonic.
    """
    if data.get("confirmNetwork") is not True:
        raise ValueError("Set confirmNetwork to true to allow the read-only explorer lookup.")

    accounts = data.get("accounts")
    if accounts is None:
        mnemonic = data.get("mnemonic")
        if not isinstance(mnemonic, str) or not mnemonic.strip():
            raise ValueError("Provide 'accounts' or a 'mnemonic' to derive and check.")
        passphrase = data.get("passphrase", "")
        if not isinstance(passphrase, str) or len(passphrase) > 256:
            raise ValueError("Passphrase must be a string of at most 256 characters.")
        templates = data.get("templates") or ["bip44-legacy", "bip84-segwit", "bip44-ethereum"]
        if not isinstance(templates, list) or not all(isinstance(t, str) for t in templates):
            raise ValueError("templates must be a list of account-template names.")
        unknown = [t for t in templates if t not in wallet_recovery.ACCOUNT_TEMPLATES]
        if unknown:
            raise ValueError("Unknown account template(s): " + ", ".join(unknown))
        count = data.get("count", 3)
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 20:
            raise ValueError("count must be an integer between 1 and 20.")
        seed = wallet_recovery.mnemonic_to_seed(mnemonic, passphrase)
        accounts = []
        for template in templates:
            for entry in wallet_recovery.derive_accounts(seed, template, count):
                accounts.append({"address": entry["address"], "coin": entry["coin"],
                                 "path": entry["path"]})
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("No addresses to check.")
    # Only ever forward public fields; drop any key material a caller included.
    public = [{"address": a.get("address"), "coin": a.get("coin"), "path": a.get("path")}
              for a in accounts if isinstance(a, dict)]
    return balance_check.check_balances(public)


def wallet_auto_recover(data: dict) -> dict:
    """Detect the seed scheme and recover without the user knowing the wallet type.

    Electrum v2 standard/segwit and Electrum old are derived with their own
    schemes; anything else is treated as BIP39 and swept across coins, accounts
    and change chains. When a phrase could be BIP39 or old Electrum, both sets
    are returned so nothing is missed. Optional balance check surfaces the funded
    path across every candidate.
    """
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("Provide the recovery phrase in 'mnemonic'.")
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    count = data.get("count", 3)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 20:
        raise ValueError("count must be an integer between 1 and 20.")
    include_change = data.get("includeChange", True) is not False

    schemes = []
    accounts = []

    def add(scheme, entries):
        schemes.append(scheme)
        for entry in entries:
            accounts.append({"scheme": scheme, "address": entry["address"],
                             "coin": entry.get("coin", "bitcoin"), "path": entry["path"]})

    v2 = wallet_recovery.electrum_seed_type(mnemonic)
    if v2 in wallet_recovery.ELECTRUM_SUPPORTED:
        add("electrum-" + v2, wallet_recovery.derive_electrum_accounts(
            mnemonic, passphrase, count=count, include_change=include_change)["accounts"])
    elif v2:
        return {"detected": "electrum-" + v2, "recoverable": False, "schemes": [],
                "derived_count": 0, "accounts": [],
                "note": "This is a 2FA (TrustedCoin) Electrum seed; it needs the cosigner and cannot be recovered from the seed alone."}
    else:
        templates = data.get("templates") or ["bip44-legacy", "bip49-p2sh-segwit",
                                               "bip84-segwit", "bip44-ethereum",
                                               "litecoin-legacy", "dogecoin-legacy", "bitcoincash"]
        if not isinstance(templates, list) or not all(isinstance(t, str) for t in templates):
            raise ValueError("templates must be a list of account-template names.")
        unknown = [t for t in templates if t not in wallet_recovery.ACCOUNT_TEMPLATES]
        if unknown:
            raise ValueError("Unknown account template(s): " + ", ".join(unknown))
        seed = wallet_recovery.mnemonic_to_seed(mnemonic, passphrase)
        bip39 = []
        for template in templates:
            bip39.extend(wallet_recovery.derive_sweep(
                seed, template, account_count=min(count, 5), include_change=include_change, per_path=2))
        add("bip39", bip39)
        if wallet_recovery.is_old_electrum_seed(mnemonic):
            add("electrum-old", wallet_recovery.derive_old_electrum_accounts(
                mnemonic, count=count, include_change=include_change)["accounts"])

    result = {"detected": "+".join(schemes), "schemes": schemes,
              "derived_count": len(accounts), "accounts": accounts,
              "note": "Derived locally across every detected scheme. Keys and the seed stay on this machine."}
    if data.get("checkBalances") is True:
        if data.get("confirmNetwork") is not True:
            raise ValueError("Set confirmNetwork to true to allow the read-only explorer lookup.")
        result["balances"] = balance_check.check_balances(
            [{"address": a["address"], "coin": a["coin"], "path": a["path"] + " [" + a["scheme"] + "]"}
             for a in accounts])
    return result


def wallet_sweep(data: dict) -> dict:
    """Derive across account indices and change chains, optionally balance-checked.

    Finds wallets whose funds sit on account 1+ or on the change chain, which a
    first-receiving-address derivation misses. With checkBalances+confirmNetwork
    it reports which derivation paths actually hold funds.
    """
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("Provide the recovery mnemonic in 'mnemonic'.")
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    templates = data.get("templates") or ["bip44-legacy", "bip84-segwit", "bip44-ethereum"]
    if not isinstance(templates, list) or not all(isinstance(t, str) for t in templates):
        raise ValueError("templates must be a list of account-template names.")
    unknown = [t for t in templates if t not in wallet_recovery.ACCOUNT_TEMPLATES]
    if unknown:
        raise ValueError("Unknown account template(s): " + ", ".join(unknown))
    account_count = data.get("accountCount", 3)
    if not isinstance(account_count, int) or isinstance(account_count, bool) or not 1 <= account_count <= 20:
        raise ValueError("accountCount must be an integer between 1 and 20.")
    per_path = data.get("perPath", 3)
    if not isinstance(per_path, int) or isinstance(per_path, bool) or not 1 <= per_path <= 50:
        raise ValueError("perPath must be an integer between 1 and 50.")
    include_change = data.get("includeChange", True) is not False

    seed = wallet_recovery.mnemonic_to_seed(mnemonic, passphrase)
    accounts = []
    for template in templates:
        accounts.extend(wallet_recovery.derive_sweep(
            seed, template, account_count=account_count,
            include_change=include_change, per_path=per_path))
    public = [{"address": a["address"], "coin": a["coin"], "path": a["path"],
               "template": a["template"], "account": a["account"], "change": a["change"]}
              for a in accounts]
    result = {"derived_count": len(public), "accounts": public,
              "note": "Derived locally across accounts and change chains. Keys stay on this machine."}
    if data.get("checkBalances") is True:
        if data.get("confirmNetwork") is not True:
            raise ValueError("Set confirmNetwork to true to allow the read-only explorer lookup.")
        result["balances"] = balance_check.check_balances(
            [{"address": a["address"], "coin": a["coin"], "path": a["path"]} for a in public])
    return result


def wallet_bip38_decrypt(data: dict) -> dict:
    """Decrypt a BIP38 ('6P...') encrypted private key with a known passphrase."""
    encrypted = data.get("encryptedKey")
    passphrase = data.get("passphrase")
    if not isinstance(encrypted, str) or not encrypted.strip():
        raise ValueError("Provide the BIP38 key in 'encryptedKey'.")
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Provide the 'passphrase'.")
    if len(passphrase) > 1024:
        raise ValueError("Passphrase is too long.")
    result = wallet_recovery.decrypt_bip38(encrypted.strip(), passphrase)
    result["note"] = "Decrypted locally. The private key and passphrase never leave this machine."
    return result


def wallet_bip38_crack(data: dict) -> dict:
    """Try a local passphrase wordlist against a BIP38 key (offline, fail-closed)."""
    encrypted = data.get("encryptedKey")
    wordlist_path = data.get("wordlistPath")
    if not isinstance(encrypted, str) or not encrypted.strip():
        raise ValueError("Provide the BIP38 key in 'encryptedKey'.")
    if not isinstance(wordlist_path, str) or not wordlist_path.strip():
        raise ValueError("Provide 'wordlistPath' (a passphrase list on this machine).")
    path = Path(wordlist_path).expanduser()
    if path.is_symlink():
        raise ValueError("Wordlist path must not be a symlink.")
    if not path.is_file():
        raise ValueError("Wordlist file not found.")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Passphrase list exceeds the 256 MiB limit.")
    max_attempts = data.get("maxAttempts", 1_000_000)
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 5_000_000:
        raise ValueError("maxAttempts must be an integer between 1 and 5,000,000.")

    def passphrases():
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                candidate = line.rstrip("\n").rstrip("\r")
                if candidate:
                    yield candidate

    result = wallet_recovery.crack_bip38(encrypted.strip(), passphrases(), max_attempts=max_attempts)
    if result["status"] == "cracked":
        result["note"] = "Passphrase recovered locally. Keep the key and passphrase offline and secure."
    return result


def soc_run_cycle(data: dict) -> dict:
    """Run one autonomous CyberSOC cycle on this host.

    Dry-run by default (analysis + escalations, no actions executed). Set
    dryRun=false to let authorized safe actions run; destructive actions still
    only run if the policy's allowed_actions explicitly includes them.
    """
    provided = data.get("events") or []
    if not isinstance(provided, list):
        raise ValueError("events must be a list.")
    host = str(data.get("host", "local"))[:120]
    collectors = []
    if data.get("fromTelemetry") is not False:
        collectors.append(cybersoc.telemetry_collector(host))
    if provided:
        collectors.append(lambda: provided)
    policy = data.get("policy") if isinstance(data.get("policy"), dict) else None
    if policy and isinstance(policy.get("allowed_actions"), list):
        policy = {**policy, "allowed_actions": set(policy["allowed_actions"])}
    dry_run = data.get("dryRun") is not False
    responder = None if dry_run else cybersoc.build_default_responder()
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    report = cybersoc.run_cycle(collectors, responder=responder, policy=policy, config=config)
    report["dry_run"] = dry_run
    return report


def soc_splunk_send(data: dict) -> dict:
    """Forward an event to Splunk HEC from the companion."""
    return splunk_connector.send_hec_event(
        str(data.get("hecUrl", "")), str(data.get("token", "")), data.get("event"),
        index=data.get("index"), sourcetype=str(data.get("sourcetype", "cyberlab:soc")),
        insecure=data.get("insecure") is True)


def soc_splunk_search(data: dict) -> dict:
    """Run a Splunk search and optionally analyze the normalized results."""
    result = splunk_connector.search(
        str(data.get("baseUrl", "")), str(data.get("token", "")), str(data.get("query", "")),
        earliest=str(data.get("earliest", "-24h")), latest=str(data.get("latest", "now")),
        max_count=int(data.get("maxCount", 100)), insecure=data.get("insecure") is True)
    if result.get("ok") and data.get("analyze") is True:
        result["analysis"] = soc_engine.analyze(result["events"])
    return result


def soc_wazuh_agents(data: dict) -> dict:
    """Authenticate to the Wazuh API and list agents."""
    token = wazuh_connector.api_login(
        str(data.get("apiUrl", "")), str(data.get("user", "")), str(data.get("password", "")),
        insecure=data.get("insecure") is True)
    return wazuh_connector.list_agents(str(data.get("apiUrl", "")), token,
                                       insecure=data.get("insecure") is True)


def soc_wazuh_alerts(data: dict) -> dict:
    """Pull recent Wazuh alerts from the Indexer and optionally analyze them."""
    result = wazuh_connector.search_alerts(
        str(data.get("indexerUrl", "")), str(data.get("user", "")), str(data.get("password", "")),
        query=data.get("query") if isinstance(data.get("query"), dict) else None,
        size=int(data.get("size", 50)), insecure=data.get("insecure") is True)
    if result.get("ok") and data.get("analyze") is True:
        result["analysis"] = soc_engine.analyze(result["events"])
    return result


def soc_analyze(data: dict) -> dict:
    """Run the CyberSOC detection engine over supplied events or live telemetry.

    Pass {"events": [...]} with normalized events, and/or {"fromTelemetry": true}
    to pull this host's live read-only telemetry and fold it into the analysis.
    """
    events = data.get("events") or []
    if not isinstance(events, list):
        raise ValueError("events must be a list of normalized event objects.")
    if len(events) > 50000:
        raise ValueError("Too many events in one request (max 50000).")
    if data.get("fromTelemetry") is True:
        security = host_telemetry.collect_security_telemetry()
        system = host_telemetry.collect_system_telemetry()
        host = str(data.get("host", "local"))[:120]
        events = events + soc_engine.events_from_telemetry(security, system, host)
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    return soc_engine.analyze(events, config)


def wallet_crack(data: dict) -> dict:
    """Run a locally installed hashcat/John against an extracted wallet hash.

    Supports several attack strategies for a forgotten password: a straight
    wordlist, a wordlist with mangling rules, a brute-force mask, and hashcat's
    wordlist+mask hybrids, as well as John's incremental mode.
    """
    tool = str(data.get("tool", "hashcat")).lower()
    hash_value = data.get("hash")
    wordlist = data.get("wordlist")
    confirmed = data.get("confirmRun") is True
    if not isinstance(hash_value, str):
        raise ValueError("Provide 'hash' (an extracted wallet hash).")
    timeout = data.get("timeoutSeconds", wallet_cracking.DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError("timeoutSeconds must be an integer.")
    if tool == "john":
        incremental = data.get("incremental")
        rules = data.get("rules")
        if not incremental and not isinstance(wordlist, str):
            raise ValueError("Provide 'wordlist' (a path on this machine) or set 'incremental'.")
        return wallet_cracking.run_john(hash_value, wordlist, confirmed=confirmed, timeout=timeout,
                                        rules=rules, incremental=incremental)
    mode = data.get("hashcatMode")
    if not isinstance(mode, int) or isinstance(mode, bool):
        raise ValueError("hashcatMode is required for hashcat (for example 11300, 15700 or 16300).")
    attack_mode = str(data.get("attackMode", "dictionary"))
    mask = data.get("mask")
    rules_file = data.get("rulesFile")
    custom_charsets = data.get("customCharsets")
    if attack_mode in {"dictionary", "hybrid-wordlist-mask", "hybrid-mask-wordlist"} and not isinstance(wordlist, str):
        raise ValueError("Provide 'wordlist' (a path on this machine) for this attack mode.")
    return wallet_cracking.run_hashcat(hash_value, mode, wordlist, confirmed=confirmed, timeout=timeout,
                                       attack_mode=attack_mode, mask=mask, rules_file=rules_file,
                                       custom_charsets=custom_charsets)


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



EIP170_LIMIT = 24576  # maximum deployed contract bytecode size, in bytes


def evaluate_eip170(bytecode_object: str, is_deployed: bool) -> dict:
    """Evaluate deployed-contract bytecode size against the EIP-170 24 KB limit."""
    hex_object = (bytecode_object or "").strip()
    if hex_object.startswith(("0x", "0X")):
        hex_object = hex_object[2:]
    if not hex_object:
        return {"bytes": 0, "limit": EIP170_LIMIT, "status": "unknown", "basis": "none",
                "note": "No bytecode was produced; the contract may be abstract, an interface, or failed to compile."}
    size = len(hex_object) // 2
    over = size > EIP170_LIMIT
    return {
        "bytes": size, "limit": EIP170_LIMIT,
        "status": "over_limit" if over else "ok",
        "basis": "deployed" if is_deployed else "creation",
        "note": ("Deployed bytecode exceeds the EIP-170 24,576-byte limit and will not deploy to most EVM chains; split the contract, remove dead code, or enable the optimizer." if over
                 else "Within the EIP-170 24,576-byte deployed-size limit." if is_deployed
                 else "Size estimated from creation bytecode; the deployed runtime size is usually smaller."),
    }


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
                "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}},
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
                evm = artifact.get("evm") or {}
                deployed = (evm.get("deployedBytecode") or {}).get("object", "")
                creation = (evm.get("bytecode") or {}).get("object", "")
                contracts.append({
                    "file": str(file_name)[:160], "name": str(name)[:128],
                    "abi": artifact.get("abi", []),
                    "bytecode": creation[:500000],
                    "deploymentSize": evaluate_eip170(deployed or creation, bool(deployed)),
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
        if not (path in {"/health", "/system", "/identity", "/capabilities", "/ollama/health", "/ollama/models", "/solidity/compiler", "/solidity/tests/status", "/wallet/status", "/tools/runners", "/telemetry/security", "/telemetry/system", "/forensics/devices", "/tools", "/burp/status", "/burp/proxy/history", "/burp/site-map", "/burp/issues", "/network/interfaces", "/academy/lab/status", "/wifi/interfaces", "/web/history", "/proxy/ca/status", "/proxy/ca/certificate", "/proxy/status", "/proxy/history", "/proxy/intercepts", "/proxy/response-intercepts", "/proxy/websocket-frames", "/proxy/websocket-intercepts", "/evidence/case/ledger/verify"} or re.fullmatch(r"/forensics/jobs/[a-f0-9]{32}", path)):
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
        if path == "/telemetry/security":
            return self.send_json(200, host_telemetry.collect_security_telemetry(), origin)
        if path == "/telemetry/system":
            return self.send_json(200, host_telemetry.collect_system_telemetry(), origin)
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
        if path == "/academy/lab/status":
            return self.send_json(200, academy_lab.lab_status(), origin)
        if path == "/wifi/interfaces":
            return self.send_json(200, {"interfaces": wifi_assessment.list_interfaces()}, origin)
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
        if path == "/identity":
            return self.send_json(200, companion_identity(), origin)
        self.send_json(200, {"status": "connected", "agent": "CyberLab Kali Bridge",
                             "nmap": bool(shutil.which("nmap")), "companion": companion_identity()}, origin)

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self.send_json(403, {"error": "Origin not allowed."})
        path = urlparse(self.path).path
        if path not in {"/plan", "/research", "/services", "/evidence/report", "/evidence/artifacts", "/evidence/case", "/evidence/case/export", "/evidence/case/verify", "/scan", "/forensics/image", "/forensics/foremost", "/forensics/photorec", "/forensics/recover-all-deleted", "/forensics/inspect", "/forensics/partitions", "/forensics/fsstat", "/forensics/deleted-list", "/forensics/recover-file", "/forensics/plist-parse", "/forensics/sqlite-inspect", "/forensics/sqlite-sample", "/network/pcap-analyze", "/burp/repeater/from-history", "/burp/send-request", "/network/capture", "/web/request", "/web/crawl", "/web/active-scan", "/web/assessment", "/web/parameters/inspect", "/web/parameters/generate", "/web/parameters/analyze", "/proxy/ca/create", "/proxy/start", "/proxy/stop", "/proxy/intercepts/decision", "/proxy/response-intercepts/decision", "/proxy/websocket-intercepts/decision", "/ollama/chat", "/solidity/compile", "/solidity/project/compile", "/solidity/tests/run", "/wallet/extract-hash", "/wallet/derive", "/wallet/electrum-derive", "/wallet/solve-seed", "/wallet/check-balances", "/wallet/sweep", "/wallet/auto-recover", "/wallet/bip38-decrypt", "/wallet/bip38-crack", "/wallet/crack", "/soc/analyze", "/soc/run-cycle", "/soc/splunk/send", "/soc/splunk/search", "/soc/wazuh/agents", "/soc/wazuh/alerts", "/academy/lab/start", "/academy/lab/stop", "/shodan/info", "/shodan/host", "/shodan/search", "/shodan/dns", "/wifi/scan", "/wifi/audit", "/wifi/crack", "/wifi/monitor/start", "/wifi/monitor/stop", "/wifi/deauth", "/wifi/capture/handshake", "/wifi/capture/pmkid", "/wifi/crack-wpa", "/wifi/crack-upload", "/wifi/wps", "/wifi/auto", "/tools/run"}:
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
                65536 if path in {"/wallet/check-balances", "/wallet/sweep", "/wallet/auto-recover"} else
                16_000_000 if path == "/wifi/crack-upload" else
                1048576 if path in {"/soc/analyze", "/soc/run-cycle"} else
                4096 if path in {"/wallet/derive", "/wallet/electrum-derive", "/wallet/bip38-decrypt", "/wallet/bip38-crack", "/wallet/solve-seed", "/wallet/crack", "/forensics/deleted-list", "/forensics/recover-file", "/forensics/plist-parse", "/forensics/sqlite-inspect", "/forensics/sqlite-sample", "/network/pcap-analyze"} else
                8192 if path == "/tools/run" else
                32768 if path in {"/web/request", "/web/crawl", "/web/active-scan", "/web/assessment", "/web/parameters/inspect", "/web/parameters/generate", "/web/parameters/analyze"} else MAX_BODY
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
            if path == "/wallet/electrum-derive":
                return self.send_json(200, wallet_electrum_derive(data), origin)
            if path == "/soc/analyze":
                return self.send_json(200, soc_analyze(data), origin)
            if path == "/soc/run-cycle":
                return self.send_json(200, soc_run_cycle(data), origin)
            if path == "/soc/splunk/send":
                return self.send_json(200, soc_splunk_send(data), origin)
            if path == "/soc/splunk/search":
                return self.send_json(200, soc_splunk_search(data), origin)
            if path == "/soc/wazuh/agents":
                return self.send_json(200, soc_wazuh_agents(data), origin)
            if path == "/soc/wazuh/alerts":
                return self.send_json(200, soc_wazuh_alerts(data), origin)
            if path == "/wallet/solve-seed":
                return self.send_json(200, wallet_solve_seed(data), origin)
            if path == "/wallet/check-balances":
                return self.send_json(200, wallet_check_balances(data), origin)
            if path == "/wallet/sweep":
                return self.send_json(200, wallet_sweep(data), origin)
            if path == "/wallet/auto-recover":
                return self.send_json(200, wallet_auto_recover(data), origin)
            if path == "/wallet/bip38-decrypt":
                return self.send_json(200, wallet_bip38_decrypt(data), origin)
            if path == "/wallet/bip38-crack":
                return self.send_json(200, wallet_bip38_crack(data), origin)
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
            if path == "/web/assessment":
                if not web_assessment_lock.acquire(blocking=False):
                    return self.send_json(409, {"error": "A native web assessment is already running."}, origin)
                try:
                    result = run_assessment(data)
                    return self.send_json(200, result, origin)
                finally:
                    web_assessment_lock.release()
            if path == "/academy/lab/start":
                return self.send_json(200, academy_lab.start_lab(), origin)
            if path == "/academy/lab/stop":
                return self.send_json(200, academy_lab.stop_lab(), origin)
            if path == "/shodan/info":
                return self.send_json(200, shodan_connector.api_info(data.get("apiKey", "")), origin)
            if path == "/shodan/host":
                result = shodan_connector.host_lookup(data.get("ip", ""), data.get("apiKey", ""), bool(data.get("history")))
                return self.send_json(200, shodan_connector.normalize_host(result), origin)
            if path == "/shodan/search":
                result = shodan_connector.search(data.get("query", ""), data.get("apiKey", ""), int(data.get("page", 1)))
                return self.send_json(200, shodan_connector.normalize_search(result), origin)
            if path == "/shodan/dns":
                return self.send_json(200, shodan_connector.dns_resolve(data.get("hostnames", ""), data.get("apiKey", "")), origin)
            if path == "/wifi/scan":
                return self.send_json(200, wifi_assessment.scan(data.get("interface", ""), int(data.get("seconds", 15))), origin)
            if path == "/wifi/audit":
                networks = wifi_assessment.parse_airodump_csv(data.get("csv", "")) if data.get("csv") else (data.get("networks") or [])
                return self.send_json(200, wifi_assessment.audit_networks(networks), origin)
            if path == "/wifi/crack":
                return self.send_json(200, wifi_assessment.crack_capture(data), origin)
            if path == "/wifi/monitor/start":
                return self.send_json(200, wifi_authorized.enable_monitor(data.get("interface", "")), origin)
            if path == "/wifi/monitor/stop":
                return self.send_json(200, wifi_authorized.disable_monitor(data.get("interface", "")), origin)
            if path == "/wifi/deauth":
                return self.send_json(200, wifi_authorized.deauth(data), origin)
            if path == "/wifi/capture/handshake":
                return self.send_json(200, wifi_authorized.capture_handshake(data), origin)
            if path == "/wifi/capture/pmkid":
                return self.send_json(200, wifi_authorized.capture_pmkid(data), origin)
            if path == "/wifi/crack-wpa":
                return self.send_json(200, wifi_authorized.crack_wpa(data), origin)
            if path == "/wifi/crack-upload":
                return self.send_json(200, wifi_authorized.crack_upload(data), origin)
            if path == "/wifi/wps":
                return self.send_json(200, wifi_authorized.wps_attack(data), origin)
            if path == "/wifi/auto":
                return self.send_json(200, wifi_authorized.auto_audit(data), origin)
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
            if path == "/burp/send-request":
                if data.get("confirmSend") is not True:
                    return self.send_json(400, {"status": "confirmation_required", "request_sent": False}, origin)
                history_id = data.get("historyId")
                if isinstance(history_id, bool) or not isinstance(history_id, int):
                    return self.send_json(400, {"status": "invalid_request", "request_sent": False}, origin)
                result = send_in_scope_request(history_id, confirmed=True)
                status_code = 200 if result.get("status") == "sent" else 400
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
                    file_types=data.get("fileTypes"),
                )
                return self.send_json(202, result, origin)
            if path == "/forensics/photorec":
                result = start_photorec_recovery(
                    str(data.get("imageJobId", "")),
                    str(data.get("outputDirectory", "")),
                    str(data.get("confirmationImage", "")),
                )
                return self.send_json(202, result, origin)
            if path == "/forensics/recover-all-deleted":
                offset = data.get("offset", 0)
                if not isinstance(offset, int) or isinstance(offset, bool):
                    raise ValueError("offset must be an integer.")
                max_files = data.get("maxFiles", 100)
                if not isinstance(max_files, int) or isinstance(max_files, bool):
                    raise ValueError("maxFiles must be an integer.")
                result = recover_all_deleted_files(
                    str(data.get("imageJobId", "")), str(data.get("confirmationImage", "")),
                    str(data.get("outputDirectory", "")), offset=offset, max_files=max_files)
                return self.send_json(201, result, origin)
            if path == "/forensics/plist-parse":
                return self.send_json(200, plist_forensics.analyze_plist(
                    str(data.get("path", ""))), origin)
            if path == "/forensics/sqlite-inspect":
                return self.send_json(200, sqlite_forensics.inspect_sqlite(
                    str(data.get("path", ""))), origin)
            if path == "/forensics/sqlite-sample":
                limit = data.get("limit", 50)
                if not isinstance(limit, int) or isinstance(limit, bool):
                    raise ValueError("limit must be an integer.")
                return self.send_json(200, sqlite_forensics.sample_table(
                    str(data.get("path", "")), str(data.get("table", "")), limit=limit), origin)
            if path == "/forensics/deleted-list":
                offset = data.get("offset", 0)
                if not isinstance(offset, int) or isinstance(offset, bool):
                    raise ValueError("offset must be an integer.")
                limit = data.get("limit", 1000)
                if not isinstance(limit, int) or isinstance(limit, bool):
                    raise ValueError("limit must be an integer.")
                result = list_deleted_files(str(data.get("imageJobId", "")), str(data.get("confirmationImage", "")), offset=offset, limit=limit)
                return self.send_json(200, result, origin)
            if path == "/network/pcap-analyze":
                result = pcap_analysis.analyze_pcap(str(data.get("pcapPath", "")))
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
