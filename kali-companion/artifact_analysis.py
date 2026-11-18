"""Bounded, non-executing analysis of static file-triage and recovery-manifest evidence."""
from __future__ import annotations

import json
import re
from collections import Counter

MAX_MANIFEST_FILES = 5000
MAX_INDICATORS = 50
MAX_BYTES = 10 * 1024 * 1024
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _clean(value, limit=240):
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", value).strip()[:limit]


def _validate_triage(value):
    if not isinstance(value, dict):
        raise ValueError("File-triage evidence must be a JSON object.")
    size = value.get("size_bytes")
    if type(size) is not int or not 0 < size <= MAX_BYTES:
        raise ValueError("Triage size must be an integer from 1 byte to 10 MB.")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("Triage evidence must include a valid SHA-256 hash.")
    entropy = value.get("entropy")
    if not isinstance(entropy, (int, float)) or isinstance(entropy, bool) or not 0 <= entropy <= 8:
        raise ValueError("Entropy must be a numeric value from 0 to 8.")
    groups = value.get("indicator_groups", [])
    strings = value.get("matched_strings", [])
    if not isinstance(groups, list) or not isinstance(strings, list):
        raise ValueError("Indicator groups and matched strings must be arrays.")
    if len(groups) > MAX_INDICATORS or len(strings) > MAX_INDICATORS:
        raise ValueError("Triage indicator arrays exceed the 50-item limit.")
    return {
        "file_name": _clean(value.get("file_name"), 180),
        "file_type": _clean(value.get("file_type"), 100),
        "size_bytes": size,
        "sha256": digest.lower(),
        "entropy": round(float(entropy), 3),
        "indicator_groups": [_clean(item, 100) for item in groups if isinstance(item, str)][:MAX_INDICATORS],
        "matched_strings": [_clean(item, 240) for item in strings if isinstance(item, str)][:MAX_INDICATORS],
    }


def _validate_manifest(value):
    if not isinstance(value, dict):
        raise ValueError("Recovery manifest evidence must be a JSON object.")
    if value.get("schema") != "cyberlab.recovery-manifest.v1" or value.get("algorithm") != "SHA-256":
        raise ValueError("Unsupported recovery-manifest schema or hash algorithm.")
    files = value.get("files")
    if not isinstance(files, list) or len(files) > MAX_MANIFEST_FILES:
        raise ValueError("Recovery manifest must contain no more than 5,000 file entries.")
    entries = []
    seen = set()
    for item in files:
        if not isinstance(item, dict):
            continue
        path = _clean(item.get("path"), 500)
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if (not path or path.startswith("/") or ".." in path.split("/")
                or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)
                or type(size) is not int or size < 0):
            continue
        if path in seen:
            continue
        seen.add(path)
        entries.append({"path": path, "size_bytes": size, "sha256": digest.lower()})
    return entries, value.get("truncated") is True


def build_artifact_report(triage_result=None, recovery_manifest=None):
    if triage_result is None and recovery_manifest is None:
        raise ValueError("Provide file-triage evidence, a recovery manifest, or both.")
    triage = _validate_triage(triage_result) if triage_result is not None else None
    files, truncated = _validate_manifest(recovery_manifest) if recovery_manifest is not None else ([], False)
    extensions = Counter()
    total_bytes = 0
    for entry in files:
        name = entry["path"].rsplit("/", 1)[-1]
        extension = name.rsplit(".", 1)[-1].lower() if "." in name else "[no extension]"
        extensions[extension[:20]] += 1
        total_bytes += entry["size_bytes"]
    observations = []
    limitations = [
        "Static indicators are heuristic strings and do not establish malicious behaviour.",
        "High entropy can result from compression, encryption or ordinary file formats; it is not a malware verdict.",
        "Hashes identify the exact bytes examined but do not establish provenance, reputation or safety.",
        "Recovered file names, extensions and content may be incomplete or misleading after carving.",
        "The manifest records hashes and sizes only; it does not validate file contents or reconstruct original paths.",
    ]
    if triage:
        observations.append({
            "type": "static_file_triage", **triage,
            "confidence": "high for the recorded hash, byte count and detected signature; low for behavioural interpretation of strings and entropy",
        })
        if triage["entropy"] >= 7.2:
            limitations.append("The sample's entropy is high; investigate compression/encryption context before interpreting it.")
        if triage["indicator_groups"]:
            limitations.append("One or more heuristic string groups matched; manually review the exact strings and surrounding context.")
    if recovery_manifest is not None:
        observations.append({
            "type": "recovery_manifest",
            "files_hashed": len(files),
            "total_bytes_hashed": total_bytes,
            "truncated": truncated,
            "extension_counts": dict(sorted(extensions.items())),
            "files": files,
            "confidence": "high that listed file bytes matched the supplied SHA-256 values when the manifest was created; no claim about authenticity or original file identity",
        })
    return {
        "status": "completed",
        "observations": observations,
        "risk_findings": [],
        "limitations": limitations,
        "recommended_next_steps": [
            "Preserve the original source and forensic image; conduct follow-up analysis on verified working copies.",
            "Validate recovered files with appropriate parsers and compare hashes against trusted originals when available.",
            "Review suspicious strings in context and use multiple independent static-analysis methods.",
            "Keep chain-of-custody notes, acquisition logs and the recovery audit.txt alongside the manifest.",
            "Do not execute recovered or suspicious samples on the analysis workstation.",
        ],
        "note": "Static artifact evidence only. No sample was executed, uploaded, unpacked or declared malicious.",
    }


def validate_artifact_payload(data):
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    triage = data.get("triageResult")
    manifest = data.get("recoveryManifest")
    if triage is None and manifest is None:
        raise ValueError("Provide triageResult or recoveryManifest.")
    if triage is not None and not isinstance(triage, dict):
        raise ValueError("Triage evidence must be a JSON object.")
    if manifest is not None and not isinstance(manifest, dict):
        raise ValueError("Recovery manifest must be a JSON object.")
    if len(json.dumps(data, ensure_ascii=False)) > 60000:
        raise ValueError("Artifact evidence exceeds the 60 KB request limit.")
    return triage, manifest
