"""Local append-only provenance ledger and unified investigation case reports."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_CASE_BYTES = 120_000
MAX_LEDGER_BYTES = 5 * 1024 * 1024
LEDGER_DIR = Path.home() / ".local" / "state" / "cyberlab"
LEDGER_FILE = LEDGER_DIR / "case-audit.jsonl"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _clean(value, limit=300):
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", value).strip()[:limit]


def _source_digest(report):
    return _digest(report)


def _append_audit(case_id, created_at, sources):
    LEDGER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(LEDGER_DIR, 0o700)
    except OSError:
        pass
    fd = os.open(str(LEDGER_FILE), os.O_CREAT | os.O_APPEND | os.O_RDWR, 0o600)
    try:
        with os.fdopen(fd, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0, os.SEEK_END)
            current_size = handle.tell()
            if current_size > MAX_LEDGER_BYTES:
                raise ValueError("The local case audit ledger reached its 5 MB limit; archive it before creating more cases.")
            previous_hash = "GENESIS"
            if current_size:
                handle.seek(0)
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        previous = json.loads(line)
                        claimed_hash = previous.pop("record_hash")
                        claimed_previous = previous.get("previous_record_hash")
                    except (json.JSONDecodeError, KeyError, AttributeError, TypeError):
                        raise ValueError("The existing local case audit ledger is malformed; preserve it for review.")
                    if claimed_previous != previous_hash or not isinstance(claimed_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", claimed_hash) or _digest(previous) != claimed_hash:
                        raise ValueError("The existing local case audit ledger failed hash-chain verification at line " + str(line_number) + "; preserve it for review.")
                    previous_hash = claimed_hash
            record = {
                "case_id": case_id,
                "created_at": created_at,
                "event": "case_created",
                "sources": [{key: source[key] for key in ("type", "sha256", "observation_count", "reference_candidate_count") if key in source} for source in sources],
                "previous_record_hash": previous_hash,
            }
            record["record_hash"] = _digest(record)
            encoded = _canonical(record) + b"\n"
            if current_size + len(encoded) > MAX_LEDGER_BYTES:
                raise ValueError("The local case audit ledger would exceed its 5 MB limit.")
            handle.seek(0, os.SEEK_END)
            handle.write(encoded.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
            return {
                "path": str(LEDGER_FILE),
                "record_hash": record["record_hash"],
                "previous_record_hash": previous_hash,
                "permissions": "0600 file / 0700 directory where supported",
                "durability": "Appended and fsynced locally; no raw evidence content stored in the ledger",
            }
    finally:
        # fdopen closes the descriptor when the with block exits.
        pass


def build_case_report(service_report=None, artifact_report=None):
    if service_report is None and artifact_report is None:
        raise ValueError("Provide a service evidence report, an artifact evidence report, or both.")
    if service_report is not None and not isinstance(service_report, dict):
        raise ValueError("Service report must be a JSON object.")
    if artifact_report is not None and not isinstance(artifact_report, dict):
        raise ValueError("Artifact report must be a JSON object.")
    payload = {"service_report": service_report, "artifact_report": artifact_report}
    if len(_canonical(payload)) > MAX_CASE_BYTES:
        raise ValueError("Combined case evidence exceeds the 120 KB limit.")
    sources = []
    observations = []
    limitations = []
    if service_report is not None:
        if service_report.get("status") != "completed":
            raise ValueError("Service report must be a completed evidence report.")
        sources.append({
            "type": "network_service_evidence",
            "sha256": _source_digest(service_report),
            "target": _clean(service_report.get("target"), 253),
            "observation_count": len(service_report.get("observations", [])) if isinstance(service_report.get("observations"), list) else 0,
            "reference_candidate_count": len(service_report.get("cve_reference_candidates", [])) if isinstance(service_report.get("cve_reference_candidates"), list) else 0,
        })
        observations.extend(service_report.get("observations", [])[:80] if isinstance(service_report.get("observations"), list) else [])
        limitations.extend(service_report.get("limitations", [])[:20] if isinstance(service_report.get("limitations"), list) else [])
    if artifact_report is not None:
        if artifact_report.get("status") != "completed":
            raise ValueError("Artifact report must be a completed evidence report.")
        sources.append({
            "type": "static_artifact_evidence",
            "sha256": _source_digest(artifact_report),
            "observation_count": len(artifact_report.get("observations", [])) if isinstance(artifact_report.get("observations"), list) else 0,
        })
        observations.extend(artifact_report.get("observations", [])[:80] if isinstance(artifact_report.get("observations"), list) else [])
        limitations.extend(artifact_report.get("limitations", [])[:20] if isinstance(artifact_report.get("limitations"), list) else [])
    case_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    audit = _append_audit(case_id, created_at, sources)
    return {
        "status": "completed",
        "case": {"case_id": case_id, "created_at": created_at, "sources": sources,
                 "observation_count": len(observations)},
        "observations": observations[:160],
        "reference_candidates": service_report.get("cve_reference_candidates", [])[:30] if service_report else [],
        "findings": [],
        "confidence_policy": "Source-level confidence is preserved from each report. Correlation does not upgrade a source observation into a confirmed vulnerability or malware finding.",
        "limitations": list(dict.fromkeys(_clean(item, 500) for item in limitations if isinstance(item, str)))[:40],
        "audit_trail": audit,
        "recommended_next_steps": [
            "Review each observation against its source report and preserve the original evidence.",
            "Record analyst identity, authorisation reference, scope, collection time and tool versions in the case-management process.",
            "Verify candidate vulnerabilities against exact affected-version ranges and official vendor advisories.",
            "Keep the original forensic image, acquisition map, recovery audit and manifests under separate protected evidence storage.",
            "Export or archive the local audit ledger under your organisation's evidence-retention policy.",
        ],
        "note": "The audit ledger stores case metadata and evidence digests only, not raw samples, banners, credentials or recovered file contents. It is a local hash-chained log, not a signed or tamper-proof chain-of-custody system.",
    }


def validate_case_payload(data):
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    service = data.get("serviceReport")
    artifact = data.get("artifactReport")
    if service is None and artifact is None:
        raise ValueError("Provide serviceReport or artifactReport.")
    if service is not None and not isinstance(service, dict):
        raise ValueError("serviceReport must be a JSON object.")
    if artifact is not None and not isinstance(artifact, dict):
        raise ValueError("artifactReport must be a JSON object.")
    if len(_canonical({"serviceReport": service, "artifactReport": artifact})) > MAX_CASE_BYTES:
        raise ValueError("Combined case evidence exceeds the 120 KB limit.")
    return service, artifact
