"""Evidence-driven wallet recovery case planner.

This module plans recovery work; it never accepts or processes seed phrases,
private keys, wallet passwords, or encrypted wallet contents. Those remain in
the existing local-only recovery operations.
"""
from __future__ import annotations

from typing import Any

WALLET_PROFILES = {
    "bitcoin-core": {
        "label": "Bitcoin Core",
        "backup": ["wallet.dat"],
        "methods": ["wallet.dat encrypted-master-key extraction", "local Hashcat/John password recovery"],
        "limits": ["Hash extraction is not a full wallet restore; Berkeley DB parsing/restore remains separate."],
    },
    "ethereum-keystore": {
        "label": "Ethereum V3 keystore",
        "backup": ["UTC--* JSON keystore"],
        "methods": ["V3 keystore hash extraction", "local Hashcat/John password recovery", "owner-controlled import verification"],
        "limits": ["Supported KDF and keystore variants must match the parser."],
    },
    "metamask": {
        "label": "MetaMask",
        "backup": ["encrypted vault JSON"],
        "methods": ["vault hash extraction", "local Hashcat/John password recovery"],
        "limits": ["Vault password recovery does not guarantee recovery of every MetaMask version or account."],
    },
    "bip39": {
        "label": "BIP39-compatible wallet",
        "backup": ["partial or complete mnemonic", "known public address (optional)"],
        "methods": ["checksum-guided missing-word reconstruction", "known-address candidate matching", "multi-path derivation and read-only balance discovery"],
        "limits": ["Unknown passphrases, unsupported languages and unbounded missing-word searches may make recovery infeasible."],
    },
    "electrum": {
        "label": "Electrum",
        "backup": ["Electrum seed or wallet backup"],
        "methods": ["Electrum seed-version detection", "supported standard/SegWit/legacy derivation"],
        "limits": ["TrustedCoin/2FA requires the cosigner; proprietary wallet-file restoration is not universal."],
    },
    "bip38": {
        "label": "BIP38 encrypted private key",
        "backup": ["encrypted BIP38 key", "remembered passphrase hints"],
        "methods": ["local BIP38 passphrase verification", "bounded offline candidate search"],
        "limits": ["A candidate list is only useful when it meaningfully narrows the passphrase."],
    },
    "unknown": {
        "label": "Unidentified wallet",
        "backup": ["wallet vendor/version and a non-secret backup-format description"],
        "methods": ["local format identification and evidence inventory"],
        "limits": ["No recovery method is selected until the format is identified."],
    },
}

SECRET_FIELDS = {
    "mnemonic", "seed", "seedphrase", "privatekey", "password", "passphrase",
    "walletpassword", "keystorejson", "vaultjson", "walletdatbase64", "hash", "encryptedkey",
}


def _has_secret_input(data: dict[str, Any]) -> bool:
    return any(str(key).replace("-", "").replace("_", "").lower() in SECRET_FIELDS
               for key in data)


def assess_recovery_case(data: dict[str, Any]) -> dict[str, Any]:
    """Return a transparent plan from metadata only; never inspect secret material."""
    if not isinstance(data, dict):
        raise ValueError("Recovery case must be a JSON object.")
    if _has_secret_input(data):
        raise ValueError(
            "The planner accepts case metadata only. Do not send seed phrases, "
            "passwords, private keys, hashes or wallet-file contents to this endpoint; "
            "use the local recovery operation instead."
        )

    wallet_type = str(data.get("walletType", "unknown")).strip().lower()
    if wallet_type not in WALLET_PROFILES:
        raise ValueError("Unsupported walletType. Choose a listed supported wallet profile.")
    profile = WALLET_PROFILES[wallet_type]
    owner_confirmed = data.get("ownerConfirmed") is True
    authorization_reference = str(data.get("authorizationReference", "")).strip()
    if len(authorization_reference) > 160:
        raise ValueError("authorizationReference must be 160 characters or fewer.")

    evidence = data.get("evidence", {})
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be an object of boolean metadata flags.")
    allowed_evidence = {
        "encryptedBackupAvailable", "partialSeedAvailable", "completeSeedAvailable",
        "passwordHintsAvailable", "knownPublicAddressAvailable", "walletVersionKnown",
        "backupFormatKnown", "twoFactorEnabled", "originalDeviceAvailable",
    }
    unknown = sorted(set(evidence) - allowed_evidence)
    if unknown:
        raise ValueError("Unknown evidence flag(s): " + ", ".join(unknown))
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Every evidence flag must be a boolean.")

    present = [name for name, value in evidence.items() if value]
    methods = list(profile["methods"])
    blockers = list(profile["limits"])
    next_steps: list[str] = []
    if not owner_confirmed:
        blockers.insert(0, "Ownership/explicit authorisation has not been confirmed.")
        next_steps.append("Verify the original owner's identity and authority before collecting or processing recovery material.")
    elif not authorization_reference:
        blockers.insert(0, "An authorisation or case reference is required before a recovery run.")
        next_steps.append("Record a case/authorisation reference before running a recovery operation.")

    if wallet_type in {"bitcoin-core", "ethereum-keystore", "metamask"}:
        if not evidence.get("encryptedBackupAvailable"):
            blockers.insert(0, "The required encrypted backup has not been confirmed available.")
            next_steps.append("Locate an original encrypted backup and preserve an untouched copy.")
        if not evidence.get("passwordHintsAvailable"):
            blockers.append("No password hints are recorded; broad brute-force searches may be computationally infeasible.")
            next_steps.append("Record only non-secret password-pattern hints (approximate length, character classes and remembered patterns).")
        else:
            next_steps.append("Extract the supported wallet hash locally, then select a bounded dictionary, mask or hybrid run.")
    elif wallet_type in {"bip39", "electrum"}:
        if not (evidence.get("partialSeedAvailable") or evidence.get("completeSeedAvailable")):
            blockers.insert(0, "No seed words or fragments are available.")
            next_steps.append("Search for a written backup or original device; do not submit guesses as if they were verified.")
        if evidence.get("partialSeedAvailable"):
            next_steps.append("Use the offline seed solver with bounded candidate limits and, if available, a known public address.")
        if evidence.get("completeSeedAvailable"):
            next_steps.append("Run local scheme detection and derive supported account/change paths; compare public addresses.")
        if evidence.get("twoFactorEnabled") and wallet_type == "electrum":
            blockers.append("Electrum 2FA/TrustedCoin requires the cosigner; seed-only reconstruction is insufficient.")
    elif wallet_type == "bip38":
        if not evidence.get("encryptedBackupAvailable"):
            blockers.insert(0, "The encrypted BIP38 key has not been confirmed available.")
        if not evidence.get("passwordHintsAvailable"):
            blockers.append("No passphrase hints are recorded; an unrestricted search is not a practical recovery plan.")
        next_steps.append("Verify candidate passphrases locally against the BIP38 address checksum; keep the resulting key offline.")
    else:
        next_steps.append("Identify the wallet vendor, version and backup format without sharing secrets.")

    if evidence.get("knownPublicAddressAvailable"):
        next_steps.append("Use the known public address only for local candidate matching or read-only explorer checks.")
    if evidence.get("originalDeviceAvailable"):
        next_steps.append("Preserve the original device and make a forensic copy before attempting repairs or migrations.")

    ready = owner_confirmed and bool(authorization_reference)
    if wallet_type == "unknown":
        ready = False
    if wallet_type in {"bitcoin-core", "ethereum-keystore", "metamask"}:
        ready = ready and evidence.get("encryptedBackupAvailable") is True
    elif wallet_type in {"bip39", "electrum"}:
        ready = ready and (evidence.get("partialSeedAvailable") is True or evidence.get("completeSeedAvailable") is True)
    elif wallet_type == "bip38":
        ready = ready and evidence.get("encryptedBackupAvailable") is True

    return {
        "planner": "cyberlab-wallet-recovery-intelligence",
        "version": 1,
        "wallet_type": wallet_type,
        "wallet_label": profile["label"],
        "status": "ready_for_operator_review" if ready else "evidence_incomplete",
        "execution_started": False,
        "ownership_confirmed": owner_confirmed,
        "authorization_reference_recorded": bool(authorization_reference),
        "evidence_flags": present,
        "recommended_methods": methods,
        "next_steps": next_steps,
        "blockers_and_limits": blockers,
        "security": [
            "This assessment uses metadata only; no secret material is accepted or transmitted.",
            "Recovery execution remains local to the paired companion and requires its own explicit confirmation.",
            "The wallet owner must control the destination wallet and approve any transfer independently.",
        ],
        "note": "A ready status means the case has enough declared evidence to review a recovery attempt; it is not a prediction or guarantee of success.",
    }
