"""Explicitly authorised, local wallet-recovery execution orchestration.

Secrets are accepted only by the loopback companion. This module never uploads,
logs, persists, signs with, or transfers wallet assets.
"""
from __future__ import annotations

from typing import Any, Callable


def execute_recovery_job(
    data: dict[str, Any],
    *,
    auto_recover: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Recovery execution request must be an object.")
    allowed = {
        "operation", "ownerConfirmed", "authorizationReference", "confirmRun",
        "mnemonic", "passphrase", "count", "includeChange", "templates",
        "checkBalances", "confirmNetwork",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError("Unsupported execution field(s): " + ", ".join(unknown))
    if data.get("ownerConfirmed") is not True:
        raise ValueError("Owner confirmation is required before local recovery execution.")
    reference = data.get("authorizationReference")
    if not isinstance(reference, str) or not reference.strip() or len(reference) > 160:
        raise ValueError("A valid case/authorisation reference is required.")
    if data.get("confirmRun") is not True:
        raise ValueError("Explicit confirmation is required to start the recovery operation.")
    operation = data.get("operation")
    if operation != "derive-and-check":
        raise ValueError("Unsupported operation. This executor currently supports derive-and-check.")
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip() or len(mnemonic) > 4096:
        raise ValueError("Enter the wallet owner's recovery phrase locally.")
    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str) or len(passphrase) > 256:
        raise ValueError("Passphrase must be a string of at most 256 characters.")
    check_balances = data.get("checkBalances") is True
    if check_balances and data.get("confirmNetwork") is not True:
        raise ValueError("Read-only public balance checks require separate network confirmation.")

    execution_input = {
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "count": data.get("count", 3),
        "includeChange": data.get("includeChange", True),
        "templates": data.get("templates"),
        "checkBalances": check_balances,
        "confirmNetwork": data.get("confirmNetwork") is True,
    }
    result = auto_recover(execution_input)
    return {
        "execution": "completed",
        "operation": operation,
        "case_reference": reference.strip(),
        "ownership_confirmed": True,
        "execution_started": True,
        "result": result,
        "security": [
            "The recovery phrase and optional passphrase were processed by the paired loopback companion only.",
            "No secret material was sent to CyberLab's hosted application or persisted by this executor.",
            "Only public addresses may be used for optional read-only balance checks.",
            "No wallet signing, transaction creation, asset transfer or destination change was performed.",
        ],
    }
