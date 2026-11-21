import pytest

from wallet_recovery_planner import assess_recovery_case


def test_keystore_case_requires_owner_authorisation_and_backup():
    result = assess_recovery_case({
        "walletType": "ethereum-keystore",
        "ownerConfirmed": True,
        "authorizationReference": "CASE-001",
        "evidence": {"encryptedBackupAvailable": True, "passwordHintsAvailable": True},
    })
    assert result["status"] == "ready_for_operator_review"
    assert result["execution_started"] is False
    assert "V3 keystore hash extraction" in result["recommended_methods"]


def test_case_without_backup_is_not_ready():
    result = assess_recovery_case({
        "walletType": "bitcoin-core",
        "ownerConfirmed": True,
        "authorizationReference": "CASE-002",
        "evidence": {"passwordHintsAvailable": True},
    })
    assert result["status"] == "evidence_incomplete"
    assert any("encrypted backup" in item.lower() for item in result["blockers_and_limits"])


def test_missing_seed_can_be_planned_without_sending_seed_words():
    result = assess_recovery_case({
        "walletType": "bip39",
        "ownerConfirmed": True,
        "authorizationReference": "CASE-003",
        "evidence": {"partialSeedAvailable": True, "knownPublicAddressAvailable": True},
    })
    assert result["status"] == "ready_for_operator_review"
    assert any("seed solver" in item.lower() for item in result["next_steps"])


def test_secret_material_is_rejected_by_planner():
    with pytest.raises(ValueError, match="metadata only"):
        assess_recovery_case({
            "walletType": "bip39",
            "mnemonic": "this must never be accepted here",
        })


def test_electrum_two_factor_limit_is_explicit():
    result = assess_recovery_case({
        "walletType": "electrum",
        "ownerConfirmed": True,
        "authorizationReference": "CASE-004",
        "evidence": {"completeSeedAvailable": True, "twoFactorEnabled": True},
    })
    assert any("TrustedCoin" in item for item in result["blockers_and_limits"])


def test_unknown_wallet_stays_in_triage():
    result = assess_recovery_case({"walletType": "unknown", "ownerConfirmed": True,
                                   "authorizationReference": "CASE-005"})
    assert result["status"] == "evidence_incomplete"
    assert result["execution_started"] is False
