import unittest

from wallet_recovery_planner import assess_recovery_case


class WalletRecoveryPlannerTests(unittest.TestCase):
    def test_keystore_case_requires_owner_authorisation_and_backup(self):
        result = assess_recovery_case({
            "walletType": "ethereum-keystore", "ownerConfirmed": True,
            "authorizationReference": "CASE-001",
            "evidence": {"encryptedBackupAvailable": True, "passwordHintsAvailable": True},
        })
        self.assertEqual(result["status"], "ready_for_operator_review")
        self.assertFalse(result["execution_started"])
        self.assertIn("V3 keystore hash extraction", result["recommended_methods"])

    def test_case_without_backup_is_not_ready(self):
        result = assess_recovery_case({
            "walletType": "bitcoin-core", "ownerConfirmed": True,
            "authorizationReference": "CASE-002",
            "evidence": {"passwordHintsAvailable": True},
        })
        self.assertEqual(result["status"], "evidence_incomplete")
        self.assertTrue(any("encrypted backup" in item.lower() for item in result["blockers_and_limits"]))

    def test_partial_seed_can_be_planned_without_sending_seed_words(self):
        result = assess_recovery_case({
            "walletType": "bip39", "ownerConfirmed": True,
            "authorizationReference": "CASE-003",
            "evidence": {"partialSeedAvailable": True, "knownPublicAddressAvailable": True},
        })
        self.assertEqual(result["status"], "ready_for_operator_review")
        self.assertTrue(any("seed solver" in item.lower() for item in result["next_steps"]))

    def test_secret_material_is_rejected_by_planner(self):
        with self.assertRaisesRegex(ValueError, "metadata only"):
            assess_recovery_case({"walletType": "bip39", "mnemonic": "never accept"})

    def test_electrum_two_factor_limit_is_explicit(self):
        result = assess_recovery_case({
            "walletType": "electrum", "ownerConfirmed": True,
            "authorizationReference": "CASE-004",
            "evidence": {"completeSeedAvailable": True, "twoFactorEnabled": True},
        })
        self.assertTrue(any("TrustedCoin" in item for item in result["blockers_and_limits"]))

    def test_unknown_wallet_stays_in_triage(self):
        result = assess_recovery_case({
            "walletType": "unknown", "ownerConfirmed": True,
            "authorizationReference": "CASE-005",
        })
        self.assertEqual(result["status"], "evidence_incomplete")
        self.assertFalse(result["execution_started"])


if __name__ == "__main__":
    unittest.main()
