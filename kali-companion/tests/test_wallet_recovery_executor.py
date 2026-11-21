import unittest
from unittest.mock import Mock

from wallet_recovery_executor import execute_recovery_job


class WalletRecoveryExecutorTests(unittest.TestCase):
    def setUp(self):
        self.auto = Mock(return_value={"detected": "bip39", "derived_count": 12, "accounts": []})

    def request(self, **extra):
        return {
            "operation": "derive-and-check",
            "ownerConfirmed": True,
            "authorizationReference": "CASE-EXEC-001",
            "confirmRun": True,
            "mnemonic": "local test phrase",
            **extra,
        }

    def test_executes_existing_local_recovery_engine(self):
        result = execute_recovery_job(self.request(), auto_recover=self.auto)
        self.auto.assert_called_once()
        self.assertEqual(result["execution"], "completed")
        self.assertTrue(result["execution_started"])
        self.assertEqual(result["result"]["detected"], "bip39")

    def test_requires_owner_confirmation(self):
        with self.assertRaisesRegex(ValueError, "Owner confirmation"):
            execute_recovery_job(self.request(ownerConfirmed=False), auto_recover=self.auto)
        self.auto.assert_not_called()

    def test_requires_explicit_run_confirmation(self):
        with self.assertRaisesRegex(ValueError, "Explicit confirmation"):
            execute_recovery_job(self.request(confirmRun=False), auto_recover=self.auto)
        self.auto.assert_not_called()

    def test_network_lookup_has_separate_confirmation(self):
        with self.assertRaisesRegex(ValueError, "network confirmation"):
            execute_recovery_job(self.request(checkBalances=True), auto_recover=self.auto)
        self.auto.assert_not_called()

    def test_rejects_unexpected_fields(self):
        with self.assertRaisesRegex(ValueError, "Unsupported execution field"):
            execute_recovery_job(self.request(privateKey="no"), auto_recover=self.auto)
        self.auto.assert_not_called()


if __name__ == "__main__":
    unittest.main()
