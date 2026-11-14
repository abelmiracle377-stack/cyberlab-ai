"""Safety tests for the CyberLab local forensics bridge helpers."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import forensics


class ForensicsSafetyTests(unittest.TestCase):
    def test_device_inventory_is_read_only_metadata(self):
        payload = {"blockdevices": [{"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 1000, "ro": False, "children": []}]}
        with patch.object(forensics, "_run", return_value=json.dumps(payload)) as run:
            result = forensics.list_block_devices()
        self.assertEqual(result["devices"][0]["path"], "/dev/sdb")
        self.assertIn("Inventory only", result["note"])
        self.assertEqual(run.call_args.args[0][0], "lsblk")

    def test_unknown_job_is_not_retrievable(self):
        self.assertIsNone(forensics.get_image_job("0" * 32))

    def test_invalid_image_filename_is_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path("/dev/null")
            with patch.object(forensics.os, "geteuid", return_value=0), patch.object(Path, "is_block_device", return_value=True):
                with self.assertRaisesRegex(ValueError, "simple name"):
                    forensics._validate_acquisition(str(source), directory, "../unsafe.img")

    def test_missing_source_path_is_rejected(self):
        with patch.object(forensics.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "device path"):
                forensics._validate_acquisition("/dev/cyberlab-test-does-not-exist", "/tmp", "disk.img")


if __name__ == "__main__":
    unittest.main()
