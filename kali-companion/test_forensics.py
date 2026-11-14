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

    def test_only_inventoried_disk_or_partition_is_accepted(self):
        inventory = [{"path": "/dev/sda", "type": "disk", "children": [
            {"path": "/dev/sda1", "type": "part", "children": []}
        ]}]
        self.assertEqual(forensics._find_inventory_device(inventory, "/dev/sda1")["type"], "part")
        self.assertIsNone(forensics._find_inventory_device(inventory, "/dev/loop0"))
        virtual = [{"path": "/dev/mapper/cryptroot", "type": "crypt", "children": []}]
        self.assertIsNone(forensics._find_inventory_device(virtual, "/dev/mapper/cryptroot"))

    def test_mounted_descendant_blocks_whole_disk_acquisition(self):
        device_tree = {"path": "/dev/sda", "mountpoints": [None], "children": [
            {"path": "/dev/sda1", "mountpoints": ["/mnt/source"], "children": []}
        ]}
        self.assertTrue(forensics._has_mounted_source(device_tree))
        self.assertFalse(forensics._has_mounted_source({"path": "/dev/sdb", "mountpoints": [None], "children": []}))

    def test_recovery_manifest_hashes_regular_files_and_skips_symlinks(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovered"
            root.mkdir()
            payload = b"recovered evidence"
            (root / "sample.bin").write_bytes(payload)
            (root / "link.bin").symlink_to(root / "sample.bin")
            result = forensics.build_recovery_manifest(str(root))
            manifest = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["files_hashed"], 1)
            self.assertEqual(manifest["files"][0]["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(manifest["files"][0]["path"], "sample.bin")
            self.assertFalse(manifest["truncated"])

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
