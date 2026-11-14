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

    def test_recovery_manifest_marks_file_limit_as_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovered"
            root.mkdir()
            (root / "a.bin").write_bytes(b"a")
            (root / "b.bin").write_bytes(b"b")
            result = forensics.build_recovery_manifest(str(root), max_files=1)
            manifest = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["files_hashed"], 1)
            self.assertTrue(manifest["truncated"])

    def test_recovery_manifest_never_overwrites_existing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovered"
            root.mkdir()
            manifest_path = root / "cyberlab-recovery-manifest.json"
            manifest_path.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                forensics.build_recovery_manifest(str(root))
            self.assertEqual(manifest_path.read_text(encoding="utf-8"), "preserve")

    def test_recovery_manifest_rejects_unbounded_file_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            for limit in (0, -1, 5001, True):
                with self.subTest(limit=limit):
                    with self.assertRaisesRegex(ValueError, "between 1 and 5000"):
                        forensics.build_recovery_manifest(directory, max_files=limit)

    def test_image_probe_requires_completed_job_and_exact_confirmation(self):
        with patch.object(forensics, "_jobs_lock"):
            with patch.dict(forensics._jobs, {"a" * 32: {"id": "a" * 32, "state": "running", "image": "/tmp/disk.img"}}):
                with self.assertRaisesRegex(ValueError, "completed"):
                    forensics.inspect_image_filesystem("a" * 32, "/tmp/disk.img")

    def test_image_probe_rejects_symlinked_image_path(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "real.img"
            target.write_bytes(b"image")
            alias = Path(directory) / "alias.img"
            alias.symlink_to(target)
            job_id = "c" * 32
            with patch.dict(forensics._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(alias)}}), \
                 patch.object(forensics.shutil, "which", return_value="/usr/sbin/blkid"), \
                 patch.object(forensics.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    forensics.inspect_image_filesystem(job_id, str(alias))
            run.assert_not_called()

    def test_image_probe_returns_only_allowlisted_read_only_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            job_id = "b" * 32
            with patch.dict(forensics._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(image)}}), \
                 patch.object(forensics.shutil, "which", return_value="/usr/sbin/blkid"), \
                 patch.object(forensics.subprocess, "run", return_value=type("Result", (), {"returncode": 0, "stdout": "TYPE=ext4\nUUID=abc\nUNSAFE=value\n", "stderr": ""})()) as run:
                result = forensics.inspect_image_filesystem(job_id, str(image))
            self.assertTrue(result["recognized"])
            self.assertEqual(result["metadata"], {"type": "ext4", "uuid": "abc"})
            self.assertIn("not mounted or modified", result["note"])
            self.assertEqual(run.call_args.args[0][:4], ["blkid", "-p", "-o", "export"])

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
