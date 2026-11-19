"""Tests for Sleuth Kit fls/icat deleted-file recovery.

Uses an injected runner and tool resolver plus a temporary acquired-image
fixture, so no real forensic tools are needed. Recovered bytes come only from
the runner's own output.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

import forensics


FLS_SAMPLE = (
    "d/d 12-144-1:\tUsers\n"
    "r/r * 14-128-3:\tUsers/alex/Pictures/holiday.jpg\n"
    "r/r 16-128-3:\tUsers/alex/notes.txt\n"
    "d/d * 20-144-1:\tUsers/alex/.Trash\n"
    "r/r * 18-128-3:\tUsers/alex/Pictures/secret.png\n"
)


class FlsParserTests(unittest.TestCase):
    def test_returns_only_deleted_entries_with_inode_and_path(self):
        entries = forensics.parse_fls_output(FLS_SAMPLE)
        paths = {e["path"] for e in entries}
        self.assertIn("Users/alex/Pictures/holiday.jpg", paths)
        self.assertIn("Users/alex/Pictures/secret.png", paths)
        self.assertNotIn("Users/alex/notes.txt", paths)  # not deleted
        inodes = {e["inode"] for e in entries}
        self.assertIn("14-128-3", inodes)

    def test_marks_directories(self):
        entries = forensics.parse_fls_output(FLS_SAMPLE)
        trash = [e for e in entries if e["path"].endswith(".Trash")][0]
        self.assertTrue(trash["isDirectory"])

    def test_limit_is_enforced(self):
        self.assertEqual(len(forensics.parse_fls_output(FLS_SAMPLE, limit=1)), 1)


class _JobFixture:
    """Register a completed acquisition job pointing at a real temp image file."""
    def __init__(self, tmp):
        self.image = Path(tmp) / "disk.dd"
        self.image.write_bytes(b"\x00" * 4096)
        self.job_id = "job-test"
        with forensics._jobs_lock:
            forensics._jobs[self.job_id] = {
                "id": self.job_id, "state": "completed",
                "image": str(self.image), "source": "/dev/does-not-exist",
            }

    def cleanup(self):
        with forensics._jobs_lock:
            forensics._jobs.pop(self.job_id, None)


class ListDeletedTests(unittest.TestCase):
    def test_lists_deleted_files_from_injected_fls(self):
        with tempfile.TemporaryDirectory() as tmp:
            fix = _JobFixture(tmp)
            try:
                def runner(cmd, **kw):
                    self.assertEqual(cmd[0], "fls")
                    self.assertIn("-d", cmd)  # deleted only
                    return subprocess.CompletedProcess(cmd, 0, FLS_SAMPLE, "")
                result = forensics.list_deleted_files(
                    fix.job_id, str(fix.image), offset=0,
                    runner=runner, which=lambda n: "/usr/bin/" + n)
                self.assertEqual(result["deleted_count"], 3)
            finally:
                fix.cleanup()

    def test_wrong_image_confirmation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fix = _JobFixture(tmp)
            try:
                with self.assertRaisesRegex(ValueError, "Retype the exact"):
                    forensics.list_deleted_files(fix.job_id, "/wrong/path.dd",
                                                 which=lambda n: "/usr/bin/" + n)
            finally:
                fix.cleanup()

    def test_missing_fls_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fix = _JobFixture(tmp)
            try:
                with self.assertRaisesRegex(ValueError, "fls is required"):
                    forensics.list_deleted_files(fix.job_id, str(fix.image),
                                                 which=lambda n: None)
            finally:
                fix.cleanup()


class RecoverDeletedTests(unittest.TestCase):
    def test_recovers_file_bytes_and_hashes_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            fix = _JobFixture(tmp)
            outdir = Path(tmp) / "out"
            outdir.mkdir()
            # Stub the physical-device safety helpers so the test does not depend
            # on real block devices; production uses lsblk/findmnt as written.
            saved_mount, saved_anc = forensics._mount_device, forensics._ancestors
            forensics._mount_device = lambda p: ("", "")
            forensics._ancestors = lambda dev: {"source"} if "does-not-exist" in str(dev) else {"dest"}
            try:
                payload = b"\xff\xd8\xff\xe0recovered-jpeg-bytes"

                def runner(cmd, **kw):
                    self.assertEqual(cmd[0], "icat")
                    self.assertIn("14-128-3", cmd)
                    return subprocess.CompletedProcess(cmd, 0, payload, b"")

                result = forensics.recover_deleted_file(
                    fix.job_id, str(fix.image), "14-128-3", str(outdir),
                    offset=0, filename="holiday.jpg",
                    runner=runner, which=lambda n: "/usr/bin/" + n)
                self.assertEqual(result["size_bytes"], len(payload))
                written = Path(result["destination"]).read_bytes()
                self.assertEqual(written, payload)
                import hashlib
                self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            finally:
                forensics._mount_device, forensics._ancestors = saved_mount, saved_anc
                fix.cleanup()

    def test_rejects_malformed_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            fix = _JobFixture(tmp)
            try:
                with self.assertRaisesRegex(ValueError, "Inode must be"):
                    forensics.recover_deleted_file(fix.job_id, str(fix.image), "../etc/passwd",
                                                   str(tmp), which=lambda n: "/usr/bin/" + n)
            finally:
                fix.cleanup()


if __name__ == "__main__":
    unittest.main()
