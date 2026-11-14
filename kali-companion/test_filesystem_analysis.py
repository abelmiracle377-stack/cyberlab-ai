"""Safety tests for read-only filesystem metadata inspection."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import filesystem_analysis


class FilesystemAnalysisTests(unittest.TestCase):
    def test_fsstat_requires_discovered_partition_start(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            job_id = "a" * 32
            sample = "002: 000:000 0000002048 0000206847 0000204800 NTFS (0x07)"
            with patch.dict(filesystem_analysis._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(image)}}):
                with patch.object(filesystem_analysis.shutil, "which", return_value="/usr/bin/mmls"):
                    with patch.object(filesystem_analysis.subprocess, "run", return_value=type("Result", (), {"returncode": 0, "stdout": sample, "stderr": ""})()) as run:
                        with self.assertRaisesRegex(ValueError, "not the start"):
                            filesystem_analysis.inspect_partition_filesystem(job_id, str(image), 2049)
            run.assert_called_once()

    def test_fsstat_uses_fixed_read_only_command_for_validated_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            job_id = "b" * 32
            sample = "002: 000:000 0000002048 0000206847 0000204800 NTFS (0x07)"
            table = type("Result", (), {"returncode": 0, "stdout": sample, "stderr": ""})()
            metadata = type("Result", (), {"returncode": 0, "stdout": "FILE SYSTEM INFORMATION\nType: NTFS\n", "stderr": ""})()
            with patch.dict(filesystem_analysis._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(image)}}):
                with patch.object(filesystem_analysis.shutil, "which", return_value="/usr/bin/tool"):
                    with patch.object(filesystem_analysis.subprocess, "run", side_effect=[table, metadata]) as run:
                        result = filesystem_analysis.inspect_partition_filesystem(job_id, str(image), 2048)
            self.assertEqual(result["partition"]["start_sector"], 2048)
            self.assertIn("Type: NTFS", result["metadata"])
            self.assertEqual(run.call_args_list[1].args[0], ["fsstat", "-o", "2048", str(image)])
            self.assertIn("not mounted", result["note"])

    def test_fsstat_requires_exact_image_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            job_id = "c" * 32
            with patch.dict(filesystem_analysis._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(image)}}):
                with self.assertRaisesRegex(ValueError, "exact acquired image path"):
                    filesystem_analysis.inspect_partition_filesystem(job_id, str(image) + ".other", 2048)

    def test_fsstat_rejects_symlinked_image(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            alias = Path(directory) / "alias.img"
            alias.symlink_to(image)
            job_id = "d" * 32
            with patch.dict(filesystem_analysis._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(alias)}}):
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    filesystem_analysis.inspect_partition_filesystem(job_id, str(image), 2048)

    def test_fsstat_rejects_unavailable_partition_tool_without_running_command(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "disk.img"
            image.write_bytes(b"image")
            job_id = "e" * 32
            with patch.dict(filesystem_analysis._jobs, {job_id: {"id": job_id, "state": "completed", "image": str(image)}}):
                with patch.object(filesystem_analysis.shutil, "which", return_value=None):
                    with patch.object(filesystem_analysis.subprocess, "run") as run:
                        with self.assertRaisesRegex(ValueError, "mmls is required"):
                            filesystem_analysis.inspect_partition_filesystem(job_id, str(image), 2048)
            run.assert_not_called()

    def test_fsstat_rejects_boolean_and_negative_offsets(self):
        for offset in (True, -1, 2**64):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "valid partition"):
                    filesystem_analysis.inspect_partition_filesystem("0" * 32, "/tmp/disk.img", offset)


if __name__ == "__main__":
    unittest.main()
