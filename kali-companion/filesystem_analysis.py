"""Read-only filesystem metadata inspection for acquired forensic images."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from forensics import _jobs, _jobs_lock, parse_mmls_partitions


def inspect_partition_filesystem(image_job_id: str, confirmation_image: str, start_sector: int) -> dict:
    """Run Sleuth Kit fsstat only at a partition start reported by mmls."""
    if type(start_sector) is not int or not 0 <= start_sector <= 2**63 - 1:
        raise ValueError("Choose a valid partition start sector from the discovered partition list.")
    with _jobs_lock:
        source_job = _jobs.get(image_job_id)
        source_job = dict(source_job) if source_job else None
    if not source_job or source_job.get("state") != "completed":
        raise ValueError("Choose a completed CyberLab ddrescue acquisition job.")
    recorded_image = Path(str(source_job.get("image", "")))
    if recorded_image.is_symlink():
        raise ValueError("The acquired image path must not be a symbolic link.")
    image = recorded_image.resolve(strict=True)
    if not image.is_file():
        raise ValueError("The acquired image is not a regular image file.")
    if confirmation_image.strip() != str(image):
        raise ValueError("Retype the exact acquired image path to confirm filesystem inspection.")
    if not shutil.which("mmls"):
        raise ValueError("Sleuth Kit mmls is required to validate the selected partition.")
    table = subprocess.run(
        ["mmls", str(image)], capture_output=True, text=True, timeout=30, check=False,
    )
    if table.returncode != 0:
        raise ValueError((table.stderr or table.stdout or "Partition validation failed.")[:500])
    partitions = parse_mmls_partitions(table.stdout)
    selected = next((part for part in partitions if part["start_sector"] == start_sector), None)
    if selected is None:
        raise ValueError("Selected sector is not the start of a discovered allocated partition.")
    if not shutil.which("fsstat"):
        raise ValueError("Sleuth Kit fsstat is required. Install it with: sudo apt install -y sleuthkit")
    result = subprocess.run(
        ["fsstat", "-o", str(start_sector), str(image)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise ValueError((result.stderr or result.stdout or "Filesystem metadata inspection failed.")[:700])
    output = result.stdout[:12000]
    return {
        "image": str(image),
        "partition": selected,
        "metadata": output,
        "truncated": len(result.stdout) > len(output),
        "method": "Sleuth Kit fsstat read-only partition metadata inspection",
        "note": "Read-only metadata inspection at a partition boundary verified from mmls. The image was not mounted, repaired or modified. Output is descriptive metadata, not a recovery guarantee.",
    }
