"""Non-destructive, allow-listed disk acquisition helpers for the Kali bridge."""
from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_acquisition_lock = threading.Lock()


def _run(args: list[str], timeout: int = 15) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise ValueError((result.stderr or result.stdout or "Command failed.")[:500])
    return result.stdout


def list_block_devices() -> dict:
    if not shutil.which("lsblk"):
        raise ValueError("lsblk is not installed.")
    raw = _run(["lsblk", "--json", "-b", "-o", "NAME,PATH,TYPE,SIZE,RO,TRAN,MODEL,FSTYPE,MOUNTPOINTS,PKNAME"])
    data = json.loads(raw)
    return {"devices": data.get("blockdevices", []), "note": "Inventory only. No device has been mounted, changed or scanned for recoverable content."}


def _ancestors(device: str) -> set[str]:
    output = _run(["lsblk", "--inverse", "--noheadings", "--raw", "--output", "MAJ:MIN", device])
    return {line.strip() for line in output.splitlines() if line.strip()}


def _find_inventory_device(nodes: list[dict], source: str) -> dict | None:
    """Return only an exact disk/partition entry from lsblk's current inventory."""
    for node in nodes:
        if node.get("path") == source and node.get("type") in {"disk", "part"}:
            return node
        match = _find_inventory_device(node.get("children") or [], source)
        if match:
            return match
    return None


def _has_mounted_source(node: dict) -> bool:
    """Detect a mountpoint anywhere in a source disk's partition tree."""
    if any(point for point in (node.get("mountpoints") or [])):
        return True
    return any(_has_mounted_source(child) for child in (node.get("children") or []))


def _mount_device(path: Path) -> tuple[str, str]:
    raw = _run(["findmnt", "--json", "--target", str(path), "--output", "SOURCE,TARGET,MAJ:MIN"])
    filesystems = json.loads(raw).get("filesystems", [])
    if not filesystems:
        raise ValueError("Destination directory is not on a mounted filesystem.")
    fs = filesystems[0]
    return str(fs.get("maj:min", "")), str(fs.get("target", ""))


def _validate_acquisition(source: str, destination_dir: str, filename: str) -> tuple[str, Path, Path]:
    if os.geteuid() != 0:
        raise ValueError("Disk imaging requires root privileges. Start the local companion with sudo after verifying the repository and script.")
    source_path = Path(source)
    if not re.fullmatch(r"/dev/[A-Za-z0-9._/-]+", source) or not source_path.exists():
        raise ValueError("Choose a device path returned by the device inventory.")
    if not source_path.is_block_device():
        raise ValueError("The selected source is not a block device.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.img", filename):
        raise ValueError("Image filename must be a simple name ending in .img.")
    dest_dir = Path(destination_dir).expanduser().resolve(strict=True)
    if not dest_dir.is_dir():
        raise ValueError("Destination must be an existing directory on a separate mounted drive.")
    dest_majmin, mountpoint = _mount_device(dest_dir)
    if not dest_majmin or not mountpoint:
        raise ValueError("Could not verify the destination filesystem device.")
    tree = json.loads(_run(["lsblk", "--json", "-o", "PATH,TYPE,MOUNTPOINTS", str(source_path)]))
    inventory_entry = _find_inventory_device(tree.get("blockdevices", []), str(source_path))
    if not inventory_entry:
        raise ValueError("Choose a whole disk or partition present in the current lsblk inventory; mapper, loop and other virtual devices are not accepted.")
    if any(_has_mounted_source(node) for node in tree.get("blockdevices", [])):
        raise ValueError("A source partition is mounted. Boot from a live USB and unmount every source partition before imaging.")
    source_ancestors = _ancestors(str(source_path))
    dest_ancestors = _ancestors("/dev/block/" + dest_majmin) if Path("/dev/block/" + dest_majmin).exists() else {dest_majmin}
    if source_ancestors.intersection(dest_ancestors):
        raise ValueError("Destination storage is on the same physical device as the source. Choose a different drive.")
    image_path = dest_dir / filename
    map_path = dest_dir / (filename + ".log")
    if image_path.exists() or map_path.exists():
        raise ValueError("Image or ddrescue map file already exists. Choose a new filename; existing files are never overwritten.")
    # The caller reserves the image only after all confirmations and tool checks pass.
    # ddrescue creates and updates its own map file; do not pre-create an invalid empty map.
    return str(source_path), image_path, map_path


def start_image_acquisition(source: str, destination_dir: str, filename: str, confirmation: str) -> dict:
    source_path, image_path, map_path = _validate_acquisition(source, destination_dir, filename)
    if confirmation.strip() != source_path:
        raise ValueError("Retype the exact source device path to confirm acquisition.")
    if not shutil.which("ddrescue"):
        raise ValueError("GNU ddrescue is required. Install it with: sudo apt install -y gddrescue")
    if not _acquisition_lock.acquire(blocking=False):
        raise ValueError("Another disk acquisition is already running.")
    try:
        fd = os.open(str(image_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        if map_path.exists():
            image_path.unlink(missing_ok=True)
            raise ValueError("The ddrescue map file already exists. Choose a new image filename.")
    except Exception:
        _acquisition_lock.release()
        raise
    job_id = uuid.uuid4().hex
    record = {"id": job_id, "state": "running", "source": source_path, "image": str(image_path), "map": str(map_path), "started_at": time.time(), "message": "Acquisition started. Source is opened read-only by ddrescue."}
    with _jobs_lock:
        _jobs[job_id] = record

    def worker():
        try:
            # -n skips the scraping phase on the first pass. No write is issued to the source.
            command = ["ddrescue", "-f", "-n", source_path, str(image_path), str(map_path)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            with _jobs_lock:
                record["state"] = "completed" if completed.returncode == 0 else "failed"
                record["return_code"] = completed.returncode
                record["message"] = "Image acquisition completed." if completed.returncode == 0 else (completed.stderr or "ddrescue failed.")[-1200:]
                record["finished_at"] = time.time()
        except Exception as exc:
            with _jobs_lock:
                record["state"] = "failed"
                record["message"] = str(exc)[:1200]
                record["finished_at"] = time.time()
        finally:
            _acquisition_lock.release()

    threading.Thread(target=worker, name="cyberlab-ddrescue", daemon=True).start()
    return {"job": {key: value for key, value in record.items() if key not in {"started_at"}}, "note": "Do not disconnect either drive while acquisition is running. Preserve the original source and ddrescue map file."}


def get_image_job(job_id: str) -> dict | None:
    with _jobs_lock:
        record = _jobs.get(job_id)
        if not record:
            return None
        return {"job": dict(record)}



def inspect_image_filesystem(image_job_id: str, confirmation_image: str) -> dict:
    """Probe a completed acquisition image for filesystem signatures without mounting it."""
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
        raise ValueError("Retype the exact acquired image path to confirm inspection.")
    if not shutil.which("blkid"):
        raise ValueError("blkid is required for read-only filesystem probing. Install util-linux.")
    result = subprocess.run(
        ["blkid", "-p", "-o", "export", str(image)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if result.returncode not in (0, 2):
        raise ValueError((result.stderr or "Filesystem probe failed.")[:500])
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"TYPE", "USAGE", "VERSION", "LABEL", "UUID", "PTTYPE", "PART_ENTRY_TYPE", "PART_ENTRY_NAME"}:
            fields[key.lower()] = value[:256]
    return {
        "image": str(image),
        "recognized": result.returncode == 0 and bool(fields),
        "metadata": fields,
        "method": "blkid low-level signature probe",
        "note": "Read-only signature probe only. The image was not mounted or modified. A missing signature does not prove that the image contains no recoverable data.",
    }


def parse_mmls_partitions(output: str) -> list[dict]:
    """Parse Sleuth Kit mmls rows, returning allocated partition entries only."""
    partitions = []
    row = re.compile(r"^\s*(\d{3}):\s+(?:(?:\d{3}:\d{3}|Meta|-------)\s+)?(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")
    for line in output.splitlines():
        match = row.match(line)
        if not match:
            continue
        slot, start, end, length, description = match.groups()
        if description.lower().startswith("unallocated") or description.lower().startswith("primary table"):
            continue
        start_sector, end_sector, sector_count = int(start), int(end), int(length)
        if sector_count <= 0 or end_sector < start_sector or end_sector - start_sector + 1 != sector_count:
            continue
        partitions.append({
            "slot": slot,
            "start_sector": start_sector,
            "end_sector": end_sector,
            "length_sectors": sector_count,
            "description": description[:200],
        })
    return partitions


def inspect_image_partitions(image_job_id: str, confirmation_image: str) -> dict:
    """List partition boundaries from a completed image using read-only Sleuth Kit mmls."""
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
        raise ValueError("Retype the exact acquired image path to confirm partition analysis.")
    if not shutil.which("mmls"):
        raise ValueError("Sleuth Kit mmls is required. Install it with: sudo apt install -y sleuthkit")
    result = subprocess.run(
        ["mmls", str(image)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise ValueError((result.stderr or result.stdout or "Partition analysis failed.")[:500])
    partitions = parse_mmls_partitions(result.stdout)
    return {
        "image": str(image),
        "partitions": partitions,
        "partition_count": len(partitions),
        "method": "Sleuth Kit mmls partition-table analysis",
        "note": "Read-only partition-boundary analysis of the acquired image. The source image was not mounted; no partition was repaired or modified. An empty result can mean an unsupported, damaged or absent partition table; it does not prove that no recoverable data exists.",
    }

def _resolve_completed_image(image_job_id: str, confirmation_image: str, action: str) -> Path:
    """Shared guard: return the regular image file of a completed acquisition job."""
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
        raise ValueError("Retype the exact acquired image path to confirm " + action + ".")
    return image


# fls rows look like:  r/r * 14-128-3:  Users/alex/Pictures/holiday.jpg
_FLS_ROW = re.compile(
    r"^(?P<ftype>[a-z\-]/[a-z\-])\s+(?P<deleted>\*?)\s*(?P<inode>\d[\d\-]*):\s+(?P<path>.+?)\s*$")


def parse_fls_output(output: str, deleted_only: bool = True, limit: int = 1000) -> list[dict]:
    """Parse Sleuth Kit fls rows into structured deleted-file entries."""
    if not 1 <= limit <= 10000:
        raise ValueError("Listing limit must be between 1 and 10000.")
    entries = []
    for line in output.splitlines():
        match = _FLS_ROW.match(line)
        if not match:
            continue
        is_deleted = match.group("deleted") == "*"
        if deleted_only and not is_deleted:
            continue
        ftype = match.group("ftype")
        entries.append({
            "inode": match.group("inode"),
            "path": match.group("path")[:400],
            "deleted": is_deleted,
            "isDirectory": ftype.startswith("d"),
        })
        if len(entries) >= limit:
            break
    return entries


def list_deleted_files(image_job_id: str, confirmation_image: str, offset: int = 0,
                       limit: int = 1000, runner=subprocess.run, which=shutil.which) -> dict:
    """List deleted files in an acquired image using read-only Sleuth Kit fls."""
    image = _resolve_completed_image(image_job_id, confirmation_image, "deleted-file listing")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 2**40:
        raise ValueError("Partition offset (in sectors) must be a non-negative integer.")
    if not which("fls"):
        raise ValueError("Sleuth Kit fls is required. Install it with: sudo apt install -y sleuthkit")
    command = ["fls", "-r", "-p", "-d", "-o", str(offset), str(image)]
    result = runner(command, capture_output=True, text=True, timeout=300, check=False)
    if result.returncode != 0:
        raise ValueError((result.stderr or result.stdout or "fls failed.")[:500])
    entries = parse_fls_output(result.stdout, deleted_only=True, limit=limit)
    return {
        "image": str(image), "offset": offset, "deleted_count": len(entries),
        "deleted_files": entries, "method": "Sleuth Kit fls recursive deleted-entry listing",
        "note": "Read-only metadata listing from the acquired image. Nothing was mounted, modified or recovered yet. Recover individual files by inode with an explicit destination on a different drive.",
    }


def recover_deleted_file(image_job_id: str, confirmation_image: str, inode: str,
                         output_directory: str, offset: int = 0, filename: str = "",
                         runner=subprocess.run, which=shutil.which) -> dict:
    """Recover one deleted file by inode with Sleuth Kit icat to a separate drive."""
    image = _resolve_completed_image(image_job_id, confirmation_image, "file recovery")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 2**40:
        raise ValueError("Partition offset (in sectors) must be a non-negative integer.")
    if not isinstance(inode, str) or not re.fullmatch(r"\d[\d\-]{0,40}", inode):
        raise ValueError("Inode must be a Sleuth Kit inode identifier, e.g. 14-128-3.")
    if not which("icat"):
        raise ValueError("Sleuth Kit icat is required. Install it with: sudo apt install -y sleuthkit")
    parent = Path(output_directory).expanduser().resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Choose an existing destination directory on a different drive.")
    dest_majmin, _ = _mount_device(parent)
    dest_ancestors = _ancestors("/dev/block/" + dest_majmin) if dest_majmin and Path("/dev/block/" + dest_majmin).exists() else {dest_majmin}
    with _jobs_lock:
        source_job = dict(_jobs.get(image_job_id) or {})
    source_ancestors = _ancestors(str(source_job.get("source", "")))
    if source_ancestors and source_ancestors.intersection(dest_ancestors):
        raise ValueError("Recovery output is on the original source device. Choose a different physical drive.")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", (filename or ("recovered-" + inode))).strip("._") or "recovered"
    safe_name = safe_name[:120]
    destination = parent / ("cyberlab-recovered-" + uuid.uuid4().hex[:8] + "-" + safe_name)
    if destination.exists():
        raise ValueError("The recovery destination already exists.")
    command = ["icat", "-o", str(offset), str(image), inode]
    fd = os.open(str(destination), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            result = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False)
            payload = result.stdout if isinstance(result.stdout, (bytes, bytearray)) else (result.stdout or "").encode()
            if result.returncode != 0:
                raise ValueError((getattr(result, "stderr", b"") or b"icat failed.")[:500].decode("utf-8", "replace") if isinstance(getattr(result, "stderr", b""), (bytes, bytearray)) else str(result.stderr)[:500])
            handle.write(payload)
            digest.update(payload)
            size = len(payload)
    except Exception:
        Path(destination).unlink(missing_ok=True)
        raise
    return {
        "inode": inode, "destination": str(destination), "size_bytes": size,
        "sha256": digest.hexdigest(), "method": "Sleuth Kit icat inode extraction",
        "note": "Recovered to a separate destination with owner-only permissions. The source image was not modified. Validate the file before trusting it; a recovered file can be partial or corrupt.",
    }


def build_recovery_manifest(output_directory: str, max_files: int = 5000) -> dict:
    """Hash regular recovered files without following symlinks; cap work for safety."""
    if type(max_files) is not int or not 1 <= max_files <= 5000:
        raise ValueError("Manifest file limit must be between 1 and 5000.")
    root = Path(output_directory).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Recovery output directory is not available.")
    entries = []
    total_bytes = 0
    truncated = False
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(current) / name).is_symlink()]
        for filename in filenames:
            path = Path(current) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if len(entries) >= max_files:
                truncated = True
                break
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            entries.append({
                "path": path.relative_to(root).as_posix(),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
            })
            total_bytes += size
        if truncated:
            break
    manifest = {
        "schema": "cyberlab.recovery-manifest.v1",
        "algorithm": "SHA-256",
        "files_hashed": len(entries),
        "total_bytes_hashed": total_bytes,
        "truncated": truncated,
        "files": entries,
    }
    manifest_path = root / "cyberlab-recovery-manifest.json"
    fd = os.open(str(manifest_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return {"path": str(manifest_path), **{key: manifest[key] for key in ("files_hashed", "total_bytes_hashed", "truncated")}}


def start_foremost_recovery(image_job_id: str, output_directory: str, confirmation_image: str) -> dict:
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
        raise ValueError("Retype the exact forensic image path to confirm recovery.")
    if not shutil.which("foremost"):
        raise ValueError("Foremost is required. Install it with: sudo apt install -y foremost")
    parent = Path(output_directory).expanduser().resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Choose an existing destination parent directory on a mounted backup drive.")
    dest_majmin, _ = _mount_device(parent)
    dest_ancestors = _ancestors("/dev/block/" + dest_majmin) if dest_majmin and Path("/dev/block/" + dest_majmin).exists() else {dest_majmin}
    source_ancestors = _ancestors(str(source_job["source"]))
    if source_ancestors.intersection(dest_ancestors):
        raise ValueError("Recovery output is on the original source device. Choose a different physical drive.")
    output = parent / ("cyberlab-foremost-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    if output.exists():
        raise ValueError("The selected recovery output directory already exists.")
    if not _acquisition_lock.acquire(blocking=False):
        raise ValueError("Another forensic acquisition or recovery job is already running.")
    job_id = uuid.uuid4().hex
    record = {"id": job_id, "kind": "foremost", "state": "running", "source": str(source_job["source"]), "image": str(image), "output": str(output), "started_at": time.time(), "message": "Foremost recovery started from the verified disk image."}
    with _jobs_lock:
        _jobs[job_id] = record

    def worker():
        try:
            command = ["foremost", "-t", "jpg,png,gif,bmp,tif,doc,pdf,xls,ppt,zip", "-i", str(image), "-o", str(output)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            manifest = None
            manifest_error = None
            if completed.returncode == 0 and output.is_dir():
                try:
                    manifest = build_recovery_manifest(str(output))
                except Exception as exc:
                    manifest_error = str(exc)[:500]
            with _jobs_lock:
                record["state"] = "completed" if completed.returncode == 0 else "failed"
                record["return_code"] = completed.returncode
                if completed.returncode == 0:
                    record["manifest"] = manifest
                    record["message"] = "Foremost finished. SHA-256 manifest created; review audit.txt and validate every recovered file." if manifest else "Foremost finished, but the SHA-256 manifest could not be created: " + (manifest_error or "output directory unavailable")
                else:
                    record["message"] = (completed.stderr or "Foremost failed.")[-1200:]
                record["finished_at"] = time.time()
        except Exception as exc:
            with _jobs_lock:
                record["state"] = "failed"
                record["message"] = str(exc)[:1200]
                record["finished_at"] = time.time()
        finally:
            _acquisition_lock.release()

    threading.Thread(target=worker, name="cyberlab-foremost", daemon=True).start()
    return {"job": {key: value for key, value in record.items() if key != "started_at"}, "note": "Recovery reads only the forensic image. Recovered output is written to a new directory on the backup drive."}
