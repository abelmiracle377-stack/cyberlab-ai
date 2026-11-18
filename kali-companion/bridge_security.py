"""Secure local pairing-token storage for the CyberLab loopback companion."""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

TOKEN_MIN_LENGTH = 40
TOKEN_MAX_LENGTH = 256
TOKEN_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def load_or_create_pairing_token(config_dir: Path, token_file: Path) -> str:
    """Load a private owner-only token or create one without following symlinks.

    An invalid existing token is rejected rather than silently overwritten. This
    prevents a suspicious file or unexpected owner from being treated as safe.
    """
    config_dir = Path(config_dir)
    token_file = Path(token_file)
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    directory_info = config_dir.lstat()
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode):
        raise PermissionError("CyberLab configuration path must be a real directory, not a symlink.")
    current_uid = os.getuid() if hasattr(os, "getuid") else directory_info.st_uid
    if directory_info.st_uid != current_uid:
        raise PermissionError("CyberLab configuration directory must be owned by the current user.")
    os.chmod(config_dir, 0o700)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    for _attempt in range(2):
        try:
            descriptor = os.open(str(token_file), os.O_RDONLY | nofollow | cloexec)
        except FileNotFoundError:
            token = secrets.token_urlsafe(48)
            try:
                descriptor = os.open(
                    str(token_file),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                    0o600,
                )
            except FileExistsError:
                continue
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(token + "\\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            return token
        except OSError as exc:
            raise PermissionError("CyberLab pairing token cannot be opened safely; check that it is not a symlink.") from exc

        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise PermissionError("CyberLab pairing token must be a regular file.")
            if info.st_uid != current_uid:
                raise PermissionError("CyberLab pairing token must be owned by the current user.")
            os.fchmod(handle.fileno(), 0o600)
            raw = handle.read(TOKEN_MAX_LENGTH + 2)

        try:
            token = raw.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise PermissionError("CyberLab pairing token contains invalid data; remove it and restart the companion.") from exc
        if not TOKEN_MIN_LENGTH <= len(token) <= TOKEN_MAX_LENGTH or any(char not in TOKEN_ALPHABET for char in token):
            raise PermissionError("CyberLab pairing token is invalid; remove it and restart the companion to rotate it.")
        return token

    raise RuntimeError("Could not create the CyberLab pairing token because another process changed the token file.")
