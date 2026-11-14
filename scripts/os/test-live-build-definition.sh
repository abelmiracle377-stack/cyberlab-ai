#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-live-iso.sh" "$ROOT_DIR/scripts/os/live-configure.chroot"; do
  bash -n "$file"
done
test -s "$ROOT_DIR/os/profiles/desktop.packages"
test -s "$ROOT_DIR/os/profiles/terminal.packages"
grep -q 'lb config' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'iso-hybrid' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'username=cyberlab' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'never started automatically' "$ROOT_DIR/scripts/os/live-configure.chroot"
echo "CyberLab AI OS live ISO definitions passed."
