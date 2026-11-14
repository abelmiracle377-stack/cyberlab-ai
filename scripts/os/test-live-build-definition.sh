#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-live-iso.sh" "$ROOT_DIR/scripts/os/live-configure.chroot"; do
  bash -n "$file"
done
test -s "$ROOT_DIR/os/profiles/desktop.packages"
test -s "$ROOT_DIR/os/profiles/terminal.packages"
test -s "$ROOT_DIR/scripts/os/cyberlab-menu.py"
python3 -c "compile(open('$ROOT_DIR/scripts/os/cyberlab-menu.py', encoding='utf-8').read(), 'cyberlab-menu.py', 'exec')"
grep -q 'lb config' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'iso-hybrid' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'username=cyberlab' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'cyberlab-menu.py' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'exec python3 /usr/local/lib/cyberlab/menu.py' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'never started automatically' "$ROOT_DIR/scripts/os/live-configure.chroot"
echo "CyberLab AI OS live ISO definitions passed."
