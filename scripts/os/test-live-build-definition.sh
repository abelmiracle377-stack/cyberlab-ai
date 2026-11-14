#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-live-iso.sh" "$ROOT_DIR/scripts/os/live-configure.chroot" "$ROOT_DIR/scripts/os/boot-smoke-test.sh"; do
  bash -n "$file"
done

DESKTOP="$ROOT_DIR/os/profiles/desktop.packages"
TERMINAL="$ROOT_DIR/os/profiles/terminal.packages"
for manifest in "$DESKTOP" "$TERMINAL"; do
  test -s "$manifest"
  # Package manifests must contain only unique Debian package names and comments.
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    !/^[a-z0-9][a-z0-9+.-]*$/ { print "Invalid package entry: " $0 > "/dev/stderr"; bad=1; next }
    seen[$0]++ { print "Duplicate package entry: " $0 > "/dev/stderr"; bad=1 }
    END { if (bad) exit 1; if (!length(seen)) exit 1 }
  ' "$manifest"
  for package in live-boot live-config live-config-systemd linux-image-amd64 systemd-sysv python3 nmap; do
    grep -qx "$package" "$manifest" || { echo "Missing required package $package in $manifest" >&2; exit 1; }
  done
done

# Desktop has the graphical shell; terminal intentionally stays headless.
for package in xfce4 xfce4-terminal lightdm firefox-esr; do
  grep -qx "$package" "$DESKTOP" || { echo "Desktop profile missing $package" >&2; exit 1; }
done
for package in xfce4 xfce4-terminal lightdm firefox-esr; do
  if grep -qx "$package" "$TERMINAL"; then
    echo "Terminal profile must not include graphical package $package" >&2
    exit 1
  fi
done

test -s "$ROOT_DIR/scripts/os/cyberlab-menu.py"
python3 -c "compile(open('$ROOT_DIR/scripts/os/cyberlab-menu.py', encoding='utf-8').read(), 'cyberlab-menu.py', 'exec')"
grep -q 'lb config' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Unsafe build work directory' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Output directory must not be inside the profile work directory' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'iso-hybrid' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'username=cyberlab' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'cyberlab-menu.py' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'exec python3 /usr/local/lib/cyberlab/menu.py' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'never started automatically' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q "desktop) EXPECTED_MARKER='Reached target Graphical Interface'" "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q "terminal) EXPECTED_MARKER='Reached target Multi-User System|login:'" "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
echo "CyberLab AI OS live ISO definitions and profile manifests passed."
