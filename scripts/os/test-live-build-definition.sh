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

for package in xfce4 xfce4-terminal lightdm firefox-esr; do
  grep -qx "$package" "$DESKTOP" || { echo "Desktop profile missing $package" >&2; exit 1; }
done
for package in xfce4 xfce4-terminal lightdm firefox-esr; do
  if grep -qx "$package" "$TERMINAL"; then
    echo "Terminal profile must not include graphical package $package" >&2
    exit 1
  fi
done

test -s "$ROOT_DIR/scripts/os/guest-security-check.sh"
bash -n "$ROOT_DIR/scripts/os/guest-security-check.sh"
test -s "$ROOT_DIR/scripts/os/test-guest-security-check.sh"
bash -n "$ROOT_DIR/scripts/os/test-guest-security-check.sh"
bash "$ROOT_DIR/scripts/os/test-guest-security-check.sh"
grep -q "guest-security-check.sh" "$ROOT_DIR/scripts/os/build-live-iso.sh"
test -s "$ROOT_DIR/scripts/os/cyberlab-menu.py"
test -s "$ROOT_DIR/kali-companion/cyberlab.py"
python3 -c "compile(open('$ROOT_DIR/scripts/os/cyberlab-menu.py', encoding='utf-8').read(), 'cyberlab-menu.py', 'exec')"
grep -q 'lb config' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'pwd -P' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Unsafe build work directory' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Build work directory must not be inside the repository' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Output directory must not be inside the profile work directory' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'iso-hybrid' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'username=cyberlab' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'Serial boot log retained' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q -- '-no-user-config' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q -- '-nic none' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q -- '-snapshot' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q 'desktop-boot.log' "$ROOT_DIR/.github/workflows/build-os-vm.yml"
grep -q 'terminal-boot.log' "$ROOT_DIR/.github/workflows/build-os-vm.yml"
grep -q 'cyberlab-menu.py' "$ROOT_DIR/scripts/os/build-live-iso.sh"
grep -q 'exec python3 /usr/local/lib/cyberlab/menu.py' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'exec python3 /opt/cyberlab-ai/kali-companion/cyberlab.py' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'kernel.kptr_restrict = 2' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'kernel.dmesg_restrict = 1' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'kernel.yama.ptrace_scope = 1' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'net.ipv4.conf.all.accept_redirects = 0' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'net.ipv6.conf.all.accept_redirects = 0' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'hard core 0' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q 'umask 027' "$ROOT_DIR/scripts/os/live-configure.chroot"
if grep -qx 'openssh-server' "$DESKTOP" "$TERMINAL"; then
  echo "SSH server must remain absent from the default live profiles." >&2
  exit 1
fi
grep -q 'never started automatically' "$ROOT_DIR/scripts/os/live-configure.chroot"
grep -q "desktop) EXPECTED_MARKER='Reached target Graphical Interface'" "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q "terminal) EXPECTED_MARKER='Reached target Multi-User System|login:'" "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q 'MEMORY_MB=4096; VCPUS=2' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
grep -q 'MEMORY_MB=1536; VCPUS=1' "$ROOT_DIR/scripts/os/boot-smoke-test.sh"
if grep -q 'run: sudo ./scripts/os/boot-smoke-test.sh' "$ROOT_DIR/.github/workflows/build-os-vm.yml"; then
  echo "QEMU boot acceptance must run as the unprivileged workflow user." >&2
  exit 1
fi
echo "CyberLab AI OS live ISO definitions and profile manifests passed."
