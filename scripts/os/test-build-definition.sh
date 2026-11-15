#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-vm.sh" "$ROOT_DIR/scripts/os/provision-vm.sh" "$ROOT_DIR/scripts/os/verify-vm.sh"; do
  bash -n "$file"
done
grep -q 'kernel.kptr_restrict = 2' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'kernel.dmesg_restrict = 1' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'kernel.yama.ptrace_scope = 1' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'net.ipv4.conf.all.accept_redirects = 0' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'net.ipv6.conf.all.accept_redirects = 0' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'hard core 0' "$ROOT_DIR/scripts/os/provision-vm.sh"
grep -q 'umask 027' "$ROOT_DIR/scripts/os/provision-vm.sh"
if grep -Eq 'apt-get install[^#]*openssh-server|openssh-server' "$ROOT_DIR/scripts/os/provision-vm.sh"; then
  echo "Secondary VM must not install an SSH server by default." >&2
  exit 1
fi
test -s "$ROOT_DIR/os/README.md"
echo "Legacy secondary VM prototype syntax checks passed."
