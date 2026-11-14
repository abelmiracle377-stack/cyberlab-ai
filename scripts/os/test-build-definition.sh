#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-vm.sh" "$ROOT_DIR/scripts/os/provision-vm.sh" "$ROOT_DIR/scripts/os/verify-vm.sh"; do
  bash -n "$file"
done
grep -q 'virt-builder debian-13' "$ROOT_DIR/scripts/os/build-vm.sh"
grep -q 'kali-companion:/opt/cyberlab-ai/' "$ROOT_DIR/scripts/os/build-vm.sh"
grep -q 'not started automatically' "$ROOT_DIR/os/README.md"
grep -q 'workflow_dispatch:' "$ROOT_DIR/.github/workflows/build-os-vm.yml"
echo "OS VM build-definition checks passed."
