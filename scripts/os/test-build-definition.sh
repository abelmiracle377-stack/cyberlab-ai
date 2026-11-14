#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for file in "$ROOT_DIR/scripts/os/build-vm.sh" "$ROOT_DIR/scripts/os/provision-vm.sh" "$ROOT_DIR/scripts/os/verify-vm.sh"; do
  bash -n "$file"
done
test -s "$ROOT_DIR/os/README.md"
echo "Legacy secondary VM prototype syntax checks passed."
