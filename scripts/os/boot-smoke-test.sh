#!/usr/bin/env bash
set -Eeuo pipefail

ISO="${1:?Usage: boot-smoke-test.sh path/to/cyberlab-ai-os-*.iso}"
PROFILE="${2:-unknown}"
command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "qemu-system-x86_64 is required." >&2; exit 2; }
[[ -f "$ISO" && -s "$ISO" && ! -L "$ISO" ]] || { echo "ISO must be a non-empty regular file." >&2; exit 2; }

LOG="$(mktemp)"
cleanup() {
  rm -f "$LOG"
}
trap cleanup EXIT

set +e
timeout --signal=TERM --kill-after=10s 180s qemu-system-x86_64 \
  -machine accel=tcg \
  -m 2048 -smp 2 \
  -cdrom "$ISO" -boot order=d,menu=off \
  -display none -serial "file:$LOG" -monitor none \
  -no-reboot -no-shutdown
QEMU_STATUS=$?
set -e

if [[ "$QEMU_STATUS" -ne 124 && "$QEMU_STATUS" -ne 0 ]]; then
  echo "QEMU exited unexpectedly with status $QEMU_STATUS ($PROFILE)." >&2
  cat "$LOG" >&2
  exit 1
fi

if ! grep -Eiq 'Reached target (Graphical Interface|Multi-User System)|login:' "$LOG"; then
  echo "No completed userspace boot marker detected for profile: $PROFILE" >&2
  tail -n 100 "$LOG" >&2
  exit 1
fi

echo "QEMU userspace boot marker detected for profile: $PROFILE"
grep -Ei 'Reached target (Graphical Interface|Multi-User System)|login:' "$LOG" | tail -n 5
