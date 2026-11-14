#!/usr/bin/env bash
set -Eeuo pipefail

ISO="${1:?Usage: boot-smoke-test.sh path/to/cyberlab-ai-os-*.iso [desktop|terminal]}"
PROFILE="${2:?Specify the expected profile: desktop or terminal}"
LOG="${3:-}"
case "$PROFILE" in
  desktop) EXPECTED_MARKER='Reached target Graphical Interface' ;;
  terminal) EXPECTED_MARKER='Reached target Multi-User System|login:' ;;
  *) echo "Unknown profile: $PROFILE (expected desktop or terminal)." >&2; exit 2 ;;
esac
command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "qemu-system-x86_64 is required." >&2; exit 2; }
[[ -f "$ISO" && -s "$ISO" && ! -L "$ISO" ]] || { echo "ISO must be a non-empty regular file." >&2; exit 2; }

if [[ -z "$LOG" ]]; then
  LOG="$(mktemp)"
  CLEANUP_LOG=1
else
  LOG_PARENT="$(dirname "$LOG")"
  mkdir -p "$LOG_PARENT"
  LOG_PARENT="$(cd "$LOG_PARENT" && pwd -P)"
  LOG="$LOG_PARENT/$(basename "$LOG")"
  [[ ! -e "$LOG" && ! -L "$LOG" ]] || { echo "Refusing to overwrite boot log: $LOG" >&2; exit 2; }
  CLEANUP_LOG=0
fi
cleanup() {
  if [[ "$CLEANUP_LOG" -eq 1 ]]; then rm -f "$LOG"; fi
}
trap cleanup EXIT
umask 077

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

if ! grep -Eiq "$EXPECTED_MARKER" "$LOG"; then
  echo "Expected $PROFILE userspace boot marker was not detected." >&2
  tail -n 100 "$LOG" >&2
  exit 1
fi

echo "QEMU $PROFILE userspace boot marker detected."
grep -Ei "$EXPECTED_MARKER" "$LOG" | tail -n 5
if [[ "$CLEANUP_LOG" -eq 0 ]]; then
  chmod 0600 "$LOG"
  echo "Serial boot log retained at $LOG"
fi
