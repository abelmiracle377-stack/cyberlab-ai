#!/usr/bin/env bash
set -Eeuo pipefail

ISO="${1:?Usage: uefi-smoke-test.sh path/to/image.iso [desktop-lite|desktop|terminal] [log-file]}"
PROFILE="${2:?Specify desktop-lite, desktop or terminal}"
LOG="${3:-}"

case "$PROFILE" in
  desktop-lite) EXPECTED_MARKER='Reached target .*Graphical Interface'; MEMORY_MB=2048; VCPUS=2; BOOT_TIMEOUT=600 ;;
  desktop) EXPECTED_MARKER='Reached target .*Graphical Interface'; MEMORY_MB=4096; VCPUS=2; BOOT_TIMEOUT=600 ;;
  terminal) EXPECTED_MARKER='Reached target .*Multi-User System|login:'; MEMORY_MB=1536; VCPUS=1; BOOT_TIMEOUT=240 ;;
  *) echo "Unknown profile: $PROFILE." >&2; exit 2 ;;
esac

command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "qemu-system-x86_64 is required." >&2; exit 2; }
[[ -f "$ISO" && -s "$ISO" && ! -L "$ISO" ]] || { echo "ISO must be a non-empty regular file." >&2; exit 2; }
[[ -d /usr/share/OVMF ]] || { echo "OVMF firmware directory not found; install the ovmf package." >&2; exit 2; }

OVMF_CODE=""
OVMF_VARS=""
for suffix in 4M 4M.ms standard; do
  case "$suffix" in
    4M) code=/usr/share/OVMF/OVMF_CODE_4M.fd; vars=/usr/share/OVMF/OVMF_VARS_4M.fd ;;
    4M.ms) code=/usr/share/OVMF/OVMF_CODE_4M.ms.fd; vars=/usr/share/OVMF/OVMF_VARS_4M.ms.fd ;;
    standard) code=/usr/share/OVMF/OVMF_CODE.fd; vars=/usr/share/OVMF/OVMF_VARS.fd ;;
  esac
  if [[ -s "$code" && -s "$vars" ]]; then OVMF_CODE="$code"; OVMF_VARS="$vars"; break; fi
done
[[ -n "$OVMF_CODE" ]] || { echo "No matching OVMF_CODE/OVMF_VARS firmware pair found." >&2; find /usr/share/OVMF -maxdepth 1 -type f -print >&2; exit 2; }

if [[ -z "$LOG" ]]; then
  LOG="$(mktemp)"
  CLEANUP_LOG=1
else
  mkdir -p "$(dirname "$LOG")"
  LOG_PARENT="$(cd "$(dirname "$LOG")" && pwd -P)"
  LOG="$LOG_PARENT/$(basename "$LOG")"
  [[ ! -e "$LOG" && ! -L "$LOG" ]] || { echo "Refusing to overwrite boot log: $LOG" >&2; exit 2; }
  CLEANUP_LOG=0
fi
VARS_COPY="$(mktemp)"
cp "$OVMF_VARS" "$VARS_COPY"
cleanup() {
  rm -f "$VARS_COPY"
  if [[ "$CLEANUP_LOG" -eq 1 ]]; then rm -f "$LOG"; fi
}
trap cleanup EXIT
umask 077

set +e
timeout --signal=TERM --kill-after=10s "${BOOT_TIMEOUT}s" qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -no-user-config \
  -m "$MEMORY_MB" -smp "$VCPUS" \
  -nic none \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$VARS_COPY" \
  -cdrom "$ISO" -boot order=d,menu=off \
  -snapshot \
  -display none -serial "file:$LOG" -monitor none \
  -no-reboot -no-shutdown
QEMU_STATUS=$?
set -e

if [[ "$QEMU_STATUS" -ne 124 && "$QEMU_STATUS" -ne 0 ]]; then
  echo "QEMU UEFI exited unexpectedly with status $QEMU_STATUS ($PROFILE)." >&2
  cat "$LOG" >&2
  exit 1
fi
if ! grep -Eiq "$EXPECTED_MARKER" "$LOG"; then
  echo "Expected $PROFILE userspace boot marker was not detected in UEFI mode." >&2
  if [[ -s "$LOG" ]]; then tail -n 100 "$LOG" >&2; else echo "UEFI serial log is empty." >&2; fi
  exit 1
fi

echo "QEMU UEFI $PROFILE userspace boot marker detected."
grep -Ei "$EXPECTED_MARKER" "$LOG" | tail -n 5
if [[ "$CLEANUP_LOG" -eq 0 ]]; then chmod 0600 "$LOG"; echo "UEFI serial boot log retained at $LOG"; fi
