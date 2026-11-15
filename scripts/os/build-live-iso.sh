#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PROFILE="${1:-desktop}"
OUTPUT_DIR="${2:-${ROOT_DIR}/dist}"
case "$PROFILE" in
  desktop|terminal) ;;
  *) echo "Usage: $0 desktop|terminal [output-directory]" >&2; exit 2 ;;
esac
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (for example: sudo $0 $PROFILE)." >&2
  exit 2
fi
for tool in lb debootstrap xorriso mksquashfs; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing build dependency: $tool" >&2; exit 2; }
done

WORK_ROOT="${CYBERLAB_OS_WORKDIR:-/var/tmp/cyberlab-ai-os-build}"
WORK_DIR="${WORK_ROOT}/${PROFILE}"
OUTPUT_NAME="cyberlab-ai-os-${PROFILE}-amd64.iso"
mkdir -p "$WORK_ROOT" "$OUTPUT_DIR"
# Resolve caller-supplied paths before changing into the live-build tree.
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
WORK_ROOT="$(cd "$WORK_ROOT" && pwd -P)"
WORK_DIR="${WORK_ROOT}/${PROFILE}"
# This script runs as root: only clean a dedicated work tree outside the
# repository and output directory. Reject nested paths, not just exact matches.
if [[ "$WORK_ROOT" == "/" || "$WORK_ROOT" == "$ROOT_DIR" || "$WORK_ROOT" == "$OUTPUT_DIR" ]]; then
  echo "Unsafe build work directory: $WORK_ROOT" >&2
  exit 2
fi
case "$WORK_ROOT/" in
  "$ROOT_DIR/"*)
    echo "Build work directory must not be inside the repository: $WORK_ROOT" >&2
    exit 2
    ;;
esac
case "$OUTPUT_DIR/" in
  "$WORK_DIR/"*)
    echo "Output directory must not be inside the profile work directory: $OUTPUT_DIR" >&2
    exit 2
    ;;
esac
if [[ -e "${OUTPUT_DIR}/${OUTPUT_NAME}" ]]; then
  echo "Refusing to overwrite existing ISO: ${OUTPUT_DIR}/${OUTPUT_NAME}" >&2
  exit 2
fi
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/config/package-lists" "$WORK_DIR/config/includes.chroot/opt/cyberlab-ai" "$WORK_DIR/config/includes.chroot/usr/local/lib/cyberlab" "$WORK_DIR/config/includes.chroot/usr/local/sbin" "$WORK_DIR/config/archives" "$WORK_DIR/config/hooks/normal"

printf '%s\n' "deb http://security.debian.org/debian-security trixie-security main contrib non-free-firmware" > "$WORK_DIR/config/archives/cyberlab-security.list.chroot"
printf '%s\n' "deb http://security.debian.org/debian-security trixie-security main contrib non-free-firmware" > "$WORK_DIR/config/archives/cyberlab-security.list.binary"
cp "${ROOT_DIR}/os/profiles/${PROFILE}.packages" "$WORK_DIR/config/package-lists/cyberlab.list.chroot"
cp -a "${ROOT_DIR}/kali-companion" "$WORK_DIR/config/includes.chroot/opt/cyberlab-ai/"
cp "${ROOT_DIR}/scripts/os/cyberlab-menu.py" "$WORK_DIR/config/includes.chroot/usr/local/lib/cyberlab/menu.py"
install -m 0755 "${ROOT_DIR}/scripts/os/guest-security-check.sh" "$WORK_DIR/config/includes.chroot/usr/local/sbin/cyberlab-guest-security-check"
cp "${ROOT_DIR}/scripts/os/live-configure.chroot" "$WORK_DIR/config/hooks/normal/0100-cyberlab-configure.hook.chroot"
chmod 0755 "$WORK_DIR/config/hooks/normal/0100-cyberlab-configure.hook.chroot"

cd "$WORK_DIR"
lb config \
  --mode debian \
  --distribution trixie \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --debian-installer live \
  --archive-areas "main contrib non-free-firmware" \
  --security false \
  --bootappend-live "boot=live components username=cyberlab hostname=cyberlab-ai locales=en_US.UTF-8 keyboard-layouts=us console=ttyS0,115200n8 loglevel=4 systemd.show_status=1" \
  --apt-recommends false \
  --iso-application "CyberLab AI OS" \
  --iso-volume "CYBERLAB_AI_OS"

lb build
ISO_PATH="$(find "$WORK_DIR" -maxdepth 1 -type f -name '*.iso' -print -quit)"
[[ -n "$ISO_PATH" && -s "$ISO_PATH" ]] || { echo "live-build completed without an ISO output." >&2; exit 1; }
install -m 0644 "$ISO_PATH" "${OUTPUT_DIR}/${OUTPUT_NAME}"
sha256sum "${OUTPUT_DIR}/${OUTPUT_NAME}" | tee "${OUTPUT_DIR}/${OUTPUT_NAME}.sha256"
echo "Created ${OUTPUT_DIR}/${OUTPUT_NAME}"
echo "This is an ISO build result; perform the documented QEMU boot test before declaring it boot-verified."
