#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/dist"
OUTPUT="${OUTPUT_DIR}/cyberlab-ai-os-amd64.qcow2"
PASSWORD_FILE=""
cleanup() {
  if [[ -n "${PASSWORD_FILE}" && -f "${PASSWORD_FILE}" ]]; then
    shred -u "${PASSWORD_FILE}" 2>/dev/null || rm -f "${PASSWORD_FILE}"
  fi
}
trap cleanup EXIT

if [[ -z "${CYBERLAB_VM_PASSWORD:-}" ]]; then
  echo "Set CYBERLAB_VM_PASSWORD to a strong password for the cyberlab account." >&2
  exit 2
fi
if [[ "${CYBERLAB_VM_PASSWORD}" == *$'\n'* || "${CYBERLAB_VM_PASSWORD}" == *$'\r'* ]]; then
  echo "Password must be a single line." >&2
  exit 2
fi
for tool in virt-builder qemu-img; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 2; }
done
mkdir -p "$OUTPUT_DIR"
if [[ -e "$OUTPUT" ]]; then
  echo "Refusing to overwrite existing image: $OUTPUT" >&2
  exit 2
fi

PASSWORD_FILE="$(mktemp)"
chmod 0600 "$PASSWORD_FILE"
printf '%s' "$CYBERLAB_VM_PASSWORD" >"$PASSWORD_FILE"
unset CYBERLAB_VM_PASSWORD

# Debian 13 is the pinned guest family. virt-builder verifies the appliance
# template metadata; no third-party prebuilt CyberLab image is downloaded.
virt-builder debian-13 \
  --arch x86_64 \
  --format qcow2 \
  --size 24G \
  --hostname cyberlab-ai \
  --timezone UTC \
  --install "xfce4,xfce4-terminal,lightdm,dbus-x11,firefox-esr,sudo,git,ca-certificates,curl,wget,python3,python3-venv,python3-pip,nmap,wireshark,tshark,tcpdump,testdisk,sleuthkit,foremost,gddrescue,yara,binutils,gdb,file,jq,unzip,xz-utils" \
  --run-command "id cyberlab >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --groups sudo,audio,video,plugdev cyberlab" \
  --password "cyberlab:file:${PASSWORD_FILE}" \
  --copy-in "${ROOT_DIR}/kali-companion:/opt/cyberlab-ai/" \
  --run-script "${ROOT_DIR}/scripts/os/provision-vm.sh" \
  --firstboot-command "passwd -e cyberlab" \
  --output "$OUTPUT"

qemu-img check "$OUTPUT"
qemu-img info --output=json "$OUTPUT"
echo "VM disk created: $OUTPUT"
echo "This build has not been boot-tested. Follow os/README.md for the QEMU boot acceptance check."
