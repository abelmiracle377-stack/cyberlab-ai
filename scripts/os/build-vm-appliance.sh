#!/usr/bin/env bash
# Build a prebuilt, importable VM appliance (VirtualBox/VMware) of CyberLab AI OS.
# Reuses the same live-build chroot as the ISO but emits a bootable disk image,
# then converts it to a stream-optimized VMDK and packages an OVA.
#
# Usage: sudo scripts/os/build-vm-appliance.sh desktop-lite|desktop|terminal [out-dir]
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PROFILE="${1:-desktop-lite}"
OUTPUT_DIR="${2:-${ROOT_DIR}/dist}"
case "$PROFILE" in desktop-lite|desktop|terminal) ;; *) echo "Usage: $0 desktop-lite|desktop|terminal [out-dir]" >&2; exit 2;; esac
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root (sudo $0 $PROFILE)." >&2; exit 2; }
for tool in lb debootstrap qemu-img tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing build dependency: $tool" >&2; exit 2; }
done

HDD_SIZE_MB="${CYBERLAB_OS_HDD_SIZE_MB:-9000}"
WORK_ROOT="${CYBERLAB_OS_WORKDIR:-/var/tmp/cyberlab-ai-os-vm}"
WORK_DIR="${WORK_ROOT}/${PROFILE}"
BASENAME="cyberlab-ai-os-${PROFILE}-amd64"
mkdir -p "$WORK_ROOT" "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
WORK_ROOT="$(cd "$WORK_ROOT" && pwd -P)"
WORK_DIR="${WORK_ROOT}/${PROFILE}"
case "$WORK_ROOT/" in "$ROOT_DIR/"*) echo "Work dir must be outside the repo." >&2; exit 2;; esac
[[ "$WORK_ROOT" != "/" && "$WORK_ROOT" != "$OUTPUT_DIR" ]] || { echo "Unsafe work dir." >&2; exit 2; }
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/config/package-lists" \
         "$WORK_DIR/config/includes.chroot/opt/cyberlab-ai" \
         "$WORK_DIR/config/includes.chroot/usr/local/lib/cyberlab" \
         "$WORK_DIR/config/includes.chroot/usr/local/sbin" \
         "$WORK_DIR/config/archives" "$WORK_DIR/config/hooks/normal"

# --- Stage the same CyberLab guest customisation as the ISO build ---
SEC="deb http://security.debian.org/debian-security trixie-security main contrib non-free-firmware"
printf '%s\n' "$SEC" > "$WORK_DIR/config/archives/cyberlab-security.list.chroot"
printf '%s\n' "$SEC" > "$WORK_DIR/config/archives/cyberlab-security.list.binary"
cp "${ROOT_DIR}/os/profiles/${PROFILE}.packages" "$WORK_DIR/config/package-lists/cyberlab.list.chroot"
cp -a "${ROOT_DIR}/kali-companion" "$WORK_DIR/config/includes.chroot/opt/cyberlab-ai/"
cp "${ROOT_DIR}/scripts/os/cyberlab-menu.py" "$WORK_DIR/config/includes.chroot/usr/local/lib/cyberlab/menu.py"
install -m 0755 "${ROOT_DIR}/scripts/os/guest-security-check.sh" "$WORK_DIR/config/includes.chroot/usr/local/sbin/cyberlab-guest-security-check"
cp "${ROOT_DIR}/scripts/os/live-configure.chroot" "$WORK_DIR/config/hooks/normal/0100-cyberlab-configure.hook.chroot"
chmod 0755 "$WORK_DIR/config/hooks/normal/0100-cyberlab-configure.hook.chroot"

# --- Build a bootable HDD disk image (BIOS/syslinux) ---
cd "$WORK_DIR"
lb config \
  --mode debian \
  --distribution trixie \
  --initsystem systemd \
  --architectures amd64 \
  --binary-images hdd \
  --hdd-size "$HDD_SIZE_MB" \
  --archive-areas "main contrib non-free-firmware" \
  --security false \
  --bootappend-live "boot=live components username=cyberlab hostname=cyberlab-ai locales=en_US.UTF-8 keyboard-layouts=us" \
  --apt-recommends false
lb build

RAW="$(find "$WORK_DIR" -maxdepth 1 -type f -name '*.img' -print -quit)"
[[ -n "$RAW" && -s "$RAW" ]] || { echo "live-build produced no disk image." >&2; exit 1; }

# --- Convert to a VMware/VirtualBox-compatible disk + OVA appliance ---
VMDK="${BASENAME}.vmdk"
OVF="${BASENAME}.ovf"
MF="${BASENAME}.mf"
OVA="${BASENAME}.ova"
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "$RAW" "${OUTPUT_DIR}/${VMDK}"
CAP="$(qemu-img info -f raw "$RAW" | sed -n 's/.*(\([0-9]\+\) bytes).*/\1/p')"
[[ -n "$CAP" ]] || CAP=$(( HDD_SIZE_MB * 1024 * 1024 ))
POP="$(stat -c %s "${OUTPUT_DIR}/${VMDK}")"

cat > "${OUTPUT_DIR}/${OVF}" <<OVFEOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References><File ovf:href="${VMDK}" ovf:id="file1" ovf:size="${POP}"/></References>
  <DiskSection><Info>Virtual disk</Info>
    <Disk ovf:capacity="${CAP}" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection><Info>Networks</Info><Network ovf:name="NAT"><Description>NAT networking</Description></Network></NetworkSection>
  <VirtualSystem ovf:id="CyberLab-AI-OS-${PROFILE}">
    <Info>CyberLab AI OS ${PROFILE}</Info>
    <Name>CyberLab AI OS ${PROFILE}</Name>
    <OperatingSystemSection ovf:id="96"><Info>Debian 64-bit</Info><Description>Debian_64</Description></OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware</Info>
      <System><vssd:ElementName>Virtual Hardware Family</vssd:ElementName><vssd:InstanceID>0</vssd:InstanceID><vssd:VirtualSystemType>virtualbox-2.2</vssd:VirtualSystemType></System>
      <Item><rasd:Caption>2 virtual CPU</rasd:Caption><rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>2</rasd:VirtualQuantity></Item>
      <Item><rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits><rasd:Caption>2048 MB of memory</rasd:Caption><rasd:InstanceID>2</rasd:InstanceID><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>2048</rasd:VirtualQuantity></Item>
      <Item><rasd:Address>0</rasd:Address><rasd:Caption>sataController0</rasd:Caption><rasd:InstanceID>3</rasd:InstanceID><rasd:ResourceSubType>AHCI</rasd:ResourceSubType><rasd:ResourceType>20</rasd:ResourceType></Item>
      <Item><rasd:Caption>disk1</rasd:Caption><rasd:HostResource>/disk/vmdisk1</rasd:HostResource><rasd:InstanceID>4</rasd:InstanceID><rasd:Parent>3</rasd:Parent><rasd:ResourceType>17</rasd:ResourceType></Item>
      <Item><rasd:AutomaticAllocation>true</rasd:AutomaticAllocation><rasd:Caption>Ethernet</rasd:Caption><rasd:Connection>NAT</rasd:Connection><rasd:InstanceID>5</rasd:InstanceID><rasd:ResourceSubType>E1000</rasd:ResourceSubType><rasd:ResourceType>10</rasd:ResourceType></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVFEOF

( cd "$OUTPUT_DIR"
  {
    printf 'SHA256(%s)= %s\n' "$OVF" "$(sha256sum "$OVF" | cut -d' ' -f1)"
    printf 'SHA256(%s)= %s\n' "$VMDK" "$(sha256sum "$VMDK" | cut -d' ' -f1)"
  } > "$MF"
  tar -cf "$OVA" "$OVF" "$MF" "$VMDK"
  sha256sum "$OVA" "$VMDK" | tee "${BASENAME}.appliance.sha256"
)
echo "Created ${OUTPUT_DIR}/${OVA} and ${OUTPUT_DIR}/${VMDK}"
echo "Import the .ova into VirtualBox/VMware, or attach the .vmdk to a new VM. BIOS boot."
