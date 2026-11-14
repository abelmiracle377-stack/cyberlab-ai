# CyberLab AI OS (VM edition)

CyberLab AI OS is a dedicated, bootable workstation image built on Debian 13. It is a separate delivery target: it does not replace the hosted CyberLab application or the existing Kali companion.

## Current implementation status

- VM build definition: `scripts/os/build-vm.sh`
- Guest provisioning: `scripts/os/provision-vm.sh`
- Image validation: `scripts/os/verify-vm.sh`
- Reproducible build workflow: `.github/workflows/build-os-vm.yml`
- Default output: `dist/cyberlab-ai-os-amd64.qcow2`

The build uses the official Debian 13 libguestfs appliance template and produces a QEMU/KVM QCOW2 disk. It installs an XFCE desktop, Firefox ESR, Python, Git and a curated set of security/forensics tools, then places the repository's existing Kali companion under `/opt/cyberlab-ai`. The companion is not automatically started, and the bridge remains loopback-only and token-paired.

**A successful build is not proof of a successful boot.** The build workflow validates the disk structure and guest configuration. A real QEMU boot smoke test is a separate acceptance gate and must be recorded before calling the VM boot-verified.

## Build locally (Debian/Ubuntu host)

Requirements: QEMU utilities, libguestfs tools, and a Debian 13 template supported by `virt-builder`.

```bash
sudo apt update
sudo apt install -y libguestfs-tools qemu-utils
```

Set a strong local password for the non-root `cyberlab` desktop account. The build script reads it from the environment and writes it to a temporary owner-only file; it is not committed to the repository.

```bash
read -rsp "CyberLab VM password: " CYBERLAB_VM_PASSWORD
export CYBERLAB_VM_PASSWORD
echo
./scripts/os/build-vm.sh
unset CYBERLAB_VM_PASSWORD
```

The script refuses to overwrite an existing image. Output is a sparse QCOW2 image; actual allocated size depends on installed packages and filesystem use.

## Run with QEMU

```bash
qemu-system-x86_64 \
  -enable-kvm -m 4096 -smp 2 \
  -drive file=dist/cyberlab-ai-os-amd64.qcow2,if=virtio,format=qcow2 \
  -nic user,model=virtio-net-pci \
  -display gtk
```

On hosts without KVM, remove `-enable-kvm` (performance will be slower). The default account is `cyberlab`; use the password supplied at build time. Change it after first login.

## Verify

```bash
./scripts/os/verify-vm.sh dist/cyberlab-ai-os-amd64.qcow2
```

The verifier checks the QCOW2 container and its virtual disk metadata. It does not boot the VM or prove every installed application works.

## Safety and boundaries

- No inbound network service is enabled by the image build.
- The local bridge is not enabled as a system service and is not started automatically.
- No generic unrestricted shell or unattended exploitation workflow is added.
- Tools are installed as workstation utilities; use active assessment only with explicit written authorisation and the existing CyberLab scope/approval controls.
- No credentials, API keys, personal data or host directories are baked into the image.
- The VM uses QEMU user-mode networking by default; do not expose guest services to untrusted networks.
- This is a Debian-based CyberLab workstation, not an anonymity OS and not an official Kali Linux distribution.

## Resource guidance

The initial VM profile targets 4 GB RAM, 2 vCPUs and a 24 GB virtual disk. The guest can be adjusted in QEMU to suit the host. A machine with 4 GB total physical RAM may struggle to run both the host desktop and this guest simultaneously; use a lighter host workload or increase memory where possible.
