# CyberLab AI OS

CyberLab AI OS is being developed as a Debian-based security distribution, not merely a desktop VM image. It has two install/live profiles built from the same source tree:

- **Desktop** — XFCE graphical workstation, browser, terminal, CyberLab companion and curated security/forensics utilities.
- **Terminal** — lighter command-line environment for lower-resource computers, with the same CyberLab command entry point and a focused set of CLI security/forensics tools.

Both profiles are amd64 hybrid ISOs intended for bootable USB media and virtual machines. The existing hosted CyberLab web application and Kali companion remain separate, preserved products integrated into this OS build.

## Build architecture

- Debian 13 (Trixie) base, built with Debian `live-build`.
- Profile package manifests: `os/profiles/desktop.packages` and `os/profiles/terminal.packages`.
- Shared guest customisation: `scripts/os/live-configure.chroot`.
- Reproducible ISO builder: `scripts/os/build-live-iso.sh`.
- Manual GitHub Actions build: [Build CyberLab AI OS Live ISOs](../.github/workflows/build-os-vm.yml).

The ISO build uses Debian package repositories. No credentials, API keys, host directories or personal data are embedded. The local companion bridge is not enabled as a service and never starts automatically.

## Build locally

Use a Debian/Ubuntu amd64 build host with internet access and sufficient disk space (allow at least 25 GB free for build working files and outputs).

```bash
sudo apt update
sudo apt install -y live-build debootstrap xorriso squashfs-tools grub-pc-bin grub-efi-amd64-bin mtools isolinux syslinux-common
chmod +x scripts/os/*.sh
sudo ./scripts/os/build-live-iso.sh desktop ./dist
sudo ./scripts/os/build-live-iso.sh terminal ./dist
```

Expected outputs:

- `dist/cyberlab-ai-os-desktop-amd64.iso`
- `dist/cyberlab-ai-os-desktop-amd64.iso.sha256`
- `dist/cyberlab-ai-os-terminal-amd64.iso`
- `dist/cyberlab-ai-os-terminal-amd64.iso.sha256`

The builder refuses to overwrite existing output ISOs. It uses an isolated working directory under `/var/tmp/cyberlab-ai-os-build` by default; set `CYBERLAB_OS_WORKDIR` to change it.

## Build through GitHub Actions

Open the repository Actions page, select **Build CyberLab AI OS Live ISOs**, and choose **Run workflow**. The workflow builds both profiles and uploads the ISO files and checksums as a short-retention artifact.

This workflow is manual so normal web/companion CI does not incur the cost of building multi-gigabyte operating-system images.

## Boot from USB or in a VM

Verify the downloaded ISO against its SHA-256 file before use. To test with QEMU:

```bash
qemu-system-x86_64 -m 4096 -smp 2 -boot d \
  -cdrom dist/cyberlab-ai-os-desktop-amd64.iso \
  -nic user,model=virtio-net-pci
```

For the terminal profile, replace the ISO filename. For a persistent USB, use a dedicated USB-writing utility and select the correct removable drive carefully; writing an ISO destroys existing contents on the selected USB device.

## Safer QEMU defaults

Start with an isolated, disposable live session: no guest network interface, no host folders, no USB passthrough, and no persistent writable disk.

```bash
qemu-system-x86_64 -m 2048 -smp 2 -boot d -no-user-config -nic none -snapshot -cdrom dist/cyberlab-ai-os-terminal-amd64.iso
```

For desktop, use its ISO and allocate 4096 MB only when the host has enough spare memory. On a machine with 4 GB total RAM, prefer terminal profile or boot the ISO directly rather than running a desktop VM beside the host desktop.

If a lab explicitly requires guest internet access, opt into QEMU user-mode networking without host port forwards:

```bash
qemu-system-x86_64 -m 2048 -smp 2 -boot d -no-user-config -nic user,model=virtio-net-pci -snapshot -cdrom dist/cyberlab-ai-os-terminal-amd64.iso
```

User-mode networking provides outbound guest networking; it is not a bridge to the physical LAN. Keep evidence and untrusted samples inside the disposable guest. Avoid shared folders, clipboard integration, USB passthrough, and host device access unless the specific lab requires them and the risks are understood. Snapshot mode keeps guest writes temporary; it does not protect the host or hypervisor from guest vulnerabilities.

## Runtime guest security verification

The live ISO includes `/usr/local/sbin/cyberlab-guest-security-check`, a read-only check for the guest kernel/network defaults, SSH-server absence, and bridge service state. Run it after boot:

```bash
sudo /usr/local/sbin/cyberlab-guest-security-check
```

A passing result checks the live values on that boot; it does not prove host/hypervisor security or replace the broader boot acceptance checklist.

## Boot acceptance checklist

A successful ISO build is not the same as a boot-tested OS. Before marking a release boot-verified, test both profiles in QEMU/KVM:

1. ISO boots to the expected desktop or terminal login.
2. Live user `cyberlab` is created by live-config.
3. Network interface can be brought up.
4. `cyberlab --help` runs and lists companion commands.
5. Desktop profile launches its graphical session.
6. Terminal profile remains usable without a graphical desktop.
7. No bridge, scan, exploit, capture or other active assessment starts automatically.
8. Reboot and shutdown work cleanly.

Record the QEMU version, host architecture, ISO SHA-256, boot profile and test result. Do not call an image boot-verified until these checks have actually passed.

## Resource targets

- Desktop profile: target 4 GB RAM, 2 vCPUs and 20 GB virtual disk.
- Terminal profile: target 1–2 GB RAM, 1 vCPU and 12 GB virtual disk.

These are initial design targets, not benchmark guarantees. A host with only 4 GB total physical RAM should prefer the terminal profile or boot the desktop ISO directly rather than running a desktop VM alongside its own desktop.

## Guest security hardening

The live guest applies a conservative baseline through /etc/sysctl.d/99-cyberlab-hardening.conf:

- Restricts kernel pointer and dmesg disclosure and limits ptrace to the normal same-user policy (kernel.yama.ptrace_scope=1).
- Disables unprivileged BPF and set-user-ID core dumps; enables protected symlink and hardlink handling.
- Disables IPv4/IPv6 redirect acceptance and source routing, and disables IPv4 redirect transmission.
- Disables core dumps through a hard user limit and sets a default shell umask of 027 for newly created files.
- Does not install an SSH server, enable remote login, start the companion bridge, or launch scans at boot.

These are guest-level defaults, not a substitute for securing the host, hypervisor, VM management interface, or physical evidence media. The baseline intentionally does not disable networking, packet capture, debuggers, or authorised lab tooling. Review kernel settings against specialised lab requirements before production use.

## Safety and limitations

- CyberLab AI OS is a Debian-based security distribution, not an official Kali or Parrot release.
- No anonymity, VPN, anti-forensics or endpoint-protection claims are made.
- Security utilities are provided for authorised research; the OS does not grant permission to assess third-party systems.
- The companion bridge is opt-in, loopback-only and token-paired.
- No generic unrestricted shell is exposed to a hosted model; local actions remain governed by companion allowlists and approval gates.
- The desktop currently opens the existing hosted CyberLab workspace through a browser; a fully offline native agent UI is a separate development milestone.

## Secondary VM disk prototype

The earlier `build-vm.sh` / `build-os-vm.yml` QCOW2 path is retained as a secondary prototype, not the primary OS distribution. The live ISO is the canonical distribution target. A QCOW2 image should be generated from and boot-tested against the same released ISO in a later packaging phase.
