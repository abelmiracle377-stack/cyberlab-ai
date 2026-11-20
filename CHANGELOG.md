# Changelog

All notable changes to CyberLab AI are recorded here. Versions follow
`MAJOR.MINOR.PATCH`. Each release tag (`v*`) builds the downloadable images on
GitHub's runners and attaches them to the matching GitHub Release.

## v0.1.0 — first standalone OS release

The headline of this release: **CyberLab AI OS is now a real, prebuilt,
standalone bootable operating system** — not a build kit. Download an image and
run it, the same way you would Kali or Parrot.

### CyberLab AI OS

- **Bootable ISO** (`cyberlab-ai-os-desktop-lite-amd64.iso`) — Debian 13
  (Trixie) based, XFCE desktop, hybrid BIOS + UEFI. Boots on physical hardware
  or in any VM by attaching it as an optical drive. **QEMU boot-tested in CI**
  (BIOS and UEFI) before publication. A `terminal` edition ISO is also built.
- **VirtualBox / VMware appliance** (`cyberlab-ai-os-desktop-lite-amd64.ova`) —
  a prebuilt, importable OVF 1.0 appliance. VirtualBox: *File → Import
  Appliance*. VMware: *Open* the `.ova`.
- **VMware disk** (`cyberlab-ai-os-desktop-lite-amd64.vmdk`) — the bare,
  stream-optimized virtual disk for building your own VM (64-bit Debian guest,
  BIOS firmware).
- **CyberLab tooling baked in** — the Kali companion ships at
  `/opt/cyberlab-ai/kali-companion`, with a `cyberlab` command-line launcher and
  a "CyberLab Terminal" desktop entry. The companion bridge is **opt-in and is
  never started automatically**.
- **Conservative guest hardening** — restricted kernel pointers/dmesg, YAMA
  ptrace scope, disabled unprivileged BPF, no core dumps, hardened sysctls, a
  private `umask 027`, plus a read-only `cyberlab-guest-security-check` you can
  run after boot. This hardens the guest; it does not replace host/hypervisor
  security.

### Platform

- **CyberSOC — standalone** (`cybersoc.tar.gz`) — the autonomous detection,
  correlation and response engine as a dependency-free, pure-Python download.
- **Kali companion** — the full toolkit remains intact: authorized Wi-Fi
  engagement (monitor mode, scan/audit, handshake & PMKID capture, WPA crack,
  WPS, wifite), Shodan OSINT, the Academy/CTF target, digital forensics, wallet
  recovery, native web assessment and the Burp connector.
- **Downloads surfaced in the app** — the dashboard (sidebar + module cards) and
  the `/os` page now link the real OS images and CyberSOC.

### Build & release

- The **Build CyberLab AI OS Live ISOs** workflow builds and QEMU boot-tests the
  ISOs, builds the VirtualBox/VMware appliances on a dedicated runner, and
  attaches every image — with `SHA256SUMS` and `APPLIANCE-SHA256SUMS` — to the
  release on a `v*` tag.

### Verifying downloads

Each release carries `SHA256SUMS` (ISOs) and `APPLIANCE-SHA256SUMS`
(OVA / VMDK / CyberSOC). After downloading, check an image against its line:

```bash
sha256sum --check --ignore-missing SHA256SUMS
sha256sum --check --ignore-missing APPLIANCE-SHA256SUMS
```

### Notes & known limitations

- The ISO and the live appliance boot a **live session** (changes are not
  persistent by default). For a persistent, traditionally installed guest, the
  `qcow2` path (`scripts/os/build-vm.sh`) remains available.
- The OVA/VMDK conversion path is new in this release; the ISO is the
  longest-tested, most reliable image and works directly in VirtualBox/VMware by
  attaching it to a new VM.

### Use responsibly

CyberLab is for authorized work only — systems you own, lab environments, and
engagements with written permission.
