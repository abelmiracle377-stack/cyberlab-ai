# Installing CyberLab AI OS in VirtualBox / VMware

CyberLab AI OS ships as prebuilt images on the
[latest release](https://github.com/abelmiracle377-stack/cyberlab-ai/releases/latest).
This guide covers the VirtualBox/VMware **appliance (OVA)**, the bare **VMDK**
disk, and booting the **ISO** directly. Pick one.

| You want… | Download | Method |
| --- | --- | --- |
| One-click import | `cyberlab-ai-os-desktop-lite-amd64.ova` | Import Appliance (VirtualBox) / Open (VMware) |
| Build your own VM from a disk | `cyberlab-ai-os-desktop-lite-amd64.vmdk` | New 64-bit Debian VM, attach disk |
| Run on real hardware, or a clean VM | `cyberlab-ai-os-desktop-lite-amd64.iso` | New VM, attach ISO, boot |

## 0. Verify the download first

```bash
# From the folder where you downloaded the image and the checksum file:
sha256sum --check --ignore-missing APPLIANCE-SHA256SUMS   # for .ova / .vmdk
sha256sum --check --ignore-missing SHA256SUMS             # for .iso
```

Only continue if the file you downloaded reports `OK`.

## 1a. VirtualBox — import the OVA

1. **File → Import Appliance…**
2. Choose `cyberlab-ai-os-desktop-lite-amd64.ova` and click **Next**.
3. Review the settings. The appliance defaults to ~2 vCPU / 2048 MB RAM — raise
   RAM to 4096 MB if your host has room. Keep the firmware as **BIOS**.
4. Click **Finish**, then **Start** the VM.

## 1b. VMware (Workstation / Player / Fusion) — open the OVA

1. **File → Open…** and select `cyberlab-ai-os-desktop-lite-amd64.ova`.
2. Give the VM a name and location, then **Import**. If VMware warns about OVF
   specification compliance, choose **Retry** (relaxed import) — the appliance
   imports and boots.
3. Power on the VM.

## 1c. Use the bare VMDK instead

1. Create a **New VM**: guest type **Linux → Debian 12/13 64-bit**, firmware
   **BIOS** (not EFI).
2. When asked about a disk, choose **use an existing disk** and select
   `cyberlab-ai-os-desktop-lite-amd64.vmdk` as the primary disk.
3. Allocate 2+ vCPU and 2–4 GB RAM, then boot.

## 1d. Boot the ISO (physical hardware or a fresh VM)

- **VM:** create a new 64-bit Debian VM, attach the `.iso` as the optical drive,
  and boot. No appliance import needed.
- **USB / hardware:** write the `.iso` to a USB stick with a dedicated imaging
  tool (e.g. balenaEtcher, Rufus in DD mode, or `dd`). Writing destroys existing
  contents on the target device — select it carefully.

## 2. First boot

- The XFCE desktop logs in automatically as the **`cyberlab`** live user.
- `sudo` works in the live session without a password. To set one:
  `sudo passwd cyberlab`.
- Networking is **NAT** by default (outbound internet, not reachable from the
  LAN). Change the adapter mode in your hypervisor if a lab needs bridged
  access.
- Changes are **not persistent** in the live session — a reboot returns a clean
  state. Use your hypervisor's snapshot feature to checkpoint work, or the
  `qcow2` build path for a persistent installed guest.

## 3. Run the CyberLab tools

- Open **CyberLab Terminal** from the applications menu, or run `cyberlab` in any
  terminal to open the companion menu.
- The companion bridge is **opt-in** and never starts on its own. Start it only
  when you intend to pair it, then connect the web app to it on
  `http://127.0.0.1:8765` using the token it prints.
- After boot you can run the read-only guest check:
  `sudo /usr/local/sbin/cyberlab-guest-security-check`.

## 4. Recommended safe defaults

- Keep untrusted samples and evidence **inside** the guest; avoid shared
  folders, clipboard sharing and USB passthrough unless a specific task needs
  them.
- Snapshot before risky work so you can roll back.
- Give the VM only the resources it needs; on a 4 GB host prefer the `terminal`
  edition or boot the ISO directly rather than a desktop VM beside your host
  desktop.

## Authorized use

CyberLab AI OS and its tools are for work you are authorized to do — systems you
own, lab environments, and engagements with written permission. It is not for
attacking systems you do not control.
