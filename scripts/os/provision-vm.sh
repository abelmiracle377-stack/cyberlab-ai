#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  xfce4 xfce4-terminal lightdm dbus-x11 \
  firefox-esr \
  sudo git ca-certificates curl wget \
  python3 python3-venv python3-pip \
  nmap wireshark tshark tcpdump \
  testdisk sleuthkit foremost gddrescue \
  yara binutils gdb file jq unzip xz-utils
apt-get clean
rm -rf /var/lib/apt/lists/*

if ! id cyberlab >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --groups sudo,audio,video,plugdev cyberlab
fi
install -d -o cyberlab -g cyberlab -m 0750 /home/cyberlab/Desktop
install -d -o root -g root -m 0755 /opt/cyberlab-ai
if [ -d /opt/cyberlab-ai/kali-companion ]; then
  chown -R root:root /opt/cyberlab-ai
  chmod -R go-w /opt/cyberlab-ai
fi

cat >/etc/motd <<'MOTD'
CyberLab AI OS — Debian-based security research workstation

Use only systems and evidence you are authorised to assess.
The local companion bridge is opt-in and is not started automatically.
MOTD

cat >/usr/local/bin/cyberlab-companion <<'LAUNCHER'
#!/usr/bin/env bash
set -Eeuo pipefail
exec python3 /opt/cyberlab-ai/kali-companion/cyberlab.py "$@"
LAUNCHER
chmod 0755 /usr/local/bin/cyberlab-companion

# Apply the same conservative guest baseline as the canonical live ISO.
install -d -m 0755 /etc/sysctl.d /etc/security/limits.d /etc/profile.d
cat >/etc/sysctl.d/99-cyberlab-hardening.conf <<'SYSCTL'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
SYSCTL
cat >/etc/security/limits.d/99-cyberlab-core.conf <<'LIMITS'
* hard core 0
LIMITS
cat >/etc/profile.d/99-cyberlab-umask.sh <<'UMASK'
# Restrict default permissions for newly created user files.
umask 027
UMASK
chmod 0644 /etc/sysctl.d/99-cyberlab-hardening.conf /etc/security/limits.d/99-cyberlab-core.conf /etc/profile.d/99-cyberlab-umask.sh

# Keep the local bridge opt-in; no systemd unit or autostart entry is installed.
systemctl set-default graphical.target
systemctl enable lightdm
