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

# Keep the local bridge opt-in; no systemd unit or autostart entry is installed.
systemctl set-default graphical.target
systemctl enable lightdm
