#!/usr/bin/env bash
set -euo pipefail
# Run as root on a fresh Ubuntu 24.04 VPS. TLS is expected at a reverse proxy.
apt-get update
apt-get install -y python3 python3-venv python3-pip
id cyberlab-gateway >/dev/null 2>&1 || useradd --system --home /var/lib/cyberlab-gateway --create-home --shell /usr/sbin/nologin cyberlab-gateway
install -d -o cyberlab-gateway -g cyberlab-gateway -m 0750 /opt/cyberlab-gateway /var/lib/cyberlab-gateway/files
python3 -m venv /opt/cyberlab-gateway/venv
/opt/cyberlab-gateway/venv/bin/pip install --upgrade pip
/opt/cyberlab-gateway/venv/bin/pip install -r requirements.txt
install -m 0640 -o root -g cyberlab-gateway .env.example /etc/cyberlab-gateway.env.example
echo "Gateway files are prepared. Configure /etc/cyberlab-gateway.env with a unique owner token, install a TLS reverse proxy, then create the systemd service."
