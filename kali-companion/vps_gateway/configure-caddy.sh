#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash configure-caddy.sh"
  exit 1
fi

if ! systemctl is-active --quiet cyberlab-gateway; then
  echo "CyberLab gateway is not active. Install/start it first with install-ubuntu.sh."
  exit 1
fi

read -r -p "Domain for this VPS gateway (for example gateway.example.com): " DOMAIN
DOMAIN="${DOMAIN,,}"
if [[ ! "${DOMAIN}" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
  echo "Invalid public DNS hostname."
  exit 1
fi

echo
echo "Before continuing, ensure this domain's A/AAAA record points to this VPS."
echo "Caddy will request and renew a public TLS certificate automatically."
read -r -p "Have you pointed the domain to this VPS? Type YES to continue: " CONFIRM
if [[ "${CONFIRM}" != "YES" ]]; then
  echo "No changes made. Update DNS first, then rerun this script."
  exit 1
fi

apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor --yes -o /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
chmod 0644 /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  -o /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy

install -d -m 0755 /etc/caddy
if [[ -f /etc/caddy/Caddyfile ]]; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup.$(date -u +%Y%m%dT%H%M%SZ)"
fi
cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000
    header {
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        -Server
    }
}
EOF

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi

systemctl enable --now caddy
systemctl reload caddy
echo
echo "Caddy is configured for https://${DOMAIN}"
echo "Gateway remains bound to 127.0.0.1:8000; do not open port 8000 publicly."
echo "Check certificate/service status with: sudo journalctl -u caddy -n 50 --no-pager"
echo "Test gateway with: curl -fsS https://${DOMAIN}/health"
