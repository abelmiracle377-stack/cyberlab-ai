#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash install-ubuntu.sh"
  exit 1
fi
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/cyberlab-gateway"
STATE_DIR="/var/lib/cyberlab-gateway"
ENV_FILE="/etc/cyberlab-gateway.env"

apt-get update
apt-get install -y python3 python3-venv python3-pip

id cyberlab-gateway >/dev/null 2>&1 || useradd --system --home-dir "${STATE_DIR}" --create-home --shell /usr/sbin/nologin cyberlab-gateway
install -d -o root -g root -m 0755 "${APP_DIR}"
install -d -o cyberlab-gateway -g cyberlab-gateway -m 0750 "${STATE_DIR}" "${STATE_DIR}/files"
install -m 0644 "${SOURCE_DIR}/app.py" "${APP_DIR}/app.py"
install -m 0644 "${SOURCE_DIR}/consent.html" "${APP_DIR}/consent.html"
install -m 0644 "${SOURCE_DIR}/requirements.txt" "${APP_DIR}/requirements.txt"

python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --disable-pip-version-check -r "${APP_DIR}/requirements.txt"

if [[ ! -f "${ENV_FILE}" ]]; then
  OWNER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  cat > "${ENV_FILE}" <<EOF
CYBERLAB_OWNER_TOKEN=${OWNER_TOKEN}
CYBERLAB_GATEWAY_DB=${STATE_DIR}/registry.sqlite3
CYBERLAB_GATEWAY_FILES=${STATE_DIR}/files
EOF
  chmod 0640 "${ENV_FILE}"
  chown root:cyberlab-gateway "${ENV_FILE}"
  echo "Generated a unique owner token in ${ENV_FILE}; retrieve it securely for option 9."
else
  echo "Keeping existing gateway environment file."
fi

cat > /etc/systemd/system/cyberlab-gateway.service <<EOF
[Unit]
Description=CyberLab Personal VPS Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cyberlab-gateway
Group=cyberlab-gateway
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${STATE_DIR}
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cyberlab-gateway
systemctl --no-pager --full status cyberlab-gateway || true

echo
echo "Gateway service listens on 127.0.0.1:8000 only."
echo "Next: configure a TLS reverse proxy for your domain to proxy to http://127.0.0.1:8000."
echo "Do not expose port 8000 directly to the internet. Allow public HTTPS only after TLS is configured."
