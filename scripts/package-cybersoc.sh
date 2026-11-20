#!/usr/bin/env bash
# Package the standalone CyberLab CyberSOC tool into a distributable tarball.
# Usage: scripts/package-cybersoc.sh [output-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
STAGE="$(mktemp -d)"
PKG="$STAGE/cybersoc"
mkdir -p "$PKG" "$OUT"

# Autonomous SOC engine + connectors (standard-library only).
for f in cybersoc.py soc_engine.py splunk_connector.py wazuh_connector.py \
         test_cybersoc.py test_soc_engine.py test_siic_connectors.py test_siem_connectors.py; do
  [ -f "$ROOT/kali-companion/$f" ] && cp "$ROOT/kali-companion/$f" "$PKG/" || true
done

cat > "$PKG/README.md" <<'EOF'
# CyberLab CyberSOC — standalone

Autonomous detection, correlation and response engine. Pure Python standard
library (no pip packages). Runs anywhere Python 3.10+ runs.

## Run

    python3 cybersoc.py --help
    python3 cybersoc.py              # run one detection+response cycle on host telemetry (dry run)
    python3 cybersoc.py --live       # allow authorized safe auto-response actions

## Test

    python3 -m unittest discover -p "test_*.py" -v

## Integrate

- `soc_engine.analyze(events, config)` — detection, scoring, ATT&CK mapping and
  union-find incident correlation. Supports threat-intel (IOC) matching and
  operator suppression rules via `config`.
- `splunk_connector` / `wazuh_connector` — pull alerts from your SIEM and
  normalise them into the engine's event shape.

See the full platform at https://github.com/abelmiracle377-stack/cyberlab-ai
EOF

cat > "$PKG/run.sh" <<'EOF'
#!/usr/bin/env bash
exec python3 "$(dirname "$0")/cybersoc.py" "$@"
EOF
chmod +x "$PKG/run.sh"

VERSION="${CYBERSOC_VERSION:-$(date +%Y.%m.%d)}"
echo "$VERSION" > "$PKG/VERSION"

tar -czf "$OUT/cybersoc.tar.gz" -C "$STAGE" cybersoc
rm -rf "$STAGE"
echo "Built $OUT/cybersoc.tar.gz"
