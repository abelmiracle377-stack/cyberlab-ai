#!/usr/bin/env bash
# Package the CyberLab AI OS build kit (profiles + build docs + companion) into a
# distributable tarball. The multi-GB VM image itself is produced by the build
# pipeline on a builder host; this bundle is what you run to produce it.
# Usage: scripts/package-os-builder.sh [output-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
STAGE="$(mktemp -d)"
PKG="$STAGE/cyberlab-os-builder"
mkdir -p "$PKG" "$OUT"

[ -d "$ROOT/os" ] && cp -r "$ROOT/os" "$PKG/os"
[ -d "$ROOT/scripts/os" ] && { mkdir -p "$PKG/scripts"; cp -r "$ROOT/scripts/os" "$PKG/scripts/os"; }
[ -d "$ROOT/kali-companion" ] && cp -r "$ROOT/kali-companion" "$PKG/kali-companion"
[ -f "$ROOT/docs/CYBERLAB_OS_ARCHITECTURE.md" ] && { mkdir -p "$PKG/docs"; cp "$ROOT/docs/CYBERLAB_OS_ARCHITECTURE.md" "$PKG/docs/"; }

cat > "$PKG/README.md" <<'EOF'
# CyberLab AI OS — build kit

A Debian-based bootable security workstation bundled with the CyberLab companion.
A full VM image is several GB and is produced by the build pipeline on a builder
host (Debian live-build / an image builder), not shipped inside the app repo.

## Build a VM image

1. Read `docs/CYBERLAB_OS_ARCHITECTURE.md` and `os/README.md`.
2. Pick a profile from `os/profiles/` (terminal, desktop-lite, desktop).
3. Run the build scripts under `scripts/os/` on a Debian builder host.
4. The output is a bootable ISO / VM image (`.iso` / `.ova`) you can run in
   VirtualBox, VMware, QEMU/KVM or import into a cloud.

The companion (`kali-companion/`) is preinstalled so the web app can pair with
the OS over the loopback bridge.

See the full platform at https://github.com/abelmiracle377-stack/cyberlab-ai
EOF

VERSION="${OS_VERSION:-$(date +%Y.%m.%d)}"
echo "$VERSION" > "$PKG/VERSION"

tar -czf "$OUT/cyberlab-os-builder.tar.gz" -C "$STAGE" cyberlab-os-builder
rm -rf "$STAGE"
echo "Built $OUT/cyberlab-os-builder.tar.gz"
