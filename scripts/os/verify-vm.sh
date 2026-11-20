#!/usr/bin/env bash
set -Eeuo pipefail
IMAGE="${1:-dist/cyberlab-ai-os-amd64.qcow2}"
command -v qemu-img >/dev/null 2>&1 || { echo "qemu-img is required." >&2; exit 2; }
[[ -f "$IMAGE" && ! -L "$IMAGE" ]] || { echo "Image must be an existing regular file (not a symlink): $IMAGE" >&2; exit 2; }
FORMAT="$(qemu-img info --output=json "$IMAGE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format", ""))')"
[[ "$FORMAT" == "qcow2" ]] || { echo "Expected qcow2, found: $FORMAT" >&2; exit 1; }
qemu-img check "$IMAGE"
qemu-img info "$IMAGE"
echo "STRUCTURAL CHECK PASSED. This does not constitute a VM boot test."
