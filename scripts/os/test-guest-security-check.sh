#!/usr/bin/env bash
# Exercise the read-only guest checker with isolated command doubles.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$ROOT_DIR/scripts/os/guest-security-check.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/sysctl" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == "-n" && $# -eq 2 ]] || exit 2
key="$2"
if [[ "${CYBERLAB_TEST_BAD_KEY:-}" == "$key" ]]; then
  echo 99
  exit 0
fi
case "$key" in
  kernel.kptr_restrict) echo 2 ;;
  kernel.dmesg_restrict) echo 1 ;;
  kernel.yama.ptrace_scope) echo 1 ;;
  kernel.unprivileged_bpf_disabled) echo 1 ;;
  fs.suid_dumpable) echo 0 ;;
  fs.protected_hardlinks|fs.protected_symlinks) echo 1 ;;
  net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.send_redirects|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_source_route|net.ipv6.conf.all.accept_redirects|net.ipv6.conf.default.accept_redirects|net.ipv6.conf.all.accept_source_route) echo 0 ;;
  *) exit 3 ;;
esac
MOCK
cat > "$tmp/systemctl" <<'MOCK'
#!/usr/bin/env bash
# The bridge is not active in this isolated test environment.
exit 1
MOCK
cat > "$tmp/dpkg-query" <<'MOCK'
#!/usr/bin/env bash
echo "unknown ok not-installed"
MOCK
chmod +x "$tmp/"*

success_log="$tmp/success.log"
PATH="$tmp:$PATH" bash "$CHECKER" >"$success_log"
grep -q 'Guest security checks passed.' "$success_log"
grep -q 'PASS CyberLab bridge is not active' "$success_log"

failure_log="$tmp/failure.log"
if PATH="$tmp:$PATH" CYBERLAB_TEST_BAD_KEY=kernel.kptr_restrict bash "$CHECKER" >"$failure_log" 2>&1; then
  echo "Guest checker accepted an incorrect kernel setting." >&2
  exit 1
fi
grep -q 'FAIL kernel.kptr_restrict expected=2 actual=99' "$failure_log"
grep -q 'Guest security check failed: 1 issue(s).' "$failure_log"
echo "Guest security checker behavior tests passed."
