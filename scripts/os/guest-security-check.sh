#!/usr/bin/env bash
# Read-only runtime checks for a booted CyberLab AI OS guest.
set -Eeuo pipefail

failures=0
check_value() {
  local key="$1" expected="$2" actual
  if ! actual="$(sysctl -n "$key" 2>/dev/null)"; then
    echo "FAIL $key (unavailable)"
    failures=$((failures + 1))
  elif [[ "$actual" != "$expected" ]]; then
    echo "FAIL $key expected=$expected actual=$actual"
    failures=$((failures + 1))
  else
    echo "PASS $key=$actual"
  fi
}

for pair in \
  "kernel.kptr_restrict:2" \
  "kernel.dmesg_restrict:1" \
  "kernel.yama.ptrace_scope:1" \
  "kernel.unprivileged_bpf_disabled:1" \
  "fs.suid_dumpable:0" \
  "fs.protected_hardlinks:1" \
  "fs.protected_symlinks:1" \
  "net.ipv4.conf.all.accept_redirects:0" \
  "net.ipv4.conf.default.accept_redirects:0" \
  "net.ipv4.conf.all.send_redirects:0" \
  "net.ipv4.conf.default.send_redirects:0" \
  "net.ipv4.conf.all.accept_source_route:0" \
  "net.ipv4.conf.default.accept_source_route:0" \
  "net.ipv6.conf.all.accept_redirects:0" \
  "net.ipv6.conf.default.accept_redirects:0" \
  "net.ipv6.conf.all.accept_source_route:0"; do
  check_value "${pair%%:*}" "${pair#*:}"
done

umask_value="$(umask)"
if [[ "$umask_value" == "0027" ]]; then
  echo "PASS interactive shell umask=$umask_value"
else
  echo "WARN shell umask=$umask_value (login shell profile may not have been loaded)"
fi

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' openssh-server 2>/dev/null | grep -q 'install ok installed'; then
  echo "FAIL openssh-server is installed by default"
  failures=$((failures + 1))
else
  echo "PASS openssh-server is not installed"
fi

if systemctl is-active --quiet cyberlab-bridge.service 2>/dev/null; then
  echo "FAIL CyberLab bridge is active without explicit opt-in"
  failures=$((failures + 1))
else
  echo "PASS CyberLab bridge is not active"
fi

if (( failures > 0 )); then
  echo "Guest security check failed: $failures issue(s)." >&2
  exit 1
fi
echo "Guest security checks passed."
