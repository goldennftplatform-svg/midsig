#!/bin/sh
# Live proof: send mail through the local Postfix and show MIDSIG enforcement.
# Run as root:  sh scripts/mailserver-self-test.sh [/path/to/domain.hex]
#
# Tests (each one prints PASS/FAIL):
#   1. unsigned mail        -> milter MUST reject (550)
#   2. spoofed From domain  -> milter MUST reject (550)
#   3. signed mail          -> milter MUST accept (250)  [requires a key for a
#                              domain whose _midsig TXT record is published]
#
# The signed test needs a real published domain (e.g. aisp.live). Generate the
# key: python3 -m midsig.cli keygen --domain yourdomain.com
# Copy the 64-char secret into a .hex file and pass it as $1.

set -u

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$REPO_DIR"
HOST="$(hostname)"
KEY_FILE="${1:-}"
EML_FILE="${EML_FILE:-/tmp/midsig-signed.eml}"

pass=0
fail=0

note() { printf '    %s\n' "$*"; }
ok() { printf '  [PASS] %s\n' "$*"; pass=$((pass+1)); }
bad() { printf '  [FAIL] %s\n' "$*"; fail=$((fail+1)); }

printf '== MIDSIG mailserver self-test (host %s) ==\n' "$HOST"

# ---------------------------------------------------------------- 1. unsigned
printf '\n[1] unsigned mail from a stranger domain\n'
out=$(swaks --to "test@${HOST}" --from "stranger@evil.com" --server 127.0.0.1:25 2>&1)
if printf '%s' "$out" | grep -qE "^<+\*\* 5(50|54)"; then
  ok "rejected: $(printf '%s' "$out" | grep -oE '5[0-9]{2} .*' | head -1)"
else
  bad "not rejected"
  note "$(printf '%s' "$out" | tail -5)"
fi

# ---------------------------------------------------------------- 2. spoofed
printf '\n[2] spoofed From: mail claiming to be aisp.live\n'
out=$(swaks --to "test@${HOST}" --from "presale@aisp.live" --header "Message-ID: <spoof-$$@aisp.live>" --server 127.0.0.1:25 2>&1)
if printf '%s' "$out" | grep -qE "^<+\*\* 5(50|54)"; then
  ok "rejected: $(printf '%s' "$out" | grep -oE '5[0-9]{2} .*' | head -1)"
else
  bad "not rejected"
  note "$(printf '%s' "$out" | tail -5)"
fi

# ---------------------------------------------------------------- 3. signed
if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
  printf '\n[3] signed mail from aisp.live (real key, real DNS)\n'
  python3 - "$KEY_FILE" > "$EML_FILE" <<'PYEOF'
import sys
sys.path.insert(0, "/opt/midsig")
from midsig import core
seed = bytes.fromhex(open(sys.argv[1]).read().strip()[:64])
domain = "aisp.live"
eml = (
    "From: Presale Safe <presale@aisp.live>\r\n"
    "To: root@localhost\r\n"
    "Subject: midsig self-test signed mail\r\n"
    "Message-ID: <selftest-signed-1@aisp.live>\r\n"
    "\r\n"
    "If this lands in the queue, MIDSIG passed a live SMTP transaction.\r\n"
)
print(core.sign_eml(seed, eml, postage_bits=16))
PYEOF
  out=$(swaks --to "test@${HOST}" --from "presale@aisp.live" --data "@${EML_FILE}" --server 127.0.0.1:25 2>&1)
  rm -f "$EML_FILE"
  if printf '%s' "$out" | grep -qE "250 2\\.0\\.0 Ok"; then
    ok "accepted — MIDSIG pass end-to-end"
  else
    bad "not accepted"
    note "$(printf '%s' "$out" | tail -5)"
  fi
else
  printf '\n[3] signed mail — SKIPPED (pass a .hex key file for a published domain)\n'
fi

printf '\n== %d passed, %d failed ==\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
