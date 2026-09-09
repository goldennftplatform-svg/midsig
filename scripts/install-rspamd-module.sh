#!/bin/sh
# Install the MIDSIG rspamd module. Run as root on the mail host.
# Usage: sh scripts/install-rspamd-module.sh

set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RSPAMD_LUA="/etc/rspamd/lua/local"
RSPAMD_CONF="/etc/rspamd/local.d"

if [ ! -d /etc/rspamd ]; then
  echo "rspamd not found at /etc/rspamd — install it first (apt install rspamd)" >&2
  exit 1
fi

mkdir -p "$RSPAMD_LUA"
cp "$REPO_DIR/rspamd/lua/midsig.lua" "$RSPAMD_LUA/midsig.lua"
cp "$REPO_DIR/rspamd/conf/midsig.conf" "$RSPAMD_CONF/midsig.conf"

if [ ! -f "$RSPAMD_CONF/groups.conf" ]; then
  echo '# MIDSIG symbol weights' > "$RSPAMD_CONF/groups.conf"
  cat >> "$RSPAMD_CONF/groups.conf" <<'EOF'
group "midsig" {
  symbols = {
    "MIDSIG_FAIL" {
      weight = 20.0;
      description = "MIDSIG verification failed (spoofed or unsigned)";
    }
    "MIDSIG_PASS" {
      weight = 0.0;
      description = "MIDSIG domain signature valid";
    }
    "MIDSIG_TEMP" {
      weight = 0.0;
      description = "MIDSIG verification deferred";
    }
  }
}
EOF
else
  echo "note: $RSPAMD_CONF/groups.conf exists — add the midsig group from GUIDE-RSPAMD.md"
fi

if [ ! -f "$RSPAMD_CONF/actions.conf" ]; then
  cat > "$RSPAMD_CONF/actions.conf" <<'EOF'
# Hard-reject mail that fails MIDSIG (start in "add header" mode first — see guide)
force_actions {
  MIDSIG_FAIL = "reject";
}
EOF
else
  echo "note: $RSPAMD_CONF/actions.conf exists — add force_actions from GUIDE-RSPAMD.md"
fi

echo "module installed. check:"
echo "  rspamadm configtest"
echo "  systemctl restart rspamd"
echo "  tail -f /var/log/rspamd/rspamd.log"
