#!/bin/sh
# Provision a fresh Ubuntu/Debian box as a MIDSIG-enforcing mail server.
# Run as root:  sh scripts/setup-mailserver.sh
#
# Installs: postfix (MTA), rspamd (filter), midsigd (milter daemon),
# and the rspamd midsig module. Wires everything with a hard-reject policy —
# see GUIDE-RSPAMD.md / POSTFIX.md if you want tag-first rollout instead.

set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(hostname)"

echo "==> updating packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q postfix rspamd python3 swaks ca-certificates

echo "==> installing midsig package"
mkdir -p /opt/midsig
cp -r "$REPO_DIR/midsig" /opt/midsig/midsig

echo "==> configuring midsigd (verify mode, hard reject)"
mkdir -p /var/run/midsigd
useradd --system --home-dir /var/lib/midsig --shell /usr/sbin/nologin midsig || true

cat > /etc/midsigd.conf <<EOF
[milter]
mode = verify
socket = unix:/var/run/midsigd/midsigd.sock
action = reject
required_bits = 0
dns_server = 127.0.0.53
cache_ttl = 300
hostname = mail.${HOST}
EOF

cat > /etc/systemd/system/midsigd.service <<'EOF'
[Unit]
Description=MIDSIG milter daemon
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -m midsig.cli daemon --config /etc/midsigd.conf
Environment=PYTHONPATH=/opt/midsig
User=midsig
Group=midsig
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "==> wiring postfix"
postconf -e "smtpd_milters = unix:/var/run/midsigd/midsigd.sock"
postconf -e "non_smtpd_milters = unix:/var/run/midsigd/midsigd.sock"
postconf -e "milter_default_action = tempfail"
postconf -e "milter_protocol = 6"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
echo "test@${HOST} root" > /etc/postfix/virtual
postmap /etc/postfix/virtual

echo "==> wiring rspamd"
cp "$REPO_DIR/rspamd/lua/midsig.lua" /etc/rspamd/lua/local/midsig.lua
cp "$REPO_DIR/rspamd/conf/midsig.conf" /etc/rspamd/local.d/midsig.conf
if [ ! -f /etc/rspamd/local.d/groups.conf ]; then
  cat > /etc/rspamd/local.d/groups.conf <<'EOF'
group "midsig" {
  symbols = {
    "MIDSIG_FAIL" { weight = 20.0; description = "MIDSIG verification failed"; }
    "MIDSIG_PASS" { weight = 0.0; description = "MIDSIG domain signature valid"; }
    "MIDSIG_TEMP" { weight = 0.0; description = "MIDSIG verification deferred"; }
  }
}
EOF
fi

echo "==> starting services"
systemctl daemon-reload
systemctl enable --now midsigd
systemctl restart postfix
systemctl restart rspamd
rspamadm configtest || true

echo ""
echo "==> done. now run:  sh scripts/mailserver-self-test.sh /path/to/aisp.live.hex"
echo "    (the key file is optional — negative tests run without it)"
