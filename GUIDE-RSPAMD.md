# Enforce MIDSIG with rspamd in 10 minutes

rspamd is the open-source spam filter behind most Postfix/Exim/Mailcow
setups. This module verifies `X-Midsig` against the sender domain's
`_midsig` TXT record on every message — no MTA config changes, no flag day
for your upstream mail flow.

## What you get

| Symbol | Meaning |
|---|---|
| `MIDSIG_PASS` | signature valid (informational) |
| `MIDSIG_FAIL` | spoofed From, unsigned mail, missing key — your lever |
| `MIDSIG_TEMP` | DNS/crypto hiccup (never hard-reject on this) |

## 1. Install (60 seconds)

```bash
git clone https://github.com/goldennftplatform-svg/midsig.git
cd midsig
sudo sh scripts/install-rspamd-module.sh
sudo rspamadm configtest
sudo systemctl restart rspamd
```

The installer copies `midsig.lua` into `/etc/rspamd/lua/local/` and writes
`midsig.conf` + symbol weights + a hard-reject `force_action`.

## 2. Start gentle (recommended first week)

Comment out the `force_actions` block in `/etc/rspamd/local.d/actions.conf`
and instead score:

```ucl
# /etc/rspamd/local.d/groups.conf
group "midsig" {
  symbols = {
    "MIDSIG_FAIL" { weight = 3.0; }
  }
}
```

Watch the symbol fire rate:

```bash
rspamc stat | grep -i midsig
grep MIDSIG /var/log/rspamd/rspamd.log | tail
```

Any false positive (legit sender without MIDSIG) shows up as
`MIDSIG_FAIL` on real mail. Add their domains to `exempt_domains` in
`/etc/rspamd/local.d/midsig.conf`.

## 3. Go hard

Uncomment `force_actions { MIDSIG_FAIL = "reject"; }`, raise weight to 20,
`systemctl restart rspamd`. Spoofed mail now bounces; unsigned strangers get
rejected unless exempted.

## 4. Demand postage (the spam-killer)

Set `required_bits = 16` in `midsig.conf`. Senders then need a valid 16-bit
proof-of-work stamp (`X-Midsig-Postage`) or their mail fails MIDSIG. Raise
bits as spam adapts. Legit senders run our signer (free); spammers pay
compute on every single message.

## Notes

- Crypto: Ed25519 verify goes through LuaJIT FFI into `libcrypto` (OpenSSL
  1.1.1+), which rspamd already links. If FFI can't load, the module emits
  `MIDSIG_TEMP` rather than silently accepting.
- DNS: uses rspamd's own async resolver with the system's configured
  nameservers (DNSSEC-aware if you run a validating resolver).
- Tested against the live `_midsig.aisp.live` record — the same key format
  every sender publishes.
- Not a replacement for SPF/DKIM. Run all three: SPF for the envelope, DKIM
  for the relay, MIDSIG for the message identity.
