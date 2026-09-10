# midsig

Email is the internet's oldest open protocol, and the From line still trusts
anyone. We fixed that.

MIDSIG signs the Message-ID with your domain's key, published in DNS. A forged
From is now a failed signature, not a guess. Spam gets a price tag: prove 5
cents of compute or I don't want your mail.

Everything here is MIT. Your keys, your inbox.

## The magic in 60 seconds

```bash
# 1. Create a key for your domain (saves <domain>.hex, prints the DNS record):
midsig setup --domain your.domain --wait 300

# 2. Publish the printed TXT record at your DNS host.

# 3. Sign a message, verify it — through public DNS, exactly like a mail server:
midsig sign --key-file your.domain.hex --input in.eml --output out.eml
midsig verify --input out.eml
#    verdict: pass

# Anyone can verify your mail on any machine with no key, no secret, no server —
# just the TXT record your domain publishes:
#    midsig verify --input out.eml
```

The whole point: `verify` needs nothing from you except your domain. The key
is only needed by *senders* — recognition comes from the pubkey you publish
in DNS, not from any directory or server.

## Proof without internet (throwaway key)

```bash
midsig demo
#    genuine message  -> PASS
#    swapped Message-ID -> FAIL: signature verification failed

python scripts/magic-proof.py                      # full printable receipt
python scripts/magic-proof.py --key-file aisp.live.hex --domain aisp.live
#    verify against public DNS ->  PASS   |   magic: pass
```

## Command reference

| Command | What it does |
|---|---|
| `midsig setup --domain D [--wait N]` | generate + save key, print the DNS record, optional propagation poll |
| `midsig publish --domain D --key-file K` | re-print the DNS record for an existing key |
| `midsig export-pub --key-file K --output K.pub` | write just the public record (share this, never the seed) |
| `midsig sign --key-file K --input in.eml [--output out.eml] [--postage-bits N]` | add the X-Midsig header |
| `midsig verify --input out.eml [--dns-server H]` | verify against DNS (the normal path) |
| `midsig verify --input out.eml --pubkey "v=midsig1;..."` | verify offline against a shared public key |
| `midsig verify --input out.eml --key-file K` | verify offline against your own seed file |
| `midsig demo` | offline pass/fail proof, no DNS |
| `midsig send --key-file K --smtp relay.example --user u --password p --from a@d --to b@d` | sign + send through an SMTP relay |
| `midsig daemon --config midsigd.conf` | milter daemon — hard enforcement on Postfix/Sendmail |
| `python scripts/magic-proof.py [--domain D --key-file K]` | printable "magic: pass" receipt |

`--key-file` reads any file containing a 64-char seed hex (like the one `setup`
writes). `--pubkey` takes the exact TXT record content (public only).

## Tests

```bash
python -m unittest discover -s tests -v        # 24 python tests
cd tests && npm install && npm run test:lua    # Lua module runtime tests
npm run test:syntax                            # luaparse syntax check
```

## What's in the box

| Piece | What it is |
|---|---|
| `midsig` | reference library + CLI (setup / sign / verify / send / demo / publish / export-pub) |
| `midsigd` | milter daemon — hard enforcement on Postfix/Sendmail |
| `rspamd/lua/midsig.lua` | Lua module — enforcement on any rspamd host |
| `docs/` | site: live verifier (client-side DoH), postage demo |
| `scripts/` | lan-proof, magic-proof, mailserver self-test, WAN relay, provisioners |

## A full enforcing mail server (when you have the infra)

`scripts/setup-mailserver.sh` provisions Postfix + `midsigd` + local
authoritative DNS; `scripts/mailserver-self-test.sh` proves the three cases:
unsigned REJECT 550, spoofed-From REJECT 550, signed ACCEPT 250. Verified on
box and over a LAN. See [POSTFIX](/POSTFIX.md) and [GUIDE-RSPAMD](/GUIDE-RSPAMD.md).

Want a public mailbox? Your ISP must give you a real public IP and accept
inbound port 25. On carrier-NAT (e.g. T-Mobile home), that is physically
impossible — the sign/verify magic above works anyway. See [PUBLIC-GO-LIVE].