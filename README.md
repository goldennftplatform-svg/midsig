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

## It ships live

`preset@aisp.live` is a real mailbox. Signed mail sent from it is accepted by
Gmail with `spf=pass`, `dmarc=pass`, `arc=pass`, `From:` intact — and every
copy verifies `pass (keys from DNS)` against the live `_midsig.aisp.live`
record. That was the send path that Gmail's own relay could never deliver
(see [docs/sending.md](docs/sending.md) for the full proof and setup).

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
| `midsig send --key-file K --smtp relay.example --user u --from a@d --to b@d` | sign + send through an SMTP relay (`--port 465` implicit TLS default; add `--starttls` for 587; `--password-file P` keeps the password out of shell history; `--dry-run` preflights auth with no mail) |
| `midsig daemon --config midsigd.conf` | milter daemon — hard enforcement on Postfix/Sendmail |
| `python scripts/magic-proof.py [--domain D --key-file K]` | printable "magic: pass" receipt |

`--key-file` reads any file containing a 64-char seed hex (like the one `setup`
writes). `--pubkey` takes the exact TXT record content (public only).

## Live verification site

`docs/` is a static GitHub Pages site (`https://midsig.aisp.live`):

- `.../verify.html` — paste a message, verify MIDSIG client-side in the
  browser against live DNS (via DoH). Ships a real sample at
  `.../sample-signed.eml` that verifies `pass`.
- `.../` — landing page with the story and a postage demo.

## Tests

```bash
python -m unittest discover -s tests -v        # 25 python tests
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

## Sending signed mail, for real

The reference `preset@aisp.live` mailbox sends through Zoho
(`smtp.zoho.com:587`, STARTTLS). The relay keeps `From:` intact — which is the
whole point, and the reason the Gmail relay path was dropped (it rewrites
`From:` and therefore can never carry a MIDSIG-verifiable message).

Recipe, full detail, and the live proof: **[docs/sending.md](docs/sending.md)**.

## A full enforcing mail server (when you have the infra)

`scripts/setup-mailserver.sh` provisions Postfix + `midsigd` + local
authoritative DNS; `scripts/mailserver-self-test.sh` proves the three cases:
unsigned REJECT 550, spoofed-From REJECT 550, signed ACCEPT 250. Verified on
box and over a LAN. See [POSTFIX](/POSTFIX.md), [GUIDE-RSPAMD](/GUIDE-RSPAMD.md),
and the VPS walkthrough in [DEPLOY-VPS](/DEPLOY-VPS.md).

Want a *self-hosted* receiving mailbox? Carrier-NAT links (T-Mobile home
included) cannot bind public port 25 — see [PUBLIC-GO-LIVE](/PUBLIC-GO-LIVE.md)
for the diagnosis and the VPS options. The hosted mail path above needs no
such server.