# midsig

MIDSIG signs the Message-ID with your domain's key, published in DNS. Receivers
can require that signature to verify against the From domain's published key.
Version 1 also supports proof-of-work, which is not a payment or a fixed dollar
cost. It complements SPF, DKIM, and DMARC; it does not replace them.

The new prepaid-postage checkout is a **no-funds preview**: 20 / 100 / 500 stamps
for 1 / 5 / 25 USDC, with a Privy integration for Base and Solana wallets. The payment
verifier, domain-bound credit ledger, and paid SMTP admission are not implemented.
See [payment status](docs/PAYMENTS.md) and [Privy setup](docs/PRIVY-SETUP.md).

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

`preset@aisp.live` is a real mailbox. A signed test sent from it was accepted by
Gmail with `spf=pass`, `dmarc=pass`, `arc=pass`, and `From:` intact. The delivered
copy verified `pass (keys from DNS)` against the live `_midsig.aisp.live` record.
The tested Gmail relay configuration rewrote that identity instead
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
- `.../postage.html` — prepaid checkout preview and optional Privy login. No
  payment or usable credit is created by previewing a purchase.

GitHub Actions builds the pinned Privy SDK from `checkout-auth/` into
`docs/privy/` before deploying the Pages artifact. `docs/release.json` identifies
the deployed commit and purchase mode. SDK build output and secrets are not
committed; only the public Privy App ID belongs in browser configuration.

## Tests

```bash
python -m unittest discover -s tests -v        # 27 python tests
node --test tests/test_postage_model.mjs       # checkout money/domain/receipt tests
node tests/ed25519-vectors.mjs                 # RFC 8032 verification vectors
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
| `checkout-auth/` | TypeScript-checked Privy login island, built into the Pages artifact |
| `scripts/` | lan-proof, magic-proof, mailserver self-test, WAN relay, provisioners |

## Sending signed mail, for real

The reference `preset@aisp.live` mailbox sends through Zoho
(`smtp.zoho.com:587`, STARTTLS). The relay keeps `From:` intact — which is the
whole point, and the reason the tested consumer Gmail relay path was dropped:
that configuration rewrote `From:` to a domain whose signing key we don't control.

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
