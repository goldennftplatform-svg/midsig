# Handoff — MIDSIG paid postage

This is the operational handoff for the paid-postage MVP and the managed-provider
prototype. Read it end to end before touching money code: MIDSIG's damage
invariants live in the `postage` ledger and the milter's `admit` path, and the
fastest way to break them is a small-looking change that is not covered by the
test suite.

## 1. The product in one paragraph

MIDSIG signs a message's `Message-ID` with a key your domain publishes in DNS
(`_midsig.<domain>` TXT). Receivers can require that signature to verify against
that published key. The paid-postage layer prices **admission**: a receiver's
milter checks the signature, then debits **0.05 USDC-equivalent credit per
envelope recipient** from the *sending domain's* ledger account before storing
the mail. Everything is domain-bound — stamps bought for `aisp.live` do not
cover mail sent from `presetnet.com`. The pitch to a big provider: **MIDSIG is
the DKIM of economics** — receivers enforce domain reputation that a sender
actually pays for, and a provider with one From domain enrolls once and signs
every message server-side; none of its users ever touch DNS or crypto.

## 2. Money model

- **Unit:** 1 stamp = 0.05 USDC = `50_000` base units (`STAMP_UNITS` in
  `midsig/postage/policy.py`). Integer math only, never floats.
- **Crypto:** native USDC on Base only (chain 8453). Settlement is verified
  against the Base RPC before credit: correct recipient, exact amount,
  successful status, ≥2 confirmations, tx sender == order payer.
- **Card:** Square (production, `midsig/postage/square.py`). Bundles
  `ten` = $10 / 200 stamps and `stack` = $25 / 500 stamps
  (`CARD_CENTS`). Webhook (`/webhooks/square`, HMAC-verified) credits the order,
  then queues an `anchor_receipts` row for later batched on-chain anchoring.
- **Payee addresses:** Base `0x47cf60BdD877203264921D05CE26F81f6d36Aa3E`,
  native USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.
- **Where settlement happens:** the *receiving* side charges the *sending*
  domain's account at delivery (`Ledger.admit`). Buying stamps only credits the
  account; sign then send. There is no pre-global approval; MIDSIG just makes
  each paid domain report its spend in its own ledger.

## 3. Current MVP state

Working, end to end:

- Card checkout for a verified domain → Square link → webhook credits stamps
  (verified live on `mail.aisp.live`).
- USDC checkout: order create → wallet transfer → `/order/credit` verifies on
  Base → credits stamps. Wallet connect is auto-attached after Privy login
  (`autoAttachWallet` in `docs/js/postage.mjs`).
- DNS enrollment: `_midsig.<domain>` TXT → two-step `_midsig-verify` challenge
  → account activated under your Privy identity.
- Milter admission, inbox, balances all tested (52 Python tests green).

Blocked / known gaps:

- **`presetnet.com` has no `_midsig` TXT and no `_midsig-verify` TXT.**
  Chain/DNS records must be created before crypto (and honestly, before card
  buying is bought for it too — card only requires the account to exist, but an
  account without a published key cannot be admitted anywhere).
- `aisp.live` needs `_midsig-verify.aisp.live` = `midsig-enroll=<id>` to finish
  the second DNS step if you want to exercise the crypto enroll flow.
- **Product/UX gap (known):** stamps are domain-bound but the checkout does not
  explain that before Pay. Fix the pivot before messaging anyone: show the
  sending domain + "stamps work only for mail from this domain" on the review
  dialog.
- **Temp diagnostics still deployed:** `AUTH-CAPTURE` in `current_user`
  (server.py) and `ORDER-CARD-REJECT` in `order_card`. Remove, redeploy,
  restart when the debugging is done.
- Square access token `EAAAl9WTAJ7…` and App ID `sq0idp-HWx4h5YGO434N6AnYy54HQ`
  were pasted in chat history; **rotate both after go-live**.

## 4. How a user actually buys postage (the true flow)

1. Publish an Ed25519 key for your domain: `midsig setup --domain your.domain`
   → prints `_midsig.your.domain TXT "v=midsig1; k=ed25519; p=<b64>"`.
2. Sign in with email or wallet (Privy — each login method is a *separate*
   Privy user; domains are owned by the identity that enrolled them).
3. Add `_midsig-verify.your.domain` = `midsig-enroll=<id>` when the API asks
   (the randomness proves you control DNS mid-enrollment).
4. Buy stamps: **card** (`/order/card`, $10 min) or **Base USDC**
   (`/order/create` then `/order/credit`).
5. Sign outgoing mail with the *same* key and send through any relay that keeps
   `From:` intact: `midsig sign --key-file your.domain.hex ...` then SMTP
   (see `docs/sending.md` for the Zoho reference; Gmail's consumer relay rewrote
   `From:` and was dropped).
6. The receiving MIDSIG milter verifies against DNS + the ledger and debits
   0.05 USDC per recipient per unique `Message-ID`. Retries are idempotent.

## 5. Managed provider API (prototype, just built)

A provider (e.g., a large mail operator) gets a server credential instead of a
human Privy login and enrolls its sending domains programmatically. The domain
still owns its balance in the normal ledger — the provider layer only *binds*
domains and reads usage, so all existing settlement/admission paths work
unchanged.

Backing store: `providers` + `provider_domains` tables in the same ledger DB
(`midsig/postage/ledger.py`). Credential format `id.secret`, stored as a SHA-256
of the secret, compared constant-time. Secrets appear in an API response exactly
once.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /managed/providers` | Privy user | create provider; returns `api_secret` **once** |
| `POST /managed/providers/{id}/rotate` | Privy user (owner) | new secret; old one dies immediately |
| `POST /managed/domains` | provider credential | enroll domain — required `public_key` must match the live `_midsig` TXT, else 400 |
| `GET /managed/domains` | provider credential | domains with balance / stamps / greenlit |
| `GET /managed/usage?since=` | provider credential | aggregated deposits + mail spend across domains |

Rules enforced by the ledger (`tests/test_provider.py`, 10 tests):

- A domain is managed by **at most one provider** (Conflict).
- A domain already owned by another user cannot be claimed (Conflict).
- Provider records are owner-scoped; non-owners get a uniform "Provider not
  found".
- Re-enrolling the same domain is idempotent.
- Rotation invalidates every prior credential.

**What the prototype does NOT do yet** (the honest gaps before a deal):

- No per-request billing or signing KMS — providers still sign with their own
  seed and pay via the existing card/USDC checkout for each domain.
- No webhooks (deposit, spend, balance thresholds) and no rate limiting on the
  managed endpoints.
- Enrollment is one-step (DNS `_midsig` match) instead of the two-step
  `_midsig-verify` challenge used on the human path.
- No receiver-side admission policy API (this is the real network effect:
  letting *receivers* say "only MIDSIG-paid domains get the fast lane").

Suggested next slice for a provider deal: (1) signing SDK / KMS so operators
never touch a seed, (2) billing webhooks + an invoice/ledger export,
(3) admission-policy endpoint so receiver domains publish "require postage
≥ X", (4) price-as-config (`STAMP_UNITS` / `unit_price_usdc`) surfaced as a
real setting, not a constant.

## 6. Handoff to a big provider (playbook)

1. **Same product at two scales.** Indie/small-business onboarding = DNS-first,
   copy-paste TXT + stamps clearly bound to "your domain". Provider onboarding
   = the managed API above.
2. **Their one-time setup:** they control DNS → one `_midsig.<fromdomain>` TXT,
   sign server-side, pay for stamps in bulk. Users never see any of it.
3. **What you must show them:** live receiving-side enforcement (a MIDSIG
   milter that rejects unsigned / underfunded mail), the ledger + `anchor_receipts`
   audit trail, and a rendered frame proving a paid message actually delivered
   and debited.
4. **Why DNS means it's real:** a sender proves it owns the From domain by DNS
   control; a receiver verifies with nothing but public records and the ledger.
   No directory, no shared secret, no server trust beyond MIDSIG's own ledger.

## 7. Ops runbook

Host `159.223.184.36` (Ubuntu). Credentials live only in this session's temp
scripts, never in the repo.

- **Code:** `/opt/midsig` (git checkout; deployment is copy files → restart).
- **Service:** `systemctl restart midsig-api.service` after any deploy; check
  `systemctl status midsig-api.service` and `journalctl -u midsig-api -n 50`.
- **Ledger:** `/var/lib/midsig/ledger.db` (SQLite, WAL). Backups: `.bak-*` and
  `.bak-transfer2-1789157299` (pre-ownership-transfer). Back up before any
  ownership/balance surgery.
- **Env:** `/etc/midsig-square.env` (Square prod), `/etc/midsig/privy.env`.
  `MIDSIG_LEDGER_PATH` points at the live DB.
- **Frontends:** `mail.aisp.live` = nginx → this API (`postage.html` + JS is
  current). `midsig.aisp.live` = GitHub Pages, serves an **older** `postage.mjs`
  (no `autoAttachWallet`) — not the checkout entry point.
- **Config:** Privy App ID `cmtvhjy3d01u50bkzpiwylxbp` (policy + JS). CSP and
  CORS lists in `server.py` must stay in sync with any new origin.

## 8. Testing / CI gate

- Local (all 52): `python -m unittest discover -s tests -p 'test_*.py'`
- JS money-model tests: `node --test tests/test_postage_model.mjs`
- `npm run test:syntax` and `test:lua` under `tests/`
- **CI constraint:** `.github/workflows/pages.yml` runs bare `unittest discover`
  with no `pip install`. Everything it touches must be stdlib-only — server tests
  that import FastAPI/Pydantic cannot live in `tests/`. Do not modify
  `pages.yml`; keep new tests ledger/CLI-level like `tests/test_provider.py`.

## 9. Invariants the next engineer must not break

- Settlement proof must come only from the server (RPC receipt, Square HMAC
  webhook). **No HTTP path may manually credit an account.** `Ledger.credit` is
  the only credit caller, and only with a verifier's proof dict.
- `Ledger.admit` is transactional: mail is *never* permanently delivered
  without an atomic debit; identical SMTP retries find the durable message and
  do not double-charge. Never soften this.
- Domains are bound to one owner identity, then optionally to one provider.
  First claim wins; transfers are explicit operations with an audit trail and a
  DB backup taken first.
- Read `README.md`, `SPEC.md`, `docs/PAYMENTS.md` before changing formats,
  prices, or the signed payload. The paid v2 payload, recipient commitments,
  and replay rules are load-bearing.