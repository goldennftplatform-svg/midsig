# Monetary postage — draft integration policy

Status: design and public receiving addresses recorded; **not implemented or
enabled in the live SMTP gateway**. Version 1 proof-of-work does not prove that
money was paid. This document is not an invoice or an instruction to send funds.

## Required inbox policy

The sender must prove control of its From domain through DNS-published signing
keys. The gateway must validate message authentication (SPF, DKIM, and DMARC
alignment), the signed message identity, and paid postage before admission.

- Minimum postage: **0.05 USDC per message per envelope recipient**.
- Use integer token units: **50,000** at USDC's six decimals.
- Payment on either supported network suffices; both are not required.
- Network, swap, and service fees must not reduce credited postage below the
  minimum. USDC is the denomination; its market price is not guaranteed to be
  exactly USD 1.
- Only the pinned Circle-issued native USDC contracts/mints qualify. Token
  symbols, bridged substitutes, and testnet receipts do not prove payment.

## Public receiving addresses

| Network | Public receiving wallet | Native USDC contract / mint |
| --- | --- | --- |
| Base mainnet (chain ID 8453) | `0x47cf60BdD877203264921D05CE26F81f6d36Aa3E` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Solana mainnet-beta | `5S9tyrZwcgV127fEQMzCaBNWmEKz3iUBdASKaurBSGHU` | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |

These are public wallet addresses, not private signing keys. The Solana wallet
is the token-account owner; USDC transfers must target the appropriate USDC
token account, not blindly use the wallet address as an SPL token account.

The user supplied the EVM address under the label "ETH". Base is the intended
network in this proposal; an Ethereum-only exchange deposit address would need
replacement or explicit Base support from the provider. An address format or
RPC lookup does not prove wallet control or a custodian's network support.

Read-only preflight performed during setup:

- EVM address decodes to 20 bytes; Base RPC reported chain ID 8453, no deployed
  code at the supplied receiving address, and six decimals for native USDC.
  This was not an EIP-55 checksum validation.
- Solana address decodes to a canonical, on-curve 32-byte public key. The
  mainnet-beta RPC returned a non-executable System Program-owned account.
- No payment, token-account creation, swap, or wallet approval was executed.

Token identities: [Circle's official USDC contract list](https://developers.circle.com/stablecoins/usdc-contract-addresses).

## Proposed SOL / ETH payment option

Senders may fund postage using SOL on Solana or ETH on Base, with a sender-approved
conversion into native USDC. Credit is based on **settled USDC actually received**,
not an estimated swap output or the amount of native coin offered. Ethereum
mainnet is a separate network and is not enabled by the Base address entry.

The least transaction-intensive option is prepaid postage: for example, **1 USDC
net received funds 20 messages**, with an atomic 0.05-USDC debit per recipient.
Prepaid bundles are the selected checkout direction, not a deployed credit system. A
sender's domain-signing identity must be bound to the deposit/credit account;
knowing a public deposit transaction ID must not allow someone else to claim it.

Pond0x was requested as a possible swap route. Its public website exposes swap
interfaces, but the documentation checked did not establish a supported
automation API, Base support, minimum trade size, or total executable fees.
Pond0x integration remains **unverified**. The unrelated 0x Swap API is not
evidence of Pond0x support.

For per-message conversions, the sender must cover fees and slippage so at least
0.05 USDC is credited. If native coins are instead held without conversion, a
separate expiring-quote and price-feed policy is required; that is not currently
selected.

## Implementation and deployment requirements

1. Specify and implement payment/deposit binding to the authenticated domain,
   message identity, envelope recipient, and message content. Publish only
   opaque commitments on-chain, not email addresses, subjects, or bodies.
2. Verify chain identity, native token identity, successful execution, correct
   receiver, amount, and finality. An RPC outage or unsettled transfer must not
   grant admission.
3. Persist payment claims or credit debits atomically. Reject reuse for another
   message/recipient; make identical SMTP retries idempotent. Admission and
   durable delivery must be coordinated to avoid lost mail or double charges.
4. Implement actual SPF/DKIM/DMARC checks and test their SMTP enforcement. DNS
   publication alone is not message authentication.
5. Test forged, missing, underpaid, wrong-token, wrong-chain, failed, pending,
   reused, content-substituted, and concurrent payment claims.
6. Prove a live paid message is durably delivered before changing the mailbox's
   MX path. DigitalOcean's SMTP egress restriction currently blocks direct
   forwarding to Zoho; a relay path still needs validation. Public backup MX
   entries must not bypass the required gateway.

RH remains undefined (Robinhood Chain, wallet, or another network) and has no
configured payment route.

## Checkout preview

`postage.html` implements a static, mobile-friendly purchase preview. Bundles are
20 / 100 / 500 stamps for 1 / 5 / 25 USDC. Base and Solana are selectable preview
routes. One domain field is remembered with bundle/route preferences locally;
no wallet authorization or credit balance is stored in the browser.

The optional wallet connector supports injected EVM wallets (EIP-6963 and legacy
EIP-1193) and injected Phantom/Solflare Solana providers. It requests public
accounts only. Connection is not proof of wallet or domain ownership. Account
or network changes invalidate the reviewed order. Native ETH/SOL swaps and RH
are not offered as executable routes.

An optional Privy React SDK island adds email/wallet login and embedded wallets;
see [Privy setup](PRIVY-SETUP.md). It remains unloaded until its public App ID is
configured and the SDK island is built. Privy wallet login may request a sign-in
signature, but no payment transaction or token approval is requested. Privy login
does not verify domain control or create postage credits.

No purchase is made: the checkout has no payment methods or live-mode toggle.
The downloadable JSON is explicitly a preview, with no payment,
credit balance, verified domain, payable total, or transaction hash. Preview
completion is not a simulated claim of successful blockchain settlement.

Before enabling purchases, implement the requirements above and the service
contract below; a static front end alone must never issue credits:

- Authenticated, domain-bound enrollment with server-generated wallet-signature
  challenges and explicit replay/expiry checks.
- A server-issued expiring quote identifying the bundle, network, pinned token,
  receiver, fees, minimum settled output, and opaque account/deposit reference.
- Wallet transaction construction and validation against that quote, including
  allowance limits and swap-route restrictions if native funding is enabled.
- Chain settlement verification, durable unique deposit claims, and the atomic
  postage ledger. Credit may only appear after server-side verification.
- A recoverable transaction-status screen and real receipt: wallet approval,
  broadcast, settlement, and postage crediting are distinct states.
- Integration with durable SMTP admission/delivery and authenticated debit
  requests. Mainnet checkout remains unavailable until credits are usable.

Run model tests with `node --test tests/test_postage_model.mjs`. Serve `docs/`
over HTTP to exercise the browser modules (opening via `file://` is unsupported).
