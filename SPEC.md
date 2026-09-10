# MIDSIG — Domain-Signed Message-IDs

Version 1 (spec-0.1). Complementary to SPF and DKIM; replaces neither.

## Problem

SPF checks sending authorization for an envelope identity. DKIM authenticates
signed message content on behalf of its signing domain and can include the
Message-ID header. DMARC evaluates alignment with the From domain. MIDSIG adds
an explicit requirement to bind the Message-ID to a key published under that
From domain. Receivers must actually verify and enforce these mechanisms;
publishing DNS records alone does not authenticate a delivered message.

## Design

### 1. DNS publication

The sending domain publishes its Ed25519 public key:

```
_midsig.example.com.  300 IN TXT "v=midsig1; k=ed25519; p=<base64 32-byte pubkey>"
```

- `v=midsig1` — record version
- `k=ed25519` — key type (only defined value in v1)
- `p=` — base64 standard alphabet, 32-byte public key

Rotate by publishing a new key; receivers accept any valid record (grace
period is receiver policy — same trust model as DKIM key rotation).

### 2. Signing header

Every message carries:

```
X-Midsig: v=1; d=example.com; i=<abc123@example.com>; t=1720600000; s=<base64 sig>
```

The signature covers the canonical UTF-8 payload, exactly:

```
midsig1:<lowercase-domain>\n<Message-ID value verbatim>\n<unix timestamp>
```

`i=` MUST equal the message's `Message-ID` header value verbatim.
`d=` MUST equal the domain of the RFC5322.From address (third-party signing —
mailing lists, relays — is a future extension via a `l=` tag, deliberately out
of scope for v1).

### 3. Postage header (optional, receiver-priced)

```
X-Midsig-Postage: v=1; n=<hex nonce>; x=<hex sha256>; b=20
```

`x` = SHA-256 of:

```
mailstamp1:<lowercase-domain>\n<Message-ID>\n<timestamp>\n<hex nonce>
```

with at least `b` leading zero bits. Receivers set the minimum `b` they accept.
This measures computational difficulty, not money: no difficulty value proves
that a sender paid $0.05. Version 1 implements no blockchain payment verification.
Monetary postage requires a separately specified payment proof, message and
recipient binding, settlement checks, and persistent replay prevention.

### 4. Receiver policy

| Check | Result |
|---|---|
| X-Midsig present | missing → quarantine/score |
| `d=` matches From domain | mismatch → reject |
| Signature verifies against `_midsig` TXT | fail → reject |
| Postage meets required difficulty (if receiver demands) | fail → reject/drop |

Receivers may still accept unsigned mail at a policy cost (newsletter
allow-lists, transitional modes). MIDSIG adds a *strong* signal; it does not
require flag-day deployment.

## Security notes

- Ed25519 over SHA-512; 128-bit security. Post-quantum: v2 can swap in
  ML-DSA/Dilithium via a new `k=` tag without changing the rest of the format.
- Version 1 signs timestamps but does not enforce freshness or maintain a replay
  ledger. A Message-ID is not proof of unique delivery; signed messages can be
  replayed. Paid postage must prevent reuse across different messages or
  recipients while handling SMTP retries without duplicate charges/deliveries.
- DNS TXT records are unauthenticated on the wire unless the resolver
  validates DNSSEC — same caveat as DKIM; DNSSEC signing the `_midsig` record
  is recommended.

## Prior art (honest lineage)

Hashcash (1997) — PoW postage for email. Penny Black (2003), Camram (2004).
DKIM (2007) — domain-signed mail. MIDSIG explicitly requires the Message-ID
binding that is optional in DKIM's signed-header selection, plus receiver postage policy.
The hard problem is not crypto; it is that email has ~4B entrenched users and
flag-day protocols have historically lost. MIDSIG is designed to be
adoptable *incrementally* by individual receiving domains.
