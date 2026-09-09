# MIDSIG — Domain-Signed Message-IDs

Version 1 (spec-0.1). Complementary to SPF and DKIM; replaces neither.

## Problem

SPF checks the *envelope* sender, DKIM checks *which relay* signed the body.
Neither binds the message identity (`Message-ID`) to the domain it claims to
come from, and both are ignorable — a receiver that doesn't validate SPF/DKIM
loses nothing. MIDSIG makes the domain → message binding *cryptographic*:
a forged From domain is a failed signature, not a failed heuristic.

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

with at least `b` leading zero bits. Receivers set the minimum `b` they accept
("if you can't afford 5 cents of compute, I don't want it"). PoW is the v1
postage primitive because it needs no payment rails; the same header is the
slot for paid tokens (Lightning invoice, L2 payment proof) — the verifier API
does not change.

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
- Timestamps: receivers should accept ±300 s skew; replay of a signed
  Message-ID is harmless (Message-IDs are globally unique by contract) but
  receivers may dedupe on `d`+`i`.
- DNS TXT records are unauthenticated on the wire unless the resolver
  validates DNSSEC — same caveat as DKIM; DNSSEC signing the `_midsig` record
  is recommended.

## Prior art (honest lineage)

Hashcash (1997) — PoW postage for email. Penny Black (2003), Camram (2004).
DKIM (2007) — domain-signed mail. MIDSIG is the narrow slice DKIM leaves
unsigned — the Message-ID binding — plus a modern take on priced postage.
The hard problem is not crypto; it is that email has ~4B entrenched users and
flag-day protocols have historically lost. MIDSIG is designed to be
adoptable *incrementally* by individual receiving domains.
