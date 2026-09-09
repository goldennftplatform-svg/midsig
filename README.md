# midsig

Domain-signed Message-IDs for email. Zero-dependency Python reference
implementation of the [MIDSIG spec](SPEC.md).

```
midsig/
├── midsig/
│   ├── ed25519.py   # pure-Python Ed25519 (RFC 8032)
│   ├── core.py      # signing, verification, postage
│   ├── dns.py       # TXT lookup (raw UDP, nslookup fallback)
│   └── cli.py       # CLI entrypoint
├── tests/
│   ├── test_ed25519.py  # RFC 8032 official vectors
│   └── test_core.py     # sign/verify/spoof/postage suites
└── SPEC.md
```

## Usage

Generate a domain key and get the DNS record:

```bash
python -m midsig.cli keygen --domain example.com
# publish the printed TXT record at _midsig.example.com
python -m midsig.cli publish --domain example.com --key-file key.hex
```

Sign an .eml (optionally stamp postage):

```bash
python -m midsig.cli sign --key-file key.hex --input in.eml --output out.eml --postage-bits 20
```

Verify (does a live TXT lookup):

```bash
python -m midsig.cli verify --input out.eml --required-bits 20
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Production notes

- `ed25519.py` is a non-constant-time reference implementation; for a
  production MTA plugin, swap it for PyNaCl / `cryptography` (same 32-byte
  keys, same 64-byte signatures — drop-in).
- ~1–2 s per pure-Python verify; the OpenSSL-backed swap is microseconds.
- Integrations worth building next: milter/Postfix plugin, an rspamd module,
  and a web verifier. The payment-rail postage (Lightning invoice in
  `X-Midsig-Postage`) plugs into the same `check_postage` seam.
