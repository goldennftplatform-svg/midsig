# midsig

Domain-signed Message-IDs for email. Zero-dependency Python reference
implementation of the [MIDSIG spec](SPEC.md).

[![Site](https://img.shields.io/badge/site-midsig.live-4fd1a5)](https://goldennftplatform-svg.github.io/midsig/)
[![Tests](https://img.shields.io/badge/tests-14%2F14%20passing-4fd1a5)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```
midsig/
├── midsig/
│   ├── ed25519.py   # pure-Python Ed25519 (RFC 8032)
│   ├── core.py      # signing, verification, postage
│   ├── dns.py       # TXT lookup (raw UDP, nslookup fallback)
│   └── cli.py       # CLI entrypoint
├── docs/
│   └── index.html   # live landing page with in-browser postage demo
├── tests/
│   ├── test_ed25519.py  # RFC 8032 official vectors
│   └── test_core.py     # sign/verify/spoof/postage suites
├── SPEC.md
└── LICENSE
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
