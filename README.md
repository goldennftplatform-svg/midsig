# midsig

####

Email is the internet's oldest open protocol, and the From line still trusts
anyone. We fixed that.

MIDSIG signs the Message-ID with your domain's key, published in DNS. A forged
From is now a failed signature, not a guess. Spam gets a price tag: prove 5
cents of compute or I don't want your mail. ez.

Everything here is MIT. Your keys, your inbox.

The internet spent 30 years building spam filters. MIDSIG spends one TXT
record and a signature. lol.

### [SPEC](/SPEC.md)

### [The site](https://goldennftplatform-svg.github.io/midsig/)

### [Postage demo](/docs) — mint a stamp in your browser

### [Unchaining your inbox](/posts/unchaining-your-inbox) — coming soon

## Quick start

```
python -m midsig.cli keygen --domain example.com      # key + DNS record
python -m midsig.cli sign --key-file key.hex \
    --input in.eml --output out.eml --postage-bits 20
python -m midsig.cli verify --input out.eml --required-bits 20
```

Zero dependencies. Pure Python. Ed25519 verified against RFC 8032 vectors.

## Tests

```
python -m unittest discover -s tests -v    # 14/14
```

## Honest lineage

Hashcash (1997) had the postage idea. DKIM (2007) proved domain signing scales.
MIDSIG is the slice DKIM leaves unsigned — the message identity itself — plus
the pricing knob. Crypto was never the hard part; adoption is. This is built
so one receiving domain can start enforcing today.

NFA on your QTC bags. This repo signs mail, not financial futures.
