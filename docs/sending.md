# Sending MIDSIG-signed mail through Zoho

The tested reference mailbox is **preset@aisp.live**. It sends through
`smtp.zoho.com:587` using STARTTLS and its full email address as the SMTP login.
The sending machine must be able to reach the relay; the DigitalOcean test
droplet currently cannot because of the provider's SMTP egress restriction.

## Keep the signing identity intact

Verification resolves `_midsig.<From-domain>` in public DNS. Publish the domain's
Ed25519 key and use a relay that preserves both the From domain and Message-ID.
Successful SMTP authentication alone does not guarantee this behavior.

The tested consumer Gmail relay configuration rewrote the From address to a
Gmail identity. We cannot publish a key under gmail.com, so that delivered copy
failed MIDSIG verification. Zoho preserved the reference domain in our test.
This is evidence about the tested configurations, not a claim about every
possible Gmail/Workspace send-as configuration.

## Keep passwords and private keys outside the repository

Save the Zoho SMTP app password in a private file and pass `--password-file`.
Do not paste secrets into command arguments, documentation, or browser code.
Use your own SMTP account, domain, and private paths in these examples.

The following commands are single-line commands suitable for PowerShell or a
POSIX shell when Python is available as `python`:

```sh
python -m midsig.cli send --key-file "../keys/aisp.live.hex.txt" --smtp smtp.zoho.com --port 587 --starttls --user preset@aisp.live --password-file "../keys/zoho-smtp.txt" --from preset@aisp.live --to preset@aisp.live --dry-run
```

Expected preflight: `authenticated to smtp.zoho.com:587 (no mail sent)`.

To send a signed message to a recipient you control:

```sh
python -m midsig.cli send --key-file "../keys/aisp.live.hex.txt" --smtp smtp.zoho.com --port 587 --starttls --user preset@aisp.live --password-file "../keys/zoho-smtp.txt" --from preset@aisp.live --to recipient@example.com --subject "MIDSIG over Zoho" --body "Signed by aisp.live; verify the delivered copy against DNS."
```

Optionally add `--postage-bits 16` for the **legacy proof-of-work** stamp. This
does not pay 0.05 USDC or buy stamps. Monetary postage is a separate, unfinished
integration: see [PAYMENTS.md](PAYMENTS.md).

## Verify the delivered copy

Download the raw message from the recipient's mailbox, then run:

```sh
python -m midsig.cli verify --input delivered.eml
```

Or use <https://midsig.aisp.live/verify.html>. A locally signed copy alone does
not prove that a relay preserved the fields during delivery.

The reference test delivered from Zoho to Gmail with the From domain intact;
Gmail's headers reported SPF, DMARC, and ARC pass, and the downloaded message
verified `pass (keys from DNS)`. Zoho's DKIM TXT record was subsequently
confirmed in DNS; publishing that record alone is not evidence of DKIM pass on
this earlier delivered message. A new delivered-header test is required for
that claim. IMAP was unavailable on the tested Zoho plan; use webmail's raw
message download if your account has the same restriction.

## Scope of a version-1 pass

MIDSIG v1 signs the From **domain**, Message-ID, and timestamp. It does not sign
all headers, the body, or recipients; it does not establish the individual
mailbox owner's identity or prevent all replays. DKIM and other checks remain
important. The proposed paid protocol requires content/recipient binding and
a persistent admission ledger before payment-backed sending can go live.
