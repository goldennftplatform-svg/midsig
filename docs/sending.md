# Sending MIDSIG-signed mail through Gmail (or any SMTP relay)

`midsig send` signs a message with your domain key, then hands it to an
SMTP relay for delivery. Gmail's relay is the common choice; any relay that
accepts AUTH works the same way.

## The one hard rule

MIDSIG verification resolves `_midsig.<From-domain>` in public DNS. The
**From address must live on a domain whose key you published** — otherwise
receivers see `fail — domain publishes no key`.

- `From: presale@aisp.live`  -> verifies (key is live in DNS). Correct sender.
- `From: nick@presetnet.com`  -> verifies once you publish its key (record below).
- `From: goldennftplatform@gmail.com` -> **cannot ever verify**. Nobody can
  publish `_midsig.gmail.com`. Gmail can only be the *transport*, never the
  signing identity.

So you authenticate to Gmail SMTP with your Gmail account, but the `From:`
must be your own domain address.

## Gmail SMTP requirements

- **2-Step Verification (2FA) must be ON** for the Gmail account. This is a
  hard Google requirement — `smtp.gmail.com` no longer accepts password
  logins, only App Passwords (which require 2FA) or OAuth.
- Create an **App Password** (not your site password):
  `myaccount.google.com/apppasswords`
- smtp.gmail.com, port **587**, `--starttls`. (Port 465 implicit TLS also
  accepted.)

## Never put the App Password on the command line

Shell history (and process listings) would record it. Store it in a file
outside the repo and use `--password-file`:

```
notepad.exe C:\Users\PreSafu\Desktop\CC\keys\gmail-app.txt
```

(one line: the 16-char App Password, no quotes). The `keys\` folder is
private and never committed.

## Preflight before you send

Prove credentials, TLS, and auth work without delivering a single message:

```
py -3 -m midsig.cli send \
  --key-file C:\Users\PreSafu\Desktop\CC\keys\aisp.live.hex.txt \
  --smtp smtp.gmail.com --port 587 --starttls \
  --user goldennftplatform@gmail.com \
  --password-file C:\Users\PreSafu\Desktop\CC\keys\gmail-app.txt \
  --from presale@aisp.live --to me@example.com \
  --dry-run
```

Expect: `preflight OK: ... authenticated to smtp.gmail.com:587 (no mail sent)`.

## Actually send (signed + postage)

```
py -3 -m midsig.cli send \
  --key-file C:\Users\PreSafu\Desktop\CC\keys\aisp.live.hex.txt \
  --smtp smtp.gmail.com --port 587 --starttls \
  --user goldennftplatform@gmail.com \
  --password-file C:\Users\PreSafu\Desktop\CC\keys\gmail-app.txt \
  --from presale@aisp.live --to recipient@example.com \
  --subject "first MIDSIG mail via Gmail" \
  --body "signed by aisp.live, verified against live DNS" \
  --postage-bits 16
```

Default is `--port 465` implicit SSL; add `--starttls` for 587.

## A signed message can't be forged

Every send stamps `X-Midsig` (domain, Message-ID, timestamp, signature). A
third party copying the headers cannot re-issue them under their own
identity, and tampering with headers invalidates the signature. Site:
`https://midsig.aisp.live/verify.html`.

## Publishing a key for a second domain (e.g. nick@presetnet.com)

```
py -3 -m midsig.cli setup --domain presetnet.com \
  --key-file C:\Users\PreSafu\Desktop\CC\keys\presetnet.com.hex.txt
```

Then add the printed `_midsig.presetnet.com TXT` record at your DNS host
(GoDaddy DNS panel). Until the record resolves, mail from that domain can't
verify.