# midsigd — Milter for Postfix / Sendmail

`midsigd` is the production MIDSIG enforcer/stamper. It speaks the standard
milter protocol, so any MTA with milter support (Postfix 2.6+, Sendmail 8.13+)
can attach it with one config line. Zero dependencies — one Python file set,
no pip install required.

It runs in two modes:

| Mode | What it does |
|---|---|
| `verify` | Checks inbound mail: forged From domains and missing/weak postage get rejected (or tagged). DNS failures *defer* (tempfail) — never a bounce storm. |
| `sign` | Stamps outbound mail for every domain you hold a key for, before it leaves your MTA. Domains without a key pass through untouched. |

## 1. Create the config

`/etc/midsigd/midsigd.conf`:

```ini
[milter]
mode = verify
socket = unix:/var/run/midsigd/midsigd.sock
action = reject          ; or: tag  (tag = accept + Authentication-Results header)
required_bits = 0        ; set e.g. 16 to demand postage on all inbound mail
dns_server = 8.8.8.8
cache_ttl = 300
hostname = mail.yourdomain.com
exempt_domains =          ; comma list: domains that may send unsigned (newsletters)
```

For outbound signing instead:

```ini
[milter]
mode = sign
socket = unix:/var/run/midsigd/midsigd.sock
keys_dir = /etc/midsigd/keys      ; one <domain>.hex per domain (64 hex chars)
postage_bits = 20
```

Generate a key:

```bash
python -m midsig.cli keygen --domain yourdomain.com
# publish the printed TXT record, save the secret to /etc/midsigd/keys/yourdomain.com.hex
```

## 2. Systemd unit

`/etc/systemd/system/midsigd.service`:

```ini
[Unit]
Description=MIDSIG milter
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -m midsig.cli daemon --config /etc/midsigd/midsigd.conf
User=milter
Group=milter
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now midsigd
```

## 3. Attach to Postfix

`/etc/postfix/main.cf`:

```
smtpd_milters = unix:/var/run/midsigd/midsigd.sock
milter_default_action = tempfail
milter_protocol = 6
```

```bash
postfix reload
```

- `milter_default_action = tempfail` means: if *midsigd itself* dies, mail
  defers instead of flowing through unchecked.
- To add MIDSIG to the standard Postfix restriction chain, keep your existing
  `smtpd_recipient_restrictions` — the milter verdicts run at end-of-data and
  are independent of them.

## 4. Rolling out (no flag day)

1. Start in `action = tag` for a week. Watch the
   `Authentication-Results: ... midsig=fail` header rate; those are the mails
   you *would* reject.
2. Whitelist your legitimate unsigned senders in `exempt_domains`.
3. Flip to `action = reject`.

Each receiving domain can do this alone and gets the full protection for its
own users. That is the whole adoption strategy.

## Protocol notes

- Wire protocol: libmilter v6, implemented from scratch (see `midsig/milter.py`).
- Verified by an MTA-side protocol harness (`tests/test_milter.py`) that drives
  full SMTP sessions against the daemon — signed accept, unsigned reject,
  spoof reject, tag mode, sign mode, deferral on DNS failure.
- Windows: no unix sockets — use `socket = inet:127.0.0.1:8891` and attach from
  a Postfix host over the network (keep it private; the milter socket has no
  auth, same as every milter).
