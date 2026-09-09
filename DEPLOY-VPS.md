# Deploy a real MIDSIG-enforcing mail server (VPS, ~15 minutes)

The receipt the repo has been missing: a live Postfix that *accepts* mail
signed by a published domain and *rejects* forged mail, shown in the logs.

## 1. Rent a box (~$5)

Any provider works — Hetzner, DigitalOcean, Vultr, Racknerd, Contabo.

- OS: **Ubuntu 22.04 or 24.04** (Debian 12 also fine)
- Size: 1 vCPU / 1 GB RAM is plenty for a demo
- Open ports: 22 (SSH). 25 inbound is optional for this demo (we test via
  localhost). If you want to also *receive* mail from the internet, open 25
  and point an MX record at the box later.

## 2. Run the provisioner

```bash
ssh root@<your-vps-ip>
git clone https://github.com/goldennftplatform-svg/midsig.git
cd midsig
sh scripts/setup-mailserver.sh
```

This installs Postfix + rspamd + midsigd, wires the milter with a hard-reject
policy, and starts everything.

## 3. Copy your signing key (optional but recommended)

The signed-mail test needs a key for a domain whose `_midsig` TXT record is
published. If you have one (e.g. aisp.live):

```bash
mkdir -p /root/keys
# paste the 64-char secret seed into /root/keys/aisp.live.hex
sh scripts/mailserver-self-test.sh /root/keys/aisp.live.hex
```

Without a key, the negative tests still run and still prove enforcement.

## 4. Read the receipt

```bash
sh scripts/mailserver-self-test.sh
# expect:
#   [PASS] unsigned mail rejected (550)
#   [PASS] spoofed From: rejected (550)
#   [PASS] signed mail accepted (250)
```

And the server log shows why:

```bash
tail -20 /var/log/mail.log | grep -i midsig
```

## 5. Screenshot it

That terminal output is the proof. Post it next to the repo link.

## Rolling out for real (not just the demo)

- Start in **tag mode** (see POSTFIX.md / GUIDE-RSPAMD.md): accept + annotate
  for a week, watch the false-positive rate, then flip to reject.
- Point an MX record at the box and it will *receive* the internet's mail
  under enforcement.
- Add postage pricing later with `required_bits` — the spam lever.

## Notes

- `milter_default_action = tempfail` means if midsigd dies, mail defers
  rather than passing unchecked. That is intentional.
- The milter socket is `0666` inside `/var/run/midsigd/` — treat that
  directory like any milter socket dir; do not expose the box to a hostile
  multiuser environment.
- rspamd and the milter are redundant enforcement layers here (both run).
  You can run either alone; both is belt-and-braces.
