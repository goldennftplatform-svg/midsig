# MIDSIG release and mail-routing status

## Current status (2026-09-10)

- Website: `https://midsig.aisp.live`. The release adds `postage.html`, a no-funds
  prepaid checkout preview with real Privy login integration. It does not sell
  usable stamps yet. GitHub Actions builds the SDK and deploys the Pages artifact.
- Mailbox: **preset@aisp.live**, hosted by Zoho. Public DNS still routes to
  `mx.zoho.com` / `mx2.zoho.com` / `mx3.zoho.com` at priorities 10 / 20 / 50.
  The Zoho DKIM record is published. See [sending proof](docs/sending.md).
- Test gateway: Postfix and MIDSIG were installed on the DigitalOcean droplet.
  Local SMTP self-tests returned unsigned 550, spoofed 550, signed 250 with
  `required_bits=16`. A separate external probe reached its SMTP banner. These
  facts do not prove a public paid-message delivery path.
- Forwarding to Zoho failed: outbound SMTP connections timed out on ports 25,
  465, and 587 while HTTPS worked. DigitalOcean's [documented restriction](https://docs.digitalocean.com/support/why-is-smtp-blocked/)
  covers those SMTP ports. Support suggested a third-party delivery service;
  no exception was approved. An alternate relay still needs validation.
- **Paid inbox enforcement is not deployed.** The existing milter checks
  signatures and optional computational work, not blockchain payment. The
  payment verifier, domain-bound ledger, and durable paid delivery are required
  before enabling purchases or changing MX. See [payment policy](docs/PAYMENTS.md).

Any future gateway must have a tested mailbox-delivery path before MX cutover.
Keeping unrestricted hosted MX records as backups would let senders bypass the
mandatory gate. Authenticated outbound submission services must be evaluated
for forwarding arbitrary external senders; preserving our own sender in a test
does not establish general forwarding compatibility.

## Historical home-hosting investigation

The material below records the earlier home-network experiment. **Do not apply
its home-IP DNS recipe to aisp.live**: that path was ruled out by CGNAT. It is
not the current mailbox configuration or a prerequisite for website deployment.

**UPDATE (2026-09-09): this connection cannot host a public mailbox.**

Diagnosis:
- Gateway is **T-Mobile Home Internet** (lighttpd React app at 192.168.12.1).
- The WAN IP (172.56.106.30) belongs to T-Mobile's carrier pool
  (RDAP NET-172-32-0-0-1) — that is **CGNAT**, not a public IP you own.
- External probes from 5 countries time out on ports 25/80/443/22.
  That is the carrier blocking inbound, not a missing forward rule.
- IPv6 addresses are handed out (2607:fb90:...) but the gateway firewall
  blocks inbound and WSL2 NATs the guest anyway.

So no firewall rule, router forward, or DNS change on this machine can
create a public MX. The options below are the only real paths.

---

## OPTION A — The magic that already ships (works everywhere, no servers)

    midsig setup --domain yours.example    # key + DNS record + wait
    midsig demo                            # offline pass/fail proof
    midsig sign --input msg.eml            # sign with your key
    midsig verify --input msg.eml          # verify vs public DNS

MIDSIG is a sender-identity stamp: anyone with your DNS can verify that a
message came from your domain. It does NOT need your own mail server.

## OPTION B — Public mailbox via a dumb VPS hop (~$1-5/mo)

A tiny VPS with a public IP owns the MX. It does NOT make decisions —
it pipe-forwards the SMTP dialogue over an OUTBOUND tunnel (SSH/WireGuard)
to this WSL Postfix, which accepts/rejects (550/250) exactly as today.
Even with a compromised VPS, the verdict logic and the key never leave
home. Requires: one VPS, one outbound tunnel, aisp.live MX -> VPS IP.

## OPTION C — A different line with a real public IP (ISP/plan change)

A business line or any ISP that assigns a true public IPv4 (or accepts
inbound 25). On any of those, the recipe below (firewall + forward + DNS)
is all that's needed — it's already proven working locally.

---

## The original 3-step recipe (only valid with a real public IP)

Everything on this machine is wired and PROVEN local:
  LAN 192.168.12.135:25 -> relay -> WSL Postfix -> milter -> 550/550/250.
The relay auto-starts at login and wakes WSL on demand.

Test that first (works right now):
    py -3 scripts\lan-proof.py
    expect: [1 unsig] REJECT 550 / [2 spoof] REJECT 550 / [3 signed] ACCEPT 250

### STEP 1 — Windows Firewall: allow inbound port 25 (one elevated command)

Open PowerShell **as Administrator** and run:

    netsh advfirewall firewall add rule name="MIDSIG WAN relay" dir=in action=allow protocol=TCP localport=25 profile=private

(If your home network profile is "Public" instead of "Private", change
`profile=private` to `profile=public` — or use `profile=any`.)

## STEP 2 — Router: forward TCP port 25 to this PC

1. Log into your router admin UI:  http://192.168.12.1
2. Find **Port Forwarding** / **NAT / Virtual Server**.
3. Add (protocol **TCP**, external **25**, internal **25**, lantern/private IP):

       external port 25  ->  192.168.12.135:25  (TCP)

4. Save / reboot the router if it asks.

Note: if this PC's LAN IP (currently 192.168.12.135) is DHCP-assigned, set a
**DHCP reservation** in the router for this PC so the forward doesn't break
on reboot.

## STEP 3 — DNS: point aisp.live MX at your home IP

Your home WAN IP is currently:  **172.56.106.30**  (verify with `curl ifconfig.me`)

At your DNS host (nameservers are ns17/ns18.domaincontrol.com = GoDaddy),
under aisp.live DNS records add:

    MX    @  10  mail.aisp.live.
    A     mail.aisp.live.  ->  172.56.106.30

So strangers' mail servers deliver to mail.aisp.live = 172.56.106.30:25 ->
router -> relay -> your Postfix.

---

## After the 3 steps

Tell me and I will, from here:
- re-probe your WAN port 25 from 5 countries (check-host.net)
- run the signed/unsigned/spoofed test through the public path
- watch /var/log/mail.log for a real inbound delivery from the internet

## If the probe still times out after all 3

Your ISP is likely carrier-NAT-ing or dropping inbound 25 (common on
residential lines). Home-public works for some ISPs, not others. That is a
physics problem the code can't fix — the fallback is a $1-5/mo relay VPS
that only sees ciphertext and lets Postfix keep enforcing.
> NOTE on firewall profile: this PC's active network is **Public** (SScupofjoe). Use profile=public (or profile=any) in the rule.
