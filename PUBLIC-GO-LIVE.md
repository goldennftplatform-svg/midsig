# Make MIDSIG reachable from the internet (3 steps, only you can do these)

Everything on this machine is already wired and PROVEN local:
  LAN 192.168.12.135:25 -> relay -> WSL Postfix -> milter -> 550/550/250.
The relay also auto-starts at login (Startup folder) and wakes WSL on demand.

Test that first (works right now):
    py -3 scripts\lan-proof.py
    expect: [1 unsig] REJECT 550 / [2 spoof] REJECT 550 / [3 signed] ACCEPT 250

---

## STEP 1 — Windows Firewall: allow inbound port 25 (one elevated command)

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