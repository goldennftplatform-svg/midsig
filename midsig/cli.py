import argparse
import base64
import re
import secrets
import sys
import time

from . import core, dns, ed25519


def _load_seed(path):
    with open(path, "r") as fh:
        raw = fh.read()
    match = re.search(r"[0-9a-fA-F]{64}", raw)
    if not match:
        raise SystemExit(f"{path}: no 64-char hex seed found")
    seed = bytes.fromhex(match.group(0))
    if len(seed) != 32:
        raise SystemExit(f"{path}: seed must be 32 bytes")
    return seed


def _read_eml(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def cmd_keygen(args):
    seed = secrets.token_bytes(32)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    zone = f"_midsig.{args.domain}. 300 IN TXT \"{record}\""
    print(f"# secret key (keep private, never publish)\n{seed.hex()}\n")
    print(f"# public key\n{pub.hex()}\n")
    print(f"# publish this DNS record:\n{zone}")


def cmd_setup(args):
    """Generate a key, save it, and print the exact DNS records to publish."""
    seed = secrets.token_bytes(32)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    zone = f'_midsig.{args.domain}. 300 IN TXT "{record}"'
    keyfile = args.key_file or f"{args.domain}.hex"

    with open(keyfile, "w", encoding="utf-8") as fh:
        fh.write(f"{args.domain} domain signing key (MIDSIG) — KEEP PRIVATE, never commit anywhere.\n\n")
        fh.write("secret seed (64 hex chars)\n")
        fh.write(seed.hex() + "\n")

    print(f"key saved:      {keyfile}")
    print(f"\npublish this DNS record (at your DNS host, for {args.domain}):\n")
    print(f"    {zone}")
    print()
    print("verifiers will resolve:  TXT _midsig.<domain>")
    print("once published, test with:  midsig verify --input signed.eml")
    if args.wait:
        print(f"\nwaiting up to {args.wait}s for the record to publish...")
        deadline = time.monotonic() + args.wait
        while time.monotonic() < deadline:
            try:
                found = dns.query_txt(f"{core.TXT_PREFIX}.{args.domain}")
            except Exception:
                found = None
            if record in (found or []):
                print("propagated: the record is live.")
                return
            time.sleep(5)
        print("not seen yet — DNS propagation can take minutes. Re-run with --wait to poll.")


def cmd_demo(args):
    """Offline proof-of-life: sign a message, then show a tampered one fails.

    Runs entirely on this machine — no DNS, no server, no key you need to
    publish. The MIDSIG flow in under ten lines of terminal output.
    """
    seed = secrets.token_bytes(32)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    domain = args.domain or "example.com"
    eml = (
        f"From: Alice <alice@{domain}>\r\n"
        f"To: Bob <bob@other.example>\r\n"
        f"Subject: signed, then tampered\r\n"
        f"Message-ID: <demo-1@{domain}>\r\n"
        "\r\n"
        "This is the payload.\r\n"
    )
    signed = core.sign_eml(seed, eml, postage_bits=args.postage_bits)

    def lookup(_d):
        return [record]

    verdict, reasons = core.verify_eml(signed, lookup=lookup, required_bits=args.postage_bits)
    if verdict != "pass":
        print(f"[FAIL] genuine message rejected: {reasons}")
        return 1

    tampered = signed.replace("<demo-1@example.com>", "<demo-1@evil.example>")
    verdict2, reasons2 = core.verify_eml(tampered, lookup=lookup, required_bits=args.postage_bits)

    print(f"domain:     {domain}")
    print(f"key:        {pub.hex()}")
    print(f"DNS record: {record}")
    print()
    print(f"genuine message  -> {verdict.upper()}")
    label = verdict2.upper()
    cause = (reasons2 or ["(not shown)"])[0]
    print(f"swapped Message-ID -> {label}: {cause}")
    print()
    if verdict == "pass" and verdict2 != "pass":
        print("MIDSIG binds sender domain + Message-ID. Change either and the")
        print("signature fails. That is the anti-spoofing guarantee it gives.")
        return 0
    print("something is inconsistent with the offline demo key — bug.")
    return 1


def cmd_publish(args):
    seed = _load_seed(args.key_file)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    print(f"_midsig.{args.domain}. 300 IN TXT \"{record}\"")


def cmd_export_pub(args):
    """Write just the public key record to a file — share this, never the seed."""
    seed = _load_seed(args.key_file)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(record + "\n")
        print(f"wrote {args.output}")
    else:
        print(record)


def cmd_sign(args):
    seed = _load_seed(args.key_file)
    eml = _read_eml(args.input)
    out = core.sign_eml(seed, eml, postage_bits=args.postage_bits)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(out)


def _lookup(args, domain):
    if args.key_file:
        seed = _load_seed(args.key_file)
        pub = ed25519.public_key(seed)
        return [f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"]
    if args.pubkey:
        return [args.pubkey]
    return dns.query_txt(f"{core.TXT_PREFIX}.{domain}", server=args.dns_server)


def cmd_verify(args):
    eml = _read_eml(args.input)
    try:
        verdict, reasons = core.verify_eml(
            eml, lookup=lambda d: _lookup(args, d),
            required_bits=args.required_bits,
        )
    except SystemExit:
        raise
    source = "key file" if args.key_file else ("pubkey" if args.pubkey else "DNS")
    print(f"verdict: {verdict}   (keys from {source})")
    for reason in reasons:
        print(f"  - {reason}")
    if verdict != "pass":
        sys.exit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="midsig", description="Domain-signed Message-IDs")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a domain signing key + DNS record")
    p.add_argument("--domain", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("setup", help="generate + save a key and print the DNS record to publish")
    p.add_argument("--domain", required=True)
    p.add_argument("--key-file", help="where to save the key (default: <domain>.hex)")
    p.add_argument("--wait", type=int, default=0, help="poll DNS for propagation up to N seconds")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("demo", help="offline proof-of-life: sign then tamper, show pass/fail (no DNS, no server)")
    p.add_argument("--domain", default="example.com")
    p.add_argument("--postage-bits", type=int, default=0)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("publish", help="print the DNS record for an existing key")
    p.add_argument("--domain", required=True)
    p.add_argument("--key-file", required=True)
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("export-pub", help="write the public key record to a file (share this, never the seed)")
    p.add_argument("--key-file", required=True)
    p.add_argument("--output")
    p.set_defaults(func=cmd_export_pub)

    p = sub.add_parser("sign", help="sign an .eml file")
    p.add_argument("--key-file", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--output")
    p.add_argument("--postage-bits", type=int, default=0,
                   help="attach a proof-of-work stamp with N leading zero bits")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify an .eml against DNS (or a key file)")
    p.add_argument("--input", required=True)
    p.add_argument("--required-bits", type=int, default=0,
                   help="require postage of at least N bits")
    p.add_argument("--key-file", help="verify against this saved key instead of DNS (no internet needed)")
    p.add_argument("--pubkey", help="verify against this public record string instead of DNS (no internet, no secret)")
    p.add_argument("--dns-server", default=dns.DEFAULT_SERVER)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("daemon", help="run the milter daemon (Postfix/Sendmail plugin)")
    p.add_argument("--config", required=True, help="path to midsigd.conf")
    p.set_defaults(func=cmd_daemon)

    p = sub.add_parser("send", help="sign a message and send it through an SMTP relay")
    p.add_argument("--key-file", required=True)
    p.add_argument("--smtp", required=True, help="relay hostname")
    p.add_argument("--port", type=int, default=465)
    p.add_argument("--user", required=True)
    cred = p.add_mutually_exclusive_group(required=True)
    cred.add_argument("--password", help="SMTP password (avoid: shows in shell history)")
    cred.add_argument("--password-file", help="read SMTP password from this file (preferred)")
    p.add_argument("--from", dest="sender", required=True)
    p.add_argument("--to", action="append", required=True)
    p.add_argument("--subject", default="")
    p.add_argument("--body", default="")
    p.add_argument("--body-file")
    p.add_argument("--postage-bits", type=int, default=0)
    p.add_argument("--starttls", action="store_true", help="use STARTTLS on port 587 instead of implicit TLS")
    p.add_argument("--dry-run", action="store_true",
                   help="connect, verify the TLS handshake and AUTH succeed, then quit WITHOUT sending mail")
    p.set_defaults(func=cmd_send)

    args = parser.parse_args(argv)
    args.func(args)


def cmd_send(args):
    import smtplib
    import time
    import uuid

    seed = _load_seed(args.key_file)
    domain = args.sender.rsplit("@", 1)[1].lower()
    message_id = f"<{uuid.uuid4().hex}@{domain}>"
    timestamp = int(time.time())

    password = args.password
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as fh:
            password = fh.read().strip()

    if args.dry_run:
        if args.starttls:
            client = smtplib.SMTP(args.smtp, args.port, timeout=30)
            client.ehlo()
            client.starttls()
            client.ehlo()
        else:
            client = smtplib.SMTP_SSL(args.smtp, args.port, timeout=30)
        client.login(args.user, password)
        client.quit()
        print(f"preflight OK: {args.user} authenticated to {args.smtp}:{args.port} (no mail sent)")
        return

    body = args.body
    if args.body_file:
        with open(args.body_file, "r", encoding="utf-8", newline="") as fh:
            body = fh.read()

    eml = (
        f"From: {args.sender}\r\n"
        f"To: {', '.join(args.to)}\r\n"
        f"Subject: {args.subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        "\r\n"
        f"{body}\r\n"
    )
    signed = core.sign_eml(seed, eml, postage_bits=args.postage_bits)

    if args.starttls:
        client = smtplib.SMTP(args.smtp, args.port, timeout=30)
        client.starttls()
    else:
        client = smtplib.SMTP_SSL(args.smtp, args.port, timeout=30)
    client.login(args.user, password)
    client.sendmail(args.sender, args.to, signed.encode("utf-8"))
    client.quit()
    print(f"sent signed message {message_id} to {', '.join(args.to)}")


def cmd_daemon(args):
    import logging

    from . import handlers, milter

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    socket_spec, handler = handlers.build_from_config(args.config)
    server = milter.MilterServer(socket_spec, lambda: handler)
    print(f"midsigd listening on {socket_spec}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
