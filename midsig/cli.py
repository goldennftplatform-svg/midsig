import argparse
import base64
import re
import secrets
import sys

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


def cmd_publish(args):
    seed = _load_seed(args.key_file)
    pub = ed25519.public_key(seed)
    record = f'v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}'
    print(f"_midsig.{args.domain}. 300 IN TXT \"{record}\"")


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


def cmd_verify(args):
    eml = _read_eml(args.input)
    verdict, reasons = core.verify_eml(
        eml, lookup=lambda d: dns.query_txt(f"{core.TXT_PREFIX}.{d}", server=args.dns_server),
        required_bits=args.required_bits,
    )
    print(f"verdict: {verdict}")
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

    p = sub.add_parser("publish", help="print the DNS record for an existing key")
    p.add_argument("--domain", required=True)
    p.add_argument("--key-file", required=True)
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("sign", help="sign an .eml file")
    p.add_argument("--key-file", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--output")
    p.add_argument("--postage-bits", type=int, default=0,
                   help="attach a proof-of-work stamp with N leading zero bits")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify an .eml file against DNS")
    p.add_argument("--input", required=True)
    p.add_argument("--required-bits", type=int, default=0,
                   help="require postage of at least N bits")
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
    p.add_argument("--password", required=True)
    p.add_argument("--from", dest="sender", required=True)
    p.add_argument("--to", action="append", required=True)
    p.add_argument("--subject", default="")
    p.add_argument("--body", default="")
    p.add_argument("--body-file")
    p.add_argument("--postage-bits", type=int, default=0)
    p.add_argument("--starttls", action="store_true", help="use STARTTLS on port 587 instead of implicit TLS")
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
    client.login(args.user, args.password)
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
