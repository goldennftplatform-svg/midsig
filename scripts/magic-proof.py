"""MIDSIG magic proof — a printable, copy-pasteable receipt.

Two modes:
  --offline     (default) prove the whole flow on this machine: generate a
                throwaway key, sign a message, verify it, then show that a
                forged From fails. No DNS, no server, no published key.
  --domain D    prove it against a *published* key: sign a message with the
                saved key file and verify through public DNS, like a real
                receiving mailserver would.

Both print a receipt you can paste anywhere ("magic: pass").

Usage:
  python magic-proof.py
  python magic-proof.py --key-file aisp.live.hex --domain aisp.live
"""
import argparse
import base64
import re
import sys

sys.path.insert(0, __file__.rsplit("scripts", 1)[0] or "..")

from midsig import core  # noqa: E402


def _seed_from_file(path):
    with open(path, "r") as fh:
        raw = fh.read()
    match = re.search(r"[0-9a-fA-F]{64}", raw)
    if not match:
        raise SystemExit(f"{path}: no 64-char hex seed found")
    return bytes.fromhex(match.group(0))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", help="verify a real signed message against DNS")
    ap.add_argument("--key-file", help="key for the real message (with --domain)")
    ap.add_argument("--postage-bits", type=int, default=0)
    args = ap.parse_args()

    if args.domain and args.key_file:
        receipt = _real_proof(args)
    else:
        receipt = _offline_proof(args)
    print()
    print("=" * 56)
    print(" MIDSIG magic proof - receipt")
    print("=" * 56)
    print(receipt.rstrip())
    print("=" * 56)


def _offline_proof(args):
    import secrets
    seed = secrets.token_bytes(32)
    pub = core.ed25519.public_key(seed)
    record = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"
    domain = "example.com"
    eml = (
        f"From: Alice <alice@{domain}>\r\n"
        f"To: Bob <bob@other.example>\r\n"
        "Subject: offline magic proof\r\n"
        "Message-ID: <magic@example.com>\r\n"
        "\r\n"
        "the magic is the binding, not the body\r\n"
    )
    signed = core.sign_eml(seed, eml, postage_bits=args.postage_bits)

    def lookup(_d):
        return [record]

    verdict, reasons = core.verify_eml(signed, lookup=lookup, required_bits=args.postage_bits)
    forged = signed.replace("alice@example.com", "alice@evil.example")
    verdict2, reasons2 = core.verify_eml(forged, lookup=lookup, required_bits=args.postage_bits)

    lines = [
        "mode:      offline (throwaway key, no DNS, no server)",
        f"domain:    {domain}",
        f"DNS key:   {record}",
        "",
        "sign a message  ->  done",
        f"verify genuine  ->  {verdict.upper()}",
        "forge the From   ->  changed to alice@evil.example",
        f"verify forged   ->  {verdict2.upper()}: {(reasons2 or [''])[0]}",
        "",
    ]
    if verdict == "pass" and verdict2 != "pass":
        lines += [
            "magic: pass",
            "",
            "A forged From address fails the signature. That is MIDSIG's",
            "anti-spoofing guarantee, and it costs nothing to check.",
        ]
        return "\n".join(lines)
    lines += ["magic: FAIL — inconsistent demo, this is a bug."]
    return "\n".join(lines)


def _real_proof(args):
    from midsig import dns
    seed = _seed_from_file(args.key_file)
    domain = args.domain.lower()
    pub = core.ed25519.public_key(seed)
    record = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"
    eml = (
        f"From: Owner <owner@{domain}>\r\n"
        f"To: Bob <bob@other.example>\r\n"
        "Subject: real DNS proof\r\n"
        "Message-ID: <proof@%s>\r\n" % domain +
        "\r\n"
        "signed here, verified against public DNS\r\n"
    )
    signed = core.sign_eml(seed, eml, postage_bits=args.postage_bits)
    verdict, reasons = core.verify_eml(
        signed,
        lookup=lambda d: dns.query_txt(f"{core.TXT_PREFIX}.{d}"),
        required_bits=args.postage_bits,
    )
    lines = [
        "mode:      published key + public DNS (exactly what a mail server does)",
        f"domain:    {domain}",
        f"key:       {record}",
        "",
        "sign a message  ->  done",
        f"verify against public DNS ->  {verdict.upper()}",
    ]
    for reason in reasons:
        lines.append(f"  - {reason}")
    lines.append("")
    lines.append("magic: pass" if verdict == "pass" else "magic: FAIL")
    return "\n".join(lines)


if __name__ == "__main__":
    main()