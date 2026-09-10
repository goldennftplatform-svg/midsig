"""MIDSIG — domain-signed Message-IDs for email.

The anti-spoofing primitive: a sending domain publishes its Ed25519 public key
in DNS (`_midsig.<domain> TXT`), and every outgoing message carries a header
signing the canonical binding of (domain, Message-ID, timestamp). A receiver
verifies the signature against DNS — a forged From domain fails cryptographically,
not heuristically. SPF/DKIM stay as-is; MIDSIG adds a domain-key binding that no
relay in the path can strip without detection.

Optional postage: a proof-of-work token under `X-Midsig-Postage` lets receivers
require computational work. It does not prove payment or a fixed dollar cost.
The token binds to the same (domain, Message-ID, timestamp) triple. The PoW
flavor is self-contained; the spec leaves room for paid tokens (Lightning
invoice / cheap-L2 payment embedded in the header) behind the same verifier
API.
"""

import hashlib

from . import ed25519

MIDSIG_HEADER = "X-Midsig"
POSTAGE_HEADER = "X-Midsig-Postage"
TXT_PREFIX = "_midsig"
VERSION = "1"
PAID_VERSION = "2"


def payload(domain: str, message_id: str, timestamp: int) -> bytes:
    """Canonical string signed by MIDSIG (UTF-8, no whitespace tolerance)."""
    return f"midsig1:{domain.lower()}\n{message_id}\n{timestamp}".encode("utf-8")



def content_digest(body: str) -> str:
    """Stable SHA-256 of the message body as received by the milter."""
    normalized = body.replace("\r\n", "\n").replace("\r", "\n")
    # SMTP transports may add/remove terminal empty lines; canonicalize like DKIM simple body handling.
    normalized = normalized.rstrip("\n") + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def recipient_commitment(address: str) -> str:
    """Privacy-preserving envelope-recipient commitment for paid MIDSIG v2."""
    return hashlib.sha256(address.strip().lower().encode("utf-8")).hexdigest()


def paid_payload(domain: str, message_id: str, timestamp: int, digest: str, recipient_hashes) -> bytes:
    hashes = sorted(set(recipient_hashes))
    return (f"midsig2:{domain.lower()}\n{message_id}\n{timestamp}\n{digest}\n" + ",".join(hashes)).encode("utf-8")

def postage_challenge(domain: str, message_id: str, timestamp: int, nonce: bytes) -> bytes:
    return (
        f"mailstamp1:{domain.lower()}\n{message_id}\n{timestamp}\n{nonce.hex()}"
    ).encode("utf-8")


def postage_stamp(domain: str, message_id: str, timestamp: int, bits: int) -> dict:
    """Find a nonce whose SHA-256 has at least `bits` leading zero bits."""
    nonce = 0
    while True:
        digest = hashlib.sha256(
            postage_challenge(domain, message_id, timestamp, nonce.to_bytes(8, "big"))
        ).digest()
        if _leading_zeros(digest) >= bits:
            return {"n": nonce.to_bytes(8, "big").hex(), "x": digest.hex(), "b": bits}
        nonce += 1


def check_postage(domain: str, message_id: str, timestamp: int, token: dict) -> bool:
    try:
        nonce = bytes.fromhex(token["n"])
        expected = token["x"]
    except (KeyError, ValueError):
        return False
    digest = hashlib.sha256(postage_challenge(domain, message_id, timestamp, nonce)).digest()
    if digest.hex() != expected.lower():
        return False
    return _leading_zeros(digest) >= int(token.get("b", 0))


def _leading_zeros(digest: bytes) -> int:
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
        else:
            total += 8 - byte.bit_length()
            break
    return total


# ---------------------------------------------------------------- email tools


def _unfold(lines):
    """Join RFC 5322 header folding: continuation lines start with space/tab."""
    out = []
    for line in lines:
        if line[:1] in (" ", "\t") and out:
            out[-1] += " " + line.strip()
        else:
            out.append(line)
    return out


def _header_map(raw_headers):
    headers = {}
    order = []
    for line in raw_headers:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        headers.setdefault(name, []).append((name, value))
        order.append((name, value))
    return headers, order


def _first(headers, name):
    vals = headers.get(name.lower())
    return vals[0][1] if vals else None


def _from_domain(headers):
    """Best-effort RFC5322.From → domain. MVP: angle-addr and bare addr forms."""
    val = _first(headers, "from")
    if not val:
        return None
    if "<" in val and ">" in val:
        val = val[val.index("<") + 1:val.index(">")]
    else:
        val = val.strip().strip('"')
    if "@" not in val:
        return None
    return val.rsplit("@", 1)[1].lower()


def _parse_midsig(value):
    fields = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            fields[k.strip().lower()] = v.strip()
    return fields


def _parse_postage(value):
    return _parse_midsig(value)


# ---------------------------------------------------------------- sign / verify


def sign_eml(seed: bytes, eml: str, postage_bits: int = 0, recipients=None) -> str:
    """Add MIDSIG (and optional postage) headers to a raw .eml string.

    The seed is the *domain* signing secret. `eml` must already contain a
    Message-ID header; if not, one is generated.
    """
    raw_headers, body = _split(eml)
    headers, order = _header_map(raw_headers)

    domain = _from_domain(headers)
    if not domain:
        raise ValueError("could not determine From domain")

    message_id = _first(headers, "message-id")
    if not message_id:
        import uuid

        message_id = f"<{uuid.uuid4().hex}@{domain}>"
        order.insert(0, ("message-id", message_id))

    timestamp = _now()

    pub = ed25519.public_key(seed)
    import base64

    if recipients:
        digest = content_digest(body)
        rhashes = sorted(set(recipient_commitment(r) for r in recipients))
        sig = ed25519.sign(seed, paid_payload(domain, message_id, timestamp, digest, rhashes))
        midsig_value = (
            f"v={PAID_VERSION}; d={domain}; i={message_id}; t={timestamp}; "
            f"c={digest}; r={','.join(rhashes)}; s={base64.b64encode(sig).decode()}"
        )
    else:
        sig = ed25519.sign(seed, payload(domain, message_id, timestamp))
        midsig_value = (
            f"v={VERSION}; d={domain}; i={message_id}; t={timestamp}; s={base64.b64encode(sig).decode()}"
        )
    out_headers = order + [("x-midsig", midsig_value)]

    if postage_bits > 0:
        token = postage_stamp(domain, message_id, timestamp, postage_bits)
        postage_value = f"v={VERSION}; n={token['n']}; x={token['x']}; b={token['b']}"
        out_headers.append(("x-midsig-postage", postage_value))

    header_block = "\r\n".join(f"{name}: {value}" for name, value in out_headers)
    return header_block + "\r\n\r\n" + body


def verify_eml(eml: str, lookup, required_bits: int = 0, recipients=None, require_paid_binding=False):
    """Verify an .eml against DNS. `lookup(domain)` returns list of TXT strings.

    Returns (verdict, reasons) where verdict is "pass", "fail" or "error".
    """
    raw_headers, _ = _split(eml)
    headers, _order = _header_map(raw_headers)

    domain = _from_domain(headers)
    if not domain:
        return "error", ["no parseable From header"]

    midsig_value = _first(headers, "x-midsig")
    if not midsig_value:
        return "fail", ["missing X-Midsig header"]

    fields = _parse_midsig(midsig_value)
    message_id = fields.get("i")
    ts_field = fields.get("t")
    sig_field = fields.get("s")

    if fields.get("d", "").lower() != domain:
        return "fail", [f"X-Midsig domain {fields.get('d')!r} does not match From domain {domain!r}"]

    if not (message_id and ts_field and sig_field):
        return "fail", ["malformed X-Midsig header"]

    if _first(headers, "message-id") != message_id:
        return "fail", ["X-Midsig i= does not match Message-ID header"]

    try:
        timestamp = int(ts_field)
    except ValueError:
        return "fail", ["non-numeric timestamp"]

    try:
        import base64

        sig = base64.b64decode(sig_field)
    except Exception:
        return "fail", ["signature is not valid base64"]

    try:
        records = lookup(domain)
    except Exception as exc:
        return "error", [f"DNS lookup failed: {exc}"]

    pub = _pubkey_from_txt(records)
    if pub is None:
        return "fail", [f"no valid _midsig TXT record for {domain}"]

    version = fields.get("v", VERSION)
    if version == PAID_VERSION:
        digest = fields.get("c", "")
        rhashes = [x for x in fields.get("r", "").split(",") if x]
        _raw, body = _split(eml)
        if digest != content_digest(body):
            return "fail", ["X-Midsig content digest does not match message body"]
        if not rhashes:
            return "fail", ["X-Midsig v2 has no recipient commitments"]
        if recipients:
            wanted = {recipient_commitment(r) for r in recipients}
            if not wanted.issubset(set(rhashes)):
                return "fail", ["envelope recipient is not authorized by X-Midsig v2"]
        elif require_paid_binding:
            return "fail", ["paid MIDSIG verification requires envelope recipients"]
        signed_payload = paid_payload(domain, message_id, timestamp, digest, rhashes)
    else:
        if require_paid_binding:
            return "fail", ["paid postage requires recipient/content-bound X-Midsig v2"]
        signed_payload = payload(domain, message_id, timestamp)

    if not ed25519.verify(pub, signed_payload, sig):
        return "fail", ["signature verification failed"]

    if required_bits > 0 or _first(headers, "x-midsig-postage"):
        postage_value = _first(headers, "x-midsig-postage")
        if not postage_value:
            return "fail", ["postage required but no X-Midsig-Postage header"]
        token = _parse_postage(postage_value)
        if not check_postage(domain, message_id, timestamp, token):
            return "fail", ["postage token invalid"]
        if int(token.get("b", 0)) < required_bits:
            return "fail", [f"postage difficulty {token.get('b')} < required {required_bits}"]

    return "pass", []


def _pubkey_from_txt(records):
    """Extract an Ed25519 public key from `_midsig` TXT record strings."""
    import base64

    for record in records:
        fields = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                fields[k.strip().lower()] = v.strip()
        if fields.get("v") == "midsig1" and fields.get("k") == "ed25519":
            try:
                pub = base64.b64decode(fields["p"])
            except Exception:
                continue
            if len(pub) == 32:
                return pub
    return None


def _split(eml):
    """Split a .eml string into (header_lines, body)."""
    normalized = eml.replace("\r\n", "\n")
    if "\n\n" in normalized:
        head, body = normalized.split("\n\n", 1)
    else:
        head, body = normalized, ""
    return _unfold(head.split("\n")), body


def _now():
    import time

    return int(time.time())
