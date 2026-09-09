"""Pure-Python Ed25519 (RFC 8032) — reference implementation.

Zero dependencies. Not constant-time — this is the portable reference used to
validate the wire format; production deployments should swap it for PyNaCl /
`cryptography` / OpenSSL, which expose the exact same 32-byte public keys and
64-byte signatures.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Base point B (extended homogeneous coordinates: X, Y, Z, T)
_BY = (4 * pow(5, -1, P)) % P
_BX = None


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    if x % 2 != 0:
        x = P - x
    return x


def _point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = (t1 * 2 * D * t2) % P
    dd = (z1 * 2 * z2) % P
    e = (b - a) % P
    f = (dd - c) % P
    g = (dd + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_dbl(p1):
    x1, y1, z1, t1 = p1
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, scalar):
    q = (0, 1, 1, 0)  # identity
    for i in range(256):
        if (scalar >> i) & 1:
            q = _point_add(q, point)
        point = _point_dbl(point)
    return q


def _basepoint():
    global _BX
    if _BX is None:
        _BX = _xrecover(_BY)
    return (_BX % P, _BY % P, 1, (_BX * _BY) % P)


def _encode_point(p):
    x, y, z, _ = p
    zi = pow(z, -1, P)
    x = x * zi % P
    y = y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(data):
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (int.from_bytes(data, "little") >> 255):
        x = P - x
    return (x % P, y % P, 1, (x * y) % P)


def _clamp_scalar(h):
    h = bytearray(h)
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def public_key(seed: bytes) -> bytes:
    """32-byte Ed25519 public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(_clamp_scalar(h[:32]), "little")
    return _encode_point(_scalarmult(_basepoint(), a))


def sign(seed: bytes, message: bytes) -> bytes:
    """64-byte Ed25519 signature (R || S)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(_clamp_scalar(h[:32]), "little")
    A = _scalarmult(_basepoint(), a)
    pub = _encode_point(A)
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    R = _scalarmult(_basepoint(), r)
    renc = _encode_point(R)
    k = int.from_bytes(hashlib.sha512(renc + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return renc + s.to_bytes(32, "little")


def verify(pub: bytes, message: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    renc, senc = sig[:32], sig[32:]
    s = int.from_bytes(senc, "little")
    if s >= L:
        return False
    try:
        A = _decode_point(pub)
        R = _decode_point(renc)
    except (ValueError, ZeroDivisionError):
        return False
    k = int.from_bytes(hashlib.sha512(renc + pub + message).digest(), "little") % L
    left = _scalarmult(_basepoint(), s)
    right = _point_add(R, _scalarmult(A, k))
    return _encode_point(left) == _encode_point(right)
