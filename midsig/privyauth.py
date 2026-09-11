"""Privy ES256 access-token verification, independent of any web framework.

Kept stdlib-only at import time so the CI test suite (plain `python -m
unittest`, no pip install) can import it; `cryptography` is imported lazily
inside the verify helpers.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.request
from typing import Any, Dict, Optional

from .postage.policy import APP_ID

_PRIVY_JWKS_URL = os.getenv("MIDSIG_PRIVY_JWKS_URL", f"https://auth.privy.io/api/v1/apps/{APP_ID}/jwks.json")
_PRIVY_JWKS_TTL = 3600
_jwks_cache: Dict[Any, Any] = {}


def _b64url_json(segment: str) -> dict:
    pad = "=" * ((4 - len(segment) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def _jwk_to_pem(jwk: dict) -> bytes:
    """Convert an EC JWK to a PEM SubjectPublicKeyInfo for ES256 verification."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pad = "=" * ((4 - len(jwk["x"]) % 4) % 4)
    x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + pad), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + pad), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _verification_keys() -> Dict[str, Optional[bytes]]:
    """Return {kid: PEM bytes} for verifying Privy access tokens.

    MIDSIG_PRIVY_VERIFICATION_KEY, when set, is a single static key (kid "").
    Otherwise the app's public JWKS is fetched from auth.privy.io and cached
    for MIDSIG_PRIVY_JWKS_TTL seconds (default 3600), matching how the
    official Privy server SDK verifies tokens.
    """
    now = time.time()
    if _jwks_cache.get("fetched_at") and now - _jwks_cache["fetched_at"] < _PRIVY_JWKS_TTL:
        return _jwks_cache["keys"]
    static = os.getenv("MIDSIG_PRIVY_VERIFICATION_KEY", "").replace("\\n", "\n").strip()
    try:
        if static:
            keys: Dict[str, Optional[bytes]] = {"": static.encode("utf-8")}
        else:
            with urllib.request.urlopen(_PRIVY_JWKS_URL, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            keys = {}
            for jwk in data.get("keys", []):
                keys[jwk["kid"]] = _jwk_to_pem(jwk)
            if not keys:
                raise RuntimeError("Privy JWKS returned no verification keys")
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"MIDSIG_PRIVY_VERIFICATION_KEY is not configured and JWKS fetch failed: {exc}") from exc
    _jwks_cache["fetched_at"] = now
    _jwks_cache["keys"] = keys
    return keys


def verify_access_token(token: str) -> str:
    """Verify a Privy ES256 access token and return the Privy user id.

    Raises RuntimeError for a configuration problem (no key source available)
    and ValueError for anything that looks like a bad token.
    """
    try:
        header_seg, payload_seg, sig_seg = token.split(".")
        claims = _b64url_json(payload_seg)
        hdr = _b64url_json(header_seg)
        if hdr.get("alg") != "ES256":
            raise ValueError("unsupported alg")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        verification_keys = _verification_keys()
        pem = verification_keys.get(hdr.get("kid") or "")
        if pem is None and "" in verification_keys:
            pem = verification_keys[""]
        if pem is None:
            raise ValueError("no verification key for token kid")
        key = serialization.load_pem_public_key(pem)
        raw_sig = base64.urlsafe_b64decode(sig_seg + "=" * ((4 - len(sig_seg) % 4) % 4))
        if len(raw_sig) != 64:
            raise ValueError("invalid ES256 signature")
        r = int.from_bytes(raw_sig[:32], "big")
        ss = int.from_bytes(raw_sig[32:], "big")
        key.verify(encode_dss_signature(r, ss), f"{header_seg}.{payload_seg}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except RuntimeError:
        raise
    except Exception as exc:
        raise ValueError(f"invalid access token: {exc}") from exc

    now = int(time.time())
    aud = claims.get("aud")
    audience_ok = aud == APP_ID or (isinstance(aud, list) and APP_ID in aud)
    if claims.get("iss") != "privy.io" or not audience_ok:
        raise ValueError("token is not for this app")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise ValueError("access token expired")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now + 30:
        raise ValueError("access token not active")
    user_id = claims.get("sub")
    if not isinstance(user_id, str) or not user_id.startswith("did:privy:"):
        raise ValueError("token is missing a user")
    return user_id