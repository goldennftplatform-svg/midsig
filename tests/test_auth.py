"""Privy access-token verification: static PEM key and live JWKS kid matching.

Signs real ES256 JWTs with a locally-generated P-256 key (the same curve
Privy uses) and asserts current_user accepts valid tokens and rejects
tampered/wrong-kid tokens with 401.
"""

import base64
import json
import os
import tempfile
import time
import unittest

from fastapi import HTTPException

from midsig.postage.policy import APP_ID
from midsig import server

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _sign_token(priv: ec.EllipticCurvePrivateKey, claims: dict, kid: str | None = None) -> str:
    header = {"alg": "ES256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    body = _b64u(json.dumps(header, separators=(",", ":")).encode("ascii"))
    payload = _b64u(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    der = priv.sign(f"{body}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{body}.{payload}.{_b64u_pad(sig)}"


def _pub_jwk(pub: ec.EllipticCurvePublicKey) -> dict:
    n = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(n.x.to_bytes(32, "big")),
        "y": _b64u(n.y.to_bytes(32, "big")),
        "kid": "test-kid-1",
        "alg": "ES256",
        "use": "sig",
    }


def _claims(sub="did:privy:testuser", extra=None) -> dict:
    now = int(time.time())
    claims = {
        "iss": "privy.io",
        "aud": APP_ID,
        "sub": sub,
        "iat": now - 10,
        "exp": now + 3600,
        "sid": "test-session",
    }
    if extra:
        claims.update(extra)
    return claims


class PrivyAuthTests(unittest.TestCase):
    def setUp(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub_pem = self.priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        self._old_key = os.environ.pop("MIDSIG_PRIVY_VERIFICATION_KEY", None)
        self._old_jwks_url = os.environ.pop("MIDSIG_PRIVY_JWKS_URL", None)
        server._jwks_cache = {}
        server._PRIVY_JWKS_URL = f"https://auth.privy.io/api/v1/apps/{APP_ID}/jwks.json"

    def tearDown(self):
        server._jwks_cache = {}
        if self._old_key is not None:
            os.environ["MIDSIG_PRIVY_VERIFICATION_KEY"] = self._old_key
        else:
            os.environ.pop("MIDSIG_PRIVY_VERIFICATION_KEY", None)
        if self._old_jwks_url is not None:
            os.environ["MIDSIG_PRIVY_JWKS_URL"] = self._old_jwks_url
        else:
            os.environ.pop("MIDSIG_PRIVY_JWKS_URL", None)
        server._PRIVY_JWKS_URL = f"https://auth.privy.io/api/v1/apps/{APP_ID}/jwks.json"

    def test_static_pem_accepts_valid_token(self):
        os.environ["MIDSIG_PRIVY_VERIFICATION_KEY"] = self.pub_pem
        token = _sign_token(self.priv, _claims(), kid="whatever")
        self.assertEqual(server.current_user(f"Bearer {token}"), "did:privy:testuser")

    def test_static_pem_rejects_tampered_body(self):
        os.environ["MIDSIG_PRIVY_VERIFICATION_KEY"] = self.pub_pem
        token = _sign_token(self.priv, _claims(sub="did:privy:attacker"))
        tampered = token.split(".")[0] + "." + token.split(".")[1][:-1] + "x" + "." + token.split(".")[2]
        with self.assertRaises(HTTPException) as ctx:
            server.current_user(f"Bearer {tampered}")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_missing_token_is_401(self):
        with self.assertRaises(HTTPException) as ctx:
            server.current_user(None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_static_pem_missing_is_503(self):
        os.environ.pop("MIDSIG_PRIVY_VERIFICATION_KEY", None)
        server._jwks_cache = {}
        server._PRIVY_JWKS_URL = "file:///nonexistent/jwks.json"
        token = _sign_token(self.priv, _claims())
        with self.assertRaises(HTTPException) as ctx:
            server.current_user(f"Bearer {token}")
        self.assertEqual(ctx.exception.status_code, 503)

    def test_jwks_kid_matching_accepts_valid_token(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write(json.dumps({"keys": [_pub_jwk(self.priv.public_key())]}))
            path = fh.name
        try:
            server._PRIVY_JWKS_URL = f"file:///{path.replace(chr(92), '/')}"
            token = _sign_token(self.priv, _claims(), kid="test-kid-1")
            self.assertEqual(server.current_user(f"Bearer {token}"), "did:privy:testuser")
        finally:
            os.unlink(path)

    def test_jwks_rejects_unknown_kid(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write(json.dumps({"keys": [_pub_jwk(self.priv.public_key())]}))
            path = fh.name
        try:
            server._PRIVY_JWKS_URL = f"file:///{path.replace(chr(92), '/')}"
            other = ec.generate_private_key(ec.SECP256R1())
            token = _sign_token(other, _claims(), kid="test-kid-1")
            with self.assertRaises(HTTPException) as ctx:
                server.current_user(f"Bearer {token}")
            self.assertEqual(ctx.exception.status_code, 401)
        finally:
            os.unlink(path)

    def test_jwks_auth_failure_is_503(self):
        server._jwks_cache = {}
        server._PRIVY_JWKS_URL = "file:///nonexistent/jwks.json"
        token = _sign_token(self.priv, _claims(), kid="anything")
        with self.assertRaises(HTTPException) as ctx:
            server.current_user(f"Bearer {token}")
        self.assertEqual(ctx.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()