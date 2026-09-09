import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from midsig import ed25519  # noqa: E402


class TestEd25519RFC8032(unittest.TestCase):
    """Official RFC 8032 §7.1 test vectors."""

    def _check(self, secret_hex, pub_hex, msg_hex, sig_hex):
        secret = bytes.fromhex(secret_hex)
        pub = bytes.fromhex(pub_hex)
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        self.assertEqual(ed25519.public_key(secret), pub)
        self.assertEqual(ed25519.sign(secret, msg), sig)
        self.assertTrue(ed25519.verify(pub, msg, sig))
        self.assertFalse(ed25519.verify(pub, msg + b"x", sig))

    def test_vector_1_empty(self):
        self._check(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )

    def test_vector_2_one_byte(self):
        self._check(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )

    def test_vector_3_two_bytes(self):
        self._check(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        )

    def test_random_roundtrip(self):
        import secrets

        for _ in range(20):
            seed = secrets.token_bytes(32)
            msg = secrets.token_bytes(secrets.randbelow(200))
            pub = ed25519.public_key(seed)
            self.assertTrue(ed25519.verify(pub, msg, ed25519.sign(seed, msg)))


if __name__ == "__main__":
    unittest.main()
