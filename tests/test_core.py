import base64
import os
import secrets
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from midsig import core, ed25519  # noqa: E402

SAMPLE_EML = (
    "From: Alice Example <alice@example.com>\r\n"
    "To: Bob <bob@receiver.org>\r\n"
    "Subject: hello\r\n"
    "Message-ID: <abc123@example.com>\r\n"
    "\r\n"
    "Hello Bob!\r\n"
)


def _fake_lookup(seed):
    pub = ed25519.public_key(seed)
    record = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"

    def lookup(domain):
        if domain != "example.com":
            raise ValueError(f"NXDOMAIN {domain}")
        return [record]

    return lookup


class TestMidsig(unittest.TestCase):
    def setUp(self):
        self.seed = secrets.token_bytes(32)

    def test_sign_and_verify_pass(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML)
        verdict, reasons = core.verify_eml(signed, _fake_lookup(self.seed))
        self.assertEqual((verdict, reasons), ("pass", []))

    def test_unsigned_fails(self):
        verdict, reasons = core.verify_eml(SAMPLE_EML, _fake_lookup(self.seed))
        self.assertEqual(verdict, "fail")
        self.assertIn("missing X-Midsig header", reasons)

    def test_tampered_message_id_fails(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML)
        tampered = signed.replace("<abc123@example.com>", "<evil@example.com>")
        verdict, _ = core.verify_eml(tampered, _fake_lookup(self.seed))
        self.assertEqual(verdict, "fail")

    def test_spoofed_from_domain_fails(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML)
        spoofed = signed.replace("alice@example.com", "alice@bank.com")
        verdict, _ = core.verify_eml(spoofed, _fake_lookup(self.seed))
        self.assertEqual(verdict, "fail")

    def test_message_id_header_must_match_signed_identity(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML, postage_bits=8)
        original = "message-id: <abc123@example.com>\r\n"
        for replacement in ("message-id: <evil@example.com>\r\n", ""):
            with self.subTest(replacement=replacement):
                tampered = signed.replace(original, replacement, 1)
                self.assertNotEqual(tampered, signed)
                verdict, reasons = core.verify_eml(
                    tampered, _fake_lookup(self.seed), required_bits=8
                )
                self.assertEqual(verdict, "fail")
                self.assertIn("X-Midsig i= does not match Message-ID header", reasons)

    def test_domain_mismatch_fails(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML)
        swapped = signed.replace("d=example.com", "d=bank.com")
        verdict, reasons = core.verify_eml(swapped, _fake_lookup(self.seed))
        self.assertEqual(verdict, "fail")
        self.assertTrue(any("does not match" in r for r in reasons))

    def test_missing_dns_record_fails(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML)

        def lookup(domain):
            return []

        verdict, _ = core.verify_eml(signed, lookup)
        self.assertEqual(verdict, "fail")

    def test_postage_roundtrip(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML, postage_bits=8)
        verdict, reasons = core.verify_eml(signed, _fake_lookup(self.seed), required_bits=8)
        self.assertEqual((verdict, reasons), ("pass", []))

    def test_postage_required_but_missing(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML, postage_bits=0)
        verdict, reasons = core.verify_eml(signed, _fake_lookup(self.seed), required_bits=8)
        self.assertEqual(verdict, "fail")
        self.assertTrue(any("postage required" in r for r in reasons))

    def test_postage_difficulty_too_low(self):
        signed = core.sign_eml(self.seed, SAMPLE_EML, postage_bits=8)
        verdict, _ = core.verify_eml(signed, _fake_lookup(self.seed), required_bits=12)
        self.assertEqual(verdict, "fail")

    def test_postage_bound_to_message_id_and_domain(self):
        token = core.postage_stamp("example.com", "<a@example.com>", 1000, 8)
        self.assertTrue(core.check_postage("example.com", "<a@example.com>", 1000, token))
        self.assertFalse(core.check_postage("example.com", "<b@example.com>", 1000, token))
        self.assertFalse(core.check_postage("bank.com", "<a@example.com>", 1000, token))
        self.assertFalse(core.check_postage("example.com", "<a@example.com>", 1001, token))


if __name__ == "__main__":
    unittest.main()
