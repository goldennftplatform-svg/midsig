import base64
import secrets
import tempfile
import unittest
from pathlib import Path

from midsig import core, ed25519, handlers
from midsig.postage.ledger import Ledger
from midsig.postage.policy import STAMP_UNITS

BASE = (
    "From: Alice <alice@example.com>\r\n"
    "To: Bob <bob@receiver.org>\r\n"
    "Subject: paid\r\n"
    "Message-ID: <paid-1@example.com>\r\n\r\n"
    "Hello paid world!\r\n"
)


def lookup_for(seed):
    pub = ed25519.public_key(seed)
    rec = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"
    return lambda domain: [rec] if domain == "example.com" else []


class PaidMvpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "ledger.db")
        self.seed = secrets.token_bytes(32)
        self.pub = ed25519.public_key(self.seed).hex()
        self.ledger = Ledger(self.path)
        with self.ledger.transaction() as db:
            db.execute("INSERT INTO accounts(domain,user_id,public_key,balance,created) VALUES (?,?,?,?,?)",
                       ("example.com", "u", self.pub, 10 * STAMP_UNITS, 1))
        self.handler = handlers.VerifyHandler(lookup_for(self.seed), ledger_path=self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def parts(self, eml):
        raw, body = core._split(eml)
        return core._header_map(raw)[1], body

    def test_paid_v2_accepts_and_charges_envelope_recipient(self):
        signed = core.sign_eml(self.seed, BASE, recipients=["bob@receiver.org"])
        headers, body = self.parts(signed)
        action, _ = self.handler.on_eom(headers, recipients=["bob@receiver.org"], body=body)
        self.assertEqual(action, "a")
        self.assertEqual(self.ledger.account("example.com", "u")["balance"], 9 * STAMP_UNITS)

    def test_paid_v2_rejects_recipient_replay(self):
        signed = core.sign_eml(self.seed, BASE, recipients=["bob@receiver.org"])
        headers, body = self.parts(signed)
        action, _ = self.handler.on_eom(headers, recipients=["victim@receiver.org"], body=body)
        self.assertEqual(action, "r")
        self.assertEqual(self.ledger.account("example.com", "u")["balance"], 10 * STAMP_UNITS)

    def test_paid_v2_rejects_body_tamper(self):
        signed = core.sign_eml(self.seed, BASE, recipients=["bob@receiver.org"])
        headers, body = self.parts(signed)
        action, _ = self.handler.on_eom(headers, recipients=["bob@receiver.org"], body=body + "EVIL")
        self.assertEqual(action, "r")

    def test_v1_signature_is_not_enough_for_paid_gateway(self):
        signed = core.sign_eml(self.seed, BASE)
        headers, body = self.parts(signed)
        action, _ = self.handler.on_eom(headers, recipients=["bob@receiver.org"], body=body)
        self.assertEqual(action, "r")

if __name__ == "__main__":
    unittest.main()
