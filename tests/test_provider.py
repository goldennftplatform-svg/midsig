import secrets
import tempfile
import unittest
from pathlib import Path

from midsig import core
from midsig.postage.ledger import Ledger
from midsig.postage.policy import STAMP_UNITS, Rejected, Conflict, public_key_hex


class ProviderLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "ledger.db")
        self.ledger = Ledger(self.path)
        self.owner = "did:privy:provider-owner"
        self.other = "did:privy:someone-else"
        self.pub = secrets.token_bytes(32).hex()

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_provider_returns_resolvable_credential(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        self.assertTrue(created["api_secret"].startswith(created["id"] + "."))
        resolved = self.ledger.provider_by_key(created["api_secret"])
        self.assertEqual(resolved["id"], created["id"])
        self.assertEqual(resolved["owner_user_id"], self.owner)
        self.assertEqual(resolved["status"], "active")
        # The secret never appears in stored state.
        self.assertEqual(self.ledger.provider(created["id"])["key_hash"].count("."), 0)

    def test_bad_credential_is_rejected(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        with self.assertRaises(Rejected):
            self.ledger.provider_by_key(created["id"] + ".wrongsecret")
        with self.assertRaises(Rejected):
            self.ledger.provider_by_key("nonsense")
        with self.assertRaises(Rejected):
            self.ledger.provider_by_key("")

    def test_provider_is_owner_scoped(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        with self.assertRaises(Rejected):
            self.ledger.provider(created["id"], user_id=self.other)

    def test_rotate_invalidates_old_credential(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        rotated = self.ledger.rotate_provider_key(created["id"], self.owner)
        with self.assertRaises(Rejected):
            self.ledger.provider_by_key(created["api_secret"])
        self.assertEqual(
            self.ledger.provider_by_key(rotated["api_secret"])["id"],
            created["id"],
        )

    def test_enroll_domain_greenlights_account(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        enrolled = self.ledger.activate_provider_domain(
            created["id"], self.owner, "example.com", self.pub
        )
        self.assertEqual(enrolled["domain"], "example.com")
        domains = self.ledger.provider_domains(created["id"], self.owner)
        self.assertEqual(len(domains), 1)
        self.assertTrue(domains[0]["greenlit"])
        self.assertEqual(domains[0]["stamps"], 0)
        self.assertEqual(self.ledger.account("example.com", self.owner)["public_key"], self.pub)

    def test_reenroll_same_domain_is_idempotent(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        first = self.ledger.activate_provider_domain(created["id"], self.owner, "example.com", self.pub)
        second = self.ledger.activate_provider_domain(created["id"], self.owner, "example.com", self.pub)
        self.assertEqual(first["added"], second["added"])
        self.assertEqual(len(self.ledger.provider_domains(created["id"], self.owner)), 1)

    def test_domain_cannot_be_managed_by_two_providers(self):
        first = self.ledger.create_provider(self.owner, "First")
        second = self.ledger.create_provider(self.owner, "Second")
        self.ledger.activate_provider_domain(first["id"], self.owner, "example.com", self.pub)
        with self.assertRaises(Conflict):
            self.ledger.activate_provider_domain(second["id"], self.owner, "example.com", self.pub)

    def test_cannot_claim_domain_owned_by_another_user(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        self.ledger.claim_domain(self.other, "example.com", self.pub)
        with self.assertRaises(Conflict):
            self.ledger.activate_provider_domain(created["id"], self.owner, "example.com", self.pub)

    def test_usage_aggregates_deposits_and_mail_spend(self):
        created = self.ledger.create_provider(self.owner, "AOL Mail Co")
        self.ledger.activate_provider_domain(created["id"], self.owner, "example.com", self.pub)
        with self.ledger.transaction() as db:
            db.execute("UPDATE accounts SET balance=? WHERE domain=?", (6 * STAMP_UNITS, "example.com"))
            db.execute("INSERT INTO entries(domain,delta,kind,reference,created) VALUES (?,?,?,?,?)",
                       ("example.com", 6 * STAMP_UNITS, "deposit", "deposit:test", 1))
        verified = {
            "domain": "example.com",
            "public_key": self.pub,
            "message_id": "<p1@example.com>",
            "recipients": ["bob@receiver.org"],
            "digest": core.content_digest("Hello Bob\r\n"),
        }
        self.ledger.admit(verified, b"raw eml bytes", now=2)
        usage = self.ledger.provider_usage(created["id"], self.owner, since=0)
        self.assertEqual(usage["received_units"], 6 * STAMP_UNITS)
        self.assertEqual(usage["spent_units"], STAMP_UNITS)
        self.assertEqual(usage["balance_units"], 5 * STAMP_UNITS)
        self.assertEqual(usage["stamps"], 5)
        self.assertEqual(usage["domains"][0]["stamps"], 5)

    def test_public_key_hex_validator(self):
        key = "ab" * 32
        self.assertEqual(public_key_hex(key.upper()), key)
        with self.assertRaises(Rejected):
            public_key_hex("ab" * 31)
        with self.assertRaises(Rejected):
            public_key_hex("zz" * 32)
        with self.assertRaises(Rejected):
            public_key_hex(key.upper() if False else None)


if __name__ == "__main__":
    unittest.main()