"""SQLite ledger. Settlement, debits, and durable inbox admission are atomic."""

import contextlib
import hashlib
import hmac
import json
import secrets
import sqlite3
import time

from .policy import BUNDLES, STAMP_UNITS, Conflict, Rejected, domain_name, payer_address


def prepaid_domain(user_id):
    return hashlib.sha256(user_id.encode()).hexdigest()[:16] + ".prepaid.midsig"


class Ledger:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    domain TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                    public_key TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),
                    created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS enrollments (
                    id TEXT PRIMARY KEY, domain TEXT NOT NULL, user_id TEXT NOT NULL,
                    expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS orders (
                    id TEXT PRIMARY KEY, domain TEXT NOT NULL REFERENCES accounts(domain),
                    user_id TEXT NOT NULL, chain TEXT NOT NULL, payer TEXT NOT NULL,
                    units INTEGER NOT NULL CHECK(units>0), stamps INTEGER NOT NULL,
                    created INTEGER NOT NULL, expires INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'created', tx_id TEXT,
                    proof TEXT, credited INTEGER,
                    UNIQUE(chain, tx_id)
                );
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY, domain TEXT NOT NULL REFERENCES accounts(domain),
                    delta INTEGER NOT NULL, kind TEXT NOT NULL, reference TEXT NOT NULL UNIQUE,
                    created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inbox (
                    id TEXT PRIMARY KEY, sender_domain TEXT NOT NULL,
                    message_id TEXT NOT NULL, recipient TEXT NOT NULL,
                    digest TEXT NOT NULL, eml BLOB NOT NULL,
                    created INTEGER NOT NULL, read_at INTEGER,
                    UNIQUE(sender_domain, message_id, recipient)
                );
                CREATE TABLE IF NOT EXISTS anchor_receipts (
                    id INTEGER PRIMARY KEY,
                    source TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    units INTEGER NOT NULL CHECK(units>0),
                    amount INTEGER NOT NULL CHECK(amount>=0),
                    currency TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    batch_id TEXT,
                    tx_id TEXT,
                    created INTEGER NOT NULL,
                    anchored INTEGER,
                    UNIQUE(source, source_id)
                );
                CREATE TABLE IF NOT EXISTS providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_user_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_domains (
                    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
                    domain TEXT NOT NULL,
                    added INTEGER NOT NULL,
                    PRIMARY KEY (provider_id, domain)
                );
                CREATE INDEX IF NOT EXISTS inbox_recipient ON inbox(recipient, created DESC);
                CREATE INDEX IF NOT EXISTS anchor_receipts_pending
                    ON anchor_receipts(status, created);
            """)

            columns = {
                row[1]
                for row in db.execute("PRAGMA table_info(anchor_receipts)")
            }
            if "tx_id" not in columns:
                db.execute(
                    "ALTER TABLE anchor_receipts ADD COLUMN tx_id TEXT"
                )

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextlib.contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def account(self, domain, user_id=None):
        with self.connect() as db:
            row = db.execute("SELECT * FROM accounts WHERE domain=?", (domain,)).fetchone()
        if row is None or (user_id is not None and row["user_id"] != user_id):
            raise Rejected("Verify ownership of this domain first")
        return dict(row)

    def accounts(self, user_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT domain,balance,public_key FROM accounts WHERE user_id=? ORDER BY domain", (user_id,)
            )]

    def enrollment(self, user_id, domain, now=None):
        now = int(time.time()) if now is None else now
        domain = domain_name(domain)
        with self.transaction() as db:
            existing = db.execute("SELECT user_id FROM accounts WHERE domain=?", (domain,)).fetchone()
            if existing and existing["user_id"] != user_id:
                raise Conflict("This domain is already linked to another account")
            db.execute("DELETE FROM enrollments WHERE expires<?", (now,))
            row = db.execute("SELECT * FROM enrollments WHERE domain=? AND user_id=? AND used=0", (domain, user_id)).fetchone()
            if row:
                return dict(row)
            if db.execute("SELECT count(*) FROM enrollments WHERE user_id=? AND used=0", (user_id,)).fetchone()[0] >= 10:
                raise Rejected("Too many pending domain enrollments")
            identifier = secrets.token_hex(32)
            db.execute("INSERT INTO enrollments(id,domain,user_id,expires) VALUES (?,?,?,?)", (identifier, domain, user_id, now + 86400))
        return {"id": identifier, "domain": domain, "user_id": user_id, "expires": now + 86400, "used": 0}

    def get_enrollment(self, user_id, identifier, now=None):
        now = int(time.time()) if now is None else now
        with self.connect() as db:
            row = db.execute("SELECT * FROM enrollments WHERE id=? AND user_id=?", (identifier, user_id)).fetchone()
        if row is None or row["expires"] < now:
            raise Rejected("Domain enrollment is missing or expired")
        return dict(row)

    def activate_domain(self, enrollment, public_key, now=None):
        """Call only after checking the DNS challenge or a domain-key signature."""
        now = int(time.time()) if now is None else now
        key = public_key.hex()
        with self.transaction() as db:
            challenge = db.execute("SELECT * FROM enrollments WHERE id=?", (enrollment["id"],)).fetchone()
            if not challenge or challenge["expires"] < now or challenge["user_id"] != enrollment["user_id"]:
                raise Rejected("Invalid domain enrollment")
            account = db.execute("SELECT * FROM accounts WHERE domain=?", (challenge["domain"],)).fetchone()
            if account and account["user_id"] != challenge["user_id"]:
                raise Conflict("Domain belongs to another account")
            if account:
                db.execute("UPDATE accounts SET public_key=? WHERE domain=?", (key, challenge["domain"]))
            else:
                db.execute("INSERT INTO accounts(domain,user_id,public_key,created) VALUES (?,?,?,?)", (challenge["domain"], challenge["user_id"], key, now))
            db.execute("UPDATE enrollments SET used=1 WHERE id=?", (challenge["id"],))
            prepaid = prepaid_domain(challenge["user_id"])
            if prepaid != challenge["domain"]:
                held = db.execute("SELECT balance FROM accounts WHERE domain=? AND user_id=?", (prepaid, challenge["user_id"])).fetchone()
                if held and held["balance"] > 0:
                    db.execute("UPDATE accounts SET balance=balance+? WHERE domain=?", (held["balance"], challenge["domain"]))
                    db.execute("UPDATE accounts SET balance=0 WHERE domain=?", (prepaid,))
                    db.execute("INSERT INTO entries(domain,delta,kind,reference,created) VALUES (?,?,?,?,?)", (challenge["domain"], held["balance"], "deposit", "prepaid:" + prepaid + ":" + str(now), now))
        return self.account(enrollment["domain"], enrollment["user_id"])

    def ensure_prepaid(self, user_id, now=None):
        now = int(time.time()) if now is None else now
        domain = prepaid_domain(user_id)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM accounts WHERE domain=?", (domain,)).fetchone()
            if row and row["user_id"] != user_id:
                raise Conflict("Prepaid account conflict")
            if not row:
                db.execute(
                    "INSERT INTO accounts(domain,user_id,public_key,created) VALUES (?,?,?,?)",
                    (domain, user_id, "00" * 32, now),
                )
        return self.account(domain, user_id)

    def claim_domain(self, user_id, domain, public_key_hex=None, now=None):
        """Green-light a sending domain for this user. First claim wins."""
        now = int(time.time()) if now is None else now
        domain = domain_name(domain)
        key = public_key_hex or ("00" * 32)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM accounts WHERE domain=?", (domain,)).fetchone()
            if row and row["user_id"] != user_id:
                raise Conflict("This domain is already green-lit by another account")
            if row:
                if public_key_hex and row["public_key"] == "00" * 32:
                    db.execute("UPDATE accounts SET public_key=? WHERE domain=?", (key, domain))
            else:
                db.execute(
                    "INSERT INTO accounts(domain,user_id,public_key,created) VALUES (?,?,?,?)",
                    (domain, user_id, key, now),
                )
        return self.account(domain, user_id)

    @staticmethod
    def _hash_key(secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    def create_provider(self, user_id, name, now=None):
        """Create a managed provider and return its one-time API credential."""
        now = int(time.time()) if now is None else now
        name = (name or "").strip()
        if not name or len(name) > 120:
            raise Rejected("A provider name is required")
        identifier = secrets.token_hex(16)
        secret = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute(
                "INSERT INTO providers(id,name,owner_user_id,key_hash,status,created) VALUES (?,?,?,?,?,?)",
                (identifier, name, user_id, self._hash_key(secret), "active", now),
            )
        return {"id": identifier, "name": name, "owner_user_id": user_id,
                "api_secret": f"{identifier}.{secret}", "created": now}

    def provider(self, provider_id, user_id=None):
        """Owner-only provider view. Same error for unknown and non-owned providers."""
        with self.connect() as db:
            row = db.execute("SELECT * FROM providers WHERE id=?", (provider_id,)).fetchone()
        if row is None or (user_id is not None and row["owner_user_id"] != user_id):
            raise Rejected("Provider not found")
        return dict(row)

    def provider_by_key(self, api_key):
        """Resolve the 'id.secret' credential. Constant-time secret comparison."""
        if not isinstance(api_key, str) or "." not in api_key:
            raise Rejected("Invalid provider API key")
        provider_id, _, secret = api_key.partition(".")
        if not provider_id or not secret:
            raise Rejected("Invalid provider API key")
        with self.connect() as db:
            row = db.execute("SELECT * FROM providers WHERE id=?", (provider_id,)).fetchone()
        if row is None or row["status"] != "active":
            raise Rejected("Provider API key is not active")
        if not hmac.compare_digest(self._hash_key(secret), row["key_hash"]):
            raise Rejected("Invalid provider API key")
        return dict(row)

    def rotate_provider_key(self, provider_id, user_id, now=None):
        """Rotate the credential. Old secrets stop working immediately."""
        self.provider(provider_id, user_id)
        secret = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute("UPDATE providers SET key_hash=? WHERE id=?", (self._hash_key(secret), provider_id))
        return {"id": provider_id, "api_secret": f"{provider_id}.{secret}"}

    def activate_provider_domain(self, provider_id, user_id, domain, public_key_hex=None, now=None):
        """Green-light a sending domain for a managed provider. One provider per domain."""
        now = int(time.time()) if now is None else now
        provider = self.provider(provider_id, user_id)
        domain = domain_name(domain)
        owned = self.claim_domain(user_id, domain, public_key_hex, now)
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM provider_domains WHERE domain=? AND provider_id!=?",
                (domain, provider_id),
            ).fetchone()
        if row is not None:
            raise Conflict("This domain is already managed by another provider")
        with self.transaction() as db:
            existing = db.execute(
                "SELECT added FROM provider_domains WHERE provider_id=? AND domain=?",
                (provider_id, domain),
            ).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO provider_domains(provider_id,domain,added) VALUES (?,?,?)",
                    (provider_id, domain, now),
                )
        return {
            "provider_id": provider_id,
            "domain": owned["domain"],
            "added": existing["added"] if existing else now,
        }

    def provider_domains(self, provider_id, user_id):
        """Provider's sending domains with live balance and stamp counts."""
        provider = self.provider(provider_id, user_id)
        with self.connect() as db:
            rows = db.execute(
                """SELECT d.domain AS domain, d.added AS added,
                          a.balance AS balance, a.public_key AS public_key
                   FROM provider_domains d
                   LEFT JOIN accounts a ON a.domain = d.domain
                   WHERE d.provider_id=?
                   ORDER BY d.added ASC""",
                (provider_id,),
            ).fetchall()
        return [{
            "domain": row["domain"],
            "added": row["added"],
            "balance": row["balance"] or 0,
            "stamps": (row["balance"] or 0) // STAMP_UNITS,
            "greenlit": bool(row["public_key"]) and row["public_key"] != "00" * 32,
        } for row in rows]

    def provider_usage(self, provider_id, user_id, since=None):
        """Aggregated deposits and mail spend across the provider's domains."""
        provider = self.provider(provider_id, user_id)
        domains = self.provider_domains(provider_id, user_id)
        since = 0 if since is None else int(since)
        by_domain = {}
        total_balance = 0
        if domains:
            names = [d["domain"] for d in domains]
            marks = ",".join("?" for _ in names)
            with self.connect() as db:
                rows = db.execute(
                    f"""SELECT domain, kind, SUM(delta) AS units
                        FROM entries WHERE domain IN ({marks}) AND created>=?
                        GROUP BY domain, kind""",
                    [*names, since],
                ).fetchall()
            for row in rows:
                by_domain.setdefault(row["domain"], {}).setdefault(row["kind"], 0)
                by_domain[row["domain"]][row["kind"]] += row["units"]
        spent_units = 0
        received_units = 0
        for domain in domains:
            total_balance += domain["balance"]
            spent_units += -by_domain.get(domain["domain"], {}).get("mail", 0)
            received_units += by_domain.get(domain["domain"], {}).get("deposit", 0)
        return {
            "provider_id": provider_id,
            "name": provider["name"],
            "domains": [{
                "domain": d["domain"],
                "balance": d["balance"],
                "stamps": d["stamps"],
                "greenlit": d["greenlit"],
            } for d in domains],
            "balance_units": total_balance,
            "stamps": total_balance // STAMP_UNITS,
            "spent_units": spent_units,
            "received_units": received_units,
            "since": since,
        }

    def create_order(self, user_id, domain, chain, payer, bundle=None, now=None, stamps=None):
        now = int(time.time()) if now is None else now
        domain = domain_name(domain)
        payer = payer_address(chain, payer)
        if stamps is None:
            if bundle not in BUNDLES:
                raise Rejected("Unknown stamp bundle")
            stamps = BUNDLES[bundle]
        else:
            if isinstance(stamps, bool) or not isinstance(stamps, int):
                raise Rejected("Stamp quantity must be an integer")
            if stamps < 20:
                raise Rejected("Base USDC checkout starts at $1")
            if stamps % 20:
                raise Rejected("Base USDC checkout uses $1 increments")
            if stamps > 20000:
                raise Rejected("Base USDC checkout is limited to $1,000 per order")
        with self.transaction() as db:
            account = db.execute("SELECT * FROM accounts WHERE domain=? AND user_id=?", (domain, user_id)).fetchone()
            if not account:
                raise Rejected("Verify this domain before buying postage")
            pending = db.execute("SELECT count(*) FROM orders WHERE user_id=? AND status='created' AND expires>?", (user_id, now)).fetchone()[0]
            if pending >= 10:
                raise Rejected("Too many open purchase orders; reuse an existing order")
            identifier = secrets.token_hex(32)
            ttl = 7200 if chain == "square" else 1800
            db.execute("""INSERT INTO orders(id,domain,user_id,chain,payer,units,stamps,created,expires)
                          VALUES (?,?,?,?,?,?,?,?,?)""", (identifier, domain, user_id, chain, payer, stamps * STAMP_UNITS, stamps, now, now + ttl))
        return self.order(user_id, identifier)

    def order_by_id(self, identifier):
        with self.connect() as db:
            row = db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise Rejected("Purchase order not found")
        return dict(row)

    def order(self, user_id, identifier):
        with self.connect() as db:
            row = db.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (identifier, user_id)).fetchone()
        if row is None:
            raise Rejected("Purchase order not found")
        return dict(row)

    def orders(self, user_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created DESC LIMIT 50", (user_id,))]

    def credit(self, user_id, identifier, tx_id, proof, now=None):
        """Call only with server-verified final chain proof. No HTTP manual credit path."""
        now = int(time.time()) if now is None else now
        with self.transaction() as db:
            order = db.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (identifier, user_id)).fetchone()
            if order is None:
                raise Rejected("Purchase order not found")
            if order["status"] == "credited":
                if order["tx_id"] != tx_id:
                    raise Conflict("Order already credited by another transaction")
                return {"status": "credited", "duplicate": True, "stamps": order["stamps"]}
            if proof.get("units") != order["units"] or proof.get("order_id") != identifier or proof.get("chain") != order["chain"]:
                raise Rejected("Settlement proof does not match purchase order")
            claimed = db.execute("SELECT id FROM orders WHERE chain=? AND tx_id=?", (order["chain"], tx_id)).fetchone()
            if claimed and claimed["id"] != identifier:
                raise Conflict("Transaction has already funded another purchase")
            db.execute("UPDATE orders SET status='credited',tx_id=?,proof=?,credited=? WHERE id=?", (tx_id, json.dumps(proof), now, identifier))
            db.execute("INSERT INTO entries(domain,delta,kind,reference,created) VALUES (?,?,?,?,?)", (order["domain"], order["units"], "deposit", "deposit:" + identifier, now))

            # Fiat/card settlement is off-chain, so queue a privacy-preserving
            # receipt for later batched anchoring on Base. Native Base payments
            # already have their own on-chain transaction as settlement proof.
            if order["chain"] == "square":
                receipt = {
                    "v": 1,
                    "source": "square",
                    "source_id": tx_id,
                    "order_id": identifier,
                    "domain": order["domain"],
                    "units": order["units"],
                    "amount": int(proof.get("cents") or 0),
                    "currency": "USD",
                    "created": now,
                }
                payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                receipt_hash = hashlib.sha256(payload.encode()).hexdigest()
                db.execute(
                    """INSERT OR IGNORE INTO anchor_receipts
                       (source,source_id,domain,units,amount,currency,receipt_hash,payload,status,created)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        "square", tx_id, order["domain"], order["units"],
                        receipt["amount"], "USD", receipt_hash, payload,
                        "pending", now,
                    ),
                )

            db.execute("UPDATE accounts SET balance=balance+? WHERE domain=?", (order["units"], order["domain"]))
        return {"status": "credited", "duplicate": False, "stamps": order["stamps"]}

    def admit(self, verified, eml, now=None):
        """Atomically charge a verified domain and persist the complete mail.

        The milter must discard its MTA copy ONLY after this transaction commits.
        Repeated identical SMTP attempts find the same durable message and do
        not charge again, including after a restart or a lost SMTP response.
        """
        now = int(time.time()) if now is None else now
        domain = verified["domain"]
        recipients = verified["recipients"]
        if not recipients or len(set(recipients)) != len(recipients):
            raise Rejected("Invalid recipient set")
        with self.transaction() as db:
            account = db.execute("SELECT * FROM accounts WHERE domain=?", (domain,)).fetchone()
            if not account or account["public_key"] != verified["public_key"]:
                raise Rejected("Sending domain is not enrolled with this signing key")
            found = []
            missing = []
            for recipient in recipients:
                row = db.execute("SELECT id,digest FROM inbox WHERE sender_domain=? AND message_id=? AND recipient=?", (domain, verified["message_id"], recipient)).fetchone()
                if row and row["digest"] != verified["digest"]:
                    raise Conflict("Message-ID was already used for different signed content")
                (found if row else missing).append(row["id"] if row else recipient)
            cost = len(missing) * STAMP_UNITS
            if account["balance"] < cost:
                raise Rejected("Insufficient postage: 0.05 USDC is required per recipient")
            for recipient in missing:
                identifier = hashlib.sha256(json.dumps([domain, verified["message_id"], recipient], separators=(",", ":")).encode()).hexdigest()
                db.execute("INSERT INTO inbox(id,sender_domain,message_id,recipient,digest,eml,created) VALUES (?,?,?,?,?,?,?)", (identifier, domain, verified["message_id"], recipient, verified["digest"], eml, now))
                db.execute("INSERT INTO entries(domain,delta,kind,reference,created) VALUES (?,?,?,?,?)", (domain, -STAMP_UNITS, "mail", "mail:" + identifier, now))
                found.append(identifier)
            db.execute("UPDATE accounts SET balance=balance-? WHERE domain=?", (cost, domain))
        return {"status": "stored", "message_ids": found, "charged_units": cost, "duplicate": not missing}

    def inbox(self, user_id, recipient):
        self.account(recipient.rsplit("@", 1)[1], user_id)
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,sender_domain,message_id,recipient,created,length(eml) AS bytes FROM inbox WHERE recipient=? ORDER BY created DESC LIMIT 100", (recipient,))]

    def message(self, user_id, identifier):
        with self.connect() as db:
            row = db.execute("SELECT * FROM inbox WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise Rejected("Message not found")
        self.account(row["recipient"].rsplit("@", 1)[1], user_id)
        return dict(row)

    def pending_anchor_receipts(self, limit=100):
        """Return oldest unanchored fiat receipts for deterministic batching."""
        limit = max(1, min(int(limit), 1000))
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM anchor_receipts
                   WHERE status='pending'
                   ORDER BY created ASC, id ASC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_anchor_submitted(self, receipt_ids, batch_id, tx_id):
        """Record the Base transaction immediately after successful broadcast."""
        if not receipt_ids:
            raise Rejected("Anchor batch is empty")

        ids = [int(x) for x in receipt_ids]
        marks = ",".join("?" for _ in ids)

        with self.transaction() as db:
            rows = db.execute(
                f"""SELECT id,status FROM anchor_receipts
                    WHERE id IN ({marks})""",
                ids,
            ).fetchall()

            if len(rows) != len(ids):
                raise Rejected("Anchor batch contains an unknown receipt")

            if any(row["status"] != "pending" for row in rows):
                raise Conflict("Anchor batch contains a non-pending receipt")

            db.execute(
                f"""UPDATE anchor_receipts
                    SET status='submitted',batch_id=?,tx_id=?
                    WHERE id IN ({marks})""",
                [batch_id, tx_id, *ids],
            )

        return {
            "status": "submitted",
            "batch_id": batch_id,
            "tx_id": tx_id,
            "receipts": len(ids),
        }

    def submitted_anchor_receipts(self, limit=1000):
        """Return receipts whose Base transaction is awaiting confirmation."""
        limit = max(1, min(int(limit), 5000))

        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM anchor_receipts
                   WHERE status='submitted'
                   ORDER BY created ASC,id ASC
                   LIMIT ?""",
                (limit,),
            ).fetchall()

            return [dict(row) for row in rows]

    def mark_anchor_confirmed(self, tx_id, anchored=None):
        """Mark every receipt in a confirmed Base transaction as anchored."""
        if not tx_id:
            raise Rejected("Anchor transaction id is required")

        anchored = int(time.time()) if anchored is None else int(anchored)

        with self.transaction() as db:
            rows = db.execute(
                """SELECT id,batch_id FROM anchor_receipts
                   WHERE status='submitted' AND tx_id=?""",
                (tx_id,),
            ).fetchall()

            if not rows:
                raise Rejected("Submitted anchor transaction not found")

            batch_ids = {row["batch_id"] for row in rows}
            if len(batch_ids) != 1:
                raise Conflict("Submitted transaction contains multiple batch ids")

            batch_id = next(iter(batch_ids))

            db.execute(
                """UPDATE anchor_receipts
                   SET status='anchored',anchored=?
                   WHERE status='submitted' AND tx_id=?""",
                (anchored, tx_id),
            )

        return {
            "status": "anchored",
            "batch_id": batch_id,
            "tx_id": tx_id,
            "receipts": len(rows),
            "anchored": anchored,
        }

