import base64
import secrets
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from midsig import core, ed25519, handlers, milter  # noqa: E402

SAMPLE_EML = (
    "From: Alice Example <alice@example.com>\r\n"
    "To: Bob <bob@receiver.org>\r\n"
    "Subject: hello\r\n"
    "Message-ID: <abc123@example.com>\r\n"
    "\r\n"
    "Hello Bob!\r\n"
)


def _stub_lookup(seed):
    pub = ed25519.public_key(seed)
    record = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"

    def lookup(domain):
        if domain != "example.com":
            return []
        return [record]

    return lookup


class FakeMTA:
    """Speaks the MTA side of the milter protocol against a running server.

    Default wire format is Postfix's ([u32 len][cmd][payload]); set
    sendmail_style=True for libmilter's ([cmd][u32 len][payload]).
    """

    def __init__(self, address, sendmail_style=False):
        self.sock = socket.create_connection(address, timeout=10)
        self.sendmail_style = sendmail_style

    def _send(self, cmd, payload=b""):
        if self.sendmail_style:
            frame = cmd.encode() + struct.pack("!I", len(payload)) + payload
        else:
            # postfix: length counts cmd byte + data
            frame = struct.pack("!I", 1 + len(payload)) + cmd.encode() + payload
        self.sock.sendall(frame)

    def _recv(self):
        if self.sendmail_style:
            head = self._read(5)
            cmd = head[:1].decode()
            length = struct.unpack("!I", head[1:])[0]
            payload = self._read(length) if length else b""
        else:
            length = struct.unpack("!I", self._read(4))[0]
            body = self._read(length)
            cmd = body[:1].decode()
            payload = body[1:]
        return cmd, payload

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("milter closed connection")
            buf += chunk
        return buf

    def negotiate(self):
        cmd, payload = self._recv()
        assert cmd == "O", f"expected filter OPTNEG, got {cmd}"
        self._send("O", struct.pack("!III", 6, 0x11, 0))
        return payload

    def deliver(self, headers, expect_reply_each=True):
        self._send("C", b"mta.example\0A\0ESMTP\0" + b"\0" * 8)
        for name, value in headers:
            self._send("L", name.encode() + b"\0" + value.encode() + b"\0")
        self._send("N")
        self._send("E")
        replies = []
        while True:
            cmd, payload = self._recv()
            replies.append((cmd, payload))
            if cmd in ("a", "r", "t", "d"):
                break
        return replies

    def close(self):
        self._send("Q")
        self.sock.close()


class _ServerThread(threading.Thread):
    def __init__(self, handler, style="postfix"):
        super().__init__(daemon=True)
        self.server = milter.MilterServer("inet:127.0.0.1:0", lambda: handler, style=style)

    def run(self):
        self.server.serve_forever()

    @property
    def address(self):
        return self.server.address


class TestVerifyMilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed = secrets.token_bytes(32)
        cls.seed = seed
        cls.server = _ServerThread(
            handlers.VerifyHandler(
                lookup=_stub_lookup(seed), action="reject", hostname="midsig.example"
            )
        )
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.server.shutdown()
        cls.server.join(timeout=2)

    def _signed_headers(self):
        eml = core.sign_eml(self.seed, SAMPLE_EML)
        return [(n, v) for n, v in core._header_map(core._split(eml)[0])[1]]

    def test_signed_message_accepted_with_auth_results(self):
        mta = FakeMTA(self.server.address)
        mta.negotiate()
        replies = mta.deliver(self._signed_headers())
        mta.close()
        actions = [c for c, _ in replies]
        self.assertEqual(actions[-1], "a")
        self.assertTrue(any(c == "h" for c, _ in replies))
        added = [p for c, p in replies if c == "h"]
        self.assertTrue(any(b"Authentication-Results" in p for p in added))
        self.assertTrue(any(b"midsig=pass" in p for p in added))

    def test_unsigned_message_rejected(self):
        mta = FakeMTA(self.server.address)
        mta.negotiate()
        headers = [(n, v) for n, v in core._header_map(core._split(SAMPLE_EML)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        self.assertEqual([c for c, _ in replies][-1], "r")

    def test_spoofed_domain_rejected(self):
        mta = FakeMTA(self.server.address)
        mta.negotiate()
        eml = SAMPLE_EML.replace("alice@example.com", "alice@bank.com")
        headers = [(n, v) for n, v in core._header_map(core._split(eml)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        self.assertEqual([c for c, _ in replies][-1], "r")

    def test_tag_mode_accepts_and_annotates(self):
        seed = secrets.token_bytes(32)
        srv = _ServerThread(
            handlers.VerifyHandler(
                lookup=_stub_lookup(seed), action="tag", hostname="midsig.example"
            )
        )
        srv.start()
        mta = FakeMTA(srv.address)
        mta.negotiate()
        headers = [(n, v) for n, v in core._header_map(core._split(SAMPLE_EML)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        srv.server.shutdown()
        self.assertEqual([c for c, _ in replies][-1], "a")
        added = [p for c, p in replies if c == "h"]
        self.assertTrue(any(b"midsig=fail" in p for p in added))

    def test_exempt_domain_passes(self):
        seed = secrets.token_bytes(32)
        srv = _ServerThread(
            handlers.VerifyHandler(
                lookup=_stub_lookup(seed),
                action="reject",
                exempt_domains=["example.com"],
            )
        )
        srv.start()
        mta = FakeMTA(srv.address)
        mta.negotiate()
        headers = [(n, v) for n, v in core._header_map(core._split(SAMPLE_EML)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        srv.server.shutdown()
        self.assertEqual([c for c, _ in replies][-1], "a")


class TestSignMilter(unittest.TestCase):
    def test_stamps_message(self):
        seed = secrets.token_bytes(32)
        srv = _ServerThread(handlers.SignHandler(keys={"example.com": seed}, postage_bits=0))
        srv.start()
        mta = FakeMTA(srv.address)
        mta.negotiate()
        headers = [(n, v) for n, v in core._header_map(core._split(SAMPLE_EML)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        srv.server.shutdown()
        self.assertEqual([c for c, _ in replies][-1], "a")
        added = dict()
        for c, p in replies:
            if c == "h":
                name, _, value = p.decode().partition("\0")
                added[name] = value
        self.assertIn("x-midsig", added)
        full = "\r\n".join(f"{n}: {v}" for n, v in headers) + "\r\n"
        full += "\r\n".join(f"{n}: {v}" for n, v in added.items()) + "\r\n\r\n"
        verdict, _ = core.verify_eml(full, _stub_lookup(seed))
        self.assertEqual(verdict, "pass")

    def test_unknown_domain_passes_through(self):
        seed = secrets.token_bytes(32)
        srv = _ServerThread(handlers.SignHandler(keys={"other.com": seed}))
        srv.start()
        mta = FakeMTA(srv.address)
        mta.negotiate()
        headers = [(n, v) for n, v in core._header_map(core._split(SAMPLE_EML)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        srv.server.shutdown()
        self.assertEqual([c for c, _ in replies][-1], "a")
        self.assertFalse(any(c == "h" for c, _ in replies))


class TestSendmailWireFormat(unittest.TestCase):
    """libmilter-style [cmd][len][data] framing still works when requested."""

    def test_sendmail_style_verifies(self):
        seed = secrets.token_bytes(32)
        srv = _ServerThread(
            handlers.VerifyHandler(lookup=_stub_lookup(seed), action="reject"),
            style="sendmail",
        )
        srv.start()
        mta = FakeMTA(srv.address, sendmail_style=True)
        mta.negotiate()
        eml = core.sign_eml(seed, SAMPLE_EML)
        headers = [(n, v) for n, v in core._header_map(core._split(eml)[0])[1]]
        replies = mta.deliver(headers)
        mta.close()
        srv.server.shutdown()
        self.assertEqual([c for c, _ in replies][-1], "a")


class TestHandlerDirect(unittest.TestCase):
    def test_verify_error_defers(self):
        seed = secrets.token_bytes(32)
        eml = core.sign_eml(seed, SAMPLE_EML)

        def flaky(domain):
            raise RuntimeError("dns down")

        handler = handlers.VerifyHandler(lookup=flaky, action="reject")
        headers = [(n, v) for n, v in core._header_map(core._split(eml)[0])[1]]
        action, added = handler.on_eom(headers)
        self.assertEqual(action, "t")
        self.assertTrue(any(b"midsig=temperror" in v.encode() for n, v in added))


class TestMilterShutdown(unittest.TestCase):
    def test_listener_stops_cleanly_after_a_connection(self):
        server = milter.MilterServer(
            "inet:127.0.0.1:0", lambda: handlers.VerifyHandler(lookup=lambda _: [])
        )
        errors = []

        def run():
            try:
                server.serve_forever()
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            mta = FakeMTA(server.address)
            mta.negotiate()
            mta.close()
        finally:
            server.shutdown()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), "listener remained blocked after shutdown")
        self.assertEqual(errors, [], "closing the listener leaked a thread exception")


if __name__ == "__main__":
    unittest.main()
