import base64
import os
import secrets
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from midsig import core, ed25519  # noqa: E402


class SMTPSink:
    """Minimal SMTP server that records the DATA payload."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.messages = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.sock.accept()
        f = conn.makefile("rb")
        conn.sendall(b"220 sink ESMTP\r\n")
        in_data = False
        data_lines = []
        while True:
            line = f.readline()
            if not line:
                break
            if in_data:
                if line == b".\r\n":
                    in_data = False
                    self.messages.append(b"".join(data_lines))
                    conn.sendall(b"250 queued\r\n")
                else:
                    data_lines.append(line)
                continue
            upper = line.upper()
            if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                conn.sendall(b"250-sink\r\n250 AUTH PLAIN\r\n")
            elif upper.startswith(b"AUTH"):
                conn.sendall(b"235 ok\r\n")
            elif upper.startswith(b"MAIL FROM") or upper.startswith(b"RCPT TO"):
                conn.sendall(b"250 ok\r\n")
            elif upper.startswith(b"DATA"):
                in_data = True
                data_lines = []
                conn.sendall(b"354 go\r\n")
            elif upper.startswith(b"QUIT"):
                conn.sendall(b"221 bye\r\n")
                break
            else:
                conn.sendall(b"250 ok\r\n")
        conn.close()

    def shutdown(self):
        self.sock.close()


class TestSend(unittest.TestCase):
    def test_send_signs_and_smtp_delivers(self):
        sink = SMTPSink()
        seed = secrets.token_bytes(32)
        domain = "example.com"

        import smtplib
        from unittest import mock

        from midsig.cli import cmd_send

        class Args:
            pass

        args = Args()
        args.sender = f"alice@{domain}"
        args.to = ["bob@receiver.org"]
        args.subject = "signed via CLI"
        args.body = "hello body"
        args.body_file = None
        args.smtp = "127.0.0.1"
        args.port = sink.port
        args.user = "u"
        args.password = "p"
        args.password_file = None
        args.postage_bits = 8
        args.starttls = False
        args.dry_run = False

        keyfile = os.path.join(os.path.dirname(__file__), "tmp-send-key.hex")
        with open(keyfile, "w") as fh:
            fh.write(seed.hex())
        args.key_file = keyfile

        with mock.patch("smtplib.SMTP_SSL", smtplib.SMTP):
            cmd_send(args)

        sink.shutdown()
        os.remove(keyfile)

        self.assertEqual(len(sink.messages), 1)
        raw = sink.messages[0].decode("utf-8", "replace")
        self.assertIn("x-midsig", raw.lower())
        self.assertIn("x-midsig-postage", raw.lower())

        pub = ed25519.public_key(seed)
        record = f"v=midsig1; k=ed25519; p={base64.b64encode(pub).decode()}"

        def lookup(d):
            return [record] if d == domain else []

        verdict, _ = core.verify_eml(raw, lookup, required_bits=8)
        self.assertEqual(verdict, "pass")

    def test_send_dry_run_authenticates_without_sending(self):
        sink = SMTPSink()
        seed = secrets.token_bytes(32)

        from unittest import mock

        import smtplib  # noqa: F401

        from midsig.cli import cmd_send

        class Args:
            pass

        args = Args()
        args.sender = "alice@example.com"
        args.to = ["bob@receiver.org"]
        args.subject = "never sent"
        args.body = ""
        args.body_file = None
        args.smtp = "127.0.0.1"
        args.port = sink.port
        args.user = "u"
        args.password = None
        args.password_file = "tmp-send-pass.txt"
        args.postage_bits = 0
        args.starttls = False
        args.dry_run = True

        keyfile = os.path.join(os.path.dirname(__file__), "tmp-send-key.hex")
        with open(keyfile, "w") as fh:
            fh.write(seed.hex())
        args.key_file = keyfile

        passfile = os.path.join(os.path.dirname(__file__), "tmp-send-pass.txt")
        with open(passfile, "w") as fh:
            fh.write("secret-app-password\n")
        args.password_file = passfile

        with mock.patch("smtplib.SMTP_SSL", smtplib.SMTP):
            cmd_send(args)

        sink.shutdown()
        os.remove(keyfile)
        os.remove(passfile)

        self.assertEqual(len(sink.messages), 0, "dry-run must not deliver mail")


if __name__ == "__main__":
    unittest.main()
