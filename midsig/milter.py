"""Pure-Python milter protocol engine (Sendmail libmilter v6 wire format).

Implements the subset Postfix/Sendmail actually use, with zero dependencies.
One daemon, two personalities (see handlers.py): a *verify* milter that
enforces MIDSIG on inbound mail, and a *sign* milter that stamps outbound
mail. The wire protocol is identical for both.
"""

import socket
import struct
import threading

SMFI_VERSION = 6

# SMFIF_* action flags (what the filter may do at EOM)
SMFIF_ADDHDRS = 0x01
SMFIF_CHGBODY = 0x02
SMFIF_ADDRCPT = 0x04
SMFIF_DELRCPT = 0x08
SMFIF_CHGHDRS = 0x10

# SMFIP_* protocol flags (which callbacks the filter wants skipped)
SMFIP_NOCONNECT = 0x00000001
SMFIP_NOHELO = 0x00000002
SMFIP_NOMAIL = 0x00000004
SMFIP_NORCPT = 0x00000008
SMFIP_NOBODY = 0x00000010
SMFIP_NOHDRS = 0x00000020
SMFIP_NOEOH = 0x00000040


class MilterError(Exception):
    pass


def _pack(cmd, payload=b""):
    return cmd.encode("ascii") + struct.pack("!I", len(payload)) + payload


def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise MilterError("connection closed by MTA")
        buf += chunk
    return buf


class MilterSession:
    """One SMTP transaction through the milter protocol.

    Two wire formats exist in the wild:
      - "postfix":  [u32 length][1-byte command][payload]  (Postfix's milter)
      - "sendmail": [1-byte command][u32 length][payload]  (libmilter / Sendmail)
    Postfix is the default (verified against a live Postfix); Sendmail's format
    is kept for compatibility via style="sendmail".
    """

    def __init__(self, conn, handler, style="postfix"):
        self.conn = conn
        self.handler = handler
        self.style = style
        self.headers = []
        self.client_host = ""
        self.client_addr = ""

    # ------------------------------------------------------------- transport

    def _send(self, cmd, payload=b""):
        if self.style == "postfix":
            # Postfix frames: [u32 length][cmd][data], where length counts
            # the command byte plus the data bytes.
            self.conn.sendall(
                struct.pack("!I", 1 + len(payload)) + cmd.encode("ascii") + payload
            )
        else:
            self.conn.sendall(cmd.encode("ascii") + struct.pack("!I", len(payload)) + payload)

    def _recv(self):
        if self.style == "postfix":
            length = struct.unpack("!I", _read_exact(self.conn, 4))[0]
            body = _read_exact(self.conn, length)
            cmd = body[:1].decode("ascii")
            payload = body[1:]
        else:
            head = _read_exact(self.conn, 5)
            cmd = head[:1].decode("ascii")
            length = struct.unpack("!I", head[1:])[0]
            payload = _read_exact(self.conn, length) if length else b""
        return cmd, payload

    # ------------------------------------------------------------- protocol

    def run(self):
        try:
            self._negotiate()
            while True:
                cmd, payload = self._recv()
                if not self._dispatch(cmd, payload):
                    return
        except (MilterError, OSError, struct.error):
            return
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _negotiate(self):
        actions = SMFIF_ADDHDRS | SMFIF_CHGHDRS
        protocol = SMFIP_NOHELO | SMFIP_NOMAIL | SMFIP_NORCPT | SMFIP_NOBODY
        self._send("O", struct.pack("!III", SMFI_VERSION, actions, protocol))
        cmd, payload = self._recv()
        if cmd != "O":
            raise MilterError(f"expected OPTNEG reply from MTA, got {cmd!r}")

    def _dispatch(self, cmd, payload):
        if cmd == "C":  # connect: hostname\0family\0port\0address\0
            fields = payload.decode("utf-8", "replace").split("\0")
            self.client_host = fields[0] if fields else ""
            self.client_addr = fields[3] if len(fields) > 3 else ""
            self._send("c")
            return True
        if cmd == "H":  # helo (normally skipped via SMFIP_NOHELO)
            self._send("c")
            return True
        if cmd == "M":  # mail from (normally skipped)
            self._send("c")
            return True
        if cmd == "R":  # rcpt to (normally skipped)
            self._send("c")
            return True
        if cmd == "T":  # data phase marker
            self._send("c")
            return True
        if cmd == "D":  # macros — informational, no reply expected
            return True
        if cmd == "L":  # header: name\0value\0
            text = payload.decode("utf-8", "replace")
            name, sep, value = text.partition("\0")
            value = value.rstrip("\0").replace("\r\n", " ").replace("\n", " ")
            self.headers.append((name, value))
            self._send("c")
            return True
        if cmd == "N":  # end of headers
            self._send("c")
            return True
        if cmd == "E":  # end of message: verdict time
            self._finish()
            return False
        if cmd == "A":  # abort: reset, no reply
            return False
        if cmd in ("Q", "K"):  # quit
            try:
                self._send("c")
            except OSError:
                pass
            return False
        if cmd == "U":  # unknown command
            self._send("c")
            return True
        self._send("c")
        return True

    def _finish(self):
        action, addheaders = self.handler.on_eom(
            self.headers, client_host=self.client_host, client_addr=self.client_addr
        )
        for name, value in addheaders:
            payload = name.encode("utf-8") + b"\0" + value.encode("utf-8") + b"\0"
            self._send("m", payload)
        self._send(action)


# ------------------------------------------------------------------- daemon


def _listener(path):
    """path: 'unix:/var/run/x.sock' or 'inet:127.0.0.1:8891'."""
    if path.startswith("unix:"):
        import os

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(path[5:])
        except FileNotFoundError:
            pass
        sock.bind(path[5:])
        os.chmod(path[5:], 0o666)  # postfix runs as a different user
        sock.listen(64)
        return sock, None
    if path.startswith("inet:"):
        host, _, port = path[5:].rpartition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host or "127.0.0.1", int(port)))
        sock.listen(64)
        return sock, sock.getsockname()[:2]
    raise ValueError(f"unsupported socket spec: {path!r}")


class MilterServer:
    """Threaded milter server. `handler_factory` returns a fresh handler per
    connection (handlers carry per-connection state like collected headers).
    `style` selects the wire format: "postfix" (default) or "sendmail"."""

    def __init__(self, path, handler_factory, style="postfix"):
        self.path = path
        self.handler_factory = handler_factory
        self.style = style
        self._stop = threading.Event()
        self.sock, self.address = _listener(path)

    def serve_forever(self):
        while not self._stop.is_set():
            conn, _ = self.sock.accept()
            session = MilterSession(conn, self.handler_factory(), style=self.style)
            t = threading.Thread(target=session.run, daemon=True)
            t.start()

    def shutdown(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
