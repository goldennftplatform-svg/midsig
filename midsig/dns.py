"""Minimal DNS TXT lookup.

Primary path: raw UDP DNS query (no system resolver dependency, works through
custom resolvers). Fallback on Windows: `nslookup` subprocess parse, for
networks where raw outbound UDP/53 is blocked.
"""

import os
import random
import socket
import struct
import subprocess

DEFAULT_SERVER = os.environ.get("MIDSIG_DNS_SERVER", "8.8.8.8")


def query_txt(name, server=DEFAULT_SERVER, port=53, timeout=3):
    try:
        return _udp_query(name, server, port, timeout)
    except Exception:
        if os.name == "nt":
            return _nslookup(name)
        raise


def _udp_query(name, server, port, timeout):
    tid = random.randint(0, 65535)
    question = b""
    for label in name.rstrip(".").split("."):
        label = label.encode("ascii")
        question += bytes([len(label)]) + label
    question += b"\x00\x00\x10\x00\x01"  # type TXT, class IN

    packet = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != tid:
        raise ValueError("bad DNS response")

    _flags, qd, an, _ns, _ar = struct.unpack("!HHHHH", data[4:14])
    offset = 12

    def skip_name(buf, off):
        while True:
            length = buf[off]
            if length & 0xC0 == 0xC0:
                return off + 2
            if length == 0:
                return off + 1
            off += 1 + length

    for _ in range(qd):
        offset = skip_name(data, offset) + 4

    records = []
    for _ in range(an):
        offset = skip_name(data, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 16:  # TXT
            records.append(_decode_txt_rdata(rdata))
    return records


def _decode_txt_rdata(rdata):
    parts = []
    i = 0
    while i < len(rdata):
        length = rdata[i]
        parts.append(rdata[i + 1:i + 1 + length].decode("utf-8", "replace"))
        i += 1 + length
    return "".join(parts)


def _nslookup(name):
    out = subprocess.run(
        ["nslookup", "-type=TXT", name],
        capture_output=True, text=True, timeout=10,
    ).stdout
    records = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('"') and '"' in line[1:]:
            value = line.split('"')[1]
            if value:
                records.append(value)
        elif "text =" in line.lower():
            value = line.split("=", 1)[1].strip().strip('"')
            if value:
                records.append(value)
    if not records:
        raise ValueError(f"no TXT records for {name}")
    return records
