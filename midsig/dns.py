"""Minimal DNS TXT lookup with a three-leg fallback chain.

  1. raw UDP/53 to the configured resolver (works through custom resolvers)
  2. DNS-over-HTTPS via Cloudflare, Google, then AliDNS — for networks where
     outbound UDP/53 is blocked, mangled, or returns empty answers (measured:
     WSL2's DNS proxy silently answers empty for TXT even against 8.8.8.8)
  3. on Windows only: `nslookup` subprocess parse as a last resort

Callers must NOT treat a return value as proof of anything other than "these
transports answered". A resolver that replies empty is NODATA only when a
second, independent transport agrees. If no transport produces an answer at
all, this module raises DnsUnavailable — that is a *transport* failure, not a
verdict, and the milter must defer (tempfail), never hard-reject (a DNS outage
must not become a bounce storm).

DoH is disabled by setting MIDSIG_DOH=0 or doh=false in midsigd.conf.
"""

import os
import random
import socket
import struct
import subprocess

DEFAULT_SERVER = os.environ.get("MIDSIG_DNS_SERVER", "8.8.8.8")


class DnsUnavailable(Exception):
    """No DNS transport produced an answer (outage, blocking, network down)."""


def query_txt(name, server=DEFAULT_SERVER, port=53, timeout=3, doh=True):
    """Return TXT records for `name`, or [] for authoritative NODATA.

    Raises DnsUnavailable only when no trustworthy answer exists — that is
    the signal the milter turns into a tempfail/defer.
    """
    # ---- leg 1: raw UDP
    udp_error = False
    try:
        udp_records = _udp_query(name, server, port, timeout)
    except Exception:
        udp_records, udp_error = [], True
    if udp_records:
        return udp_records

    # ---- leg 2: DoH. An empty UDP answer is ambiguous (WSL2 answers empty
    # even for records that exist), so confirm it over independent transports.
    if doh:
        try:
            return _doh_query(name, timeout=timeout)  # records or authoritative NODATA
        except DnsUnavailable:
            pass
        # DoH is down and UDP said empty/errored: we cannot tell "no record"
        # from "resolver lying / network mangled" — defer, never hard-reject.
        raise DnsUnavailable(f"UDP empty or failed and DoH unreachable for {name}")

    # ---- DoH disabled: legacy behavior, trust the configured resolver
    if os.name == "nt" and not udp_records:
        return _nslookup(name)  # raises if no records (propagates as error)
    if udp_error:
        raise DnsUnavailable(f"no DNS transport answered for {name}")
    return udp_records


def _doh_query(name, timeout=4):
    """DNS-over-HTTPS JSON API (RFC 8484-adjacent / Google's JSON interface).

    Returns the TXT records from the first endpoint that answered with a
    well-formed response (that response is authoritative — NODATA included).
    Raises DnsUnavailable only if every endpoint failed at the transport or
    parse level.
    """
    import json
    import urllib.parse
    import urllib.request

    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    endpoints = (
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
        "https://dns.alidns.com/resolve",
    )
    failures = []
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(
                endpoint + "?" + query,
                headers={"Accept": "application/dns-json", "User-Agent": "midsig/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            records = []
            for answer in payload.get("Answer", []):
                data = answer.get("data")
                if answer.get("type") != 16 or not data:
                    continue
                txt = data.strip().strip('"')
                if txt:
                    records.append(txt)
            return records  # definitive: records or authoritative NODATA
        except Exception as exc:
            failures.append(f"{endpoint}: {exc}")
    raise DnsUnavailable("DoH unavailable: " + "; ".join(failures))


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
