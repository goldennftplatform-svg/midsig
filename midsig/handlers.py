"""Milter personalities: verify (inbound enforcement) and sign (outbound stamping).

Both return (final_action_char, [(header_name, header_value), ...]) where the
action char is one of: 'a' accept, 'r' reject, 't' tempfail, 'd' discard.
"""

import configparser
import logging
import time

from . import core
from .dns import DnsUnavailable

log = logging.getLogger("midsig.handlers")

ACTION_CHARS = {"accept": "a", "reject": "r", "tempfail": "t", "discard": "d"}


class _CachedLookup:
    """DNS TXT lookup with positive and negative caching.

    NODATA ([]) is cached for the full TTL. A transport failure
    (DnsUnavailable) is cached for a short window but re-raised so the
    caller can tempfail instead of reading an outage as "no records" — a
    DNS outage must never hard-reject (bounce storm).
    """

    def __init__(self, server, ttl=300, doh=True):
        self.server = server
        self.ttl = ttl
        self.doh = doh
        self._cache = {}

    def __call__(self, domain):
        now = time.time()
        entry = self._cache.get(domain)
        if entry and entry[0] > now:
            if entry[1] is _UNAVAILABLE:
                raise DnsUnavailable(f"cached DNS outage for {domain}")
            return entry[1]
        try:
            from . import dns

            records = dns.query_txt(
                f"{core.TXT_PREFIX}.{domain}", server=self.server, doh=self.doh
            )
        except DnsUnavailable as exc:
            # do not hammer a dead resolver: remember briefly, but keep
            # deferring every message in the window, not rejecting it
            self._cache[domain] = (now + min(60, self.ttl // 2), _UNAVAILABLE)
            raise DnsUnavailable(str(exc)) from exc
        except Exception as exc:
            self._cache[domain] = (now + min(60, self.ttl // 2), _UNAVAILABLE)
            raise DnsUnavailable(f"DNS lookup failed: {exc}") from exc
        self._cache[domain] = (now + self.ttl, records)
        return records


_UNAVAILABLE = object()


def _eml_from_headers(headers):
    return "\r\n".join(f"{name}: {value}" for name, value in headers) + "\r\n\r\n"


class VerifyHandler:
    """Inbound: enforce MIDSIG per receiver policy."""

    def __init__(
        self,
        lookup,
        action="reject",
        required_bits=0,
        hostname="midsig",
        exempt_domains=(),
    ):
        self.lookup = lookup
        self.action = action
        self.required_bits = required_bits
        self.hostname = hostname
        self.exempt_domains = set(d.lower() for d in exempt_domains)

    def _auth_header(self, result, reason=""):
        value = f"{self.hostname}; midsig={result}"
        if reason:
            value += f' reason="{reason}"'
        return ("Authentication-Results", value)

    def on_eom(self, headers, client_host="", client_addr=""):
        eml = _eml_from_headers(headers)
        verdict, reasons = core.verify_eml(
            eml, self.lookup, required_bits=self.required_bits
        )
        reason = reasons[0] if reasons else ""
        domain = None
        hmap, _ = core._header_map(core._split(eml)[0])
        domain = core._from_domain(hmap) or "-"
        log.info(
            "verify domain=%s verdict=%s reason=%s client=%s",
            domain, verdict, reason or "-", client_addr or "-",
        )

        if verdict == "pass":
            return "a", [self._auth_header("pass", "ok")]

        if domain in self.exempt_domains:
            return "a", [self._auth_header("none", f"exempt domain {domain}")]

        if verdict == "error":
            # DNS trouble must not turn into a bounce storm: defer.
            if self.action == "reject":
                return "t", [self._auth_header("temperror", reason)]
            return "a", [self._auth_header("temperror", reason)]

        if self.action == "reject":
            return "r", [self._auth_header("fail", reason)]

        # tag mode: accept but annotate so downstream filters can act
        return "a", [self._auth_header("fail", reason)]


class SignHandler:
    """Outbound: stamp mail for every From-domain we hold a key for.

    `keys` maps domain -> 32-byte seed. Domains without a key pass through
    unsigned (deliberate: partial rollout on one MTA must not break mail).
    """

    def __init__(self, keys, postage_bits=0):
        self.keys = keys
        self.postage_bits = postage_bits

    def on_eom(self, headers, client_host="", client_addr=""):
        eml = _eml_from_headers(headers)
        raw_headers, _body = core._split(eml)
        hmap, _order = core._header_map(raw_headers)
        domain = core._from_domain(hmap)
        if not domain or domain not in self.keys:
            log.info("sign domain=%s verdict=unsigned client=%s", domain or "-", client_addr or "-")
            return "a", []

        signed = core.sign_eml(
            self.keys[domain], eml, postage_bits=self.postage_bits
        )
        new_raw, _ = core._split(signed)
        new_hmap, _ = core._header_map(new_raw)

        additions = []
        for name in ("message-id", "x-midsig", "x-midsig-postage"):
            old = core._first(hmap, name)
            new = core._first(new_hmap, name)
            if new and new != old:
                additions.append((name, new))
        log.info("sign domain=%s verdict=signed client=%s", domain, client_addr or "-")
        return "a", additions


# ------------------------------------------------------------------- config


def build_from_config(path):
    parser = configparser.ConfigParser()
    with open(path, "r", encoding="utf-8") as fh:
        parser.read_file(fh)
    section = parser["milter"]

    mode = section.get("mode", "verify")
    socket_spec = section.get("socket", "unix:/var/run/midsigd/midsigd.sock")
    hostname = section.get("hostname", "midsig")
    dns_server = section.get("dns_server", "8.8.8.8")
    cache_ttl = int(section.get("cache_ttl", "300"))
    doh = section.getboolean("doh", True)

    if mode == "verify":
        handler = VerifyHandler(
            lookup=_CachedLookup(dns_server, ttl=cache_ttl, doh=doh),
            action=section.get("action", "reject"),
            required_bits=int(section.get("required_bits", "0")),
            hostname=hostname,
            exempt_domains=_csv(section.get("exempt_domains", "")),
        )
    elif mode == "sign":
        keys = {}
        keys_dir = section.get("keys_dir")
        if keys_dir:
            import os

            for fname in os.listdir(keys_dir):
                if not fname.endswith(".hex"):
                    continue
                with open(os.path.join(keys_dir, fname), "r", encoding="utf-8") as fh:
                    seed = bytes.fromhex(fh.read().strip())
                keys[fname[:-4]] = seed
        handler = SignHandler(
            keys=keys, postage_bits=int(section.get("postage_bits", "0"))
        )
    else:
        raise ValueError(f"unknown mode: {mode!r}")

    return socket_spec, handler


def _csv(value):
    return [part.strip() for part in value.split(",") if part.strip()]
