"""Milter personalities: verify (inbound enforcement) and sign (outbound stamping).

Both return (final_action_char, [(header_name, header_value), ...]) where the
action char is one of: 'a' accept, 'r' reject, 't' tempfail, 'd' discard.
"""

import configparser
import time

from . import core

ACTION_CHARS = {"accept": "a", "reject": "r", "tempfail": "t", "discard": "d"}


class _CachedLookup:
    """DNS TXT lookup with positive and negative caching."""

    def __init__(self, server, ttl=300):
        self.server = server
        self.ttl = ttl
        self._cache = {}

    def __call__(self, domain):
        now = time.time()
        entry = self._cache.get(domain)
        if entry and entry[0] > now:
            return entry[1]
        try:
            from . import dns

            records = dns.query_txt(
                f"{core.TXT_PREFIX}.{domain}", server=self.server
            )
        except Exception:
            records = []
            self._cache[domain] = (now + self.ttl // 2, [])
            return []
        self._cache[domain] = (now + self.ttl, records)
        return records


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

        if verdict == "pass":
            return "a", [self._auth_header("pass", "ok")]

        domain = None
        hmap, _ = core._header_map(core._split(eml)[0])
        domain = core._from_domain(hmap)
        if domain and domain in self.exempt_domains:
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

    if mode == "verify":
        handler = VerifyHandler(
            lookup=_CachedLookup(dns_server, ttl=cache_ttl),
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
