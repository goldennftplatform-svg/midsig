"""Pinned payment policy. Amounts are integer USDC base units, never floats."""

import re

APP_ID = "cmtvhjy3d01u50bkzpiwylxbp"
STAMP_UNITS = 50_000
BUNDLES = {"starter": 20, "regular": 100, "ten": 200, "stack": 500}
CARD_CENTS = {"ten": 1000, "stack": 2500}
CARD_MIN_CENTS = 1000
BASE_CHAIN_ID = 8453
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_RECEIVER = "0x47cf60BdD877203264921D05CE26F81f6d36Aa3E"
SOL_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOL_RECEIVER = "5S9tyrZwcgV127fEQMzCaBNWmEKz3iUBdASKaurBSGHU"
SOL_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
SOL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SOL_MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Rejected(ValueError):
    """A permanent invalid request, identity, payment, or message."""


class Unavailable(RuntimeError):
    """A dependency outage. Must not produce credits or a permanent mail bounce."""


class Pending(Unavailable):
    """A payment is not yet settled; the caller can retry the same transaction."""


class Conflict(Rejected):
    """An ownership, transaction reuse, or message identity conflict."""


def domain_name(value):
    if not isinstance(value, str) or len(value) > 253:
        raise Rejected("Invalid domain")
    value = value.strip().rstrip(".").lower()
    if "://" in value:
        host = value.split("://", 1)[1].split("/")[0].split("?")[0]
        value = host
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise Rejected("Invalid domain") from exc
    labels = value.split(".")
    if len(labels) < 2 or len(value) > 253 or not re.search("[a-z]", labels[-1]):
        raise Rejected("A complete sending domain is required")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise Rejected("Invalid domain")
    return value


def mailbox(value):
    if not isinstance(value, str) or len(value) > 254 or value.count("@") != 1:
        raise Rejected("Invalid envelope mailbox")
    local, domain = value.strip().split("@")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local):
        raise Rejected("Unsupported mailbox local part")
    return f"{local}@{domain_name(domain)}"


def evm_address(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise Rejected("A 20-byte EVM wallet address is required")
    if int(value[2:], 16) == 0:
        raise Rejected("The zero address is not a payer")
    return value.lower()


def base58_bytes(value, size):
    if not isinstance(value, str) or not 1 <= len(value) <= 90:
        raise Rejected("Invalid base58 value")
    number = 0
    try:
        for char in value:
            number = number * 58 + BASE58.index(char)
    except ValueError as exc:
        raise Rejected("Invalid base58 character") from exc
    result = b"\0" * (len(value) - len(value.lstrip("1")))
    result += number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(result) != size:
        raise Rejected("Invalid base58 byte length")
    return result


def public_key_hex(value):
    """An Ed25519 public key as exactly 64 lowercase hex characters."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise Rejected("An Ed25519 public key is 64 hex characters")
    return value.lower()


def payer_address(chain, value):
    if chain == "square":
        return "square:card"
    if chain == "base":
        value = evm_address(value)
        if value == BASE_RECEIVER.lower():
            raise Rejected("Self-transfers do not fund postage")
    elif chain == "solana":
        base58_bytes(value, 32)
        if value == SOL_RECEIVER:
            raise Rejected("Self-transfers do not fund postage")
    else:
        raise Rejected("Only card or native USDC on Base and Solana is supported")
    return value


def transfer_data(order):
    """ERC-20 transfer plus opaque 32-byte invoice reference in trailing calldata.

    The native USDC contract must be preflighted for this calldata form before
    payments are enabled. No domain, email, or message content goes on-chain.
    """
    if not re.fullmatch("[0-9a-f]{64}", order["id"]):
        raise Rejected("Invalid order reference")
    return "0xa9059cbb" + BASE_RECEIVER[2:].lower().zfill(64) + format(order["units"], "064x") + order["id"]
