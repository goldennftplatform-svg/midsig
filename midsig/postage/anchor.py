"""MidSig fiat receipt batching and Merkle anchoring primitives."""

import hashlib


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def receipt_leaf(receipt_hash: str) -> bytes:
    """Convert the canonical SHA-256 receipt hash into a Merkle leaf."""
    try:
        raw = bytes.fromhex(receipt_hash)
    except ValueError as exc:
        raise ValueError("receipt hash must be hex") from exc

    if len(raw) != 32:
        raise ValueError("receipt hash must be 32 bytes")

    # Domain-separate leaves from internal nodes.
    return _sha256(b"\x00" + raw)


def merkle_root(receipt_hashes) -> str:
    """
    Deterministic SHA-256 Merkle root.

    Leaves preserve ledger order.
    Odd nodes are duplicated.
    Returns 0x-prefixed 32-byte root.
    """
    hashes = list(receipt_hashes)
    if not hashes:
        raise ValueError("cannot anchor an empty receipt batch")

    level = [receipt_leaf(h) for h in hashes]

    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])

        level = [
            _sha256(b"\x01" + level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]

    return "0x" + level[0].hex()


def batch_commitment(receipts) -> dict:
    """Create the public commitment for a batch of private fiat receipts."""
    rows = list(receipts)
    if not rows:
        raise ValueError("cannot anchor an empty receipt batch")

    root = merkle_root(row["receipt_hash"] for row in rows)

    batch_material = (
        "midsig-anchor-v1:"
        + root
        + ":"
        + str(len(rows))
    ).encode()

    batch_id = "0x" + hashlib.sha256(batch_material).hexdigest()

    return {
        "version": 1,
        "root": root,
        "batch_id": batch_id,
        "count": len(rows),
    }

ANCHOR_MAGIC = b"MIDSIG\x01"


def anchor_calldata(batch: dict) -> str:
    """
    Encode MidSig anchor payload for an EOA/self transaction.

    Layout:
      7 bytes  magic/version
      32 bytes Merkle root
      32 bytes batch id
      8 bytes  receipt count (big endian)
    """
    root = batch["root"]
    batch_id = batch["batch_id"]
    count = int(batch["count"])

    if not root.startswith("0x") or len(root) != 66:
        raise ValueError("invalid Merkle root")
    if not batch_id.startswith("0x") or len(batch_id) != 66:
        raise ValueError("invalid batch id")
    if count < 1:
        raise ValueError("invalid receipt count")

    payload = (
        ANCHOR_MAGIC
        + bytes.fromhex(root[2:])
        + bytes.fromhex(batch_id[2:])
        + count.to_bytes(8, "big")
    )

    return "0x" + payload.hex()


def build_anchor_transaction(
    sender: str,
    batch: dict,
    nonce: int,
    gas_limit: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    chain_id: int = 8453,
) -> dict:
    """Build an unsigned Base EIP-1559 self-transaction carrying the batch proof."""
    if not isinstance(sender, str) or not sender.startswith("0x") or len(sender) != 42:
        raise ValueError("invalid sender address")

    return {
        "type": 2,
        "chainId": int(chain_id),
        "nonce": int(nonce),
        "to": sender,
        "value": 0,
        "data": anchor_calldata(batch),
        "gas": int(gas_limit),
        "maxFeePerGas": int(max_fee_per_gas),
        "maxPriorityFeePerGas": int(max_priority_fee_per_gas),
    }
