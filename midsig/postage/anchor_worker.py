"""MidSig Base anchor worker.

Default behavior is DRY RUN. Broadcasting requires:
    MIDSIG_ANCHOR_BROADCAST=1
"""

import json
import os
import urllib.request

from eth_account import Account

from .anchor import batch_commitment, build_anchor_transaction
from .ledger import Ledger


BASE_RPC = os.getenv("MIDSIG_BASE_RPC", "https://mainnet.base.org")
CHAIN_ID = 8453


def rpc(method, params):
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode()

    req = urllib.request.Request(
        BASE_RPC,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "midsig-anchor/1.0",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(req, timeout=15) as response:
        result = json.loads(response.read().decode())

    if result.get("error"):
        raise RuntimeError(result["error"].get("message", "Base RPC error"))

    return result.get("result")


def load_private_key():
    path = os.getenv("MIDSIG_ANCHOR_KEY_FILE", "").strip()

    if not path:
        raise RuntimeError("MIDSIG_ANCHOR_KEY_FILE is not configured")

    with open(path, "r", encoding="ascii") as handle:
        key = handle.read().strip()

    if key.startswith("0x"):
        key = key[2:]

    if len(key) != 64:
        raise RuntimeError("Anchor key must be a 32-byte hex private key")

    int(key, 16)
    return "0x" + key


def confirm_submitted(db):
    confirmations_required = max(
        1,
        int(os.getenv("MIDSIG_BASE_CONFIRMATIONS", "2")),
    )

    submitted = db.submitted_anchor_receipts()
    if not submitted:
        return 0

    tx_ids = []
    seen = set()

    for row in submitted:
        tx_id = row.get("tx_id")
        if tx_id and tx_id not in seen:
            tx_ids.append(tx_id)
            seen.add(tx_id)

    latest_block = int(rpc("eth_blockNumber", []), 16)

    confirmed = 0

    for tx_id in tx_ids:
        receipt = rpc("eth_getTransactionReceipt", [tx_id])

        if receipt is None:
            print("ANCHOR_PENDING:", tx_id)
            continue

        status = int(receipt.get("status", "0x0"), 16)
        if status != 1:
            raise RuntimeError(
                f"Anchor transaction failed on Base: {tx_id}"
            )

        block_number = int(receipt["blockNumber"], 16)
        confirmations = latest_block - block_number + 1

        if confirmations < confirmations_required:
            print(
                "ANCHOR_CONFIRMING:",
                tx_id,
                f"{confirmations}/{confirmations_required}",
            )
            continue

        result = db.mark_anchor_confirmed(tx_id)

        print("ANCHOR_CONFIRMED")
        print("TX:", tx_id)
        print("BATCH:", result["batch_id"])
        print("RECEIPTS:", result["receipts"])
        print("CONFIRMATIONS:", confirmations)

        confirmed += 1

    return confirmed


def run():
    ledger_path = os.getenv(
        "MIDSIG_LEDGER_PATH",
        "/var/lib/midsig/ledger.db",
    )

    limit = max(
        1,
        min(int(os.getenv("MIDSIG_ANCHOR_BATCH_SIZE", "100")), 1000),
    )

    db = Ledger(ledger_path)

    confirm_submitted(db)

    receipts = db.pending_anchor_receipts(limit)

    if not receipts:
        print("ANCHOR_QUEUE_EMPTY")
        return 0

    batch = batch_commitment(receipts)
    key = load_private_key()
    account = Account.from_key(key)

    nonce_hex = rpc(
        "eth_getTransactionCount",
        [account.address, "pending"],
    )
    nonce = int(nonce_hex, 16)

    priority_hex = rpc("eth_maxPriorityFeePerGas", [])
    priority = int(priority_hex, 16)

    block = rpc("eth_getBlockByNumber", ["latest", False])
    base_fee = int(block["baseFeePerGas"], 16)

    # Give the next block room to move without creating an unlimited gas price.
    max_fee = base_fee * 2 + priority

    provisional = build_anchor_transaction(
        sender=account.address,
        batch=batch,
        nonce=nonce,
        gas_limit=100000,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=priority,
        chain_id=CHAIN_ID,
    )

    estimate_hex = rpc(
        "eth_estimateGas",
        [{
            "from": account.address,
            "to": account.address,
            "value": "0x0",
            "data": provisional["data"],
        }],
    )

    estimated = int(estimate_hex, 16)

    # 20% headroom over RPC estimate.
    gas_limit = max(21000, (estimated * 120 + 99) // 100)

    tx = build_anchor_transaction(
        sender=account.address,
        batch=batch,
        nonce=nonce,
        gas_limit=gas_limit,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=priority,
        chain_id=CHAIN_ID,
    )

    signed = Account.sign_transaction(tx, key)

    print("ANCHOR_BATCH_READY")
    print("ADDRESS:", account.address)
    print("COUNT:", batch["count"])
    print("ROOT:", batch["root"])
    print("BATCH:", batch["batch_id"])
    print("NONCE:", nonce)
    print("GAS_LIMIT:", gas_limit)
    print("MAX_FEE_WEI:", max_fee)
    print("MAX_COST_WEI:", gas_limit * max_fee)

    if os.getenv("MIDSIG_ANCHOR_BROADCAST", "0") != "1":
        print("BROADCAST: NO (DRY RUN)")
        return 0

    tx_hash = rpc(
        "eth_sendRawTransaction",
        ["0x" + signed.raw_transaction.hex()],
    )

    if not tx_hash:
        raise RuntimeError("Base RPC did not return a transaction hash")

    db.mark_anchor_submitted(
        [row["id"] for row in receipts],
        batch["batch_id"],
        tx_hash,
    )

    print("BROADCAST: YES")
    print("TX:", tx_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
