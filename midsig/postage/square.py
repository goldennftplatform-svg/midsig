"""Square hosted checkout. Secrets come from the environment, never the repo."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request

from .policy import CARD_CENTS, CARD_MIN_CENTS, Rejected, Unavailable

SQUARE_VERSION = "2026-08-19"


def configured():
    return bool(os.getenv("SQUARE_ACCESS_TOKEN") and os.getenv("SQUARE_LOCATION_ID"))


def api_root():
    if os.getenv("SQUARE_ENV", "sandbox") == "production":
        return "https://connect.squareup.com"
    return "https://connect.squareupsandbox.com"


def cents_for(bundle):
    if bundle not in CARD_CENTS:
        raise Rejected("Card checkout requires the $10 or $25 stamp book")
    cents = CARD_CENTS[bundle]
    if cents < CARD_MIN_CENTS:
        raise Rejected("Card purchases start at $10")
    return cents


def _request(method, path, payload=None):
    token = os.getenv("SQUARE_ACCESS_TOKEN")
    if not token:
        raise Unavailable("Card checkout is not configured")
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        api_root() + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Square-Version": SQUARE_VERSION,
            "User-Agent": "midsig/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise Unavailable(f"Square error {exc.code}: {body[:400]}") from exc


def create_payment_link(order, redirect_url):
    if not configured():
        raise Unavailable("Card checkout is not configured")
    location = os.getenv("SQUARE_LOCATION_ID")
    cents = cents_for(_bundle_from_stamps(order["stamps"]))
    payload = {
        "idempotency_key": order["id"],
        "quick_pay": {
            "name": f"MIDSIG postage · {order['stamps']} stamps",
            "price_money": {"amount": cents, "currency": "USD"},
            "location_id": location,
        },
        "checkout_options": {"redirect_url": redirect_url},
        "payment_note": order["id"],
    }
    result = _request("POST", "/v2/online-checkout/payment-links", payload)
    link = result.get("payment_link") or {}
    url = link.get("url")
    if not url:
        raise Unavailable("Square did not return a checkout URL")
    return {"checkout_url": url, "square_link_id": link.get("id"), "cents": cents}


def _bundle_from_stamps(stamps):
    from .policy import BUNDLES
    for name, count in BUNDLES.items():
        if count == stamps and name in CARD_CENTS:
            return name
    raise Rejected("This stamp book cannot be purchased with a card")


def verify_webhook(body: bytes, signature: str, notification_url: str) -> bool:
    key = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY", "")
    if not key or not signature:
        return False
    digest = hmac.new(key.encode(), (notification_url + body.decode("utf-8")).encode(), hashlib.sha256).digest()
    import base64
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)


def payment_order_id(payment: dict) -> str:
    note = payment.get("note") or ""
    if len(note) == 64 and all(c in "0123456789abcdef" for c in note):
        return note
    raise Rejected("Payment is missing an order reference")
