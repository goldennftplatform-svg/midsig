"""Paid-postage HTTP API. Shares the SQLite ledger with the milter."""

from __future__ import annotations

import base64
import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from .core import _pubkey_from_txt
from .dns import DnsUnavailable, query_txt
from .postage.ledger import Ledger
from .postage import square as squarepay
from .postage.policy import (
    APP_ID,
    BASE_RECEIVER,
    BASE_USDC,
    BUNDLES,
    CARD_CENTS,
    Conflict,
    Rejected,
    SOL_RECEIVER,
    STAMP_UNITS,
    Unavailable,
    domain_name,
)

LEDGER_PATH = os.getenv("MIDSIG_LEDGER_PATH", "./ledger.db")
DOCS_DIR = os.getenv("MIDSIG_DOCS_DIR", os.path.join(os.path.dirname(__file__), "..", "docs"))
BASE_RPC = os.getenv("MIDSIG_BASE_RPC", "https://mainnet.base.org")

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://challenges.cloudflare.com 'wasm-unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https:; "
    "font-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self' https://square.link https://checkout.square.site; "
    "frame-ancestors 'none'; "
    "child-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org; "
    "frame-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org https://challenges.cloudflare.com; "
    "connect-src 'self' https://auth.privy.io wss://relay.walletconnect.com wss://relay.walletconnect.org "
    "wss://www.walletlink.org https://*.rpc.privy.systems https://explorer-api.walletconnect.com "
    "https://mainnet.base.org https://api.mainnet-beta.solana.com "
    "https://connect.squareup.com https://connect.squareupsandbox.com "
    "https://square.link https://checkout.square.site "
    "http://159.223.184.36:8767 https://mail.aisp.live https://midsig.aisp.live; "
    "worker-src 'self'; "
    "manifest-src 'self'"
)


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app = FastAPI(title="MIDSIG Paid Postage", version="0.2.0")
app.add_middleware(SecurityHeaders)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://midsig.aisp.live",
        "https://mail.aisp.live",
        "https://aisp.live",
        "http://127.0.0.1:8766",
        "http://127.0.0.1:8767",
        "http://159.223.184.36:8767",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ledger: Optional[Ledger] = None


def get_ledger() -> Ledger:
    global ledger
    if ledger is None:
        ledger = Ledger(LEDGER_PATH)
    return ledger


@app.on_event("startup")
def _startup():
    get_ledger()


def _b64url_json(segment: str) -> dict:
    pad = "=" * ((4 - len(segment) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def current_user(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in first")
    token = authorization[7:].strip()
    try:
        header, payload, _sig = token.split(".")
        claims = _b64url_json(payload)
        hdr = _b64url_json(header)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid access token")
    if hdr.get("alg") != "ES256":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unsupported token")
    if claims.get("iss") != "privy.io" or claims.get("aud") not in (APP_ID, [APP_ID]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token is not for this app")
    user_id = claims.get("sub")
    if not isinstance(user_id, str) or not user_id.startswith("did:privy:"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token is missing a user")
    return user_id


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, Conflict):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, Unavailable):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    if isinstance(exc, Rejected):
        return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))


class EnrollBody(BaseModel):
    domain: str


class OrderBody(BaseModel):
    domain: str
    chain: str
    bundle: str
    payer: str


class CreditBody(BaseModel):
    order_id: str
    tx_id: str


class CardOrderBody(BaseModel):
    domain: str = ""
    bundle: str


def _rpc(url: str, method: str, params: list) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "midsig/1.0"}
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        body = json.loads(resp.read().decode())
    if body.get("error"):
        raise Rejected(body["error"].get("message", "RPC error"))
    return body.get("result")


def _verify_base(order: dict, tx_id: str) -> dict:
    if not tx_id.startswith("0x") or len(tx_id) != 66:
        raise Rejected("Base transaction hash must be 32 bytes hex")
    tx = _rpc(BASE_RPC, "eth_getTransactionByHash", [tx_id])
    if not tx:
        raise Rejected("Transaction not found on Base")
    receipt = _rpc(BASE_RPC, "eth_getTransactionReceipt", [tx_id])
    if not receipt or receipt.get("status") != "0x1":
        raise Rejected("Transaction is not a successful Base settlement")
    if int(tx.get("chainId", "0x0"), 16) not in (0, 8453):
        raise Rejected("Transaction is not on Base")
    if (tx.get("to") or "").lower() != BASE_USDC.lower():
        raise Rejected("Transaction must call native USDC on Base")
    if (tx.get("from") or "").lower() != order["payer"]:
        raise Rejected("Transaction sender does not match the purchase order")
    data = (tx.get("input") or tx.get("data") or "").lower().replace("0x", "")
    expected = (
        "a9059cbb"
        + BASE_RECEIVER[2:].lower().zfill(64)
        + format(order["units"], "064x")
    )
    if not data.startswith(expected):
        raise Rejected("USDC transfer does not match this order's receiver and amount")
    return {
        "chain": "base",
        "order_id": order["id"],
        "units": order["units"],
        "tx_id": tx_id,
        "block": receipt.get("blockNumber"),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return RedirectResponse("/postage.html")


@app.post("/auth/verify")
def auth_verify(user_id: str = Depends(current_user)):
    return {"user_id": user_id, "authenticated": True}


@app.post("/domain/enroll")
def domain_enroll(body: EnrollBody, user_id: str = Depends(current_user)):
    try:
        domain = domain_name(body.domain)
        records = query_txt(f"_midsig.{domain}")
        pub = _pubkey_from_txt(records)
        if pub is None:
            raise Rejected("No valid _midsig TXT record for this domain")
        db = get_ledger()
        enrollment = db.enrollment(user_id, domain)
        account = db.activate_domain(enrollment, pub)
        return {
            "domain": account["domain"],
            "balance": account["balance"],
            "public_key": account["public_key"],
        }
    except DnsUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.post("/order/create")
def order_create(body: OrderBody, user_id: str = Depends(current_user)):
    try:
        db = get_ledger()
        order = db.create_order(user_id, body.domain, body.chain, body.payer, body.bundle)
        receiver = BASE_RECEIVER if order["chain"] == "base" else SOL_RECEIVER
        token = BASE_USDC if order["chain"] == "base" else None
        return {
            "order_id": order["id"],
            "domain": order["domain"],
            "chain": order["chain"],
            "bundle_stamps": order["stamps"],
            "units": order["units"],
            "usdc": f"{order['units'] / 1_000_000:.2f}",
            "receiver": receiver,
            "token": token,
            "payer": order["payer"],
            "expires": order["expires"],
            "status": order["status"],
        }
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.post("/order/credit")
def order_credit(body: CreditBody, user_id: str = Depends(current_user)):
    try:
        db = get_ledger()
        order = db.order(user_id, body.order_id)
        if order["chain"] != "base":
            raise Rejected("Solana settlement verification is not live yet; use Base USDC")
        proof = _verify_base(order, body.tx_id)
        result = db.credit(user_id, body.order_id, body.tx_id, proof)
        account = db.account(order["domain"], user_id)
        result["balance"] = account["balance"]
        result["domain"] = order["domain"]
        return result
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.get("/balance/{domain}")
def domain_balance(domain: str, user_id: str = Depends(current_user)):
    try:
        return get_ledger().account(domain_name(domain), user_id)
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.get("/inbox/{recipient}")
def inbox_list(recipient: str, user_id: str = Depends(current_user)):
    try:
        return {"messages": get_ledger().inbox(user_id, recipient)}
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.get("/me")
def me(user_id: str = Depends(current_user)):
    accounts = []
    total = 0
    for row in get_ledger().accounts(user_id):
        stamps = int(row["balance"]) // STAMP_UNITS
        total += stamps
        accounts.append({
            "domain": row["domain"],
            "stamps": stamps,
            "balance": row["balance"],
            "greenlit": row["public_key"] != "00" * 32,
        })
    return {"user_id": user_id, "stamps": total, "accounts": accounts}


@app.get("/order/{order_id}")
def get_order(order_id: str, user_id: str = Depends(current_user)):
    try:
        order = get_ledger().order(user_id, order_id)
        return {
            "order_id": order["id"],
            "domain": order["domain"],
            "stamps": order["stamps"],
            "status": order["status"],
            "chain": order["chain"],
        }
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


@app.post("/order/card")
def order_card(body: CardOrderBody, user_id: str = Depends(current_user)):
    try:
        if body.bundle not in CARD_CENTS:
            raise Rejected("Card checkout starts at $10")
        if not (body.domain or "").strip():
            raise Rejected("A sending domain is required")
        db = get_ledger()
        domain = domain_name(body.domain)
        pub_hex = None
        try:
            records = query_txt(f"_midsig.{domain}")
            pub = _pubkey_from_txt(records)
            if pub is not None:
                pub_hex = pub.hex()
        except DnsUnavailable:
            pub_hex = None
        db.claim_domain(user_id, domain, pub_hex)
        order = db.create_order(user_id, domain, "square", "square:card", body.bundle)
        redirect = "https://mail.aisp.live/postage.html?paid=1&order=" + order["id"]
        link = squarepay.create_payment_link(order, redirect)
        return {
            "order_id": order["id"],
            "domain": order["domain"],
            "stamps": order["stamps"],
            "usd": f"{link['cents'] / 100:.2f}",
            "checkout_url": link["checkout_url"],
        }
    except DnsUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    except (Rejected, Conflict, Unavailable) as exc:
        raise _http_error(exc)


@app.post("/webhooks/square")
async def square_webhook(
    request: Request,
    x_square_hmacsha256_signature: str = Header(None),
    x_square_signature: str = Header(None),
):
    body = await request.body()
    signature = x_square_hmacsha256_signature or x_square_signature or ""
    notify = os.getenv("SQUARE_WEBHOOK_URL", "https://mail.aisp.live/webhooks/square")
    if not squarepay.verify_webhook(body, signature, notify):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Square signature")
    try:
        payload = json.loads(body.decode())
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON")
    payment = ((payload.get("data") or {}).get("object") or {}).get("payment") or {}
    if payment.get("status") != "COMPLETED":
        return {"ok": True, "ignored": True}
    try:
        order_id = squarepay.payment_order_id(payment)
        db = get_ledger()
        order = db.order_by_id(order_id)
        if order["chain"] != "square":
            raise Rejected("Not a card order")
        amount = (payment.get("amount_money") or {}).get("amount")
        expected = squarepay.cents_for(squarepay._bundle_from_stamps(order["stamps"]))
        if amount != expected:
            raise Rejected("Paid amount does not match the stamp book")
        proof = {
            "chain": "square",
            "order_id": order_id,
            "units": order["units"],
            "cents": amount,
        }
        result = db.credit(order["user_id"], order_id, payment.get("id"), proof)
        return result
    except (Rejected, Conflict) as exc:
        raise _http_error(exc)


docs_path = os.path.abspath(DOCS_DIR)
if os.path.isdir(docs_path):
    @app.get("/postage.html")
    def postage_page():
        return FileResponse(os.path.join(docs_path, "postage.html"))

    app.mount("/", StaticFiles(directory=docs_path, html=True), name="docs")
