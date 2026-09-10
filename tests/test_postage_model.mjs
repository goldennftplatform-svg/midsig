import test from "node:test";
import assert from "node:assert/strict";
import { BUNDLES, STAMP_UNITS, ROUTES, selection, normalizeDomain, formatUsdc, previewReceipt } from "../docs/js/postage-model.mjs";

test("every bundle preserves the five-cent price without floating point", () => {
  const expected = [[20, "1.00", 1_000_000n], [100, "5.00", 5_000_000n], [200, "10.00", 10_000_000n], [500, "25.00", 25_000_000n]];
  BUNDLES.forEach((bundle, i) => {
    const result = selection(bundle.id, "base", "example.com");
    assert.deepEqual([result.stamps, result.usdc, result.units], expected[i]);
    assert.equal(result.units / BigInt(result.stamps), STAMP_UNITS);
  });
});

test("only configured native USDC routes are selectable", () => {
  for (const route of ["eth", "sol", "rh", "ethereum", "__proto__", "constructor", "testnet"]) {
    assert.throws(() => selection("starter", route, "example.com"));
  }
  for (const bundle of ["free", "-1", "1.5", "__proto__"]) {
    assert.throws(() => selection(bundle, "base", "example.com"));
  }
  assert.equal(ROUTES.base.chainId, "0x2105");
  assert.equal(ROUTES.base.receiver, "0x47cf60BdD877203264921D05CE26F81f6d36Aa3E");
  assert.equal(ROUTES.solana, undefined);
});

test("domains are canonicalized without interpreting addresses or URLs as domains", () => {
  assert.equal(normalizeDomain("  MAIL.Example.com. "), "mail.example.com");
  assert.equal(normalizeDomain("bücher.de"), "xn--bcher-kva.de");
  for (const domain of ["", "localhost", "alice@example.com", "https://example.com", "example.com/path",
    "example.com?x=1", "evil\\example.com", "127.0.0.1", "[::1]", "example.123", "bad..com",
    "-bad.com", "bad-.com", "a".repeat(64) + ".com", "<img>.com", "example.com\nmalicious.com"]) {
    assert.throws(() => normalizeDomain(domain), domain);
  }
});

test("price formatter rejects invalid or rounded monetary input", () => {
  assert.equal(formatUsdc(50_000n), "0.05");
  assert.equal(formatUsdc(0n), "0.00");
  for (const units of [50_000, -1n, 49_999n, "50000"]) assert.throws(() => formatUsdc(units));
});

test("downloaded previews can never be mistaken for paid or verified credits", () => {
  const receipt = previewReceipt(selection("regular", "base", "example.com"), "none");
  assert.equal(receipt.type, "midsig-checkout-preview");
  assert.equal(receipt.planned_usdc_units, "5000000");
  assert.equal(receipt.payment_status, "not_requested");
  assert.equal(receipt.credit_status, "not_created");
  assert.equal(receipt.domain_status, "not_verified");
  assert.equal(receipt.network_fee, null);
  assert.equal(receipt.total_payable, null);
  assert.equal(receipt.transaction_hash, undefined);
  assert.doesNotThrow(() => JSON.stringify(receipt));
});
