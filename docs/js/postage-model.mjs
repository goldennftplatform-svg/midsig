// Public checkout data. This is not a payment verifier or a credit ledger.
export const STAMP_UNITS = 50_000n;
export const BUNDLES = Object.freeze([
  Object.freeze({ id: "starter", stamps: 20, title: "A little hello" }),
  Object.freeze({ id: "regular", stamps: 100, title: "Keep in touch" }),
  Object.freeze({ id: "ten", stamps: 200, title: "A book of stamps" }),
  Object.freeze({ id: "stack", stamps: 500, title: "The full stack" }),
]);
export const ROUTES = Object.freeze({
  card: Object.freeze({
    label: "Card", walletType: "none",
  }),
  base: Object.freeze({
    label: "USDC on Base", walletType: "evm", chainId: "0x2105",
    receiver: "0x47cf60BdD877203264921D05CE26F81f6d36Aa3E",
    token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  }),
  solana: Object.freeze({
    label: "USDC on Solana", walletType: "solana",
    receiver: "5S9tyrZwcgV127fEQMzCaBNWmEKz3iUBdASKaurBSGHU",
    token: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  }),
});

export function bundleById(id) {
  const bundle = BUNDLES.find(item => item.id === id);
  if (!bundle) throw new Error("Choose one of the available stamp bundles.");
  return bundle;
}

export function routeById(id) {
  if (!Object.hasOwn(ROUTES, id)) throw new Error("This payment route is not available.");
  return ROUTES[id];
}

export function formatUsdc(units) {
  if (typeof units !== "bigint" || units < 0n || units % 10_000n !== 0n) {
    throw new Error("Amount must be a non-negative whole number of USDC cents.");
  }
  return `${units / 1_000_000n}.${((units % 1_000_000n) / 10_000n).toString().padStart(2, "0")}`;
}

export function normalizeDomain(value) {
  const input = value.trim().replace(/\.$/, "");
  if (!input || /[\s@/:?#\\%]/u.test(input)) {
    throw new Error("Enter your sending domain, like yourdomain.com, without https:// or an email address.");
  }
  let domain;
  try { domain = new URL(`https://${input}`).hostname.toLowerCase(); }
  catch { throw new Error("That domain doesn't look right. Try yourdomain.com."); }
  const labels = domain.split(".");
  if (domain.length > 253 || labels.length < 2 ||
      labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      !/[a-z]/.test(labels.at(-1)) || domain !== domain.replace(/[\[\]]/g, "")) {
    throw new Error("Enter a complete sending domain, like yourdomain.com.");
  }
  return domain;
}

export function selection(bundleId, routeId, domain) {
  const bundle = bundleById(bundleId);
  const route = routeById(routeId);
  const units = BigInt(bundle.stamps) * STAMP_UNITS;
  return Object.freeze({
    bundleId, routeId, domain: normalizeDomain(domain), stamps: bundle.stamps,
    units, usdc: formatUsdc(units), route,
  });
}

export function previewReceipt(order, walletKind) {
  return {
    type: "midsig-checkout-preview", version: 1,
    payment_status: "not_requested", credit_status: "not_created",
    domain_status: "not_verified", domain: order.domain,
    network: order.routeId, token: "USDC", token_address: order.route.token,
    receiver: order.route.receiver, planned_stamps: order.stamps,
    planned_usdc_units: order.units.toString(), unit_price_usdc: "0.05",
    network_fee: null, total_payable: null, wallet_kind: walletKind,
    notice: "Preview only. No payment, usable stamps, transaction hash, or verified domain claim.",
  };
}
