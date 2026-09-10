import { bundleById, formatUsdc, STAMP_UNITS, routeById, selection, previewReceipt } from "./postage-model.mjs";
import { PRIVY_SETTINGS } from "./privy-settings.mjs";

// Deliberately preview-only. There are no signing, sending, approval, swap,
// credit-balance, or wallet-network mutation methods anywhere in this controller.
const $ = id => document.getElementById(id);
const form = $("postage-form");
const storageKey = "midsig.checkout.preferences.v1";
const evmProviders = new Map();
const state = { wallet: null, cleanup: null, attempt: 0, busy: false, order: null, receipt: null };
let privySession = { authenticated: false, userId: null, accessToken: null };
const API_BASE = (location.hostname === "mail.aisp.live")
  ? ""
  : "https://mail.aisp.live";
const shortAddress = address => `${address.slice(0, 6)}…${address.slice(-4)}`;
const bundleId = () => form.elements.bundle.value;
const routeId = () => form.elements.route.value;

function showMessage(id, message) {
  $(id).textContent = message;
  $(id).hidden = !message;
}

function invalidateOrder() {
  state.order = null;
  state.receipt = null;
  $("page-status").textContent = "";
  for (const id of ["review-dialog", "done-dialog"]) {
    if ($(id).open) $(id).close();
  }
}

function savePreferences() {
  // UI preferences only. Never persist a wallet authorization, claimed balance,
  // receipt as proof of payment, or a live-mode toggle in browser storage.
  const preferences = {
    bundle: bundleId(), route: routeId(), domain: $("sending-domain").value.trim(),
  };
  try { localStorage.setItem(storageKey, JSON.stringify(preferences)); } catch { /* private mode */ }
}

function restorePreferences() {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey));
    if (!saved || typeof saved !== "object") return;
    try { bundleById(saved.bundle); if (saved.bundle === "ten" || saved.bundle === "stack") form.elements.bundle.value = saved.bundle; } catch { /* default */ }
    form.elements.route.value = "card";
    if (typeof saved.domain === "string" && saved.domain.length <= 253) {
      $("sending-domain").value = saved.domain;
    }
  } catch { /* damaged or unavailable storage must not break checkout */ }
}

function render() {
  const bundle = bundleById(bundleId());
  $("art-count").textContent = bundle.stamps;
  $("summary-stamps").textContent = `${bundle.stamps} stamps`;
  const usd = `$${(bundle.stamps * 5 / 100).toFixed(2)}`;
  $("summary-amount").textContent = usd;
  if ($("summary-due")) $("summary-due").textContent = usd;
  $("checkout-button-label").textContent = privySession.authenticated
    ? `Pay ${usd} with card`
    : `Sign in to pay ${usd}`;
  $("checkout-button").disabled = false;
  $("wallet-status").textContent = state.wallet
    ? `${state.wallet.name} · ${shortAddress(state.wallet.address)}`
    : "No wallet needed to try it";
  $("connect-wallet").textContent = state.wallet ? "Disconnect" : "Connect wallet ↗";
}

function disconnect(message = "") {
  state.attempt += 1;
  state.busy = false;
  if (state.cleanup) state.cleanup();
  state.cleanup = null;
  state.wallet = null;
  invalidateOrder();
  showMessage("wallet-notice", message);
  render();
}

function watchWallet(provider) {
  const events = ["accountsChanged", "accountChanged", "chainChanged", "disconnect"];
  const onChange = () => {
    disconnect("Your wallet account or network changed. Reconnect to refresh it. No funds were requested.");
    if ($("wallet-dialog").open) $("wallet-dialog").close();
  };
  if (typeof provider.on !== "function") return () => {};
  for (const name of events) provider.on(name, onChange);
  return () => {
    for (const name of events) provider.removeListener?.(name, onChange);
  };
}

function walletError(error) {
  if (error?.code === 4001 || /reject|declin|cancel/i.test(error?.message || "")) {
    return "Connection cancelled. You can try again or preview without a wallet.";
  }
  if (error?.code === -32002) return "Your wallet already has a request open. Check its window.";
  if (error?.message === "timeout") return "Your wallet didn't respond. Close its pending request and try again.";
  return "Couldn't connect to that wallet. Unlock it and try again, or continue without one.";
}

async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), 45_000); }),
    ]);
  } finally { clearTimeout(timer); }
}

async function connect(option) {
  if (state.busy) return;
  const attempt = ++state.attempt;
  state.busy = true;
  showMessage("wallet-error", "");
  renderWalletOptions();
  try {
    let address, chainId;
    if (option.kind === "evm") {
      const accounts = await bounded(option.provider.request({ method: "eth_requestAccounts" }));
      if (!Array.isArray(accounts) || !/^0x[0-9a-fA-F]{40}$/.test(accounts[0] || "")) {
        throw new Error("invalid address");
      }
      address = accounts[0];
      chainId = await bounded(option.provider.request({ method: "eth_chainId" }));
    } else {
      const result = await bounded(option.provider.connect());
      address = (result?.publicKey || option.provider.publicKey)?.toString();
      if (typeof address !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
        throw new Error("invalid address");
      }
    }
    if (attempt !== state.attempt || !$("wallet-dialog").open) return;
    state.wallet = { address, chainId, kind: option.kind, name: option.name };
    state.cleanup = watchWallet(option.provider);
    showMessage("wallet-notice", option.kind === "evm" && chainId !== "0x2105"
      ? "Your wallet is on another network. Live Base checkout will need Base; this preview won't switch networks or request funds."
      : "Read-only connection. No ownership proof, signature, or payment requested.");
    $("wallet-dialog").close();
    render();
  } catch (error) {
    if (attempt === state.attempt && $("wallet-dialog").open) showMessage("wallet-error", walletError(error));
  } finally {
    if (attempt === state.attempt) {
      state.busy = false;
      renderWalletOptions();
    }
  }
}

function availableWallets() {
  if (routeId() === "base") {
    const options = [...evmProviders.values()];
    const legacy = window.ethereum;
    if (legacy?.request && !options.some(option => option.provider === legacy)) {
      options.push({ name: "Browser Ethereum wallet", provider: legacy, kind: "evm" });
    }
    return options;
  }
  const options = [];
  for (const [name, provider] of [
    ["Phantom", window.phantom?.solana], ["Solflare", window.solflare],
    ["Browser Solana wallet", window.solana],
  ]) {
    if (typeof provider?.connect === "function" && !options.some(option => option.provider === provider)) {
      options.push({ name, provider, kind: "solana" });
    }
  }
  return options;
}

function renderWalletOptions() {
  const container = $("wallet-options");
  container.replaceChildren();
  const options = availableWallets();
  if (!options.length) {
    const empty = document.createElement("p");
    empty.className = "wallet-empty";
    empty.textContent = routeId() === "base"
      ? "No Base-compatible browser wallet detected. Open this page in your wallet's browser, or try the preview without connecting."
      : "No Phantom or Solflare browser wallet detected. Open this page in your wallet's browser, or try the preview without connecting.";
    container.append(empty);
  }
  for (const option of options) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "wallet-option";
    button.disabled = state.busy;
    // Provider-supplied labels are untrusted text. Do not render provider icons,
    // HTML, or arbitrary installation/deep-link URLs supplied by extensions.
    button.textContent = state.busy ? "Check your wallet…" : option.name;
    button.addEventListener("click", () => connect(option));
    container.append(button);
  }
}

window.addEventListener("eip6963:announceProvider", event => {
  const detail = event.detail;
  if (!detail || typeof detail.provider?.request !== "function" ||
      typeof detail.info?.uuid !== "string" || typeof detail.info?.name !== "string") return;
  if (evmProviders.size >= 16 && !evmProviders.has(detail.info.uuid)) return;
  evmProviders.set(detail.info.uuid, {
    name: detail.info.name.slice(0, 60), provider: detail.provider, kind: "evm",
  });
  if ($("wallet-dialog").open && !state.busy) renderWalletOptions();
});
window.dispatchEvent(new Event("eip6963:requestProvider"));

$("connect-wallet").addEventListener("click", () => {
  if (state.wallet) { disconnect("Wallet disconnected from this page."); return; }
  showMessage("wallet-error", "");
  renderWalletOptions();
  $("wallet-dialog").showModal();
  window.dispatchEvent(new Event("eip6963:requestProvider"));
});
$("skip-wallet").addEventListener("click", () => $("wallet-dialog").close());
$("wallet-dialog").addEventListener("close", () => {
  state.attempt += 1;
  state.busy = false;
});

form.addEventListener("change", event => {
  if (event.target.name === "route") {
    disconnect("Payment route changed. You can reconnect a compatible wallet or continue the preview without one.");
  } else invalidateOrder();
  savePreferences();
  render();
});
$("sending-domain").addEventListener("input", () => {
  $("sending-domain").removeAttribute("aria-invalid");
  showMessage("domain-error", "");
  invalidateOrder();
});

form.addEventListener("submit", event => {
  event.preventDefault();
  let order;
  try { order = selection(bundleId(), routeId(), $("sending-domain").value); }
  catch (error) {
    showMessage("domain-error", error.message);
    $("sending-domain").setAttribute("aria-invalid", "true");
    $("sending-domain").focus();
    return;
  }
  $("sending-domain").value = order.domain;
  $("sending-domain").removeAttribute("aria-invalid");
  showMessage("domain-error", "");
  savePreferences();
  state.order = order;
  state.receipt = null;
  $("review-domain").textContent = `${order.domain} · not verified`;
  $("review-stamps").textContent = `${order.stamps} stamps`;
  $("review-route").textContent = order.route.label;
  $("review-amount").textContent = `$${(order.stamps * 5 / 100).toFixed(2)}`;
  $("review-dialog").showModal();
});

async function api(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (privySession.accessToken) headers.Authorization = `Bearer ${privySession.accessToken}`;
  const response = await fetch(`${API_BASE}${path}`, {
    method: body ? "POST" : "GET",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || data.message || `Request failed (${response.status})`);
  return data;
}

$("finish-preview").addEventListener("click", async () => {
  if (!state.order) { $("review-dialog").close(); return; }
  if (!privySession.authenticated || !privySession.accessToken) {
    showMessage("domain-error", "Sign in with email first, then pay with your card.");
    $("review-dialog").close();
    return;
  }
  $("finish-preview").disabled = true;
  try {
    const created = await api("/order/card", {
      domain: state.order.domain,
      bundle: state.order.bundleId,
    });
    window.location.href = created.checkout_url;
  } catch (error) {
    showMessage("domain-error", error.message);
    $("review-dialog").close();
  } finally {
    $("finish-preview").disabled = false;
  }
});

$("download-preview").addEventListener("click", () => {
  if (!state.receipt) return;
  const blob = new Blob([JSON.stringify(state.receipt, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "midsig-checkout-PREVIEW.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
});

for (const button of document.querySelectorAll("[data-close]")) {
  button.addEventListener("click", () => $(button.dataset.close).close());
}
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", event => {
    const rect = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right ||
        event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
  });
}
restorePreferences();
render();
$("page-status").textContent = location.hostname === "mail.aisp.live"
  ? ""
  : "Live checkout: https://mail.aisp.live/postage.html";

// The independently built React island is loaded only when an operator has
// supplied the public App ID. It does not enable payment or domain verification.
if (PRIVY_SETTINGS.appId) {
  const root = $("privy-auth-root");
  root.hidden = false;
  root.textContent = "Loading Privy sign-in…";
  document.querySelector(".preview-notice span").textContent =
    "Sign in with email, enter the domain you send from, then pay with a card. $10 minimum.";
  document.querySelector(".under-button").textContent = "Card checkout. No wallet. No crypto.";
  $("browser-wallet-row").hidden = true;
  import("../privy/privy-entry.js").then(({ mountPrivy }) => {
    mountPrivy({
      appId: PRIVY_SETTINGS.appId, clientId: PRIVY_SETTINGS.clientId || undefined, container: root,
      onSession: session => {
        if (session.userId !== privySession.userId || session.authenticated !== privySession.authenticated) invalidateOrder();
        privySession = session;
      },
    });
  }).catch(() => {
    root.textContent = "Privy sign-in is unavailable. You can still preview postage without logging in.";
    root.className = "field-help";
    $("browser-wallet-row").hidden = false;
  });
}
