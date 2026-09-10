# Privy setup for MIDSIG checkout

Privy provides email/wallet login, embedded wallets, and wallet transaction UX.
It is not the MIDSIG postage ledger, a proof of sending-domain ownership, or an
automatic Pond0x integration. The integration here is **login only**; mainnet
postage purchases remain disabled.

## Dashboard steps

1. Create a MIDSIG app at <https://dashboard.privy.io/>.
2. Enable **Email** and **Wallet** login, including **Sign in with Solana / Solana
   wallet authentication**. The frontend supports EVM (Base) and Solana, with
   embedded wallets for users who do not already have wallets.
3. Configure the allowed origins for the relevant development/production app:
   - `http://127.0.0.1:8766` (the local preview)
   - `https://midsig.aisp.live` (the existing website)
   Add another origin only if deploying there; do not use a wildcard.
4. Set the app's display name to MIDSIG. Copy the **public App ID** into
   `docs/js/privy-settings.mjs`. If using a separate app client, also set its public
   Client ID there. The App Secret and authorization private keys belong only in
   a backend secret store, never in browser code or GitHub Pages.

Login methods and allowed origins must be enabled on the same Privy app/client
whose IDs are configured. A successful email login does not establish ownership
of the email address's domain; separate domain enrollment remains required.

## Build and preview

From `checkout-auth/`:

```sh
npm ci
npm run build
```

The TypeScript-checked React SDK island builds into `docs/privy/`. This generated
directory is ignored by Git. `.github/workflows/pages.yml` installs the locked
dependencies, tests the release, builds the SDK, and includes it in the Pages
artifact. GitHub Pages must use **GitHub Actions** as its deployment source,
rather than serving unbuilt files directly from the branch. With a blank App ID,
the static preview also works without the SDK build.

Serve `docs/` over HTTP and open `postage.html`, for example from the repo root:

```sh
python -m http.server 8766 --bind 127.0.0.1 --directory docs
```

The source lives in `checkout-auth/src/privy-entry.tsx`. Supported EVM networks
are restricted to Base; external Solana connectors are enabled. No transaction
or signing hooks are exposed by this code, although wallet-based **login** may
use Privy's sign-in challenge. Authenticated session changes invalidate an open
checkout review. Login does not grant stamps, and tokens/user IDs shown by a
browser must never be trusted for server-side authorization without verification.

## Before payment activation

- Verify Privy access tokens on the backend, validate issuer/audience, and bind
  the authenticated user to an independently verified sending-domain account.
- Issue expiring payment quotes server-side; verify actual native-USDC
  settlement and uniquely claim deposits before crediting the postage ledger.
- Connect the ledger to durable SMTP admission and idempotent stamp debits.
- Add wallet approval/broadcast/settlement/recovery screens only once there is
  a tested purchase service. Never equate funding a wallet with buying stamps.
- Card funding/onramps, gas sponsorship, and swaps are separate integrations
  with provider availability, minimums, and fees. None is enabled here. Do not
  promise a one-dollar card purchase or free gas without checking actual quotes.
- Confirm any Pond0x integration independently; Privy doesn't establish its
  API availability or chain support.
- Verify that login/recovery is possible under the inbox's mandatory-postage
  policy. Ordinary email OTP messages are not automatically MIDSIG-signed or
  postage-paid; wallet login or a separate reachable login mailbox is needed
  if those OTPs would be rejected. Do not introduce a hidden sender exemption.

## Verification status

- TypeScript check and production SDK build pass. The generated entry imports
  successfully in Chromium. Vite reports optional Node worker-thread modules
  from transitive Tempo code as browser-externalized; no runtime import error
  was observed for this auth-only entry.
- The five checkout model tests pass. Browser checks cover bundle prices,
  domain validation, no-wallet checkout, honest preview downloads, remembered
  preferences, wallet rejection, wrong network, late connection responses,
  account/network changes, Phantom connection, keyboard dismissal/focus, and
  widths from 320 to 1280 pixels.
- Privy mounting, logout invalidation, and SDK-load fallback were exercised
  with a browser fixture. The supplied public App ID
  `cmtvhjy3d01u50bkzpiwylxbp` is now configured. A real request to Privy's public
  app endpoint returned HTTP 200; the SDK initialized, and its email-login
  screen and wallet picker opened in Chromium. **Completed user login and
  embedded-wallet creation have not been tested**; these require the user's
  email-code or wallet-signature interaction.
- The public app readback confirms both listed origins are allowlisted and
  `email_auth` / `wallet_auth` are true. **`solana_wallet_auth` is false** and
  still needs enabling in the Privy dashboard. Seeing Phantom in a wallet
  picker is not proof that Solana sign-in is enabled. After the user's dashboard
  update, automatic wallet creation is set to `users-without-wallets` for both
  Ethereum and Solana, matching the frontend. This enables testing the email
  signup / embedded-wallet path independently of external Solana wallet login;
  completed login and wallet creation still need user verification.
- No runtime errors were observed during real SDK initialization/login-screen
  opening. The SDK emitted one duplicate WalletConnect Core initialization
  warning; wallet selection and actual wallet login need follow-up verification.
- The SDK dependency tree initially reported high-severity advisories in
  Axios/ws. Same-major overrides plus a lockfile refresh remove the reported
  high-severity findings. The current audit still reports **23 moderate
  transitive advisories** (including legacy wallet connector dependencies).
  Review their reachability and upstream fixes before production activation;
  do not apply npm's suggested forced SDK downgrade blindly.

References: [SDK setup](https://docs.privy.io/basics/react/setup),
[Solana setup](https://docs.privy.io/recipes/solana/getting-started-with-privy-and-solana),
[embedded wallets](https://docs.privy.io/wallets/overview/embedded).
