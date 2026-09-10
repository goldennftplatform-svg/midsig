import { Component, useEffect, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { PrivyProvider, usePrivy } from "@privy-io/react-auth";
import { toSolanaWalletConnectors } from "@privy-io/react-auth/solana";
import { base } from "viem/chains";

type Session = { authenticated: boolean; userId: string | null };
type Options = {
  appId: string;
  clientId?: string;
  container: HTMLElement;
  onSession: (session: Session) => void;
};

const connectors = toSolanaWalletConnectors();

class AuthBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return <p className="error" role="alert">Sign-in is unavailable. You can still preview postage without logging in.</p>;
    return this.props.children;
  }
}

function Login({ onSession }: Pick<Options, "onSession">) {
  const { ready, authenticated, user, login, logout } = usePrivy();
  const [error, setError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    onSession({ authenticated: ready && authenticated, userId: ready && authenticated ? user?.id ?? null : null });
  }, [ready, authenticated, user?.id, onSession]);

  async function signOut() {
    setLoggingOut(true);
    setError("");
    try { await logout(); }
    catch { setError("Couldn't sign out. Please try again."); }
    finally { setLoggingOut(false); }
  }

  return <div className="privy-card">
    <div className="wallet-row"><span>{authenticated ? "Signed in with Privy" : "Email or wallet. Your choice."}</span><span className="privy-label">PRIVY</span></div>
    {authenticated
      ? <button type="button" className="secondary-button" disabled={!ready || loggingOut} onClick={signOut}>{loggingOut ? "Signing out…" : "Sign out"}</button>
      : <button type="button" className="secondary-button" disabled={!ready} onClick={() => { setError(""); login(); }}>{ready ? "Continue with email or wallet" : "Loading secure sign-in…"}</button>}
    <p className="field-help">{authenticated ? "Login complete. Sending-domain verification and usable postage credits still require the backend." : "Privy handles login and embedded wallets. Wallet login may ask for a sign-in signature; no payment is requested."}</p>
    {error && <p className="error" role="alert">{error}</p>}
  </div>;
}

// Auth only: no sendTransaction/signTransaction, token approvals, onramps,
// server-wallet secrets, gas sponsorship, crediting, or payment APIs are exposed.
export function mountPrivy({ appId, clientId, container, onSession }: Options) {
  if (!appId.trim()) throw new Error("A public Privy App ID is required.");
  const root = createRoot(container);
  root.render(<AuthBoundary><PrivyProvider
    appId={appId}
    {...(clientId ? { clientId } : {})}
    config={{
      loginMethods: ["email", "wallet"],
      appearance: {
        theme: "dark", accentColor: "#b5f7ca", walletChainType: "ethereum-and-solana",
        showWalletLoginFirst: false, landingHeader: "Your next hello starts here",
        loginMessage: "Sign in to MIDSIG. Postage payments are not enabled yet.",
      },
      defaultChain: base,
      supportedChains: [base],
      externalWallets: { solana: { connectors } },
      embeddedWallets: {
        ethereum: { createOnLogin: "users-without-wallets" },
        solana: { createOnLogin: "users-without-wallets" },
      },
    }}
  ><Login onSession={onSession} /></PrivyProvider></AuthBoundary>);
  return () => root.unmount();
}
