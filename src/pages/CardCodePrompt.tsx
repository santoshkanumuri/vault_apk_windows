import { useEffect, useRef, useState, type FormEvent } from "react";
import { CreditCard, Fingerprint, ShieldCheck } from "lucide-react";
import { Button } from "../components/Button";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { api, type CardCodeRequest } from "../lib/api";
import { humanError } from "../lib/errors";
import { BrandMark } from "./Unlock";

/**
 * Approves releasing one card's security code to the browser. Opened by the extension after a
 * card fill; Windows Hello starts on its own when available, the master password always works.
 */
export function CardCodePrompt() {
  const [request, setRequest] = useState<CardCodeRequest | null | undefined>(undefined);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"" | "password" | "hello">("");
  const [error, setError] = useState("");
  const passwordRef = useRef<HTMLInputElement>(null);
  const helloStarted = useRef(false);

  const decline = () => { if (request) void api.declineCardCode(request.id); else void api.declineCardCode(""); };

  const approveHello = async (current: CardCodeRequest) => {
    setBusy("hello"); setError("");
    try {
      await api.approveCardCode(current.id);
    } catch (failure) {
      setError(humanError(failure, "Windows Hello didn't approve it. Use your master password."));
      passwordRef.current?.focus();
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    api.pendingCardCode().then((next) => {
      setRequest(next);
      if (next?.helloAvailable && !helloStarted.current) { helloStarted.current = true; void approveHello(next); }
      else window.setTimeout(() => passwordRef.current?.focus(), 0);
    }).catch(() => setRequest(null));
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) decline(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!request) return;
    if (!password) { setError("Enter your master password."); passwordRef.current?.focus(); return; }
    setBusy("password"); setError("");
    try {
      await api.approveCardCode(request.id, password);
      setPassword("");
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "That password didn't work."));
      window.setTimeout(() => passwordRef.current?.focus(), 0);
    } finally {
      setBusy("");
    }
  };

  return (
    <main className="prompt-screen" aria-labelledby="code-title">
      <div className="auth-brand">
        <BrandMark />
        <div>
          <strong id="code-title">Fill security code?</strong>
          <span>Your browser asked for a card's security code</span>
        </div>
      </div>

      {request === null ? (
        <StatusBanner kind="info">This request expired. Choose the card in your browser again.</StatusBanner>
      ) : request && (
        <>
          <div className="prompt-summary">
            <span className="prompt-summary-icon" aria-hidden="true"><CreditCard /></span>
            <span>
              <strong>{request.title || "Card"}</strong>
              <span>{request.card}</span>
            </span>
          </div>
          <p className="prompt-site"><ShieldCheck aria-hidden="true" /> For <strong>{request.site}</strong></p>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          {request.helloAvailable && (
            <>
              <Button variant="primary" size="lg" block icon={Fingerprint} busy={busy === "hello"} disabled={busy !== ""} onClick={() => void approveHello(request)}>Approve with Windows Hello</Button>
              <div className="auth-divider"><span>or use your master password</span></div>
            </>
          )}
          <form className="auth-form" onSubmit={(event) => void submit(event)} noValidate>
            <PasswordField
              ref={passwordRef}
              label="Master password"
              name="masterPassword"
              autoComplete="current-password"
              value={password}
              onValue={(value) => { setPassword(value); if (error) setError(""); }}
              disabled={busy !== ""}
              capsLockWarning
              required
            />
            <Button type="submit" variant={request.helloAvailable ? "secondary" : "primary"} size="lg" block busy={busy === "password"} disabled={busy !== ""}>
              Approve
            </Button>
          </form>
        </>
      )}

      <div className="prompt-actions">
        <Button variant="ghost" size="sm" disabled={busy !== ""} onClick={decline}>{request === null ? "Close" : "Don't fill"}</Button>
      </div>
      <p className="auth-footnote">Only this code is sent, and only to the browser tab that asked.</p>
    </main>
  );
}
