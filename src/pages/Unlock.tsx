import { useEffect, useRef, useState, type FormEvent } from "react";
import { Fingerprint, LockKeyhole, Moon, ShieldCheck, Sun } from "lucide-react";
import { Button, IconButton } from "../components/Button";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useTheme } from "../app/theme";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, usingDevMock } from "../lib/api";
import { humanError } from "../lib/errors";
import { cx } from "../lib/format";
import { passwordStrength } from "../lib/strength";

export function BrandMark({ size = "md" }: { size?: "md" | "lg" }) {
  return <span className={cx("brand-mark", size === "lg" && "brand-mark-lg")} aria-hidden="true"><ShieldCheck /></span>;
}

export function UnlockPage() {
  const { snapshot, setSnapshot } = useVault();
  const configured = snapshot.vaultState === "locked";
  const toast = useToast();
  const { resolved, toggle } = useTheme();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<"" | "password" | "hello">("");
  const [error, setError] = useState("");
  const [helloAvailable, setHelloAvailable] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const strength = passwordStrength(password);
  const helloReady = configured && snapshot.helloEnabled && helloAvailable;

  useEffect(() => {
    if (!configured || !snapshot.helloEnabled) { setHelloAvailable(false); return; }
    api.helloAvailable().then(setHelloAvailable).catch(() => setHelloAvailable(false));
  }, [configured, snapshot.helloEnabled]);

  useEffect(() => { if (!helloReady) passwordRef.current?.focus(); }, [helloReady, configured]);

  const finish = (message: string) => {
    setPassword(""); setConfirm("");
    toast.success(message);
  };

  const unlockHello = async () => {
    setBusy("hello"); setError("");
    try {
      const next = await api.unlockHello();
      finish("Vault unlocked");
      setSnapshot(next);
    } catch (failure) {
      setError(humanError(failure, "Windows Hello didn't unlock the vault."));
    } finally {
      setBusy("");
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!password) { setError("Enter your master password."); passwordRef.current?.focus(); return; }
    if (!configured) {
      if (password.length < 12) { setError("Use at least 12 characters."); passwordRef.current?.focus(); return; }
      if (password !== confirm) { setError("The passwords don't match."); confirmRef.current?.focus(); return; }
    }
    setBusy("password"); setError("");
    try {
      const next = configured ? await api.unlockVault(password) : await api.createVault(password);
      finish(configured ? "Vault unlocked" : "Vault created");
      setSnapshot(next);
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, configured ? "That password didn't work." : "Couldn't create the vault."));
      window.setTimeout(() => passwordRef.current?.focus(), 0);
    } finally {
      setBusy("");
    }
  };

  const strengthTone = ["error", "warning", "info", "success", "success"][strength.score];

  return (
    <div className="auth-screen">
      <div className="auth-corner">
        <IconButton label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"} icon={resolved === "dark" ? Sun : Moon} onClick={() => toggle()} />
      </div>
      <main className="auth-card" aria-labelledby="auth-title">
        <div className="auth-brand">
          <BrandMark size="lg" />
          <div>
            <strong>Nuvori</strong>
            <span>Yours, by design</span>
          </div>
        </div>
        <div className="auth-heading">
          <h1 id="auth-title">{configured ? "Welcome back" : "Create your vault"}</h1>
          <p>{configured ? "Unlock to use your saved items and browser filling." : "Your vault is encrypted on this PC. Pick a master password you'll remember. It can differ from your phone's."}</p>
        </div>

        {error && <StatusBanner kind="error">{error}</StatusBanner>}

        {helloReady && (
          <>
            <Button variant="primary" size="lg" block icon={Fingerprint} busy={busy === "hello"} disabled={busy !== ""} onClick={() => void unlockHello()}>Unlock with Windows Hello</Button>
            <div className="auth-divider"><span>or use your master password</span></div>
          </>
        )}

        <form className="auth-form" onSubmit={(event) => void submit(event)} noValidate>
          <PasswordField
            ref={passwordRef}
            label="Master password"
            name="masterPassword"
            autoComplete={configured ? "current-password" : "new-password"}
            value={password}
            onValue={(value) => { setPassword(value); if (error) setError(""); }}
            disabled={busy !== ""}
            capsLockWarning
            required
          />
          {!configured && password && (
            <div className="strength" aria-live="polite">
              <div className={cx("strength-bar", `tone-${strengthTone}`)} data-score={strength.score}>
                {[0, 1, 2, 3].map((index) => <span key={index} className={cx(index < Math.max(1, strength.score) && "is-on")} />)}
              </div>
              <span className="strength-label">{strength.label}{strength.hint ? ` · ${strength.hint}` : ""}</span>
            </div>
          )}
          {!configured && (
            <PasswordField
              ref={confirmRef}
              label="Confirm master password"
              name="confirmPassword"
              autoComplete="new-password"
              value={confirm}
              onValue={(value) => { setConfirm(value); if (error) setError(""); }}
              disabled={busy !== ""}
              error={confirm && confirm !== password && confirm.length >= password.length ? "Doesn't match yet" : undefined}
              hint={confirm && confirm === password ? "Passwords match" : undefined}
              required
            />
          )}
          <Button type="submit" variant={helloReady ? "secondary" : "primary"} size="lg" block icon={LockKeyhole} busy={busy === "password"} disabled={busy !== ""}>
            {configured ? "Unlock" : "Create vault"}
          </Button>
        </form>
        <p className="auth-footnote">
          {configured ? "Nuvori can't recover a forgotten master password. Your phone keeps its own copy of the vault." : "There's no password recovery. If you forget it, you'll need to set up this PC again from your phone."}
        </p>
        {usingDevMock && <p className="auth-footnote">Preview mode with sample data. Any password unlocks except "wrong".</p>}
      </main>
    </div>
  );
}

export function SplashScreen() {
  return <div className="auth-screen"><div className="splash"><BrandMark size="lg" /></div></div>;
}
