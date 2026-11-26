import { useEffect, useRef, useState, type FormEvent } from "react";
import { AppWindow, Fingerprint, LockKeyhole } from "lucide-react";
import { Button } from "../components/Button";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { api, type AppSnapshot } from "../lib/api";
import { humanError } from "../lib/errors";
import { helloLockScreen } from "../lib/helloWindow";
import { BrandMark } from "./Unlock";
import { strings } from "../strings";

/**
 * The small window the browser extension asks for when the vault is locked. Nuvori closes it
 * after an unlock from any window and keeps running in the tray.
 */
export function UnlockPrompt() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"" | "password" | "hello">("");
  const [error, setError] = useState("");
  const [helloAvailable, setHelloAvailable] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const helloRef = useRef<HTMLButtonElement>(null);
  const configured = snapshot?.vaultState !== "notConfigured";
  // Windows Hello shows only inside the master password window (lib/helloWindow.ts).
  const hello = helloLockScreen(snapshot ?? { helloEnabled: false }, helloAvailable);
  const helloReady = hello.button;

  useEffect(() => {
    api.snapshot().then((next) => {
      setSnapshot(next);
      if (next.vaultState === "unlocked") void api.closeUnlockPrompt();
      else if (next.helloEnabled) api.helloAvailable().then(setHelloAvailable).catch(() => setHelloAvailable(false));
    }).catch(() => setSnapshot(null));
  }, []);

  useEffect(() => {
    if (!snapshot) return;
    if (helloReady) helloRef.current?.focus();
    else passwordRef.current?.focus();
  }, [snapshot, helloReady]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) void api.closeUnlockPrompt(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy]);

  const done = () => { setPassword(""); void api.closeUnlockPrompt(); };

  const unlockHello = async () => {
    setBusy("hello"); setError("");
    try {
      await api.unlockHello();
      done();
    } catch (failure) {
      setError(humanError(failure, "Windows Hello didn't unlock the vault."));
      // Past the master password window the button goes away (hello_window.rs).
      api.snapshot().then(setSnapshot).catch(() => {});
      passwordRef.current?.focus();
    } finally {
      setBusy("");
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!password) { setError("Enter your master password."); passwordRef.current?.focus(); return; }
    setBusy("password"); setError("");
    try {
      await api.unlockVault(password);
      done();
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "That password didn't work."));
      window.setTimeout(() => passwordRef.current?.focus(), 0);
    } finally {
      setBusy("");
    }
  };

  const openApp = () => { void api.showMainWindow().then(() => api.closeUnlockPrompt()); };

  return (
    <main className="prompt-screen" aria-labelledby="prompt-title">
      <div className="auth-brand">
        <BrandMark />
        <div>
          <strong id="prompt-title">{strings.unlockNuvori}</strong>
          <span>{strings.forFillingAndSavingInYour}</span>
        </div>
      </div>

      {!configured ? (
        <>
          <StatusBanner kind="info">{strings.setUpYourVaultInNuvori}</StatusBanner>
          <Button variant="primary" size="lg" block icon={AppWindow} onClick={openApp}>{strings.openNuvori}</Button>
        </>
      ) : (
        <>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          {!error && hello.notice && <StatusBanner kind="info">{hello.notice === "password" ? strings.enterYourMasterPasswordWindowsHello : strings.nuvoriAsksForYourMasterPassword}</StatusBanner>}
          {helloReady && (
            <>
              <Button ref={helloRef} variant="primary" size="lg" block icon={Fingerprint} busy={busy === "hello"} disabled={busy !== ""} onClick={() => void unlockHello()}>{strings.unlockWithWindowsHello}</Button>
              <div className="auth-divider"><span>{strings.orUseYourMasterPassword}</span></div>
            </>
          )}
          <form className="auth-form" onSubmit={(event) => void submit(event)} noValidate>
            <PasswordField
              ref={passwordRef}
              label={strings.masterPassword}
              name="masterPassword"
              autoComplete="current-password"
              value={password}
              onValue={(value) => { setPassword(value); if (error) setError(""); }}
              disabled={busy !== "" || !snapshot}
              capsLockWarning
              required
            />
            <Button type="submit" variant={helloReady ? "secondary" : "primary"} size="lg" block icon={LockKeyhole} busy={busy === "password"} disabled={busy !== "" || !snapshot}>{strings.unlock}</Button>
          </form>
        </>
      )}

      <div className="prompt-actions">
        <Button variant="ghost" size="sm" disabled={busy !== ""} onClick={() => void api.closeUnlockPrompt()}>{strings.notNow}</Button>
        <Button variant="ghost" size="sm" icon={AppWindow} disabled={busy !== ""} onClick={openApp}>{strings.openNuvori}</Button>
      </div>
      <p className="auth-footnote">{strings.nuvoriKeepsRunningInTheTray}</p>
    </main>
  );
}
