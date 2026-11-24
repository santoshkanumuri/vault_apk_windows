import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { ChevronRight, Clock, Fingerprint, LockKeyhole, Moon, RotateCcw, ShieldCheck, Sun } from "lucide-react";
import { Button, IconButton } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { PasswordField, TextField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useRouter } from "../app/router";
import { useTheme } from "../app/theme";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, usingDevMock, type AppSnapshot } from "../lib/api";
import { humanError } from "../lib/errors";
import { cx } from "../lib/format";
import { lastUsedText, lockedView, startFreshConfirmed, type LockedChoice } from "../lib/startFresh";
import { passwordStrength } from "../lib/strength";
import { strings } from "../strings";

export function BrandMark({ size = "md" }: { size?: "md" | "lg" }) {
  return <span className={cx("brand-mark", size === "lg" && "brand-mark-lg")} aria-hidden="true"><ShieldCheck /></span>;
}

export function UnlockPage() {
  const { snapshot, setSnapshot } = useVault();
  const router = useRouter();
  // "Welcome back" for a vault from an earlier install; the same choices behind the
  // "Forgot the password or starting over?" link (lib/startFresh.ts).
  const [chosen, setChosen] = useState<LockedChoice>("");
  const [freshOpen, setFreshOpen] = useState(false);
  const [startedFresh, setStartedFresh] = useState(false);
  const view = lockedView(snapshot, chosen);
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
  const helloRef = useRef<HTMLButtonElement>(null);
  const strength = passwordStrength(password);
  const helloReady = configured && snapshot.helloEnabled && helloAvailable;

  useEffect(() => {
    if (!configured || !snapshot.helloEnabled) { setHelloAvailable(false); return; }
    api.helloAvailable().then(setHelloAvailable).catch(() => setHelloAvailable(false));
  }, [configured, snapshot.helloEnabled]);

  useEffect(() => {
    if (view !== "unlock" && view !== "create") return;
    if (!helloReady) { passwordRef.current?.focus(); return; }
    // Windows Hello is the default way in and comes first on screen, so it also comes first for
    // the keyboard: Tab then reaches the password. Not when typing has already started.
    // Also when focus was lost because the choices screen closed.
    const field = passwordRef.current;
    const active = document.activeElement;
    if (field && ((active === field && !field.value) || !active || active === document.body)) helloRef.current?.focus();
  }, [helloReady, configured, view]);

  // Typing while Windows Hello has the focus goes to the password field, so no keystroke is lost.
  const typeIntoPassword = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key.length === 1 && event.key !== " " && !event.ctrlKey && !event.metaKey && !event.altKey) passwordRef.current?.focus();
  };

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
      // After "Start fresh" the next step is pairing with the phone.
      if (!configured && startedFresh) await router.root({ page: "sync" });
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

  const freshDone = (next: AppSnapshot) => {
    setFreshOpen(false);
    setChosen("");
    setStartedFresh(true);
    setPassword(""); setConfirm(""); setError("");
    toast.success(strings.thisPcSVaultWasDeleted);
    setSnapshot(next);
  };

  return (
    <div className="auth-screen">
      <div className="auth-corner">
        <IconButton label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"} icon={resolved === "dark" ? Sun : Moon} onClick={() => toggle()} />
      </div>
      <main className="auth-card" aria-labelledby="auth-title">
        <div className="auth-brand">
          <BrandMark size="lg" />
          <div>
            <strong>{strings.nuvori}</strong>
            <span>{strings.yoursByDesign}</span>
          </div>
        </div>
        {(view === "welcome" || view === "choices") ? (
          <LockedChoices welcome={view === "welcome"} lastUsedAt={snapshot.lastUsedAt} onUnlock={() => setChosen("unlock")} onStartFresh={() => setFreshOpen(true)} />
        ) : <>
        <div className="auth-heading">
          <h1 id="auth-title">{configured ? "Welcome back" : "Create your vault"}</h1>
          <p>{configured ? "Unlock to use your saved items and browser filling." : "Your vault is encrypted on this PC. Pick a master password you'll remember. It can differ from your phone's."}</p>
        </div>

        {!configured && startedFresh && <StatusBanner kind="info">{strings.createANewVaultThenPair}</StatusBanner>}
        {error && <StatusBanner kind="error">{error}</StatusBanner>}

        {helloReady && (
          <>
            <Button ref={helloRef} onKeyDown={typeIntoPassword} variant="primary" size="lg" block icon={Fingerprint} busy={busy === "hello"} disabled={busy !== ""} onClick={() => void unlockHello()}>{strings.unlockWithWindowsHello}</Button>
            <div className="auth-divider"><span>{strings.orUseYourMasterPassword}</span></div>
          </>
        )}

        <form className="auth-form" onSubmit={(event) => void submit(event)} noValidate>
          <PasswordField
            ref={passwordRef}
            label={strings.masterPassword}
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
              label={strings.confirmMasterPassword}
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
        {configured && <button type="button" className="link-button auth-link" disabled={busy !== ""} onClick={() => { setError(""); setPassword(""); setChosen("choices"); }}>{strings.forgotThePasswordOrStartingOver}</button>}
        <p className="auth-footnote">
          {configured ? "Nuvori can't recover a forgotten master password. Your phone keeps its own copy of the vault." : "There's no password recovery. If you forget it, you'll need to set up this PC again from your phone."}
        </p>
        </>}
        {usingDevMock && <p className="auth-footnote">{strings.previewModeWithSampleDataAny}</p>}
      </main>
      <StartFreshDialog open={freshOpen} onClose={() => setFreshOpen(false)} onDone={freshDone} />
    </div>
  );
}

/** "Welcome back" (a vault from an earlier install) or the choices behind the unlock screen's link. */
function LockedChoices({ welcome, lastUsedAt, onUnlock, onStartFresh }: { welcome: boolean; lastUsedAt?: number; onUnlock: () => void; onStartFresh: () => void }) {
  const lastUsed = lastUsedText(lastUsedAt);
  const firstRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { firstRef.current?.focus(); }, [welcome]);
  return (
    <>
      <div className="auth-heading">
        <h1 id="auth-title">{welcome ? strings.welcomeBack : strings.forgotThePassword}</h1>
        <p>{welcome ? strings.nuvoriFoundAVaultFromAnEarlierInstall : strings.nuvoriCanTRecoverAMasterPassword}</p>
        {lastUsed && <p className="auth-meta"><Clock aria-hidden="true" />{lastUsed}</p>}
      </div>
      <div className="locked-choices" role="group" aria-label={strings.whatToDoWithThisVault}>
        <button ref={firstRef} type="button" className="locked-choice" onClick={onUnlock}>
          <span className="row-icon"><LockKeyhole aria-hidden="true" /></span>
          <span className="row-text"><span className="row-title">{strings.unlockIt}</span><span className="row-description">{strings.useItsMasterPasswordEverythingIsKept}</span></span>
          <ChevronRight aria-hidden="true" className="row-chevron" />
        </button>
        <button type="button" className="locked-choice" onClick={onStartFresh}>
          <span className="row-icon is-danger"><RotateCcw aria-hidden="true" /></span>
          <span className="row-text"><span className="row-title">{strings.startFreshOnThisPc}</span><span className="row-description">{strings.deleteThisPcSVaultAndSetUpANewOne}</span></span>
          <ChevronRight aria-hidden="true" className="row-chevron" />
        </button>
      </div>
      <p className="auth-footnote">{strings.neitherChoiceChangesYourPhone}</p>
    </>
  );
}

/** Deletes this PC's locked vault without its password, after the person types RESET. */
function StartFreshDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (next: AppSnapshot) => void }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const close = () => { if (busy) return; setTyped(""); setError(""); onClose(); };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!startFreshConfirmed(typed)) { setError("Type RESET exactly to confirm."); return; }
    setBusy(true); setError("");
    try {
      const next = await api.startFresh(typed);
      setTyped("");
      onDone(next);
    } catch (failure) {
      setError(humanError(failure, "Couldn't delete this PC's vault."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={strings.startFreshOnThisPc2} locked={busy} size="sm"
      description={strings.thisDeletesThisPcSVaultWithoutItsPassword}
      footer={<>
        <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
        <Button variant="danger" type="submit" form="start-fresh-form" icon={RotateCcw} busy={busy} disabled={!startFreshConfirmed(typed)}>{strings.deleteAndStartFresh}</Button>
      </>}>
      <form id="start-fresh-form" className="form-stack" onSubmit={(event) => void submit(event)}>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        <ul className="fresh-facts">
          <li><strong>{strings.itemsOnlyOnThisPcAreLost}</strong></li>
          <li>{strings.itsDeviceIdentityHelloAndPhotosAreDeleted}</li>
          <li>{strings.yourPhoneAndOtherDevicesAreNotTouched}</li>
          <li>{strings.yourPhoneMayStillListThisPc}</li>
        </ul>
        <TextField label={strings.typeResetToConfirm} value={typed} onValue={(value) => { setTyped(value); if (error) setError(""); }} autoComplete="off" spellCheck={false} disabled={busy} data-autofocus />
      </form>
    </Dialog>
  );
}

export function SplashScreen() {
  return <div className="auth-screen"><div className="splash"><BrandMark size="lg" /></div></div>;
}
