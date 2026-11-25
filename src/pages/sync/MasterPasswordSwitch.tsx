import { useEffect, useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { PasswordField } from "../../components/Field";
import { StatusBanner } from "../../components/Status";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api } from "../../lib/api";
import { humanError } from "../../lib/errors";
import { accountText, masterPasswordText } from "../../strings";

/**
 * Protocol master-password-v1 (master_password.rs): the managing phone changed the vault's master
 * password, and this PC switches to it. The typed password is tested against the phone's check, then
 * this PC's key file is wrapped under it (`switch_master_password`). The vault stays unlocked; the
 * current password is not needed. Until the switch, sync is paused.
 */
function SwitchDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { snapshot, setSnapshot } = useVault();
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const pending = snapshot.masterPasswordSwitch;

  const close = () => { if (busy) return; setPassword(""); setError(""); onClose(); };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) { setError(masterPasswordText.enterPassword); return; }
    setBusy(true); setError("");
    try {
      const next = await api.switchMasterPassword(password);
      setPassword("");
      setSnapshot(next);
      toast.success(masterPasswordText.switched);
      onClose();
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, masterPasswordText.failed));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open && Boolean(pending)} onClose={close} title={masterPasswordText.title} locked={busy}
      footer={<>
        <Button variant="ghost" onClick={close} disabled={busy}>{masterPasswordText.notNow}</Button>
        <Button variant="primary" type="submit" form="switch-master-password-form" busy={busy} disabled={!password}>{masterPasswordText.usePassword}</Button>
      </>}>
      <form id="switch-master-password-form" className="form-stack" onSubmit={(event) => void submit(event)}>
        <p>{masterPasswordText.changedBy(pending?.managerName ?? "")}</p>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        {busy && <StatusBanner kind="info">{masterPasswordText.checking}</StatusBanner>}
        <PasswordField label={masterPasswordText.newPassword} value={password} onValue={(value) => { setPassword(value); setError(""); }}
          autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
        <p className="muted">{masterPasswordText.paused}{snapshot.helloEnabled ? ` ${accountText.hello}` : ""}</p>
      </form>
    </Dialog>
  );
}

/**
 * Asks once per unlock (Shell mounts only while the vault is unlocked): at the unlock, or when the
 * phone's change arrives while the vault is open. "Not now" waits for the next unlock.
 */
export function MasterPasswordSwitchPrompt() {
  const { snapshot } = useVault();
  const pending = Boolean(snapshot.masterPasswordSwitch);
  const [open, setOpen] = useState(false);
  const [asked, setAsked] = useState(false);
  useEffect(() => {
    if (pending && !asked) { setOpen(true); setAsked(true); }
    if (!pending) setOpen(false);
  }, [pending, asked]);
  return <SwitchDialog open={open} onClose={() => setOpen(false)} />;
}

/** Devices & sync: why sync is paused, with the way to resume. */
export function MasterPasswordSwitchBanner() {
  const { snapshot } = useVault();
  const [open, setOpen] = useState(false);
  if (!snapshot.masterPasswordSwitch) return null;
  return (
    <>
      <StatusBanner kind="warning" title={masterPasswordText.bannerTitle}
        action={<Button size="sm" onClick={() => setOpen(true)}>{masterPasswordText.bannerAction}</Button>}>
        {masterPasswordText.bannerBody}
      </StatusBanner>
      <SwitchDialog open={open} onClose={() => setOpen(false)} />
    </>
  );
}
