import { useState, type FormEvent } from "react";
import { ArchiveRestore, DatabaseBackup, FolderInput, FolderOpen } from "lucide-react";
import { Button } from "../components/Button";
import { SettingsRow } from "../components/Display";
import { Dialog } from "../components/Dialog";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api } from "../lib/api";
import { backupContents, localDate, restoredMessage, type BackupReview } from "../lib/backupFile";
import { humanError } from "../lib/errors";
import { strings } from "../strings";

/**
 * Restore from backup (backup_restore.rs), as Nuvori for Android restores: choose a .pvault file,
 * open it with its password and see what it holds, then replace this vault. Nothing changes until
 * "Replace vault", which the current master password confirms. "Save this vault first" exports the
 * vault as it is now. A PC in a sync group leaves it first, so the old items can't sync back.
 */
export function RestoreBackupRow() {
  const toast = useToast();
  const { setSnapshot, refresh } = useVault();
  const [fileName, setFileName] = useState<string | null>(null);
  const [review, setReview] = useState<BackupReview | null>(null);
  const [backupPassword, setBackupPassword] = useState("");
  const [password, setPassword] = useState("");
  const [saved, setSaved] = useState("");
  const [busy, setBusy] = useState<"" | "choose" | "open" | "save" | "replace">("");
  const [error, setError] = useState("");

  const reset = () => {
    setFileName(null); setReview(null); setBackupPassword(""); setPassword(""); setSaved(""); setError("");
    // The opened backup goes from memory too.
    void api.restoreCancel().catch(() => { /* Locking the vault forgets it as well. */ });
  };
  const close = () => { if (!busy) reset(); };

  const choose = async () => {
    if (busy) return;
    setBusy("choose");
    try {
      const name = await api.restoreChooseFile();
      if (name) { setReview(null); setBackupPassword(""); setPassword(""); setSaved(""); setError(""); setFileName(name); }
    } catch (failure) {
      toast.error(failure, "Couldn't open the backup file.");
    } finally {
      setBusy("");
    }
  };

  const open = async (event: FormEvent) => {
    event.preventDefault();
    if (!backupPassword) { setError("Enter the backup's password."); return; }
    setBusy("open"); setError("");
    try {
      setReview(await api.restoreOpenBackup(backupPassword));
    } catch (failure) {
      setError(humanError(failure, "The backup couldn't be opened."));
    } finally {
      setBackupPassword("");
      setBusy("");
    }
  };

  const saveFirst = async () => {
    if (!password) { setError("Enter your master password to save this vault."); return; }
    setBusy("save"); setError("");
    try {
      const done = await api.exportBackup(password, localDate());
      if (done) setSaved(done.fileName);
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "Couldn't save this vault."));
    } finally {
      setBusy("");
    }
  };

  const replace = async (event: FormEvent) => {
    event.preventDefault();
    if (!review || review.sync === "manager") return;
    if (!password) { setError("Enter your master password."); return; }
    setBusy("replace"); setError("");
    try {
      const next = await api.restoreReplaceVault(password);
      setSnapshot(next);
      const unlocked = next.vaultState === "unlocked";
      if (unlocked) await refresh();
      toast.success(restoredMessage(review, unlocked));
      setBusy("");
      reset();
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "Couldn't restore the backup."));
      setBusy("");
    }
  };

  const working = busy !== "";
  return (
    <>
      <SettingsRow icon={FolderInput} title={strings.restoreFromBackup} description={strings.replaceThisVaultWithAPvault} onClick={() => void choose()} />
      <Dialog open={fileName !== null} onClose={close} locked={working} size="md"
        title={review ? strings.replaceThisVaultWithTheBackup : strings.restoreFromBackup}
        description={fileName}
        footer={review ? <>
          <Button variant="ghost" onClick={close} disabled={working}>{strings.cancel}</Button>
          <Button variant="danger" type="submit" form="restore-replace-form" icon={ArchiveRestore} busy={busy === "replace"}
            disabled={review.sync === "manager" || busy === "save"}>{strings.replaceVault}</Button>
        </> : <>
          <Button variant="ghost" onClick={close} disabled={working}>{strings.cancel}</Button>
          <Button variant="primary" type="submit" form="restore-open-form" icon={FolderOpen} busy={busy === "open"}>{strings.openBackup}</Button>
        </>}>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        {!review ? (
          <form id="restore-open-form" className="form-stack" onSubmit={(event) => void open(event)}>
            <PasswordField label={strings.backupPassword} value={backupPassword} onValue={setBackupPassword} autoComplete="off"
              hint={strings.theMasterPasswordTheVaultHadWhen} capsLockWarning disabled={working} data-autofocus />
            <p className="field-hint">{strings.openingTheBackupChecksAllOf}</p>
          </form>
        ) : (
          <form id="restore-replace-form" className="form-stack" onSubmit={(event) => void replace(event)}>
            <p>{backupContents(review)}</p>
            {review.sync === "member" && (
              <StatusBanner kind="warning"><strong>{strings.thisPcWillLeaveItsSyncGroup}</strong> {strings.nuvoriTellsTheManagingPhoneWhichRemoves}</StatusBanner>
            )}
            {review.sync === "manager" && <StatusBanner kind="error">{strings.thisPcManagesItsSyncGroupSo}</StatusBanner>}
            <StatusBanner kind="warning">{strings.everythingInThisVaultNowIsReplaced}</StatusBanner>
            <PasswordField label={strings.currentMasterPassword} value={password} onValue={setPassword} autoComplete="current-password"
              hint={strings.afterwardUnlockWithYourCurrentMaster} capsLockWarning disabled={working} data-autofocus />
            <div className="restore-save-first">
              <Button icon={DatabaseBackup} onClick={() => void saveFirst()} busy={busy === "save"} disabled={busy === "replace"}>{strings.saveThisVaultFirst}</Button>
              {saved && <span className="field-hint" role="status">Saved as {saved}.</span>}
            </div>
          </form>
        )}
      </Dialog>
    </>
  );
}
