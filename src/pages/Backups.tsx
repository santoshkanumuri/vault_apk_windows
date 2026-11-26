import { type FormEvent, useState } from "react";
import { CloudUpload, LogIn, Power, Timer, Upload } from "lucide-react";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { Card, SettingsRow } from "../components/Display";
import { PasswordField, Segmented } from "../components/Field";
import { Spinner } from "../components/Spinner";
import { StatusBanner, StatusChip } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { usePolling } from "../app/hooks";
import { useToast } from "../app/toast";
import { api, type DriveBackupStatus } from "../lib/api";
import { DEFAULT_INTERVAL, INTERVALS, driveBackupIndicator, everyWords } from "../lib/driveBackup";
import { humanError } from "../lib/errors";
import { formatDateTime, relativeTime } from "../lib/format";
import { driveBackupText as text, strings } from "../strings";

/** "12 Nov 2026": the day a master password was entered. */
function shortDate(at: number): string {
  return new Date(at).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/** Asks for the master password, to make the backup key from it (turning on, or after a change). */
function PasswordDialog({
  open,
  renewing,
  interval,
  onInterval,
  onClose,
  onSave,
}: {
  open: boolean;
  renewing: boolean;
  interval: string;
  onInterval: (value: string) => void;
  onClose: () => void;
  onSave: (password: string) => Promise<string>;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const close = () => {
    setPassword("");
    setError("");
    onClose();
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) {
      setError(text.enterPassword);
      return;
    }
    setBusy(true);
    setError("");
    const failure = await onSave(password);
    setPassword("");
    setBusy(false);
    if (failure) setError(failure);
    else close();
  };

  return (
    <Dialog open={open} onClose={close} locked={busy}
      title={renewing ? text.renewTitle : text.turnOnTitle}
      description={renewing ? text.renewDescription : text.turnOnDescription}
      footer={<>
        <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
        <Button variant="primary" type="submit" form="drive-backup-form" icon={CloudUpload} busy={busy}>
          {renewing ? text.renewConfirm : text.turnOnConfirm}
        </Button>
      </>}>
      <form id="drive-backup-form" className="form-stack" onSubmit={(event) => void submit(event)}>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        <PasswordField label={text.currentMasterPassword} value={password} onValue={setPassword}
          autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
        {!renewing && (
          <>
            <Segmented label={text.howOften} value={interval} onChange={onInterval} options={INTERVALS} />
            <p className="field-hint">{text.howOftenHint}</p>
          </>
        )}
      </form>
    </Dialog>
  );
}

/** Google Drive backup (drive_backup.rs): the whole vault, encrypted, on a schedule. */
function DriveBackupCard() {
  const toast = useToast();
  const confirm = useConfirm();
  const backup = usePolling<DriveBackupStatus>(api.driveBackupStatus, 3000);
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<"off" | "on" | "renew">("off");
  const [chosen, setChosen] = useState(String(DEFAULT_INTERVAL));
  const status = backup.data;

  if (!status) {
    return (
      <Card title={text.cardTitle} className="center">
        {backup.error ? <StatusBanner kind="warning">{humanError(backup.error, text.couldntRead)}</StatusBanner> : <Spinner label={text.cardTitle} />}
      </Card>
    );
  }

  const indicator = driveBackupIndicator(status);
  const waiting = busy || status.running;

  /** Returns a sentence for the dialog when it failed, or "" when it worked. */
  const save = async (password: string): Promise<string> => {
    const renewing = dialog === "renew";
    try {
      const next = await api.setDriveBackup(password, renewing ? status.intervalMs : Number(chosen));
      toast.success(renewing ? text.passwordSaved : text.backupOn(everyWords(next.intervalMs)));
      return "";
    } catch (failure) {
      return humanError(failure, renewing ? text.couldntSavePassword : text.couldntTurnOn);
    } finally {
      await backup.reload();
    }
  };

  const connect = async () => {
    setBusy(true);
    try {
      const next = await api.cloudConnect();
      if (next.connected) toast.success(text.connected(next.account));
      else toast.info(text.connectCancelled);
    } catch (failure) {
      toast.error(failure, text.couldntConnect);
    } finally {
      setBusy(false);
      await backup.reload();
    }
  };

  const changeInterval = async (value: string) => {
    setBusy(true);
    try {
      const next = await api.setDriveBackupInterval(Number(value));
      toast.success(text.intervalChanged(everyWords(next.intervalMs)));
    } catch (failure) {
      toast.error(failure, text.couldntChange);
    } finally {
      setBusy(false);
      await backup.reload();
    }
  };

  const backUpNow = async () => {
    setBusy(true);
    try {
      await api.backUpToDriveNow();
      toast.success(text.backedUp);
    } catch (failure) {
      toast.error(failure, text.couldntBackUp);
    } finally {
      setBusy(false);
      await backup.reload();
    }
  };

  const turnOff = async () => {
    const agreed = await confirm({ title: text.turnOffTitle, message: text.turnOffMessage, confirmLabel: text.turnOffConfirm });
    if (!agreed) return;
    setBusy(true);
    try {
      await api.turnOffDriveBackup();
      toast.success(text.backupOff);
    } catch (failure) {
      toast.error(failure, text.couldntTurnOff);
    } finally {
      setBusy(false);
      await backup.reload();
    }
  };

  return (
    <section className="card card-padded connection" aria-labelledby="drive-backup-title">
      <div className="connection-head">
        <span className="connection-icon" aria-hidden="true"><CloudUpload /></span>
        <div className="connection-text">
          <h2 id="drive-backup-title">{status.enabled ? text.cardTitle : text.cardOff}</h2>
          <p className="muted small">{status.enabled && status.account ? status.account : text.cardSub}</p>
        </div>
        <StatusChip kind={indicator.kind} label={indicator.label} />
      </div>

      {!status.available ? (
        <p className="muted small">{text.notSetUp}</p>
      ) : (
        <>
          {!status.enabled && (
            <ul className="how-list">
              <li><strong>{text.whyWholeVault}</strong> {text.whyWholeVaultBody}</li>
              <li><strong>{text.whyEncrypted}</strong> {text.whyEncryptedBody}</li>
              <li><strong>{text.whyFolder}</strong> {text.whyFolderBody}</li>
              <li><strong>{text.whyAndroid}</strong> {text.whyAndroidBody}</li>
            </ul>
          )}

          {!status.connected ? (
            <>
              <StatusBanner kind="info" title={text.connectFirst}>{text.connectFirstBody}</StatusBanner>
              <div className="button-row">
                <Button variant="primary" icon={LogIn} busy={busy} onClick={() => void connect()}>{text.connectGoogleDrive}</Button>
              </div>
            </>
          ) : !status.enabled ? (
            <div className="button-row">
              <Button variant="primary" icon={CloudUpload} onClick={() => { setChosen(String(DEFAULT_INTERVAL)); setDialog("on"); }}>{text.turnOn}</Button>
            </div>
          ) : (
            <>
              {status.needsPassword ? (
                <StatusBanner kind="warning" title={text.passwordChanged}
                  action={<Button size="sm" onClick={() => setDialog("renew")}>{text.passwordChangedAction}</Button>}>
                  {text.passwordChangedBody}
                </StatusBanner>
              ) : status.lastError ? (
                <StatusBanner kind="warning" action={status.needsSignIn
                  ? <Button size="sm" busy={busy} onClick={() => void connect()}>{strings.signIn}</Button>
                  : undefined}>{status.lastError}</StatusBanner>
              ) : null}

              <dl className="connection-facts">
                <div>
                  <dt>{text.lastBackup}</dt>
                  <dd title={status.lastBackupAt ? formatDateTime(status.lastBackupAt) : undefined}>
                    {status.lastBackupAt ? relativeTime(status.lastBackupAt) : text.notYet}
                  </dd>
                </div>
                <div><dt>{text.storedIn}</dt><dd>{text.wholeVault}</dd></div>
                {status.passwordSetAt ? (
                  <div><dt>{text.opensWith}</dt><dd>{text.opensWithDate(shortDate(status.passwordSetAt))}</dd></div>
                ) : null}
              </dl>

              <SettingsRow icon={Timer} title={text.howOften} description={text.howOftenHint}
                control={<Segmented label={text.howOften} size="sm" value={String(status.intervalMs)}
                  onChange={(value) => void changeInterval(value)} options={INTERVALS} />} />

              <div className="button-row">
                <Button variant="primary" icon={Upload} busy={waiting} disabled={status.needsPassword}
                  onClick={() => void backUpNow()}>{text.backUpNow}</Button>
                <Button variant="ghost" icon={Power} disabled={busy} onClick={() => void turnOff()}>{text.turnOff}</Button>
              </div>
            </>
          )}
        </>
      )}

      <PasswordDialog open={dialog !== "off"} renewing={dialog === "renew"} interval={chosen} onInterval={setChosen}
        onClose={() => setDialog("off")} onSave={save} />
    </section>
  );
}

/** Backups: the scheduled copy in Google Drive, and where a backup is restored. */
export function BackupsPage() {
  return (
    <div className="page page-narrow">
      <DriveBackupCard />
      <Card title={text.restoreTitle}>
        <p className="muted small">{text.restoreBody}</p>
        <p className="muted small">{text.exportRow}</p>
      </Card>
    </div>
  );
}
