import { useState } from "react";
import { Cloud, LogOut, Timer } from "lucide-react";
import { Button } from "../../components/Button";
import { SettingsRow } from "../../components/Display";
import { Segmented } from "../../components/Field";
import { StatusBanner, StatusChip, type StatusKind } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { usePolling } from "../../app/hooks";
import { useToast } from "../../app/toast";
import { api, type CloudStatus } from "../../lib/api";
import { formatDateTime, relativeTime } from "../../lib/format";
import { codeText, driveBackupText, strings, syncStatusText } from "../../strings";

const DRIVE_CHECK_LABELS: Record<string, string> = { "15": "15 seconds", "60": "minute", "300": "5 minutes" };
const DRIVE_CHECK_OPTIONS = [{ value: "15", label: "15 s" }, { value: "60", label: codeText.t1Min }, { value: "300", label: codeText.t5Min }, { value: "0", label: codeText.syncNowOnly }];

/** What the chip in the card's corner says. */
export function cloudIndicator(status: CloudStatus): { kind: StatusKind; label: string } {
  if (status.connecting) return { kind: "progress", label: codeText.waitingForSignIn };
  if (!status.connected) return { kind: "neutral", label: driveBackupText.chipOff };
  if (status.needsSignIn) return { kind: "warning", label: codeText.signInAgain };
  if (status.lastError) return { kind: "warning", label: strings.needsAttention };
  return { kind: "success", label: status.lastSync ? driveBackupText.chipOn : codeText.starting };
}

/**
 * Sync through the user's own Google Drive, for devices that are not on the same Wi-Fi.
 * Shown on the Sync page once this PC is paired.
 */
export function CloudCard() {
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const cloud = usePolling<CloudStatus>(api.cloudStatus, 2500);
  const status = cloud.data;
  if (!status) return null;
  const indicator = cloudIndicator(status);
  const waiting = busy || status.connecting;

  const connect = async () => {
    setBusy(true);
    try {
      const next = await api.cloudConnect();
      if (next.connected) toast.success(codeText.googleDriveConnectedAsNowConnect(next.account));
      else toast.info(driveBackupText.connectCancelled);
    } catch (failure) {
      toast.error(failure, driveBackupText.couldntConnect);
    } finally {
      setBusy(false);
      await cloud.reload();
    }
  };

  const changeInterval = async (value: string) => {
    setBusy(true);
    try {
      await api.setSyncSchedule({ driveSeconds: Number(value) });
      toast.success(value === "0" ? codeText.googleDriveIsCheckedOnlyWhen : codeText.checksGoogleDriveEvery(DRIVE_CHECK_LABELS[value] ?? value));
    } catch (failure) {
      toast.error(failure, codeText.couldnTChangeTheCheckInterval);
    } finally {
      setBusy(false);
      await cloud.reload();
    }
  };

  const cancel = async () => {
    await api.cloudCancelConnect().catch(() => {});
    await cloud.reload();
  };

  const disconnect = async () => {
    const agreed = await confirm({
      title: codeText.disconnectGoogleDriveOnThisPc,
      message: codeText.thisPcStopsSyncingThroughGoogle,
      confirmLabel: strings.disconnect,
    });
    if (!agreed) return;
    setBusy(true);
    try {
      await api.cloudDisconnect();
      toast.success(codeText.googleDriveDisconnectedOnThisPc);
    } catch (failure) {
      toast.error(failure, codeText.couldnTDisconnectGoogleDrive);
    } finally {
      setBusy(false);
      await cloud.reload();
    }
  };

  return (
    <section className="card card-padded connection" aria-labelledby="cloud-title">
      <div className="connection-head">
        <span className="connection-icon" aria-hidden="true"><Cloud /></span>
        <div className="connection-text">
          <h2 id="cloud-title">{status.connected ? syncStatusText.factDrive : codeText.syncWhenYourDevicesAreApart}</h2>
          <p className="muted small">{status.connected ? status.account : driveBackupText.cardSub}</p>
        </div>
        <StatusChip kind={indicator.kind} label={indicator.label} />
      </div>

      {!status.available && !status.connected && (
        <p className="muted small">{strings.googleDriveSyncIsNotSet}</p>
      )}

      {status.available && !status.connected && !waiting && (
        <>
          <ul className="how-list">
            <li><strong>{strings.worksAnywhere}</strong> Your phone and this PC sync through your Drive when they are not on the same Wi-Fi.</li>
            <li><strong>{strings.googleCanTReadIt}</strong> Every change is encrypted on this PC before it is uploaded.</li>
            <li><strong>{strings.onlyAHiddenNuvoriFolder}</strong> Nuvori can't see or change your other Drive files.</li>
            <li><strong>{strings.oneAccountForAllDevices}</strong> Sign in to the same Google account on each device.</li>
          </ul>
          <div className="button-row">
            <Button variant="primary" icon={Cloud} onClick={() => void connect()}>{strings.connectGoogleDrive}</Button>
          </div>
        </>
      )}

      {waiting && !status.connected && (
        <>
          <StatusBanner kind="info" title={strings.finishSigningInInYourBrowser}>{strings.chooseYourGoogleAccountAndAllow}</StatusBanner>
          <div className="button-row">
            <Button variant="ghost" onClick={() => void cancel()}>{strings.cancel}</Button>
          </div>
        </>
      )}

      {status.connected && (
        <>
          {status.needsSignIn ? (
            <StatusBanner kind="warning" title={strings.googleNeedsYouToSignIn}
              action={<Button size="sm" busy={waiting} onClick={() => void connect()}>{strings.signIn}</Button>}>{strings.accessWasRemovedOrExpiredNothing}</StatusBanner>
          ) : status.lastError ? (
            <StatusBanner kind="warning" title={strings.lastDriveSyncDidnTFinish}>{status.lastError}</StatusBanner>
          ) : null}
          <dl className="connection-facts">
            <div><dt>{strings.lastDriveSync}</dt><dd title={status.lastSync ? formatDateTime(status.lastSync) : undefined}>{status.lastSync ? relativeTime(status.lastSync) : driveBackupText.notYet}</dd></div>
            <div><dt>{strings.storedInYourDrive}</dt><dd>{strings.encryptedChangesOnly}</dd></div>
          </dl>
          {status.checkSeconds !== undefined && (
            <SettingsRow icon={Timer} title={strings.checkGoogleDriveEvery} description={status.checkSeconds === 0
              ? codeText.onlyWhenThisPcUnlocksAnd
              : codeText.whileThisPcIsUnlockedShorter}
              control={<Segmented label={strings.checkGoogleDriveEvery} size="sm" value={String(status.checkSeconds)} onChange={(value) => void changeInterval(value)}
                options={DRIVE_CHECK_OPTIONS} />} />
          )}
          <p className="muted small">On your phone, open Settings &gt; Devices &amp; sync and connect the same Google account. Changes then sync through Drive whenever a device is unlocked and online.</p>
          <div className="button-row">
            <Button variant="ghost" icon={LogOut} busy={busy} onClick={() => void disconnect()}>{strings.disconnect}</Button>
          </div>
        </>
      )}
    </section>
  );
}
