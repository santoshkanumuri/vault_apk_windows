import { useState } from "react";
import { Cloud, LogOut } from "lucide-react";
import { Button } from "../../components/Button";
import { StatusBanner, StatusChip, type StatusKind } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { usePolling } from "../../app/hooks";
import { useToast } from "../../app/toast";
import { api, type CloudStatus } from "../../lib/api";
import { formatDateTime, relativeTime } from "../../lib/format";

/** What the chip in the card's corner says. */
export function cloudIndicator(status: CloudStatus): { kind: StatusKind; label: string } {
  if (status.connecting) return { kind: "progress", label: "Waiting for sign-in" };
  if (!status.connected) return { kind: "neutral", label: "Off" };
  if (status.needsSignIn) return { kind: "warning", label: "Sign in again" };
  if (status.lastError) return { kind: "warning", label: "Needs attention" };
  return { kind: "success", label: status.lastSync ? "On" : "Starting" };
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
      if (next.connected) toast.success(`Google Drive connected as ${next.account}. Now connect the same account on your phone.`);
      else toast.info("Google sign-in was canceled. Nothing changed.");
    } catch (failure) {
      toast.error(failure, "Couldn't connect Google Drive.");
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
      title: "Disconnect Google Drive on this PC?",
      message: "This PC stops syncing through Google Drive. Sync over Wi-Fi keeps working. The encrypted files stay in your Drive for your other devices.",
      confirmLabel: "Disconnect",
    });
    if (!agreed) return;
    setBusy(true);
    try {
      await api.cloudDisconnect();
      toast.success("Google Drive disconnected on this PC");
    } catch (failure) {
      toast.error(failure, "Couldn't disconnect Google Drive.");
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
          <h2 id="cloud-title">{status.connected ? "Google Drive" : "Sync when your devices are apart"}</h2>
          <p className="muted small">{status.connected ? status.account : "Optional. Uses your own Google Drive, not a Nuvori server."}</p>
        </div>
        <StatusChip kind={indicator.kind} label={indicator.label} />
      </div>

      {!status.available && !status.connected && (
        <p className="muted small">Google Drive sync is not set up in this build of Nuvori. Sync over Wi-Fi works as usual.</p>
      )}

      {status.available && !status.connected && !waiting && (
        <>
          <ul className="how-list">
            <li><strong>Works anywhere.</strong> Your phone and this PC sync through your Drive when they are not on the same Wi-Fi.</li>
            <li><strong>Google can't read it.</strong> Every change is encrypted on this PC before it is uploaded.</li>
            <li><strong>Only a hidden Nuvori folder.</strong> Nuvori can't see or change your other Drive files.</li>
            <li><strong>One account for all devices.</strong> Sign in to the same Google account on each device.</li>
          </ul>
          <div className="button-row">
            <Button variant="primary" icon={Cloud} onClick={() => void connect()}>Connect Google Drive</Button>
          </div>
        </>
      )}

      {waiting && !status.connected && (
        <>
          <StatusBanner kind="info" title="Finish signing in in your browser">
            Choose your Google account and allow Nuvori to use its own app folder. This card updates by itself.
          </StatusBanner>
          <div className="button-row">
            <Button variant="ghost" onClick={() => void cancel()}>Cancel</Button>
          </div>
        </>
      )}

      {status.connected && (
        <>
          {status.needsSignIn ? (
            <StatusBanner kind="warning" title="Google needs you to sign in again"
              action={<Button size="sm" busy={waiting} onClick={() => void connect()}>Sign in</Button>}>
              Access was removed or expired. Nothing is lost. Sync over Wi-Fi keeps working.
            </StatusBanner>
          ) : status.lastError ? (
            <StatusBanner kind="warning" title="Last Drive sync didn't finish">{status.lastError}</StatusBanner>
          ) : null}
          <dl className="connection-facts">
            <div><dt>Last Drive sync</dt><dd title={status.lastSync ? formatDateTime(status.lastSync) : undefined}>{status.lastSync ? relativeTime(status.lastSync) : "Not yet"}</dd></div>
            <div><dt>Stored in your Drive</dt><dd>Encrypted changes only</dd></div>
          </dl>
          <p className="muted small">On your phone, open Devices and connect the same Google account. Changes then sync through Drive whenever a device is unlocked and online.</p>
          <div className="button-row">
            <Button variant="ghost" icon={LogOut} busy={busy} onClick={() => void disconnect()}>Disconnect</Button>
          </div>
        </>
      )}
    </section>
  );
}
