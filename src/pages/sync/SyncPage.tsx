import { useEffect, useState, type FormEvent } from "react";
import { History, Image, Laptop, Pencil, RefreshCw, Smartphone, Wifi } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Card, SettingsGroup, SettingsRow } from "../../components/Display";
import { DangerZone } from "../SettingsPage";
import { TextField, Toggle } from "../../components/Field";
import { ProgressBar } from "../../components/Spinner";
import { StatusBanner, StatusChip } from "../../components/Status";
import { useConflicts, useMembership, usePhotoSyncStatus, usePolling, useSyncStatus } from "../../app/hooks";
import { DevicesGroup, PendingLeaveChip, RemovedNoticeBanner } from "./Membership";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type ActivityEvent, type SyncStatus } from "../../lib/api";
import { formatDateTime, plural, relativeTime } from "../../lib/format";
import { isSyncing, phaseLabel, syncIndicator } from "../../lib/syncState";
import { ActivityList } from "../ActivityPage";
import { useSyncNow } from "../Home";
import { PairingCard } from "./Pairing";
import { CloudCard } from "./Cloud";

export function SyncPage() {
  const { snapshot } = useVault();
  const router = useRouter();
  const sync = useSyncStatus(snapshot.enrolled ? 1500 : 10000);
  const activity = usePolling<ActivityEvent[]>(() => api.activityLog(200), 5000);
  const conflicts = useConflicts();
  const membership = useMembership();
  const membershipShown = Boolean(membership.data && !membership.error && membership.data.devices.length > 0);
  const conflictCount = conflicts.data ? conflicts.data.length : sync.data?.conflicts ?? 0;
  const recent = (activity.data ?? []).filter((event) => event.category === "sync" || event.category === "pairing").slice(0, 6);

  return (
    <div className="page page-narrow">
      <RemovedNoticeBanner membership={membership.data} reload={membership.reload} />
      {!snapshot.enrolled && membership.data?.pendingLeave && (
        <StatusBanner kind="info" title="You left the sync group" action={<PendingLeaveChip membership={membership.data} />}>
          This PC keeps its items. Your phone is told the next time this PC reaches it.
        </StatusBanner>
      )}
      {!snapshot.enrolled && (
        <Card title="Add this PC to your vault" id="how-pairing">
          <ol className="how-list">
            <li><strong>Connect.</strong> Scan the QR from your phone, or show a QR for your phone to scan. Both must be on the same Wi-Fi.</li>
            <li><strong>Confirm the code.</strong> Make sure both screens show the same code. Same Wi-Fi never grants trust on its own.</li>
            <li><strong>Import.</strong> This PC receives an encrypted copy and keeps any items it already has.</li>
          </ol>
        </Card>
      )}
      {snapshot.enrolled ? <ConnectionCard status={sync.data} error={sync.error} reload={sync.reload} /> : <PairingCard />}
      {snapshot.enrolled && <CloudCard />}

      {snapshot.enrolled && conflictCount > 0 && (
        <StatusBanner kind="warning" title={`${plural(conflictCount, "change")} need${conflictCount === 1 ? "s" : ""} review`}
          action={conflicts.data ? <Button size="sm" onClick={() => void router.navigate({ page: "conflicts" })}>Review</Button> : undefined}>
          {conflicts.data ? "The same item changed on both devices. Both versions are kept until you choose." : "The same item changed on both devices. Both versions are kept; choose one on your phone under Devices."}
        </StatusBanner>
      )}
      {snapshot.enrolled && sync.data && sync.data.waitingToApply - (sync.data.setAside ?? 0) > 0 && (
        <StatusBanner kind="info" title={`${plural(sync.data.waitingToApply - (sync.data.setAside ?? 0), "change")} waiting to apply`}>
          They'll be applied on a later sync.
        </StatusBanner>
      )}
      {snapshot.enrolled && sync.data && (sync.data.setAside ?? 0) > 0 && (
        <StatusBanner kind="warning" title={`${plural(sync.data.setAside ?? 0, "change")} could not be read`}>
          Nuvori set {sync.data.setAside === 1 ? "it" : "them"} aside and tries again on each sync. Other changes still sync. Update Nuvori on this PC and on your phone.
        </StatusBanner>
      )}
      {snapshot.enrolled && <PhotoTransfer />}

      {snapshot.enrolled && membershipShown && <DevicesGroup membership={membership.data!} />}
      {snapshot.enrolled && !membershipShown && (
        <SettingsGroup title="Devices">
          <SettingsRow icon={Laptop} title="This PC" description="Keeps its own encrypted copy and catches up when connected." control={<StatusChip kind="success" label="Paired" />} />
          <SettingsRow icon={Smartphone} title="Paired devices" description="Devices sharing this vault, including your phone." control={<span className="row-value">{snapshot.pairedDevices}</span>} />
          <SettingsRow icon={History} title="Local changes recorded" description="Signed changes kept in the encrypted vault." control={<span className="row-value">{snapshot.pendingChanges}</span>} />
        </SettingsGroup>
      )}

      {snapshot.enrolled && sync.data && <PhoneConnection status={sync.data} reload={sync.reload} />}

      <section className="section" aria-labelledby="sync-activity-title">
        <div className="section-header">
          <h2 id="sync-activity-title">Recent sync activity</h2>
          <Button variant="ghost" size="sm" onClick={() => void router.navigate({ page: "activity" })}>View all</Button>
        </div>
        {activity.error ? <div className="card card-padded muted small">Activity log unavailable.</div>
          : recent.length === 0 ? <div className="card card-padded muted small">No sync activity yet.</div>
          : <ActivityList events={recent} />}
      </section>

      {snapshot.enrolled && !membershipShown && <DangerZone stopOnly />}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Photo transfer progress, shown only when the backend reports it and something is moving. */
function PhotoTransfer() {
  const photos = usePhotoSyncStatus(3000);
  const data = photos.data;
  if (!data || (data.waiting === 0 && (data.totalBytes === 0 || data.transferredBytes >= data.totalBytes))) return null;
  const known = data.totalBytes > 0;
  return (
    <div className="card card-padded photo-transfer" aria-live="polite">
      <div className="photo-transfer-head">
        <span className="row-icon" aria-hidden="true"><Image /></span>
        <span className="row-text">
          <span className="row-title">{data.waiting > 0 ? `${plural(data.waiting, "photo")} to transfer` : "Finishing photo transfer"}</span>
          <span className="row-description">{known ? `${formatBytes(data.transferredBytes)} of ${formatBytes(data.totalBytes)}` : "Photos move during the next sync."}</span>
        </span>
      </div>
      {known && <ProgressBar label="Photo transfer" value={data.transferredBytes} max={data.totalBytes} />}
    </div>
  );
}

function ConnectionCard({ status, error, reload }: { status: SyncStatus | null; error: unknown; reload: () => Promise<void> }) {
  const { snapshot } = useVault();
  const syncNow = useSyncNow(status?.phoneAddress ?? "", reload);
  const indicator = syncIndicator(snapshot, status, Boolean(error));
  const running = isSyncing(status) || syncNow.busy;
  const total = status?.progressTotal ?? 0;
  const done = status?.progressDone ?? 0;
  const retry = status?.nextRetrySeconds ?? 0;
  const failures = status?.consecutiveFailures ?? 0;

  return (
    <section className="card card-padded connection" aria-labelledby="connection-title">
      <div className="connection-head">
        <span className="connection-icon" aria-hidden="true"><Smartphone /></span>
        <div className="connection-text">
          <h2 id="connection-title">Your devices</h2>
          <p className="muted small">{status?.phoneAddress ? status.phoneAddress : "Find paired devices automatically on this network"}</p>
        </div>
        <StatusChip kind={indicator.kind} label={indicator.label} />
      </div>

      {running && status && (
        <div className="connection-progress" aria-live="polite">
          <div className="connection-progress-label"><span>{phaseLabel(status)}</span>{total > 0 && <span className="muted">{done} of {total}</span>}</div>
          <ProgressBar label="Sync progress" value={done} max={total} indeterminate={total === 0} />
        </div>
      )}

      {!running && indicator.detail && (indicator.kind === "error" || indicator.kind === "warning") && indicator.label !== "Needs review" && (
        <StatusBanner kind={indicator.kind} title={indicator.label}>
          {indicator.detail}
          {failures > 1 && ` Failed ${failures} times in a row.`}
          {retry > 0 && status?.automatic && ` Retrying in ${retry < 60 ? `${retry}s` : `${Math.round(retry / 60)} min`}.`}
        </StatusBanner>
      )}
      {error ? <StatusBanner kind="warning">Sync status is unavailable right now.</StatusBanner> : null}

      <dl className="connection-facts">
        <div><dt>Last checked</dt><dd title={status?.lastAttempt || status?.lastSync ? formatDateTime(status?.lastAttempt || status?.lastSync || "") : undefined}>{relativeTime(status?.lastAttempt || status?.lastSync)}</dd></div>
        <div><dt>Last successful sync</dt><dd title={status?.lastSync ? formatDateTime(status.lastSync) : undefined}>{relativeTime(status?.lastSync)}</dd></div>
        <div><dt>Auto-sync</dt><dd>{status?.automatic ? "On" : "Off"}</dd></div>
      </dl>
      {!running && status?.message && indicator.kind !== "error" && indicator.kind !== "warning" && <p className="muted small">{status.message}</p>}

      <div className="button-row">
        <Button variant="primary" icon={RefreshCw} busy={running} disabled={!status} onClick={() => void syncNow.run()}>{running ? "Syncing changes" : "Sync now"}</Button>
      </div>
    </section>
  );
}

function PhoneConnection({ status, reload }: { status: SyncStatus; reload: () => Promise<void> }) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [address, setAddress] = useState(status.phoneAddress);
  const [busy, setBusy] = useState(false);
  const running = isSyncing(status);
  const syncNow = useSyncNow(address, reload);

  useEffect(() => { if (!editing) setAddress(status.phoneAddress); }, [status.phoneAddress, editing]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    const value = address.trim();
    setBusy(true);
    try {
      await api.configureSync(value, status.automatic);
      toast.success("Connection saved");
      setEditing(false);
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't save the address.");
    } finally {
      setBusy(false);
    }
  };

  const saveAndSync = async () => {
    const value = address.trim();
    if (await syncNow.run({ address: value, automatic: status.automatic })) setEditing(false);
  };

  const toggleAuto = async (automatic: boolean) => {
    setBusy(true);
    try {
      await api.configureSync(status.phoneAddress, automatic);
      toast.success(automatic ? "Auto-sync on" : "Auto-sync off");
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't change auto-sync.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsGroup title="Connection">
      <SettingsRow icon={Wifi} title="Optional device address" description={editing ? "Leave blank for discovery. If needed, enter a paired device's local IP address and optional :port." : status.phoneAddress || "Find paired devices automatically"}
        control={!editing && <IconButton label="Edit optional device address" icon={Pencil} onClick={() => setEditing(true)} disabled={running} />}>
        {editing && (
          <form className="inline-form" onSubmit={(event) => void save(event)}>
            <TextField label="Optional device address" value={address} onValue={setAddress} placeholder="192.168.1.24" autoComplete="off" spellCheck={false} disabled={busy || running} autoFocus />
            <div className="button-row">
              <Button variant="primary" type="submit" busy={busy}>Save</Button>
              <Button onClick={() => void saveAndSync()} busy={syncNow.busy} disabled={busy}>Save and sync</Button>
              <Button variant="ghost" onClick={() => { setEditing(false); setAddress(status.phoneAddress); }}>Cancel</Button>
            </div>
          </form>
        )}
      </SettingsRow>
      <SettingsRow icon={RefreshCw} title="Sync automatically" description="Finds paired phones and PCs on your local network while unlocked. Sends new changes sooner and retries after a dropped connection."
        control={<Toggle label="Sync automatically" checked={status.automatic} disabled={busy || running} onChange={(value) => void toggleAuto(value)} />} />
    </SettingsGroup>
  );
}
