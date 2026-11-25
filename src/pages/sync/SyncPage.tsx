import { useEffect, useState, type FormEvent } from "react";
import { History, Image, Laptop, Pencil, RefreshCw, Smartphone, Timer, Wifi, Zap } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Card, SettingsGroup, SettingsRow } from "../../components/Display";
import { DangerZone } from "../SettingsPage";
import { Segmented, TextField, Toggle } from "../../components/Field";
import { ProgressBar } from "../../components/Spinner";
import { StatusBanner, StatusChip } from "../../components/Status";
import { useConflicts, useMembership, usePhotoSyncStatus, usePolling, useSyncStatus } from "../../app/hooks";
import { useSyncOverview, type SyncOverviewState } from "../../app/useSyncOverview";
import { DevicesGroup, PendingLeaveChip, RemovedNoticeBanner } from "./Membership";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type ActivityEvent, type SyncStatus } from "../../lib/api";
import { formatDateTime, plural, relativeTime } from "../../lib/format";
import { isSyncing, phaseLabel } from "../../lib/syncState";
import { waitingToApplyHere } from "../../lib/syncOverview";
import { ActivityList } from "../ActivityPage";
import { useSyncNow } from "../Home";
import { PairedNotice, PairingCard } from "./Pairing";
import { CloudCard } from "./Cloud";
import { strings, syncStatusText } from "../../strings";

export function SyncPage() {
  const { snapshot } = useVault();
  const router = useRouter();
  const sync = useSyncStatus(snapshot.enrolled ? 1500 : 10000);
  const activity = usePolling<ActivityEvent[]>(() => api.activityLog(200), 5000);
  const conflicts = useConflicts();
  const membership = useMembership();
  const membershipShown = Boolean(membership.data && !membership.error && membership.data.devices.length > 0);
  const conflictCount = conflicts.data ? conflicts.data.length : sync.data?.conflicts ?? 0;
  // M4: changes of a kind only a newer Nuvori applies. The device's own name, as the overview uses.
  const updateFrom = (sync.data?.needsUpdate ?? []).map((device) => ({
    ...device, name: membership.data?.devices.find((known) => known.deviceId === device.deviceId)?.name || device.name }));
  const updateCount = updateFrom.reduce((sum, device) => sum + device.count, 0);
  const recent = (activity.data ?? []).filter((event) => event.category === "sync" || event.category === "pairing").slice(0, 6);
  // One status over Wi-Fi and Google Drive: a success on either counts.
  const overview = useSyncOverview(sync.data, membershipShown ? membership.data : null, conflictCount);

  return (
    <div className="page page-narrow">
      <RemovedNoticeBanner membership={membership.data} reload={membership.reload} />
      {snapshot.enrolled && <PairedNotice />}
      {!snapshot.enrolled && membership.data?.pendingLeave && (
        <StatusBanner kind="info" title={strings.youLeftTheSyncGroup} action={<PendingLeaveChip membership={membership.data} />}>{strings.thisPcKeepsItsItemsYour}</StatusBanner>
      )}
      {!snapshot.enrolled && (
        <Card title={strings.addThisPcToYourVault} id="how-pairing">
          <ol className="how-list">
            <li><strong>{strings.connect}</strong> Scan the QR from your phone, or show a QR for your phone to scan. Both must be on the same Wi-Fi.</li>
            <li><strong>{strings.confirmTheCode}</strong> Make sure both screens show the same code. Same Wi-Fi never grants trust on its own.</li>
            <li><strong>{strings.import2}</strong> This PC receives an encrypted copy and keeps any items it already has. Items already on your phone are not added twice.</li>
          </ol>
        </Card>
      )}
      {snapshot.enrolled ? <ConnectionCard status={sync.data} error={sync.error} reload={sync.reload} overview={overview} /> : <PairingCard />}
      {snapshot.enrolled && <CloudCard />}

      {snapshot.enrolled && conflictCount > 0 && (
        <StatusBanner kind="warning" title={`${plural(conflictCount, "change")} need${conflictCount === 1 ? "s" : ""} review`}
          action={conflicts.data ? <Button size="sm" onClick={() => void router.navigate({ page: "conflicts" })}>{strings.review}</Button> : undefined}>
          {conflicts.data ? "The same item changed on both devices. Both versions are kept until you choose." : "The same item changed on both devices. Both versions are kept; choose one on your phone under Devices & sync."}
        </StatusBanner>
      )}
      {snapshot.enrolled && sync.data?.waitingForKeys && (
        <StatusBanner kind="info" title={strings.waitingForNewSyncKeysFrom}>{strings.aDeviceWasRemovedSoThe}</StatusBanner>
      )}
      {snapshot.enrolled && sync.data && waitingToApplyHere(sync.data) > 0 && (
        <StatusBanner kind="info" title={`${plural(waitingToApplyHere(sync.data), "change")} waiting to apply`}>{strings.theyLlBeAppliedOnA}</StatusBanner>
      )}
      {snapshot.enrolled && updateCount > 0 && (
        <StatusBanner kind="warning" title={`${plural(updateCount, "change")} from ${updateFrom.length === 1 ? updateFrom[0].name : `${updateFrom.length} devices`} ${updateCount === 1 ? "needs" : "need"} a newer Nuvori`}>
          Update Nuvori on this PC to apply {updateCount === 1 ? "it" : "them"}. Other changes still sync.
        </StatusBanner>
      )}
      {snapshot.enrolled && sync.data && (sync.data.setAside ?? 0) > 0 && (
        <StatusBanner kind="warning" title={`${plural(sync.data.setAside ?? 0, "change")} couldn't be read`}>
          Nuvori set {sync.data.setAside === 1 ? "it" : "them"} aside and tries again on each sync. Other changes still sync. Update Nuvori on this PC and on your phone.
        </StatusBanner>
      )}
      {snapshot.enrolled && <PhotoTransfer />}

      {snapshot.enrolled && membershipShown && <DevicesGroup membership={membership.data!} reload={membership.reload} overview={overview} />}
      {snapshot.enrolled && membership.data?.managerLost && <PairingCard />}
      {snapshot.enrolled && !membershipShown && (
        <SettingsGroup title={strings.devices}>
          <SettingsRow icon={Laptop} title={strings.thisPc} description={strings.keepsItsOwnEncryptedCopyAnd} control={<StatusChip kind="success" label={strings.paired} />} />
          <SettingsRow icon={Smartphone} title={strings.pairedDevices} description={strings.devicesSharingThisVaultIncludingYour} control={<span className="row-value">{snapshot.pairedDevices}</span>} />
          <SettingsRow icon={History} title={strings.localChangesRecorded} description={strings.signedChangesKeptInTheEncrypted} control={<span className="row-value">{snapshot.pendingChanges}</span>} />
        </SettingsGroup>
      )}

      {snapshot.enrolled && sync.data && <PhoneConnection status={sync.data} reload={sync.reload} />}

      <section className="section" aria-labelledby="sync-activity-title">
        <div className="section-header">
          <h2 id="sync-activity-title">{strings.recentSyncActivity}</h2>
          <Button variant="ghost" size="sm" onClick={() => void router.navigate({ page: "activity" })}>{strings.viewAll}</Button>
        </div>
        {activity.error ? <div className="card card-padded muted small">{strings.activityLogUnavailable2}</div>
          : recent.length === 0 ? <div className="card card-padded muted small">{strings.noSyncActivityYet}</div>
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
      {known && <ProgressBar label={strings.photoTransfer} value={data.transferredBytes} max={data.totalBytes} />}
    </div>
  );
}

function ConnectionCard({ status, error, reload, overview }: { status: SyncStatus | null; error: unknown; reload: () => Promise<void>; overview: SyncOverviewState | null }) {
  const syncNow = useSyncNow(status?.phoneAddress ?? "", reload);
  const running = isSyncing(status) || syncNow.busy;
  const total = status?.progressTotal ?? 0;
  const done = status?.progressDone ?? 0;
  const retry = status?.nextRetrySeconds ?? 0;
  const failures = status?.consecutiveFailures ?? 0;
  const text = overview?.text;
  const facts = overview?.facts;
  // Conflicts, set-aside changes, changes waiting here and missing keys have their own banners on this page.
  const shownBelow = overview?.overview.state === "conflicts" || overview?.overview.state === "waitingHere"
    || overview?.overview.cause === "rejected";
  const problem = text && (text.kind === "error" || text.kind === "warning") && !shownBelow;
  const wifiFact = facts?.wifi === "failed" ? syncStatusText.factCouldntReach : status?.lastSync ? relativeTime(status.lastSync) : syncStatusText.factNotYet;
  const driveFact = !facts || facts.drive === "off" ? syncStatusText.factOff : facts.drive === "failed" ? syncStatusText.factDidntFinish
    : facts.lastDriveSync ? relativeTime(facts.lastDriveSync) : syncStatusText.factNotYet;

  return (
    <section className="card card-padded connection" aria-labelledby="connection-title">
      <div className="connection-head">
        <span className="connection-icon" aria-hidden="true"><Smartphone /></span>
        <div className="connection-text">
          <h2 id="connection-title">{strings.yourDevices}</h2>
          <p className="muted small">{text?.lastSynced ?? (status?.phoneAddress ? status.phoneAddress : "Find paired devices automatically on this network")}</p>
        </div>
        {text ? <StatusChip kind={text.kind} label={text.title} /> : <StatusChip kind="neutral" label={strings.syncStatusIsUnavailableRightNow} />}
      </div>

      {running && status && (
        <div className="connection-progress" aria-live="polite">
          <div className="connection-progress-label"><span>{phaseLabel(status)}</span>{total > 0 && <span className="muted">{done} of {total}</span>}</div>
          <ProgressBar label={strings.syncProgress} value={done} max={total} indeterminate={total === 0} />
        </div>
      )}

      {!running && text && problem && (
        <StatusBanner kind={text.kind} title={text.title}>
          {text.detail}
          {overview?.overview.cause === "localProblem" && failures > 1 && ` Failed ${failures} times in a row.`}
          {overview?.overview.cause === "localProblem" && retry > 0 && status?.automatic && ` Retrying in ${retry < 60 ? `${retry}s` : `${Math.round(retry / 60)} min`}.`}
        </StatusBanner>
      )}
      {!running && text && !problem && text.detail && <p className="small" aria-live="polite">{text.detail}</p>}
      {/* A transport that failed while the other one carried the changes: a quiet line, not the headline. */}
      {text?.note && <p className="muted small">{text.note}</p>}
      {error ? <StatusBanner kind="warning">{strings.syncStatusIsUnavailableRightNow}</StatusBanner> : null}

      <dl className="connection-facts">
        <div><dt>{syncStatusText.factLastSynced}</dt><dd title={overview?.overview.lastSynced ? formatDateTime(overview.overview.lastSynced) : undefined}>{relativeTime(overview?.overview.lastSynced || status?.lastSync)}</dd></div>
        <div><dt>{syncStatusText.factWifi}</dt><dd title={status?.lastSync ? formatDateTime(status.lastSync) : undefined}>{wifiFact}</dd></div>
        <div><dt>{syncStatusText.factDrive}</dt><dd title={facts?.lastDriveSync ? formatDateTime(facts.lastDriveSync) : undefined}>{driveFact}</dd></div>
        <div><dt>{strings.autoSync}</dt><dd>{status?.automatic ? "On" : "Off"}</dd></div>
      </dl>

      <div className="button-row">
        <Button variant="primary" icon={RefreshCw} busy={running} disabled={!status} onClick={() => void syncNow.run()}>{running ? "Syncing changes" : "Sync now"}</Button>
      </div>
    </section>
  );
}

const WIFI_CHECK_LABELS: Record<string, string> = { "30": "30 seconds", "60": "minute", "300": "5 minutes", "900": "15 minutes" };
const WIFI_CHECK_OPTIONS = [{ value: "30", label: "30 s" }, { value: "60", label: "1 min" }, { value: "300", label: "5 min" }, { value: "900", label: "15 min" }];

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

  const changeInterval = async (value: string) => {
    setBusy(true);
    try {
      await api.setSyncSchedule({ wifiSeconds: Number(value) });
      toast.success(`Checks devices on this Wi-Fi every ${WIFI_CHECK_LABELS[value] ?? value}`);
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't change the check interval.");
    } finally {
      setBusy(false);
    }
  };

  const toggleOnOpen = async (enabled: boolean) => {
    setBusy(true);
    try {
      await api.setSyncOnOpen(enabled);
      toast.success(enabled ? "Nuvori syncs each time you open it" : "Opening Nuvori no longer starts a sync");
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't change this setting.");
    } finally {
      setBusy(false);
    }
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
    <SettingsGroup title={strings.connection}>
      <SettingsRow icon={Wifi} title={strings.optionalDeviceAddress} description={editing ? "Leave blank for discovery. If needed, enter a paired device's local IP address and optional :port." : status.phoneAddress || "Find paired devices automatically"}
        control={!editing && <IconButton label={strings.editOptionalDeviceAddress} icon={Pencil} onClick={() => setEditing(true)} disabled={running} />}>
        {editing && (
          <form className="inline-form" onSubmit={(event) => void save(event)}>
            <TextField label={strings.optionalDeviceAddress} value={address} onValue={setAddress} placeholder="192.168.1.24" autoComplete="off" spellCheck={false} disabled={busy || running} autoFocus />
            <div className="button-row">
              <Button variant="primary" type="submit" busy={busy}>{strings.save}</Button>
              <Button onClick={() => void saveAndSync()} busy={syncNow.busy} disabled={busy}>{strings.saveAndSync}</Button>
              <Button variant="ghost" onClick={() => { setEditing(false); setAddress(status.phoneAddress); }}>{strings.cancel}</Button>
            </div>
          </form>
        )}
      </SettingsRow>
      <SettingsRow icon={RefreshCw} title={strings.syncAutomatically} description={strings.findsPairedPhonesAndPcsOn}
        control={<Toggle label={strings.syncAutomatically} checked={status.automatic} disabled={busy || running} onChange={(value) => void toggleAuto(value)} />} />
      {status.syncOnOpen !== undefined && (
        <SettingsRow icon={Zap} title={strings.syncWhenNuvoriOpens} description={strings.eachTimeYouOpenNuvoriIt}
          control={<Toggle label={strings.syncWhenNuvoriOpens} checked={status.syncOnOpen} disabled={busy || running} onChange={(value) => void toggleOnOpen(value)} />} />
      )}
      {status.automatic && status.wifiCheckSeconds !== undefined && (
        <SettingsRow icon={Timer} title={strings.checkDevicesEvery} description={strings.howOftenThisPcLooksFor}
          control={<Segmented label={strings.checkDevicesEvery} size="sm" value={String(status.wifiCheckSeconds)} onChange={(value) => void changeInterval(value)}
            options={WIFI_CHECK_OPTIONS} />} />
      )}
    </SettingsGroup>
  );
}
