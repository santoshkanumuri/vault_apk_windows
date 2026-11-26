import { useCallback, useRef, useState, type FormEvent } from "react";
import { CircleHelp, Crown, LogOut, Monitor, Pencil, ShieldAlert, Smartphone, type LucideIcon } from "lucide-react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SettingsGroup, SettingsRow } from "../../components/Display";
import { TextField } from "../../components/Field";
import { StatusBanner, StatusChip } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useMembership } from "../../app/hooks";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type MemberDevice, type MembershipStatus } from "../../lib/api";
import { humanError, isUnavailable } from "../../lib/errors";
import { cx, formatDateTime, plural, relativeTime } from "../../lib/format";
import { deviceNameProblem, isStale, removeHelp, splitDevices, staleHint } from "../../lib/deviceList";
import { accountText, codeText, strings } from "../../strings";
import { peerAckText } from "../../lib/syncOverview";
import type { SyncOverviewState } from "../../app/useSyncOverview";

const platformIcon: Record<MemberDevice["platform"], LucideIcon> = { android: Smartphone, windows: Monitor, unknown: CircleHelp };

type LeaveChoice = "keep" | "empty";

/**
 * Leave the sync group. The user chooses to keep this PC's items or start with an empty vault (ready to join
 * another group). A signed leave request goes to the managing phone at the saved address.
 * Falls back to the older stop_sharing command when leave_group isn't available. Render `dialog`.
 */
export function useLeaveGroup(managerName?: string) {
  const { setSnapshot } = useVault();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<LeaveChoice>("keep");
  const [phoneAddress, setPhoneAddress] = useState<string | null>(null);
  const after = useRef<(() => void | Promise<void>) | undefined>(undefined);
  const phone = managerName && !/^this device$/i.test(managerName) ? managerName : "your phone";

  const run = useCallback(async (then?: () => void | Promise<void>) => {
    after.current = then;
    setChoice("keep");
    setPhoneAddress(null);
    setOpen(true);
    try {
      const [membership, sync] = await Promise.all([api.membershipStatus(), api.syncStatus()]);
      setPhoneAddress(membership.leaveAddress || sync.phoneAddress);
    } catch { setPhoneAddress(""); }
  }, []);

  const leave = useCallback(async () => {
    if (choice === "empty") {
      const sure = await confirm({
        title: codeText.removeEveryItemFromThisPc,
        message: codeText.passwordsCardsCodesNotesPasskeysAnd,
        confirmLabel: codeText.leaveAndEmptyThisPc,
        danger: true
      });
      if (!sure) return;
    }
    setOpen(false);
    setBusy(true);
    const progress = toast.progress(codeText.leavingTheSyncGroup);
    try {
      let next;
      try {
        next = await api.leaveGroup(choice === "keep");
      } catch (failure) {
        if (!isUnavailable(failure) || choice === "empty") throw failure;
        next = await api.stopSharing();
      }
      setSnapshot(next);
      progress.success(choice === "keep" ? codeText.leftTheSyncGroupThisPc : codeText.leftTheSyncGroupThisPc2);
      await after.current?.();
    } catch (failure) {
      progress.error(failure, codeText.couldnTLeaveTheSyncGroup);
    } finally {
      setBusy(false);
    }
  }, [choice, confirm, setSnapshot, toast]);

  const told = phoneAddress === null ? null
    : phoneAddress
      ? `${phone === "your phone" ? "Your phone" : phone} is told at ${phoneAddress}, now or the next time this PC reaches it.`
      : codeText.thisPcHasNoSavedRoute(phone);

  const dialog = (
    <Dialog open={open} title={strings.leaveTheSyncGroup} onClose={() => setOpen(false)} size="md"
      description={strings.thisPcStopsSyncingYourPhone}
      footer={<>
        <Button variant="ghost" onClick={() => setOpen(false)} data-confirm-default="">{strings.cancel}</Button>
        <Button variant="danger" onClick={() => void leave()}>{choice === "keep" ? strings.leaveGroup : codeText.leaveAndEmptyThisPc}</Button>
      </>}>
      <div className="leave-choices" role="radiogroup" aria-label={strings.whatHappensToThisPcS}>
        <label className={cx("leave-choice", choice === "keep" && "is-selected")}>
          <input type="radio" name="leave-choice" checked={choice === "keep"} onChange={() => setChoice("keep")} />
          <span><strong>{strings.keepThisPcSItems}</strong><small>{strings.everythingStaysHereAsASeparate}</small></span>
        </label>
        <label className={cx("leave-choice", choice === "empty" && "is-selected")}>
          <input type="radio" name="leave-choice" checked={choice === "empty"} onChange={() => setChoice("empty")} />
          <span><strong>{strings.startWithAnEmptyVault}</strong><small>{strings.removeEveryItemFromThisPc}</small></span>
        </label>
      </div>
      {told && <StatusBanner kind={phoneAddress ? "info" : "warning"}>{told}</StatusBanner>}
    </Dialog>
  );
  return { busy, run, dialog };
}

/** Persistent notice after this PC was removed from the group. Shown until dismissed. */
export function RemovedNoticeBanner({ membership, reload }: { membership: MembershipStatus | null; reload: () => Promise<void> }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const notice = membership?.removedNotice;
  if (!notice) return null;
  const dismiss = async () => {
    setBusy(true);
    try {
      await api.dismissRemovedNotice();
      toast.info(codeText.noticeDismissed);
      await reload();
    } catch (failure) {
      toast.error(failure, codeText.couldnTDismissTheNotice);
    } finally {
      setBusy(false);
    }
  };
  return (
    <StatusBanner kind="warning" title={strings.thisPcWasRemovedFromThe2}
      action={<Button size="sm" onClick={() => void dismiss()} busy={busy}>{strings.dismiss}</Button>}>
      Removed by {notice.by || codeText.theManagingDevice}{notice.at ? codeText.on2(formatDateTime(notice.at)) : ""}. Your items stay on this PC. To sync again, pair from your phone: this PC joins as a new device, and its items are added to the group as new copies.
      {notice.kept ? ` ${plural(notice.kept, "item")} from your other devices had not finished syncing. ${notice.kept === 1 ? "It is" : "They are"} in Recently deleted; restore ${notice.kept === 1 ? "it" : "them"} there within 30 days.` : ""}
    </StatusBanner>
  );
}

export function PendingLeaveChip({ membership }: { membership: MembershipStatus | null }) {
  if (!membership?.pendingLeave) return null;
  return <StatusChip kind="progress" label={strings.leaveRequestPending} title={strings.yourPhoneIsToldTheNext} />;
}

const changes = (count: number) => plural(count, "change");

/** This device's state by its verified progress over Wi-Fi and Google Drive; null without one. */
function deviceAck(device: MemberDevice, overview: SyncOverviewState | null | undefined) {
  if (!overview || device.isThisDevice || device.status === "removed") return null;
  const peer = overview.facts.peers.find((item) => item.deviceId === device.deviceId);
  const ack = overview.overview.peers[device.deviceId];
  return peer && ack ? peerAckText(peer, ack, overview.facts.now) : null;
}

/** The same states and words as the phone's device card. */
function deviceChip(device: MemberDevice, membership: MembershipStatus, overview?: SyncOverviewState | null) {
  if (device.status === "removed") return <StatusChip kind="neutral" label={strings.removed} />;
  if (membership.pendingTransferTo === device.deviceId) {
    return membership.transferAccepted ? <StatusChip kind="progress" label={strings.acceptedManagingRole} title={strings.acceptedManagingRole} /> : <StatusChip kind="info" label={strings.waitingToAcceptManagingRole} title={strings.waitingToAcceptManagingRole} />;
  }
  if (device.isThisDevice) return <StatusChip kind="success" label={strings.active} />;
  const counts = device.counts;
  // Up to date when its applied progress covers this PC's changes, whichever transport carried them.
  const ack = deviceAck(device, overview);
  // M12: a refused session (or a device silent for days) shows before changes waiting here.
  if (ack?.kind === "error") return <StatusChip kind={ack.kind} label={ack.label} title={ack.detail} />;
  if (counts?.toApplyHere) return <StatusChip kind="warning" label={strings.waitingToApply} />;
  if (ack && ack.kind !== "success") return <StatusChip kind={ack.kind} label={ack.label} />;
  if (isStale(device)) return <StatusChip kind="warning" label={strings.notSeenRecently} />;
  if (ack) return <StatusChip kind={ack.kind} label={ack.label} />;
  if (counts && (counts.toSend || counts.toReceiveHere || counts.receivedThere)) return <StatusChip kind="warning" label={strings.changesWaiting} />;
  if (device.lastSeen) return <StatusChip kind="success" label={strings.active} />;
  return <StatusChip kind="neutral" label={strings.notCheckedYet} />;
}

/** One line about what still has to move, as on the phone. */
function deviceDetail(device: MemberDevice, managerName?: string, overview?: SyncOverviewState | null): string {
  const platform = device.platform === "android" ? "Android" : device.platform === "windows" ? "Windows" : codeText.unknownDevice;
  if (device.status === "removed") return codeText.canTSyncWithYourDevices(platform);
  if (device.isThisDevice) return platform;
  const ack = deviceAck(device, overview);
  if (isStale(device) && (!ack || ack.kind === "success")) return `${platform} · ${staleHint(device, managerName)}`;
  const counts = device.counts;
  const seen = device.lastSeen ? codeText.lastSeen(relativeTime(device.lastSeen)) : codeText.notSeenYet;
  const detail = ack?.kind === "error" ? ack.detail
    : counts?.toApplyHere ? codeText.receivedFromItStillNeedTo(changes(counts.toApplyHere))
    : ack ? ack.detail
    : !counts?.checked ? codeText.waitingForTheFirstCheck
    : counts.toSend ? codeText.fromThisPcStillNeedTo(changes(counts.toSend))
    : counts.toReceiveHere ? codeText.changesFromThisDeviceAreWaiting
    : counts.receivedThere ? codeText.itReceivedChangesAndStillNeeds
    : codeText.theLastCheckFinishedWithNo;
  return `${platform} · ${seen}. ${detail}`;
}

/**
 * "Mark as lost" for a managing phone that is gone. This PC keeps the group as it is, takes no new
 * changes from that phone, and may pair with a new managing phone, keeping its items. Local only.
 */
export function useMarkLost(membership: MembershipStatus, reload?: () => Promise<void>) {
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const phone = membership.managerName || "the managing phone";
  const run = async (lost: boolean) => {
    if (lost && !(await confirm({
      title: codeText.markAsLost(phone),
      message: codeText.thisPcStopsTakingChangesFrom(phone),
      confirmLabel: strings.markAsLost,
      danger: true,
    }))) return;
    setBusy(true);
    try {
      await api.markManagerLost(lost);
      if (lost) toast.success(codeText.markedAsLostPairThisPc);
      else toast.info(codeText.theManagingPhoneIsTrustedAgain);
      await reload?.();
    } catch (failure) {
      toast.error(failure, codeText.couldnTChangeThat);
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}

/**
 * Rename this PC (Android: Devices & sync > This device > Rename). Sends a signed `device_name` change,
 * so the new name shows on every paired device after the next sync. Render `dialog`.
 */
export function useRenameThisPc(current: string, reload?: () => Promise<void>) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const trimmed = name.trim();
  const problem = deviceNameProblem(name);

  const start = () => { setName(current); setError(""); setOpen(true); };
  const close = () => { if (!busy) setOpen(false); };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (problem || trimmed === current) return;
    setBusy(true); setError("");
    try {
      await api.renameThisDevice(trimmed);
      await reload?.();
      setOpen(false);
      toast.success(accountText.renamed);
    } catch (failure) {
      setError(humanError(failure, accountText.renameFailed));
    } finally {
      setBusy(false);
    }
  };

  const dialog = (
    <Dialog open={open} onClose={close} title={accountText.nameThisDevice} locked={busy} size="sm"
      footer={<>
        <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
        <Button variant="primary" type="submit" form="rename-device-form" busy={busy} disabled={!!problem || trimmed === current}>{accountText.saveName}</Button>
      </>}>
      <form id="rename-device-form" className="form-stack" onSubmit={(event) => void save(event)}>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        <TextField label={accountText.deviceName} value={name} onValue={(value) => { setName(value); setError(""); }}
          maxLength={40} autoComplete="off" spellCheck={false} disabled={busy} data-autofocus
          error={name && problem ? problem : undefined} hint={accountText.nameAppearsOnPairedDevices} />
      </form>
    </Dialog>
  );
  return { start, dialog };
}

/** Devices in the group as reported by the signed membership chain. Read-only: Windows can't manage devices. */
export function DevicesGroup({ membership, reload, overview }: { membership: MembershipStatus; reload?: () => Promise<void>; overview?: SyncOverviewState | null }) {
  const leave = useLeaveGroup(membership.managerName);
  const lost = useMarkLost(membership, reload);
  const phone = membership.managerName || "the managing phone";
  const self = membership.devices.find((device) => device.isThisDevice);
  const selfName = self?.name && !/^this pc$/i.test(self.name) ? self.name : "";
  const rename = useRenameThisPc(selfName, reload);
  const target = membership.devices.find((device) => device.deviceId === membership.pendingTransferTo);
  const { active, removed } = splitDevices(membership.devices);
  const row = (device: MemberDevice) => {
    const Icon = platformIcon[device.platform] ?? CircleHelp;
    return (
      <SettingsRow key={device.deviceId} icon={Icon}
        title={<span className="device-name">{device.isThisDevice ? (!device.name || /^this pc$/i.test(device.name) ? strings.thisPc : codeText.thisPc(device.name)) : device.name || codeText.unnamedDevice}{device.isManager && <span className="badge"><Crown aria-hidden="true" />Managing device</span>}</span>}
        description={deviceDetail(device, membership.managerName, overview)}
        control={device.isThisDevice && device.status === "active"
          ? <>{deviceChip(device, membership, overview)}<Button size="sm" variant="ghost" icon={Pencil} aria-label={accountText.renameThisPc(device.name || "this PC")} onClick={rename.start}>{accountText.rename}</Button></>
          : deviceChip(device, membership, overview)} />
    );
  };

  return (
    <>
      {membership.cleanupHint && (
        <StatusBanner kind="info" title={strings.oldSyncHistoryIsKept}>
          {membership.cleanupHint[1]} {removeHelp(membership.managerName)}
        </StatusBanner>
      )}
      {membership.managerLost && (
        <StatusBanner kind="warning" title={codeText.isMarkedAsLost(phone)}
          action={<Button size="sm" variant="ghost" busy={lost.busy} onClick={() => void lost.run(false)}>{strings.itSBack}</Button>}>{strings.thisPcNoLongerTakesChanges}</StatusBanner>
      )}
      {target && (
        <StatusBanner kind="info" title={codeText.managingRoleIsMovingTo(target.name)}>
          {membership.transferAccepted
            ? `${target.name} accepted. Waiting for ${membership.managerName || "the managing device"} to complete the transfer.`
            : `Waiting for ${target.name} to accept on that device. ${membership.managerName || "The managing device"} can cancel at any time.`}
        </StatusBanner>
      )}
      <SettingsGroup title={strings.devices} description={`Only the managing device adds and removes devices; this PC can't. ${removeHelp(membership.managerName)}`}>
        {active.map(row)}
        <SettingsRow icon={LogOut} danger title={strings.leaveGroup}
          description={self?.isManager ? codeText.thisDeviceManagesTheGroupTransfer : strings.stopSyncingKeepThisPcS}
          control={<Button size="sm" variant="ghost" className="btn-danger-text" disabled={self?.isManager} busy={leave.busy} onClick={() => void leave.run()}>{strings.leaveGroup}</Button>} />
        {!self?.isManager && !membership.managerLost && (
          <SettingsRow icon={ShieldAlert} title={codeText.lost(phone)}
            description={strings.markItAsLostThisPc}
            control={<Button size="sm" variant="ghost" busy={lost.busy} onClick={() => void lost.run(true)}>{strings.markAsLost}</Button>} />
        )}
      </SettingsGroup>
      {removed.length > 0 && (
        <SettingsGroup title={strings.removedDevices} description={strings.theseDevicesWereRemovedFromThe}>
          {removed.map(row)}
        </SettingsGroup>
      )}
      {leave.dialog}
      {rename.dialog}
    </>
  );
}

/** Convenience wrapper used by Home and Sync. */
export function useMembershipStatus() {
  const membership = useMembership();
  const available = membership.data !== null && !membership.error;
  return { ...membership, available };
}
