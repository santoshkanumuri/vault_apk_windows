import { useCallback, useRef, useState } from "react";
import { CircleHelp, Crown, LogOut, Monitor, ShieldAlert, Smartphone, type LucideIcon } from "lucide-react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SettingsGroup, SettingsRow } from "../../components/Display";
import { StatusBanner, StatusChip } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useMembership } from "../../app/hooks";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type MemberDevice, type MembershipStatus } from "../../lib/api";
import { isUnavailable } from "../../lib/errors";
import { cx, formatDateTime, plural, relativeTime } from "../../lib/format";
import { isStale, removeHelp, splitDevices, staleHint } from "../../lib/deviceList";
import { strings } from "../../strings";

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
        title: "Remove every item from this PC?",
        message: "Passwords, cards, codes, notes, passkeys, and photos are deleted from this PC. Your phone and other devices keep their copies. This can't be undone on this PC.",
        confirmLabel: "Leave and empty this PC",
        danger: true
      });
      if (!sure) return;
    }
    setOpen(false);
    setBusy(true);
    const progress = toast.progress("Leaving the sync group…");
    try {
      let next;
      try {
        next = await api.leaveGroup(choice === "keep");
      } catch (failure) {
        if (!isUnavailable(failure) || choice === "empty") throw failure;
        next = await api.stopSharing();
      }
      setSnapshot(next);
      progress.success(choice === "keep" ? "Left the sync group. This PC keeps its items." : "Left the sync group. This PC's vault is empty and ready to pair again.");
      await after.current?.();
    } catch (failure) {
      progress.error(failure, "Couldn't leave the sync group.");
    } finally {
      setBusy(false);
    }
  }, [choice, confirm, setSnapshot, toast]);

  const told = phoneAddress === null ? null
    : phoneAddress
      ? `${phone === "your phone" ? "Your phone" : phone} is told at ${phoneAddress}, now or the next time this PC reaches it.`
      : `This PC has no saved route to ${phone}, so it can't tell it. After leaving, remove this PC on your phone too (Devices & sync).`;

  const dialog = (
    <Dialog open={open} title={strings.leaveTheSyncGroup} onClose={() => setOpen(false)} size="md"
      description={strings.thisPcStopsSyncingYourPhone}
      footer={<>
        <Button variant="ghost" onClick={() => setOpen(false)} data-confirm-default="">{strings.cancel}</Button>
        <Button variant="danger" onClick={() => void leave()}>{choice === "keep" ? "Leave group" : "Leave and empty this PC"}</Button>
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
      toast.info("Notice dismissed");
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't dismiss the notice.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <StatusBanner kind="warning" title={strings.thisPcWasRemovedFromThe2}
      action={<Button size="sm" onClick={() => void dismiss()} busy={busy}>{strings.dismiss}</Button>}>
      Removed by {notice.by || "the managing device"}{notice.at ? ` on ${formatDateTime(notice.at)}` : ""}. Your items stay on this PC. To sync again, pair from your phone: this PC joins as a new device, and its items are added to the group as new copies.
      {notice.kept ? ` ${plural(notice.kept, "item")} from your other devices had not finished syncing. ${notice.kept === 1 ? "It is" : "They are"} in Recently deleted; restore ${notice.kept === 1 ? "it" : "them"} there within 30 days.` : ""}
    </StatusBanner>
  );
}

export function PendingLeaveChip({ membership }: { membership: MembershipStatus | null }) {
  if (!membership?.pendingLeave) return null;
  return <StatusChip kind="progress" label={strings.leaveRequestPending} title={strings.yourPhoneIsToldTheNext} />;
}

const changes = (count: number) => plural(count, "change");

/** The same states and words as the phone's device card. */
function deviceChip(device: MemberDevice, membership: MembershipStatus) {
  if (device.status === "removed") return <StatusChip kind="neutral" label={strings.removed} />;
  if (membership.pendingTransferTo === device.deviceId) {
    return membership.transferAccepted ? <StatusChip kind="progress" label={strings.acceptedManagingRole} title={strings.acceptedManagingRole} /> : <StatusChip kind="info" label={strings.waitingToAcceptManagingRole} title={strings.waitingToAcceptManagingRole} />;
  }
  if (device.isThisDevice) return <StatusChip kind="success" label={strings.active} />;
  const counts = device.counts;
  if (counts?.toApplyHere) return <StatusChip kind="warning" label={strings.waitingToApply} />;
  if (counts && (counts.toSend || counts.toReceiveHere || counts.receivedThere)) return <StatusChip kind="warning" label={strings.changesWaiting} />;
  if (isStale(device)) return <StatusChip kind="warning" label={strings.notSeenRecently} />;
  if (device.lastSeen) return <StatusChip kind="success" label={strings.active} />;
  return <StatusChip kind="neutral" label={strings.notCheckedYet} />;
}

/** One line about what still has to move, as on the phone. */
function deviceDetail(device: MemberDevice, managerName?: string): string {
  const platform = device.platform === "android" ? "Android" : device.platform === "windows" ? "Windows" : "Unknown device";
  if (device.status === "removed") return `${platform} · Can't sync with your devices. It keeps its own copy, and can pair again as a new device.`;
  if (device.isThisDevice) return platform;
  if (isStale(device)) return `${platform} · ${staleHint(device, managerName)}`;
  const counts = device.counts;
  const seen = device.lastSeen ? `Last seen ${relativeTime(device.lastSeen)}` : "Not seen yet";
  const detail = !counts?.checked ? "Waiting for the first check."
    : counts.toSend ? `${changes(counts.toSend)} from this PC still need to reach it.`
    : counts.toApplyHere ? `${changes(counts.toApplyHere)} received from it still need to apply here.`
    : counts.toReceiveHere ? "Changes from this device are waiting to arrive here."
    : counts.receivedThere ? "It received changes and still needs to apply them."
    : "The last check finished with no known changes waiting.";
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
      title: `Mark ${phone} as lost?`,
      message: `This PC stops taking changes from ${phone}. Your items stay. You can undo this.`,
      confirmLabel: "Mark as lost",
      danger: true,
    }))) return;
    setBusy(true);
    try {
      await api.markManagerLost(lost);
      if (lost) toast.success("Marked as lost. Pair this PC with your new managing phone to move.");
      else toast.info("The managing phone is trusted again.");
      await reload?.();
    } catch (failure) {
      toast.error(failure, "Couldn't change that.");
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}

/** Devices in the group as reported by the signed membership chain. Read-only: Windows can't manage devices. */
export function DevicesGroup({ membership, reload }: { membership: MembershipStatus; reload?: () => Promise<void> }) {
  const leave = useLeaveGroup(membership.managerName);
  const lost = useMarkLost(membership, reload);
  const phone = membership.managerName || "the managing phone";
  const self = membership.devices.find((device) => device.isThisDevice);
  const target = membership.devices.find((device) => device.deviceId === membership.pendingTransferTo);
  const { active, removed } = splitDevices(membership.devices);
  const row = (device: MemberDevice) => {
    const Icon = platformIcon[device.platform] ?? CircleHelp;
    return (
      <SettingsRow key={device.deviceId} icon={Icon}
        title={<span className="device-name">{device.isThisDevice ? (!device.name || /^this pc$/i.test(device.name) ? "This PC" : `${device.name} (this PC)`) : device.name || "Unnamed device"}{device.isManager && <span className="badge"><Crown aria-hidden="true" />Managing device</span>}</span>}
        description={deviceDetail(device, membership.managerName)}
        control={deviceChip(device, membership)} />
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
        <StatusBanner kind="warning" title={`${phone} is marked as lost`}
          action={<Button size="sm" variant="ghost" busy={lost.busy} onClick={() => void lost.run(false)}>{strings.itSBack}</Button>}>{strings.thisPcNoLongerTakesChanges}</StatusBanner>
      )}
      {target && (
        <StatusBanner kind="info" title={`Managing role is moving to ${target.name}`}>
          {membership.transferAccepted
            ? `${target.name} accepted. Waiting for ${membership.managerName || "the managing device"} to complete the transfer.`
            : `Waiting for ${target.name} to accept on that device. ${membership.managerName || "The managing device"} can cancel at any time.`}
        </StatusBanner>
      )}
      <SettingsGroup title={strings.devices} description={`Only the managing device adds and removes devices; this PC can't. ${removeHelp(membership.managerName)}`}>
        {active.map(row)}
        <SettingsRow icon={LogOut} danger title={strings.leaveGroup}
          description={self?.isManager ? "This device manages the group. Transfer the managing role on your phone first." : "Stop syncing. Keep this PC's items or start with an empty vault."}
          control={<Button size="sm" variant="ghost" className="btn-danger-text" disabled={self?.isManager} busy={leave.busy} onClick={() => void leave.run()}>{strings.leaveGroup}</Button>} />
        {!self?.isManager && !membership.managerLost && (
          <SettingsRow icon={ShieldAlert} title={`Lost ${phone}?`}
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
    </>
  );
}

/** Convenience wrapper used by Home and Sync. */
export function useMembershipStatus() {
  const membership = useMembership();
  const available = membership.data !== null && !membership.error;
  return { ...membership, available };
}
