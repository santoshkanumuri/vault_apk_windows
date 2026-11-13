import { useCallback, useRef, useState } from "react";
import { CircleHelp, Crown, LogOut, Monitor, Smartphone, type LucideIcon } from "lucide-react";
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
    <Dialog open={open} title="Leave the sync group?" onClose={() => setOpen(false)} size="md"
      description="This PC stops syncing. Your phone and other devices keep their copies."
      footer={<>
        <Button variant="ghost" onClick={() => setOpen(false)} data-confirm-default="">Cancel</Button>
        <Button variant="danger" onClick={() => void leave()}>{choice === "keep" ? "Leave group" : "Leave and empty this PC"}</Button>
      </>}>
      <div className="leave-choices" role="radiogroup" aria-label="What happens to this PC's items">
        <label className={cx("leave-choice", choice === "keep" && "is-selected")}>
          <input type="radio" name="leave-choice" checked={choice === "keep"} onChange={() => setChoice("keep")} />
          <span><strong>Keep this PC's items</strong><small>Everything stays here as a separate vault. You can pair again later.</small></span>
        </label>
        <label className={cx("leave-choice", choice === "empty" && "is-selected")}>
          <input type="radio" name="leave-choice" checked={choice === "empty"} onChange={() => setChoice("empty")} />
          <span><strong>Start with an empty vault</strong><small>Remove every item from this PC, ready to join another sync group. Your master password stays the same.</small></span>
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
    <StatusBanner kind="warning" title="This PC was removed from the sync group"
      action={<Button size="sm" onClick={() => void dismiss()} busy={busy}>Dismiss</Button>}>
      Removed by {notice.by || "the managing device"}{notice.at ? ` on ${formatDateTime(notice.at)}` : ""}. Your items stay on this PC. Pair again from your phone to resume syncing.
    </StatusBanner>
  );
}

export function PendingLeaveChip({ membership }: { membership: MembershipStatus | null }) {
  if (!membership?.pendingLeave) return null;
  return <StatusChip kind="progress" label="Leave request pending" title="Your phone is told the next time this PC reaches it." />;
}

const changes = (count: number) => plural(count, "change");

/** The same states and words as the phone's device card. */
function deviceChip(device: MemberDevice, membership: MembershipStatus) {
  if (device.status === "removed") return <StatusChip kind="neutral" label="Removed" />;
  if (membership.pendingTransferTo === device.deviceId) {
    return membership.transferAccepted ? <StatusChip kind="progress" label="Accepted managing role" title="Accepted managing role" /> : <StatusChip kind="info" label="Waiting to accept managing role" title="Waiting to accept managing role" />;
  }
  if (device.isThisDevice) return <StatusChip kind="success" label="Active" />;
  const counts = device.counts;
  if (counts?.toApplyHere) return <StatusChip kind="warning" label="Waiting to apply" />;
  if (counts && (counts.toSend || counts.toReceiveHere || counts.receivedThere)) return <StatusChip kind="warning" label="Changes waiting" />;
  if (device.lastSeen) return <StatusChip kind="success" label="Active" />;
  return <StatusChip kind="neutral" label="Not checked yet" />;
}

/** One line about what still has to move, as on the phone. */
function deviceDetail(device: MemberDevice): string {
  const platform = device.platform === "android" ? "Android" : device.platform === "windows" ? "Windows" : "Unknown device";
  if (device.isThisDevice || device.status === "removed") return platform;
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

/** Devices in the group as reported by the signed membership chain. Read-only: Windows can't manage devices. */
export function DevicesGroup({ membership }: { membership: MembershipStatus }) {
  const leave = useLeaveGroup(membership.managerName);
  const self = membership.devices.find((device) => device.isThisDevice);
  const target = membership.devices.find((device) => device.deviceId === membership.pendingTransferTo);
  const devices = [...membership.devices].sort((a, b) => Number(b.isManager) - Number(a.isManager) || Number(b.isThisDevice) - Number(a.isThisDevice) || Number(a.status === "removed") - Number(b.status === "removed") || a.name.localeCompare(b.name));

  return (
    <>
      {target && (
        <StatusBanner kind="info" title={`Managing role is moving to ${target.name}`}>
          {membership.transferAccepted
            ? `${target.name} accepted. Waiting for ${membership.managerName || "the managing device"} to complete the transfer.`
            : `Waiting for ${target.name} to accept on that device. ${membership.managerName || "The managing device"} can cancel at any time.`}
        </StatusBanner>
      )}
      <SettingsGroup title="Devices" description="The managing device adds and removes devices and holds invitations. Manage devices from your phone; this PC can't be the managing device.">
        {devices.map((device) => {
          const Icon = platformIcon[device.platform] ?? CircleHelp;
          return (
            <SettingsRow key={device.deviceId} icon={Icon}
              title={<span className="device-name">{device.isThisDevice ? (!device.name || /^this pc$/i.test(device.name) ? "This PC" : `${device.name} (this PC)`) : device.name || "Unnamed device"}{device.isManager && <span className="badge"><Crown aria-hidden="true" />Managing device</span>}</span>}
              description={deviceDetail(device)}
              control={deviceChip(device, membership)} />
          );
        })}
        <SettingsRow icon={LogOut} danger title="Leave group"
          description={self?.isManager ? "This device manages the group. Transfer the managing role on your phone first." : "Stop syncing. Keep this PC's items or start with an empty vault."}
          control={<Button size="sm" variant="ghost" className="btn-danger-text" disabled={self?.isManager} busy={leave.busy} onClick={() => void leave.run()}>Leave group</Button>} />
      </SettingsGroup>
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
