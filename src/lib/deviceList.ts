// How the Devices list on the Sync page groups and explains devices. Windows can't add or remove
// devices: only the managing phone signs those changes, so this PC tells the user where to do it.
import type { MemberDevice } from "./api";
import { accountText, codeText, strings } from "../strings.ts";

/** An active device not seen for this long is shown as possibly unused. */
export const STALE_AFTER_DAYS = 30;
const DAY = 24 * 60 * 60 * 1000;

/** The phone's name for instructions, or a generic one. */
export function managerLabel(managerName?: string): string {
  return managerName && !/^this device$/i.test(managerName) && managerName !== "Managing device" ? managerName : "your managing phone";
}

/** Where to remove a device: on the managing phone, never on this PC. */
export function removeHelp(managerName?: string): string {
  return `To remove a device, open Nuvori on ${managerLabel(managerName)}, go to Settings > Devices & sync, and tap Remove on that device's card. The device doesn't need to be on.`;
}

/** True for another active device that synced before but not in the last STALE_AFTER_DAYS days. */
export function isStale(device: MemberDevice, now = Date.now()): boolean {
  return device.status === "active" && !device.isThisDevice && !!device.lastSeen && now - device.lastSeen > STALE_AFTER_DAYS * DAY;
}

/** Days since the device was last seen, rounded down. */
export function daysSinceSeen(device: MemberDevice, now = Date.now()): number {
  return device.lastSeen ? Math.floor((now - device.lastSeen) / DAY) : 0;
}

/** Active devices first (manager, then this PC, then by name) and removed devices in their own list. */
export function splitDevices(devices: MemberDevice[]): { active: MemberDevice[]; removed: MemberDevice[] } {
  const byName = (a: MemberDevice, b: MemberDevice) => a.name.localeCompare(b.name);
  const active = devices.filter((device) => device.status !== "removed")
    .sort((a, b) => Number(b.isManager) - Number(a.isManager) || Number(b.isThisDevice) - Number(a.isThisDevice) || byName(a, b));
  const removed = devices.filter((device) => device.status === "removed").sort(byName);
  return { active, removed };
}

/** The one-line hint under a device that may be lost or unused. */
export function staleHint(device: MemberDevice, managerName?: string, now = Date.now()): string {
  const days = daysSinceSeen(device, now);
  if (device.isManager) return codeText.notSeenForDaysOnlyThis(days);
  return codeText.notSeenForDaysIfYou(days, managerLabel(managerName));
}

/**
 * Why a new name for this PC can't be saved, or "" when it can. Same rule as Android's
 * LocalDeviceNameChangeWriter and incoming_apply.rs: not blank, at most 40 UTF-16 units, no control characters.
 */
export function deviceNameProblem(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return accountText.nameRequired;
  if (trimmed.length > 40) return accountText.nameTooLong;
  if (/\p{Cc}/u.test(trimmed)) return accountText.nameHasControls;
  return "";
}
