import { restoreText as words } from "../strings.ts";

/** What a backup holds, as the restore review shows it (`restore_open_backup`). */
export type BackupReview = {
  fileName: string;
  items: number;
  /** Authenticators, counted in `items` too. */
  codes: number;
  folders: number;
  photos: number;
  passkeys: number;
  /** What the restore does to this PC's sync group: nothing, leave it first, or refuse (the managing device). */
  sync: "none" | "member" | "manager";
};

/** The local date, "2026-11-05", for a backup's suggested file name. */
export function localDate(now = new Date()): string {
  const two = (value: number) => String(value).padStart(2, "0");
  return `${now.getFullYear()}-${two(now.getMonth() + 1)}-${two(now.getDate())}`;
}

function count(value: number, one: string, many = `${one}s`): string {
  return `${value} ${value === 1 ? one : many}`;
}

function list(parts: string[]): string {
  return parts.length < 2 ? parts.join("") : `${parts.slice(0, -1).join(", ")} ${words.and} ${parts[parts.length - 1]}`;
}

/** "The backup has 12 items, including 2 authenticators. It also has 3 folders and 1 photo.", as Android words it. */
export function backupContents(review: Pick<BackupReview, "items" | "codes" | "folders" | "photos" | "passkeys">): string {
  const items = review.codes > 0
    ? words.holdsWithCodes(count(review.items, words.item), count(review.codes, words.authenticator))
    : words.holds(count(review.items, words.item));
  const more = [
    review.folders > 0 && count(review.folders, words.folder),
    review.photos > 0 && count(review.photos, words.photo),
    review.passkeys > 0 && count(review.passkeys, words.passkey),
  ].filter(Boolean) as string[];
  return more.length ? `${items} ${words.alsoHolds(list(more))}` : items;
}

/** The message after a restore. A vault that locked to finish says so. */
export function restoredMessage(review: Pick<BackupReview, "items">, unlocked: boolean): string {
  const items = count(review.items, words.item);
  return unlocked ? words.restored(items) : words.restoredThenLocked(items);
}
