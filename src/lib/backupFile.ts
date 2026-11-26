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
  return parts.length < 2 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/** "The backup has 12 items, including 2 authenticators. It also has 3 folders and 1 photo.", as Android words it. */
export function backupContents(review: Pick<BackupReview, "items" | "codes" | "folders" | "photos" | "passkeys">): string {
  const items = review.codes > 0
    ? `The backup has ${count(review.items, "item")}, including ${count(review.codes, "authenticator")}.`
    : `The backup has ${count(review.items, "item")}.`;
  const more = [
    review.folders > 0 && count(review.folders, "folder"),
    review.photos > 0 && count(review.photos, "photo"),
    review.passkeys > 0 && count(review.passkeys, "passkey"),
  ].filter(Boolean) as string[];
  return more.length ? `${items} It also has ${list(more)}.` : items;
}

/** The message after a restore. A vault that locked to finish says so. */
export function restoredMessage(review: Pick<BackupReview, "items">, unlocked: boolean): string {
  return unlocked
    ? `Restored ${count(review.items, "item")} from the backup.`
    : `Restored ${count(review.items, "item")} from the backup. Unlock Nuvori to finish.`;
}
