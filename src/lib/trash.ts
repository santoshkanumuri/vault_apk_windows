import { api } from "./api";
import { codeText } from "../strings.ts";

/** Shown in delete confirmations: how long Recently deleted keeps an item on this PC. */
export const TRASH_DAYS = 30;

export const deleteMessage = codeText.itWillBeRemovedFromThis(TRASH_DAYS);

/**
 * Undo for a delete: restores the copy that this PC just put in Recently deleted. It comes back as
 * a new item, with its folders and previous passwords; photos are not kept.
 */
export async function restoreDeleted(itemId: string) {
  const copy = (await api.listTrash()).find((item) => item.itemId === itemId);
  if (!copy) throw new Error("The deleted copy is no longer in Recently deleted.");
  return api.restoreTrashed(copy.id);
}
