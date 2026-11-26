/**
 * A login's "Linked code": the authenticator item whose one-time code belongs with it, as on the
 * phone (`linkedAuthenticatorId`). The link is stored on the login and travels with it in sync and
 * in backups. A link that cannot be followed counts as no link, so nothing is shown for it.
 */
import type { VaultEntry } from "./api";

/** The codes a login can link to, as the phone lists them: favorites first, then by name. */
export function codesToLink(entries: VaultEntry[]): VaultEntry[] {
  return entries.filter((entry) => entry.type === "AUTHENTICATOR")
    .sort((left, right) => Number(right.favorite) - Number(left.favorite) || left.title.localeCompare(right.title));
}

/**
 * The code a login is linked to, or `null` when it has no link, the code was deleted, or the link
 * names something that is not a code.
 */
export function linkedCode(entry: VaultEntry, entries: VaultEntry[]): VaultEntry | null {
  if (entry.type !== "PASSWORD" || !entry.linkedAuthenticatorId) return null;
  return entries.find((item) => item.id === entry.linkedAuthenticatorId && item.type === "AUTHENTICATOR") ?? null;
}

/** How a code reads in the picker and under a login: "GitHub · octocat". */
export function codeLabel(code: VaultEntry): string {
  return [code.title.trim() || "Untitled", code.primaryValue.trim()].filter(Boolean).join(" · ");
}
