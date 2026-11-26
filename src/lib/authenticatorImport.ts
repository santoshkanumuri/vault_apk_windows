// Import authenticator codes (authenticator_import.rs), with Android's checks and wording. The
// dialog keeps what it has read and sends all of it each time, so the review and the import match.

import { plural } from "./format.ts";

/** One QR page or file the dialog read. Setup keys stay in these until the dialog closes. */
export type AuthenticatorSource =
  | { kind: "qr"; text: string }
  | { kind: "text"; text: string }
  | { kind: "oneAuth"; text: string; password: string };

export type AuthenticatorStatus = "new" | "alreadySaved" | "conflict";

export type AuthenticatorReview = {
  pages: number;
  expected: number;
  items: Array<{ issuer: string; account: string; status: AuthenticatorStatus }>;
  new: number;
  alreadySaved: number;
  conflicts: number;
};

export type AuthenticatorSummary = { added: number; alreadySaved: number; conflicts: number };

/** Android reads export files up to 1 MiB. */
export const MAX_EXPORT_BYTES = 1_048_576;

/** Android `isEncryptedOneAuthExport`: a Zoho OneAuth export asks for its password first. */
export function isOneAuthExport(text: string): boolean {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value) && (value as { format?: unknown }).format === "oneauth_04";
  } catch {
    return false;
  }
}

/** Android's heading: a file or a single QR is one complete batch, so it never says "1 of 1". */
export function reviewHeading(review: AuthenticatorReview): string {
  return review.expected === 1 ? "Accounts to import" : `${review.pages} of ${review.expected} QR pages scanned`;
}

export function reviewLabel(item: AuthenticatorReview["items"][number]): string {
  const status = item.status === "new" ? "New" : item.status === "alreadySaved" ? "Already saved" : "Different setup key, skipped";
  return `${item.issuer.trim() || item.account} · ${item.account} · ${status}`;
}

/** Android `importAuthenticatorAccounts`' message, and the toast tone it picks. */
export function importResult(summary: AuthenticatorSummary): { message: string; tone: "success" | "info" | "warning" } {
  const message = `Imported ${plural(summary.added, "authenticator account")}. ${summary.alreadySaved} already saved. ${plural(summary.conflicts, "conflict")} skipped.`;
  const tone = summary.conflicts > 0 ? "warning" : summary.added === 0 ? "info" : "success";
  return { message, tone };
}

/** A QR the camera or an image gave again adds nothing: the same page is already in the batch. */
export function alreadyRead(sources: readonly AuthenticatorSource[], source: AuthenticatorSource): boolean {
  return sources.some((known) => known.kind === source.kind && known.text === source.text);
}
