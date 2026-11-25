// Import passwords (password_import.rs): types of the dialog's two steps and the wording that
// Android builds in VaultViewModel.kt, kept here so it can be tested without the UI.
import { plural } from "./format.ts";
import { passwordImportText as text } from "../strings.ts";

export type ImportStatus = "new" | "alreadySaved" | "passwordDiffers" | "ambiguous";
export type ColumnMapping = { title: string | null; website: string | null; username: string | null; password: string | null; notes: string | null };
export type ColumnPreview = { header: string; sampleShape: string };
export type ImportReviewItem = { row: number; title: string; username: string; status: ImportStatus };
export type ImportReview = {
  kind: "review"; rows: number; duplicateRows: number; new: number; alreadySaved: number; passwordDiffers: number; ambiguous: number;
  items: ImportReviewItem[]; token: string;
};
export type ImportPreview = ImportReview | { kind: "mapping"; columns: ColumnPreview[]; suggested: ColumnMapping };
export type ImportChoices = { token: string; skipNew: number[]; useImported: number[] };
export type ImportSummary = { added: number; updated: number; skippedExact: number; skippedConflicts: number; duplicateRows: number };
export type ImportFilter = "all" | "new" | "alreadySaved" | "needsDecision";

/** Android's check before "Review import": the three required columns, each column used once. */
export function mappingValid(mapping: ColumnMapping): boolean {
  const picked = [mapping.title, mapping.website, mapping.username, mapping.password, mapping.notes].filter((name) => name !== null);
  return mapping.website !== null && mapping.username !== null && mapping.password !== null && new Set(picked).size === picked.length;
}

export function matchesFilter(filter: ImportFilter, status: ImportStatus): boolean {
  if (filter === "new") return status === "new";
  if (filter === "alreadySaved") return status === "alreadySaved";
  if (filter === "needsDecision") return status === "passwordDiffers" || status === "ambiguous";
  return true;
}

/** "3 new · 1 already saved · 2 password changes", as Android's review heading. */
export function reviewCounts(review: ImportReview): string {
  return [
    text.countNew(review.new),
    text.countAlreadySaved(review.alreadySaved),
    text.countPasswordChanges(review.passwordDiffers),
    review.ambiguous > 0 ? text.countAmbiguous(review.ambiguous) : "",
    review.duplicateRows > 0 ? text.countRepeated(review.duplicateRows) : "",
  ].filter(Boolean).join(" · ");
}

export const itemLabel = (item: ImportReviewItem) => `${item.title} · ${item.username}`;

/** New logins are ticked and changed passwords keep the saved one unless the user chose otherwise. */
export function importChoices(review: ImportReview, unticked: ReadonlySet<number>, useImported: ReadonlySet<number>): ImportChoices {
  return {
    token: review.token,
    skipNew: review.items.filter((item) => item.status === "new" && unticked.has(item.row)).map((item) => item.row),
    useImported: review.items.filter((item) => item.status === "passwordDiffers" && useImported.has(item.row)).map((item) => item.row),
  };
}

/** Android's message after an import (`confirmPasswordImport`). */
export function importResult(summary: ImportSummary): string {
  return text.result(plural(summary.added, "login"), summary.updated,
    plural(summary.skippedExact + summary.duplicateRows, "duplicate"), plural(summary.skippedConflicts, "incoming password change"));
}
