import type { LocalNote, VaultEntry } from "./api";
import { entrySubtitle, profileFrom } from "./entries";
import { cardLast4, hostFromUrl } from "./format";
import { fold, tokenize } from "./text.ts";

// Folding, tokenizing and highlighting moved to text.ts, which imports nothing, so the Help page and
// the tests can load them. They stay part of this module's surface for everything that already uses it.
export { fold, highlight, tokenize } from "./text.ts";
export type { Segment } from "./text.ts";

type Field = { text: string; weight: number };

export type SearchDoc =
  | { kind: "entry"; id: string; title: string; subtitle: string; favorite: boolean; updatedAt: number; entry: VaultEntry; fields: Field[] }
  | { kind: "note"; id: string; title: string; subtitle: string; favorite: boolean; updatedAt: number; note: LocalNote; fields: Field[] };

const field = (text: string, weight: number): Field => ({ text: fold(text), weight });

/** Builds index text without secret values (no passwords, answers, card numbers beyond last 4, or TOTP keys). */
export function buildIndex(entries: VaultEntry[], notes: LocalNote[]): SearchDoc[] {
  const docs: SearchDoc[] = entries.map((entry) => {
    const fields: Field[] = [field(entry.title, 10), field(entry.tags.replace(/,/g, " "), 4), field(entry.notes, 2)];
    switch (entry.type) {
      case "PASSWORD": fields.push(field(entry.primaryValue, 5), field(hostFromUrl(entry.tertiaryValue), 6)); break;
      case "CARD": fields.push(field(cardLast4(entry.primaryValue), 6), field(entry.network, 4), field(entry.secondaryValue, 3)); break;
      case "AUTHENTICATOR": fields.push(field(entry.primaryValue, 5)); break;
      case "QUESTION": fields.push(field(entry.primaryValue, 4)); break;
      case "AUTOFILL": { const p = profileFrom(entry.primaryValue); fields.push(field(p.name, 5), field(p.email, 5), field(p.phone, 3), field(p.city, 2)); break; }
    }
    return { kind: "entry", id: entry.id, title: entry.title, subtitle: entrySubtitle(entry), favorite: entry.favorite, updatedAt: entry.updatedAt, entry, fields: fields.filter((f) => f.text) };
  });
  for (const note of notes) {
    const preview = note.body.split(/\r?\n/).find((line) => line.trim()) ?? "";
    docs.push({ kind: "note", id: note.id, title: note.title, subtitle: preview.slice(0, 120), favorite: false, updatedAt: note.updatedAt, note, fields: [field(note.title, 10), field(note.body, 2)] });
  }
  return docs;
}

function boundaryBefore(text: string, index: number): boolean {
  return index === 0 || /[\s\-_.@/:,(]/.test(text[index - 1]);
}

/** Score a doc against tokens. Every token must match some field. Returns 0 when it does not match. */
export function scoreDoc(doc: SearchDoc, tokens: string[]): number {
  if (!tokens.length) return 0;
  let total = 0;
  for (const token of tokens) {
    let best = 0;
    for (const f of doc.fields) {
      const at = f.text.indexOf(token);
      if (at < 0) continue;
      const position = at === 0 ? 3 : boundaryBefore(f.text, at) ? 2 : 1;
      best = Math.max(best, position * f.weight);
    }
    if (!best) return 0;
    total += best;
  }
  const title = fold(doc.title);
  const whole = tokens.join(" ");
  if (title === whole) total += 60;
  else if (title.startsWith(whole)) total += 30;
  if (doc.favorite) total += 2;
  return total;
}

export function searchDocs(docs: SearchDoc[], query: string, limit = 60): Array<{ doc: SearchDoc; score: number }> {
  const tokens = tokenize(query);
  if (!tokens.length) return [];
  return docs
    .map((doc) => ({ doc, score: scoreDoc(doc, tokens) }))
    .filter((result) => result.score > 0)
    .sort((a, b) => b.score - a.score || b.doc.updatedAt - a.doc.updatedAt)
    .slice(0, limit);
}

/** Simple list filter used by category pages. */
export function matchesFilter(doc: SearchDoc, query: string): boolean {
  const tokens = tokenize(query);
  return !tokens.length || scoreDoc(doc, tokens) > 0;
}
