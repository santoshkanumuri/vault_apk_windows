import { CircleHelp, Clock3, CreditCard, KeyRound, UserRound, type LucideIcon } from "lucide-react";
import type { EntryDraft, EntryType, VaultEntry, VaultGroup } from "./api";
import { cardLast4, hostFromUrl, maskCard } from "./format";

export type Category = "logins" | "cards" | "codes" | "questions" | "autofill";

export type CategoryInfo = {
  key: Category;
  type: EntryType;
  label: string;
  singular: string;
  icon: LucideIcon;
};

export const categories: Record<Category, CategoryInfo> = {
  logins: { key: "logins", type: "PASSWORD", label: "Passwords", singular: "password", icon: KeyRound },
  cards: { key: "cards", type: "CARD", label: "Cards", singular: "card", icon: CreditCard },
  codes: { key: "codes", type: "AUTHENTICATOR", label: "Codes", singular: "code", icon: Clock3 },
  questions: { key: "questions", type: "QUESTION", label: "Questions", singular: "question", icon: CircleHelp },
  autofill: { key: "autofill", type: "AUTOFILL", label: "Autofill", singular: "profile", icon: UserRound }
};

export const categoryOrder: Category[] = ["cards", "logins", "codes", "questions", "autofill"];

export function categoryForType(type: EntryType): Category {
  return ({ PASSWORD: "logins", CARD: "cards", AUTHENTICATOR: "codes", QUESTION: "questions", AUTOFILL: "autofill" } as const)[type];
}

export type Profile = { name: string; email: string; phone: string; address1: string; address2: string; unit: string; city: string; state: string; postalCode: string; country: string };
export const emptyProfile: Profile = { name: "", email: "", phone: "", address1: "", address2: "", unit: "", city: "", state: "", postalCode: "", country: "" };
export const profileFields: ReadonlyArray<readonly [keyof Profile, string]> = [
  ["name", "Full name"], ["email", "Email"], ["phone", "Phone"], ["address1", "Address line 1"], ["address2", "Address line 2"],
  ["unit", "Flat or unit"], ["city", "City"], ["state", "State or region"], ["postalCode", "Postal code"], ["country", "Country"]
];

export function profileFrom(value: string): Profile {
  try {
    const parsed = JSON.parse(value) as Partial<Profile>;
    return { ...emptyProfile, ...(parsed && typeof parsed === "object" ? parsed : {}) };
  } catch {
    return { ...emptyProfile };
  }
}

export function emptyEntry(type: EntryType): EntryDraft {
  return { type, title: "", primaryValue: "", secondaryValue: "", tertiaryValue: "", fourthValue: "", cardKind: "CREDIT", network: "", totpAlgorithm: "SHA1", totpDigits: 6, totpPeriod: 30, notes: "", tags: "", favorite: false, groupIds: [] };
}

/** One-line, non-secret description shown under the title in lists and search. */
export function entrySubtitle(entry: VaultEntry): string {
  switch (entry.type) {
    case "CARD": return [entry.cardKind === "DEBIT" ? "Debit" : "Credit", entry.network, maskCard(entry.primaryValue)].filter(Boolean).join(" · ");
    case "PASSWORD": return [entry.primaryValue, hostFromUrl(entry.tertiaryValue)].filter(Boolean).join(" · ") || "Password";
    case "AUTHENTICATOR": return entry.primaryValue || "Authenticator";
    case "QUESTION": return entry.primaryValue || "Security question";
    case "AUTOFILL": { const p = profileFrom(entry.primaryValue); return [p.name, p.email].filter(Boolean).join(" · ") || "Contact profile"; }
  }
}

export function typeLabel(type: EntryType): string {
  return ({ PASSWORD: "Password", CARD: "Card", AUTHENTICATOR: "Code", QUESTION: "Question", AUTOFILL: "Autofill" } as const)[type];
}

export function foldersFor(groups: VaultGroup[], type: EntryType | "NOTE"): VaultGroup[] {
  return groups.filter((group) => !group.folderType || group.folderType === type);
}

export type SortMode = "recent" | "name" | "favorites";

export function sortItems<T extends { title: string; updatedAt: number; favorite?: boolean }>(items: T[], mode: SortMode): T[] {
  const byName = (a: T, b: T) => a.title.localeCompare(b.title, undefined, { sensitivity: "base", numeric: true });
  const copy = [...items];
  if (mode === "name") return copy.sort(byName);
  if (mode === "favorites") return copy.sort((a, b) => Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)) || byName(a, b));
  return copy.sort((a, b) => b.updatedAt - a.updatedAt || byName(a, b));
}

export { cardLast4 };
