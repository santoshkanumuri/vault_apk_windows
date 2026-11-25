// Card expiry warnings, as Android's Home (`cardExpiryKind` in HomeUi.kt) and card details
// (`expiryState` in VaultUi.kt) work them out, so both apps warn about the same cards.

export type CardExpiryKind = "error" | "warning";

const SOON_MS = 90 * 24 * 60 * 60 * 1000;

/** Kotlin's String.toIntOrNull: an optional sign and decimal digits, within a 32-bit int. */
function toIntOrNull(text: string | undefined): number | null {
  if (text === undefined || !/^[+-]?\d+$/.test(text)) return null;
  const value = Number(text);
  return value > 2147483647 || value < -2147483648 ? null : value;
}

/**
 * Expired cards are errors and cards expiring within 90 days are warnings; anything else, or an
 * expiry that can't be read ("0829", "Dec 26"), is null. The expiry is read as month, then year,
 * split on "/", "-" or a space, with a two-digit year in the 2000s. A card stays valid to the last
 * moment of its expiry month, in this PC's time zone, as on Android.
 */
export function cardExpiryKind(value: string, now: number): CardExpiryKind | null {
  const parts = value.trim().split(/[/\- ]/);
  const month = toIntOrNull(parts[0]);
  if (month === null) return null;
  let year = toIntOrNull(parts[1]);
  if (year === null) return null;
  if (year < 100) year += 2000;
  if (month < 1 || month > 12) return null;
  // The first day of the month after the expiry month, less a millisecond.
  const first = new Date(2000, 0, 1);
  first.setFullYear(year, month, 1);
  const end = first.getTime() - 1;
  if (end < now) return "error";
  if (end - now <= SOON_MS) return "warning";
  return null;
}

/** The last four digits of a card number, for "Card ending 1234". */
export function cardLastFour(number: string): string {
  return number.replace(/\D/g, "").slice(-4);
}
