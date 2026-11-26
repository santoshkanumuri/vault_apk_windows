import { NETWORK_MARKS, type NetworkMark } from "./networkMarks";
import { codeText } from "../strings.ts";

/** The network from the card number's prefix, when the Network field is empty. Same rules as the phone. */
export function cardNetwork(number: string): string {
  const digits = number.replace(/\D/g, "");
  const n = (count: number) => Number(digits.slice(0, count)) || 0;
  const two = n(2), three = n(3), four = n(4), six = n(6);
  if (digits.startsWith("4")) return "Visa";
  if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720)) return "Mastercard";
  if (two === 34 || two === 37) return codeText.americanExpress;
  if (digits.startsWith("6011") || two === 65 || (three >= 644 && three <= 649) || (six >= 622126 && six <= 622925)) return "Discover";
  if (four >= 3528 && four <= 3589) return "JCB";
  if (two === 62) return "UnionPay";
  if ((three >= 300 && three <= 305) || [36, 38, 39].includes(two)) return codeText.dinersClub;
  return "";
}

/** The mark to draw for a network name, or null for an unknown network (shown as text). */
export function networkMark(network: string, lightInk: boolean): NetworkMark | null {
  const key = network.toLowerCase().replace(/[\s-]/g, "");
  const base = { visa: "visa", mastercard: "mastercard", americanexpress: "amex", amex: "amex", discover: "discover",
    dinersclub: "diners", diners: "diners", jcb: "jcb", unionpay: "unionpay", chinaunionpay: "unionpay", rupay: "rupay" }[key];
  if (!base) return null;
  // Discover and RuPay have a variant that stays readable on dark cards.
  return NETWORK_MARKS[lightInk && (base === "discover" || base === "rupay") ? `${base}-light` : base] ?? null;
}

/** The number in its usual grouping with every digit hidden except the last four. */
export function maskedCardNumber(number: string): string {
  const digits = number.replace(/\D/g, "");
  if (digits.length < 4) return "•••• •••• •••• ••••";
  const shown = [..."•".repeat(digits.length - 4) + digits.slice(-4)];
  // The same grouping as groupCardNumber: 4-6-5 for 15 digits (Amex), otherwise blocks of 4.
  const sizes = shown.length === 15 ? [4, 6, 5] : Array.from({ length: Math.ceil(shown.length / 4) }, () => 4);
  const groups: string[] = [];
  let at = 0;
  for (const size of sizes) { groups.push(shown.slice(at, at + size).join("")); at += size; }
  return groups.filter(Boolean).join(" ");
}
