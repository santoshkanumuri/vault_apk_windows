export function cx(...names: Array<string | false | null | undefined>): string {
  return names.filter(Boolean).join(" ");
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** Unix ms, seconds, or an ISO string → ms (0 when unknown). */
export function toMillis(value: number | string | undefined | null): number {
  if (value === undefined || value === null || value === "") return 0;
  if (typeof value === "number") return value < 1e12 ? value * 1000 : value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export function relativeTime(value: number | string | undefined | null, now = Date.now()): string {
  const at = toMillis(value);
  if (!at) return "Never";
  const diff = Math.round((now - at) / 1000);
  if (diff < -30) return formatDateTime(at);
  if (diff < 45) return "Just now";
  const minutes = Math.round(diff / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return new Date(at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: new Date(at).getFullYear() === new Date(now).getFullYear() ? undefined : "numeric" });
}

export function formatDateTime(value: number | string): string {
  const at = toMillis(value);
  if (!at) return "Never";
  return new Date(at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function hostFromUrl(url: string): string {
  const value = url.trim();
  if (!value) return "";
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return value.replace(/^[a-z]+:\/\//i, "").split("/")[0];
  }
}

export function cardLast4(number: string): string {
  const digits = number.replace(/\D/g, "");
  return digits.length >= 4 ? digits.slice(-4) : "";
}

export function maskCard(number: string): string {
  const last4 = cardLast4(number);
  return last4 ? `•••• ${last4}` : "";
}

export function groupCardNumber(number: string): string {
  const digits = number.replace(/\D/g, "");
  if (digits.length === 15) return `${digits.slice(0, 4)} ${digits.slice(4, 10)} ${digits.slice(10)}`;
  return digits.replace(/(.{4})/g, "$1 ").trim();
}

/** "123456" → "123 456", "12345678" → "1234 5678". */
export function groupCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  if (code.length === 7) return `${code.slice(0, 3)} ${code.slice(3)}`;
  return code;
}

export function monogram(title: string): string {
  const words = title.trim().replace(/^https?:\/\//i, "").split(/[\s._@-]+/).filter(Boolean);
  if (!words.length) return "?";
  const first = Array.from(words[0])[0] ?? "?";
  return first.toLocaleUpperCase();
}

/** Stable small integer for picking an avatar tint. */
export function hashIndex(value: string, buckets: number): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) hash = (hash * 31 + value.charCodeAt(i)) | 0;
  return Math.abs(hash) % buckets;
}

export function greeting(date = new Date()): string {
  const hour = date.getHours();
  if (hour < 5) return "Good evening";
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}
