// Website icons: which icon belongs to a login's website or a passkey's relying-party ID.
// No imports, so `node --test` loads it directly (src/lib/siteIcons.test.mjs).
// The lookup rules are the same on Android and in the extension; keep them in step.

/** A built-in icon: brand title, brand color (hex, no "#") and an SVG path for a 24x24 viewBox. */
export type BuiltinIcon = { title: string; hex: string; path: string };

/** The shape of `site-icons.json`. */
export type SiteIconData = { icons: Array<[string, string, string]>; domains: Record<string, number> };

/** The host of a website or relying-party ID, or "" when no icon can apply (IPs, localhost, app links). */
export function hostOf(value: string | undefined | null): string {
  let text = (value ?? "").trim();
  if (!text) return "";
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text);
  if (scheme) {
    if (!/^https?$/i.test(scheme[1])) return "";
    text = text.slice(scheme[0].length);
  }
  text = text.split(/[/?#]/, 1)[0];
  text = text.slice(text.lastIndexOf("@") + 1);
  text = text.replace(/:\d*$/, "").toLowerCase().replace(/\.+$/, "");
  if (!text || !text.includes(".") || text === "localhost") return "";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text) || text.includes(":") || text.startsWith("[")) return "";
  if (!/^[a-z0-9._-]+$/.test(text) || text.startsWith(".") || text.includes("..")) return "";
  return text;
}

/** The host, then the host without its leftmost label, while at least 2 labels remain. */
export function lookupKeys(host: string): string[] {
  if (!host) return [];
  const labels = host.split(".");
  const keys: string[] = [];
  for (let i = 0; labels.length - i >= 2; i++) keys.push(labels.slice(i).join("."));
  return keys;
}

/** The first key of `value` that `map` has. Public suffixes are never keys, so "co.uk" cannot match. */
export function findIcon<T>(map: { get(key: string): T | undefined } | null | undefined, value: string | undefined | null): T | undefined {
  if (!map) return undefined;
  for (const key of lookupKeys(hostOf(value))) {
    const found = map.get(key);
    if (found !== undefined) return found;
  }
  return undefined;
}

/** WCAG relative luminance of a hex color ("181717" or "#181717"), 0 (black) to 1 (white). */
export function relativeLuminance(hex: string): number {
  const text = hex.replace(/^#/, "");
  const channel = (offset: number) => {
    const value = parseInt(text.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
}

/** White glyph on dark brand colors, near-black on light ones. */
export function glyphColor(hex: string): string {
  return relativeLuminance(hex) < 0.4 ? "#FFFFFF" : "#111111";
}

/** Very light brand colors need a hairline border so the tile does not vanish on a light page. */
export function needsBorder(hex: string): boolean {
  return relativeLuminance(hex) > 0.85;
}

/** Build the domain map from the JSON data. */
export function buildBuiltinMap(data: SiteIconData): Map<string, BuiltinIcon> {
  const map = new Map<string, BuiltinIcon>();
  for (const [domain, index] of Object.entries(data.domains)) {
    const row = data.icons[index];
    if (row) map.set(domain, { title: row[0], hex: row[1], path: row[2] });
  }
  return map;
}

/** A brand name as the icon lookup compares it: "Amazon Web Services" and "amazon-web services" give "amazonwebservices". */
export function brandKey(name: string | undefined | null): string {
  return (name ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Brand name -> one of its domains, from the JSON data. The first domain of a brand wins. */
export function buildBrandDomains(data: SiteIconData): Map<string, string> {
  const map = new Map<string, string>();
  for (const [domain, index] of Object.entries(data.domains)) {
    const key = brandKey(data.icons[index]?.[0]);
    if (key && !map.has(key)) map.set(key, domain);
  }
  return map;
}

/** The fields of a vault item that the icon hints read. `linkedAuthenticatorId` comes with every login from the app. */
export type IconHintItem = { id: string; type: string; title: string; tertiaryValue: string; linkedAuthenticatorId?: string };

/**
 * The website to use for a code's icon. A code has no website of its own, so:
 * 1. the website of a login that links this code;
 * 2. the issuer, when it is a host ("github.com");
 * 3. the website of the logins with the same title, when they all share one host.
 * Else undefined: the issuer name then goes to the brand lookup (`iconHints`).
 */
export function codeSite(code: IconHintItem, items: readonly IconHintItem[]): string | undefined {
  const logins = items.filter((item) => item.type === "PASSWORD" && hostOf(item.tertiaryValue));
  const linked = logins.find((item) => item.linkedAuthenticatorId === code.id);
  if (linked) return linked.tertiaryValue;
  if (hostOf(code.title) && /\.[a-z]{2,}$/i.test(code.title.trim())) return code.title.trim();
  const title = code.title.trim().toLowerCase();
  if (!title) return undefined;
  const same = logins.filter((item) => item.title.trim().toLowerCase() === title);
  const hosts = new Set(same.map((item) => hostOf(item.tertiaryValue)));
  return hosts.size === 1 ? same[0].tertiaryValue : undefined;
}

/** What `Avatar` looks up for an item: a login's website; a code's website or issuer name. */
export function iconHints(item: IconHintItem, items: readonly IconHintItem[]): { site?: string; brand?: string } {
  if (item.type === "PASSWORD") return { site: item.tertiaryValue };
  if (item.type === "AUTHENTICATOR") return { site: codeSite(item, items), brand: item.title };
  return {};
}
