// Sign-in methods ("Continue with GitHub" and the account) that the browser extension remembered.
// No imports, so `node --test` loads it directly (src/lib/signIns.test.mjs). The provider ids are the
// same in sign_ins.rs and extension/signins.js; the Rust tests check all three lists.

export type SignInProvider = "google" | "apple" | "microsoft" | "github" | "facebook" | "x" | "linkedin" | "discord" | "amazon" | "slack";

export const PROVIDERS: ReadonlyArray<{ id: SignInProvider; name: string }> = [
  { id: "google", name: "Google" },
  { id: "apple", name: "Apple" },
  { id: "microsoft", name: "Microsoft" },
  { id: "github", name: "GitHub" },
  { id: "facebook", name: "Facebook" },
  { id: "x", name: "X" },
  { id: "linkedin", name: "LinkedIn" },
  { id: "discord", name: "Discord" },
  { id: "amazon", name: "Amazon" },
  { id: "slack", name: "Slack" },
];

/** One remembered method: a site (registrable domain), a provider and the account ("" when not known). */
export type SignIn = {
  id: string;
  site: string;
  provider: string;
  account: string;
  firstUsedAt: number;
  lastUsedAt: number;
  useCount: number;
};

/** What `sign_ins` returns: the setting, every row, and the logins saved for each site with a row. */
export type SignInsState = { enabled: boolean; items: SignIn[]; logins: Record<string, string[]> };

export type SignInFilter = { provider?: string; account?: string; query?: string };

export type SiteGroup = { site: string; methods: SignIn[]; lastUsedAt: number };

export function providerName(id: string): string {
  return PROVIDERS.find((provider) => provider.id === id)?.name ?? id;
}

/** "https://Login.Example.com/path" -> "login.example.com"; plain words stay as typed, in lower case. */
export function searchHost(text: string): string {
  let value = text.trim().toLowerCase();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/, 1)[0].replace(/:\d*$/, "").replace(/\.+$/, "");
  return value.replace(/^www\./, "");
}

/**
 * The search box matches a site the way logins match a page: the site itself, any page of it
 * ("login.example.com" or "https://app.example.com/x" finds example.com), or part of its name.
 */
export function siteMatches(site: string, query: string): boolean {
  const host = searchHost(query);
  if (!host) return true;
  return site === host || host.endsWith(`.${site}`) || site.includes(host);
}

/** Groups by site, most recently used site first; each group's methods most recent first. */
export function groupBySite(items: SignIn[], filter: SignInFilter = {}): SiteGroup[] {
  const account = (filter.account ?? "").trim().toLowerCase();
  const groups = new Map<string, SignIn[]>();
  for (const item of items) {
    if (filter.provider && item.provider !== filter.provider) continue;
    if (filter.account !== undefined && filter.account !== "" && (filter.account === "\u0000none" ? item.account !== "" : item.account.toLowerCase() !== account)) continue;
    if (filter.query && !siteMatches(item.site, filter.query)) continue;
    const list = groups.get(item.site) ?? [];
    list.push(item);
    groups.set(item.site, list);
  }
  return [...groups.entries()]
    .map(([site, methods]) => {
      const sorted = [...methods].sort((a, b) => b.lastUsedAt - a.lastUsedAt || a.account.localeCompare(b.account));
      return { site, methods: sorted, lastUsedAt: sorted[0].lastUsedAt };
    })
    .sort((a, b) => b.lastUsedAt - a.lastUsedAt || a.site.localeCompare(b.site));
}

/** The accounts in use, for the account filter: distinct ignoring case, sorted. */
export function accountsOf(items: SignIn[]): string[] {
  const seen = new Map<string, string>();
  for (const item of items) if (item.account && !seen.has(item.account.toLowerCase())) seen.set(item.account.toLowerCase(), item.account);
  return [...seen.values()].sort((a, b) => a.localeCompare(b));
}

/** Providers that have at least one row, in the fixed order, for the chip filter. */
export function providersOf(items: SignIn[]): SignInProvider[] {
  const used = new Set(items.map((item) => item.provider));
  return PROVIDERS.filter((provider) => used.has(provider.id)).map((provider) => provider.id);
}

/** The rows for a login: those of the sites the app linked to the login's id. */
export function forLogin(state: SignInsState | null, loginId: string): SignIn[] {
  if (!state) return [];
  const sites = Object.entries(state.logins).filter(([, ids]) => ids.includes(loginId)).map(([site]) => site);
  return state.items.filter((item) => sites.includes(item.site)).sort((a, b) => b.lastUsedAt - a.lastUsedAt);
}

/** An account the user types: at most 256 characters, no line breaks or invisible characters. */
export function accountProblem(text: string): string | null {
  const value = text.trim();
  if (value.length > 256) return "Use at most 256 characters.";
  if (/[\p{Cc}\p{Cf}]/u.test(value)) return "Remove line breaks and invisible characters.";
  return null;
}
