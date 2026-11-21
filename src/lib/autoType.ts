// Which logins fit the window that the auto-type shortcut recorded (auto_type.rs).
// No imports, so `node --test` loads it directly (src/lib/autoType.test.mjs).

export type AutoTypeCandidate = { id: string; type: string; title: string; tertiaryValue?: string; primaryValue?: string };

/**
 * Words that many sign-in pages and host names share. They say nothing about which site it is:
 * "account" is in "account.lenovo.com" and in "Log in or Create Your Skechers Plus Account".
 */
const GENERIC = new Set([
  "www", "app", "apps", "web", "my", "id", "api", "home", "online", "portal", "cloud", "secure",
  "login", "logon", "signin", "signup", "sign", "auth", "sso", "oauth", "idp", "connect",
  "account", "accounts", "user", "users", "member", "members", "profile", "service", "services",
  "admin", "password", "email", "mail", "work", "personal", "the", "and", "for", "your",
]);

/** Second-level labels under a country code: "co" in "bbc.co.uk", "com" in "abc.com.au". */
const COUNTRY_SECOND_LEVEL = new Set(["co", "com", "net", "org", "ac", "gov", "edu", "gen", "ltd", "ne", "or", "go"]);

/** Browsers: their name and the " - Brave" title suffix say nothing about the site. */
const BROWSERS = new Set(["brave", "chrome", "msedge", "firefox", "opera", "vivaldi", "iexplore", "arc", "waterfox", "librewolf"]);

const words = (text: string) => text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);

function hostLabels(url: string | undefined): string[] {
  if (!url) return [];
  const host = (url.includes("://") ? url.split("://")[1] : url).split(/[/?#:@]/)[0].toLowerCase();
  if (/^[\d.]+$/.test(host)) return [];
  return host.split(".").filter(Boolean);
}

/**
 * The site's own name: "skechers" for www.skechers.com, "windowsazure" for
 * account.activedirectory.windowsazure.com, "bbc" for www.bbc.co.uk.
 */
export function siteName(url: string | undefined): string {
  const labels = hostLabels(url);
  if (labels.length < 2) return labels[0] ?? "";
  const last = labels[labels.length - 1];
  const second = labels[labels.length - 2];
  if (labels.length >= 3 && last.length === 2 && COUNTRY_SECOND_LEVEL.has(second)) return labels[labels.length - 3];
  return second;
}

/** Host labels worth matching, the site name first: "outlook.office.com" gives ["office", "outlook"]. */
export function siteWords(url: string | undefined): string[] {
  const labels = hostLabels(url);
  const name = siteName(url);
  const rest = labels.slice(0, Math.max(0, labels.indexOf(name)));
  return [name, ...rest].filter((label, index, all) => label.length >= 3 && !GENERIC.has(label) && all.indexOf(label) === index);
}

/** True when `phrase` appears in `text` as whole words in order. */
function hasPhrase(text: string[], phrase: string[]): boolean {
  if (phrase.length === 0) return false;
  for (let start = 0; start + phrase.length <= text.length; start++) {
    if (phrase.every((word, offset) => text[start + offset] === word)) return true;
  }
  return false;
}

/** For a browser, the page title without the " - Brave" part. */
function pageTitle(windowTitle: string, browser: boolean): string {
  if (!browser) return windowTitle;
  const cut = Math.max(windowTitle.lastIndexOf(" - "), windowTitle.lastIndexOf(" — "));
  return cut > 0 ? windowTitle.slice(0, cut) : windowTitle;
}

/**
 * 3: the login's name is in the window title as whole words ("Microsoft Teams" in
 *    "Sign in | Microsoft Teams"). One generic word ("Account", "Work") never counts.
 * 2: the site's own name is a word of the window title, or part of the app name
 *    ("skechers" for www.skechers.com; "github" in GitHubDesktop.exe).
 * 1: another label of the website is a word of the title ("outlook" for outlook.office.com), or
 *    the app name is in the login's name ("Steam" for steam.exe). Browsers never match by app.
 * 0: no match.
 */
export function windowScore(entry: AutoTypeCandidate, windowTitle: string, appName: string): number {
  if (entry.type !== "PASSWORD") return 0;
  const app = appName.toLowerCase().replace(/\.exe$/, "");
  const browser = BROWSERS.has(app);
  const title = words(pageTitle(windowTitle, browser));
  const name = words(entry.title);
  const meaningful = name.filter((word) => !GENERIC.has(word));
  if (meaningful.length > 0 && meaningful.join("").length >= 3 && hasPhrase(title, name)) return 3;

  const inApp = (word: string) => !browser && word.length >= 4 && app.includes(word);
  const [site, ...others] = siteWords(entry.tertiaryValue);
  if (site && site === siteName(entry.tertiaryValue) && (title.includes(site) || inApp(site))) return 2;
  if ([site, ...others].some((word) => word && (title.includes(word) || inApp(word)))) return 1;
  if (!browser && app.length >= 3 && !GENERIC.has(app) && name.some((word) => word.includes(app))) return 1;
  return 0;
}

/** Logins only, best match first; the rest follow by title so the user can still pick any login. */
export function rankForWindow<T extends AutoTypeCandidate>(entries: readonly T[], windowTitle: string, appName: string): Array<{ entry: T; score: number }> {
  return entries
    .filter((entry) => entry.type === "PASSWORD")
    .map((entry) => ({ entry, score: windowScore(entry, windowTitle, appName) }))
    .sort((a, b) => b.score - a.score || a.entry.title.localeCompare(b.entry.title));
}
