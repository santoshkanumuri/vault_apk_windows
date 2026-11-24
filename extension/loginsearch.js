// Searching every saved login from the toolbar popup, by site, name or username.
//
// Loaded by the popup only. It is never a content script: pages can't list or fill logins saved for
// other sites (security review M-06). Everything here is pure: the popup asks the app for the
// listing ("all_logins": names, usernames and saved sites, never passwords) and filters it here.
// eslint-disable-next-line no-unused-vars
var NuvoriLoginSearch = (() => {
  /** Shown at most; the user narrows the search to see others. */
  const MAX_RESULTS = 25;
  const MAX_QUERY = 100;
  /** Typing pauses this long before the list redraws. */
  const DEBOUNCE_MS = 150;

  const lower = (text) => String(text ?? "").toLocaleLowerCase();

  /** The query's words, lowercased, without a URL's scheme or path: "https://Mail.Example.com/x" → ["mail.example.com"]. */
  function queryWords(query) {
    const text = lower(query).slice(0, MAX_QUERY).trim();
    if (!text) return [];
    return text.split(/\s+/).map((word) => {
      const url = word.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/);
      const host = url ? url[1].replace(/^[^@]*@/, "").replace(/:\d+$/, "") : word;
      return host.replace(/^www\./, "");
    }).filter(Boolean);
  }

  /** A host without a leading "www.". */
  const bare = (host) => lower(host).replace(/^www\./, "");

  /**
   * Logins whose saved site, name or username contain every word of `query`, best first: a site that
   * starts with the query, then a name or username that does, then the rest, each in A to Z order.
   * At most `limit`; `total` counts every match.
   */
  function search(logins, query, limit = MAX_RESULTS) {
    const words = queryWords(query);
    if (!words.length || !Array.isArray(logins)) return { results: [], total: 0 };
    const scored = [];
    for (const login of logins) {
      if (!login || typeof login.id !== "string" || typeof login.selectionToken !== "string") continue;
      const site = bare(login.site);
      const title = lower(login.title);
      const username = lower(login.username);
      const haystack = `${site}\n${title}\n${username}`;
      if (!words.every((word) => haystack.includes(word))) continue;
      const first = words[0];
      const rank = site.startsWith(first) || site.split(".").some((part) => part.startsWith(first)) ? 0
        : title.startsWith(first) || username.startsWith(first) ? 1 : 2;
      scored.push({ login, rank, key: `${site}\n${title}\n${username}` });
    }
    scored.sort((a, b) => a.rank - b.rank || a.key.localeCompare(b.key));
    return { results: scored.slice(0, Math.max(0, limit)).map((entry) => entry.login), total: scored.length };
  }

  /**
   * True when a login saved for `site` (a host, or "" for none) belongs to the page at `origin`: the
   * same host, or a domain and its "www." name. Anything else fills only after a warning.
   */
  function sameSite(site, origin) {
    let host;
    try { host = new URL(origin).hostname; } catch { return false; }
    const saved = lower(site).replace(/:\d+$/, "");
    if (!saved || !host) return false;
    return bare(saved) === bare(host);
  }

  /** The page's host for messages, without "www.". */
  function hostOf(origin) {
    try { return bare(new URL(origin).hostname); } catch { return ""; }
  }

  return { MAX_RESULTS, MAX_QUERY, DEBOUNCE_MS, queryWords, search, sameSite, hostOf };
})();
