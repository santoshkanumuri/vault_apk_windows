// Applies the saved theme before the app renders, so there is no flash of the wrong theme.
(function () {
  try {
    var pref = localStorage.getItem("nuvori.theme") || localStorage.getItem("nuvori-theme");
    var resolved = pref === "light" || pref === "dark" ? pref
      : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    var root = document.documentElement;
    root.setAttribute("data-theme", resolved);
    root.setAttribute("data-theme-preference", pref === "light" || pref === "dark" ? pref : "system");
    root.style.colorScheme = resolved;
    // Cached accent and background (ids only); anything unexpected falls back to green and sage.
    var id = /^[a-z][a-z0-9-]{0,31}$/, accent = "green", surface = "sage";
    try {
      var cached = JSON.parse(localStorage.getItem("nuvori.appearance") || "null");
      if (cached && typeof cached.accent === "string" && id.test(cached.accent)) accent = cached.accent;
      if (cached && typeof cached.surface === "string" && id.test(cached.surface)) surface = cached.surface;
    } catch (e) { /* Use the defaults. */ }
    root.setAttribute("data-accent", accent);
    root.setAttribute("data-surface", surface);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", resolved === "light" ? "#F8FAF5" : "#050705");
  } catch (e) { /* Storage unavailable: CSS falls back to the system theme. */ }
})();
