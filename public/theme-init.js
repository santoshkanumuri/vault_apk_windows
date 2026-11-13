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
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", resolved === "light" ? "#F8FAF5" : "#050705");
  } catch (e) { /* Storage unavailable: CSS falls back to the system theme. */ }
})();
