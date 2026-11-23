/* Nuvori website: theme switch, "Copy link" buttons, the year, and the browser picker on the home page.
   Every page works without this file. */
(() => {
  "use strict";
  const root = document.documentElement;
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

  /* ---------- Theme: follows the system until the visitor picks one ---------- */
  const KEY = "nuvori.site.theme";
  const themeButton = $("#theme");
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  const isDark = () => root.dataset.theme ? root.dataset.theme === "dark" : systemDark.matches;
  function labelTheme() {
    if (!themeButton) return;
    themeButton.setAttribute("aria-label", isDark() ? "Use light theme" : "Use dark theme");
  }
  themeButton?.addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem(KEY, next); } catch { /* private window: the choice lasts for this page only */ }
    labelTheme();
  });
  systemDark.addEventListener?.("change", labelTheme);
  labelTheme();

  /* ---------- Year ---------- */
  $$("[data-year]").forEach((el) => { el.textContent = String(new Date().getFullYear()); });

  /* ---------- Copy link ---------- */
  const snack = $("#snack");
  let snackTimer;
  function toast(text) {
    if (!snack) return;
    snack.textContent = text;
    snack.classList.add("is-on");
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => snack.classList.remove("is-on"), 2200);
  }
  $$("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      toast("Link copied");
    } catch {
      toast("Copy failed. Open the store link and copy it from the address bar.");
    }
  }));

  /* ---------- Browser picker (home) ---------- */
  const picker = $("[data-picker]");
  if (!picker) return;

  // Notes for single browsers. The engine panels in index.html hold the steps.
  const SAVE_PROMPT = (name) => `To stop ${name} asking to save passwords as well, turn on Use Nuvori instead of the browser's password manager in the extension's Settings.`;
  const NOTES = {
    helium: () => "Helium has no password manager of its own, by design. Nuvori fills that gap.",
    edge: () => "In Edge, allow extensions from other stores first.",
    comet: () => "Comet uses the same extension as Chrome.",
    arc: () => "Arc uses the same extension as Chrome.",
    chrome: SAVE_PROMPT,
    brave: SAVE_PROMPT,
    vivaldi: SAVE_PROMPT,
    opera: SAVE_PROMPT,
  };

  function show(input) {
    const name = input.dataset.name || input.nextElementSibling?.textContent.trim() || "";
    const panel = $(`.answer[data-for="${input.dataset.engine}"]`, picker);
    if (!panel) return;
    $$("[data-name]", panel).forEach((el) => { el.textContent = name; });
    const note = $("[data-note]", panel);
    if (note) note.textContent = NOTES[input.value] ? NOTES[input.value](name) : "";
  }
  picker.addEventListener("change", (e) => { if (e.target.matches("input[type=radio]")) show(e.target); });

  // Pre-select the browser this page is open in, when the page can tell (Windows only).
  function detect() {
    const ua = navigator.userAgent;
    if (!/Windows NT/.test(ua)) return "";
    if (/Edg\//.test(ua)) return "edge";
    if (/OPR\//.test(ua)) return "opera";
    if (/Vivaldi/.test(ua)) return "vivaldi";
    if (navigator.brave) return "brave";
    if (/Firefox\//.test(ua)) return "firefox";
    if (/Chrome\//.test(ua) && navigator.userAgentData?.brands?.some((b) => b.brand === "Google Chrome")) return "chrome";
    return "";
  }
  const found = detect();
  const start = (found && $(`input[value="${found}"]`, picker)) || $("input:checked", picker);
  if (start) { start.checked = true; show(start); }
})();
