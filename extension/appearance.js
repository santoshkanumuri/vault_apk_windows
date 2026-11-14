// Colors and theme for the popup. Theme: system | light | dark, stored in chrome.storage.local "theme".
// Accent and background: the desktop's choice, cached in chrome.storage.local "appearance" by background.js.
// The header button is the quick toggle; Settings has the same choice as a segmented control.

const APPEARANCE_ID = /^[a-z][a-z0-9-]{0,31}$/;

/**
 * Pure: picks the mode and the popup CSS variables for a theme and cached ids.
 * Unknown or invalid ids fall back to the palette defaults (green and sage).
 */
function resolveAppearance(palette, appearance, theme, systemDark) {
  const mode = theme === "dark" || (theme !== "light" && systemDark) ? "dark" : "light";
  const pick = (table, id, fallback) => (typeof id === "string" && APPEARANCE_ID.test(id) && Object.hasOwn(table, id) ? table[id] : table[fallback]);
  const a = pick(palette.accents, appearance?.accent, palette.defaults.accent)[mode];
  const b = pick(palette.surfaces, appearance?.surface, palette.defaults.surface)[mode];
  return {
    mode,
    vars: {
      "--primary": a.primary, "--on-primary": a.onPrimary, "--pc": a.primaryContainer, "--opc": a.onPrimaryContainer, "--focus": a.primary,
      "--bg": b.background, "--surface": b.container, "--surface-2": b.containerHighest, "--hover": b.hover,
      "--text": b.text, "--muted": b.muted, "--outline": b.outline, "--hairline": b.hairline
    }
  };
}
globalThis.NuvoriAppearance = { resolveAppearance };

const themeButton = typeof document === "object" ? document.querySelector("#theme") : null;
if (themeButton) {
const themes = ["system", "light", "dark"];
let theme = "system";
let appearance = null;
const dark = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;

function renderColors() {
  const palette = globalThis.NuvoriAppearancePalette;
  if (!palette) return;
  const { vars } = resolveAppearance(palette, appearance, theme, Boolean(dark?.matches));
  for (const [name, value] of Object.entries(vars)) document.documentElement.style.setProperty(name, value);
}

renderColors();
function renderTheme() {
  document.documentElement.dataset.theme = theme;
  renderColors();
  const next = themes[(themes.indexOf(theme) + 1) % themes.length];
  themeButton.setAttribute("aria-label", `Theme: ${theme}. Switch to ${next}`);
  themeButton.title = `Theme: ${theme}`;
  for (const radio of document.querySelectorAll('input[name="theme-choice"]')) radio.checked = radio.value === theme;
}

function setTheme(value) {
  if (!themes.includes(value)) return;
  theme = value;
  renderTheme();
  void chrome.storage.local.set({ theme });
}

chrome.storage.local.get(["theme", "appearance"]).then((saved) => {
  if (themes.includes(saved.theme)) theme = saved.theme;
  appearance = saved.appearance ?? null;
  renderTheme();
});
chrome.storage.onChanged?.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.appearance) appearance = changes.appearance.newValue ?? null;
  if (changes.theme && themes.includes(changes.theme.newValue)) theme = changes.theme.newValue;
  renderTheme();
});
dark?.addEventListener?.("change", renderColors);
themeButton.addEventListener("click", () => setTheme(themes[(themes.indexOf(theme) + 1) % themes.length]));
for (const radio of document.querySelectorAll('input[name="theme-choice"]')) {
  radio.addEventListener("change", () => { if (radio.checked) setTheme(radio.value); });
}
}
