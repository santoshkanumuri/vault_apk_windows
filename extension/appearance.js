// Theme for the popup: system | light | dark, stored in chrome.storage.local "theme".
// The header button is the quick toggle; Settings has the same choice as a segmented control.
const themeButton = document.querySelector("#theme");
const themes = ["system", "light", "dark"];
let theme = "system";

function renderTheme() {
  document.documentElement.dataset.theme = theme;
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

chrome.storage.local.get("theme").then((saved) => {
  if (themes.includes(saved.theme)) theme = saved.theme;
  renderTheme();
});
themeButton.addEventListener("click", () => setTheme(themes[(themes.indexOf(theme) + 1) % themes.length]));
for (const radio of document.querySelectorAll('input[name="theme-choice"]')) {
  radio.addEventListener("change", () => { if (radio.checked) setTheme(radio.value); });
}
