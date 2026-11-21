# Nuvori 2.3.0

Windows version 2.3.0. Browser extension version 0.7.8. Pairs with Android 2.3.3 (version code 74).

## Firefox, Zen and other browsers

- **Fixed: Firefox-based browsers could not reach the Store build.** The Store build registered its browser host as a Store app shortcut (an app execution alias). Firefox starts a host only when it is a plain file ([subprocess_win.sys.mjs](https://github.com/mozilla-firefox/firefox/blob/main/toolkit/modules/subprocess/subprocess_win.sys.mjs)), so Firefox, Zen, LibreWolf, Waterfox and Floorp showed "Start Nuvori". The Store build now keeps a copy of its host in `%LOCALAPPDATA%\Nuvori\BrowserHost` for them and refreshes it at each start. When it must open Nuvori, the copy starts the Store app by its package ID.
- **Every installed browser is found.** Nuvori reads the browsers Windows lists as installed, plus the known profile folders. Browsers built on Firefox read Firefox's registration; Vivaldi, Opera, Thorium, Arc and Chromium read Chrome's or Chromium's. Before, only Chrome, Edge, Brave and Firefox were registered, and only when their own profile folder existed.
- **Settings > Browser extension > Browsers** lists each browser with **Connected** and **Ask for the password when it starts**. A browser Nuvori does not know asks whether it is built on Chromium or Firefox. All browsers start connected.
- The browser host tells Nuvori which browser started it (from the process that started the host), so "Used 3 min ago" and the per-browser startup setting can't be claimed by another browser.

## Website icons

Logins and passkeys show the logo of their website instead of a letter.

- About 800 popular sites have a logo built in, from [Simple Icons](https://simpleicons.org) 16.36.0 (CC0 icons only), matched to real domains by `scripts/build-site-icons.py`.
- When you use a site that already has a login or passkey in Nuvori, the extension sends that page's own icon. The extension redraws it as a 64×64 PNG, so Nuvori never stores the site's original file. It fetches without cookies, at most once every 6 hours per site, and never in a private window.
- Nothing goes to an icon service, and no icon is kept for a site you have no login or passkey for. Icons stay in the encrypted vault on this PC and are not synced.
- **Settings > Website icons** turns them off and deletes saved icons.

## Other changes

- **Home:** "Last sync" shows the newer of Wi-Fi sync and Google Drive sync.
- **Auto-type:** the login list matches the site name instead of words like "account", and the list scrolls.
- **Extension 0.7.8:** sends site icons when the app asks, and marks the password prompt at browser start, so each browser can be turned off in the app.

## Store package

The package now lists five registry keys outside the package: Chrome, Edge, Brave, Firefox and the new Chromium key. The justification in [Microsoft Store](MICROSOFT-STORE.md) is updated.

## Checks

- **Rust:** 273 unit tests passed (5 ignored), plus 54 native-host tests. New tests cover the icon checks (site match, PNG size and type, 30-day refresh, 2,000-icon limit, purge), browser detection and classification with real registry formats, which browser started the host, the "skipped" startup answer, and the Firefox host copy path.
- **Extension and frontend:** 173 tests passed, `tsc --noEmit` passed, and the production build keeps the icon data in its own file.
- Not run: the Firefox host copy with a real Firefox-based browser and the Store-signed package. Test with the test MSIX first.
