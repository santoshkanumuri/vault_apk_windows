# Publish the browser extension on Firefox Add-ons (AMO)

This guide publishes **Nuvori Password Fill** (`extension/`) on [addons.mozilla.org](https://addons.mozilla.org) for Firefox on Windows. The Firefox package is built from the same code as the Chrome package.

## What you need

| Item | Where |
| --- | --- |
| A Firefox Add-ons developer account (free) | [Developer Hub](https://addons.mozilla.org/developers/) |
| Firefox package | `artifacts/Nuvori_extension_<version>_firefox.zip`. Make it with `scripts\package-extension.ps1 -Firefox`. |
| Privacy policy link | The same public `privacy-policy.html` as for the Chrome Web Store. |
| At least 1 screenshot | AMO accepts the Chrome Web Store screenshots (`store-assets/chrome-web-store/`). |
| A Nuvori for Windows release with Firefox support | The first release built from the change that added `FIREFOX_EXTENSION_ID` to `src-tauri/src/browser_setup.rs`. Older releases don't register the host for Firefox, so the add-on can't reach them. |

## The add-on ID

The ID is `password-fill@nuvori.santoshkanumuri.com`. It is written into the package by `scripts\package-extension.ps1` (`$FirefoxId`) and trusted by Nuvori for Windows (`FIREFOX_EXTENSION_ID`). A Rust test checks that both use the same value.

AMO fixes the ID on the first upload. It can never change afterwards.

## What the Firefox package changes

`-Firefox` changes only `manifest.json`. All code is the same as for Chrome.

| Chrome manifest | Firefox manifest | Why |
| --- | --- | --- |
| `background.service_worker` | `background.scripts` | Firefox runs the background as an event page. |
| `key`, `minimum_chrome_version` | removed | Chrome-only keys. |
| `offscreen` permission and `offscreen.*` files | removed | Firefox has no offscreen documents. The background page clears the clipboard itself. |
| none | `browser_specific_settings.gecko`: the ID, `strict_min_version` 140.0, `data_collection_permissions` | Firefox requires these. |

The zip is written with forward slashes in its paths. AMO rejects the backslashes that `Compress-Archive` writes on Windows PowerShell 5.1.

Firefox 140 is the minimum version. It is the current ESR, and the first version that reads `data_collection_permissions`. It also covers popover (125), `sender.origin` (126) and `match_origin_as_fallback` (128).

## How Nuvori behaves in Firefox

Firefox has no IntersectionObserver v2 (`trackVisibility` / `isVisible`; [MDN compatibility data](https://github.com/mdn/browser-compat-data/blob/main/api/IntersectionObserverEntry.json)). In Chrome, the extension uses that observer to prove that its in-page list is really visible before a click counts. This is the clickjacking defence. Firefox can't give that proof, so the extension splits its features by risk:

- **In the page:** logins saved for the page's own site, and authenticator codes that match the site. The other defences still apply: a trusted event, a 400 ms delay, a hit test, the top layer, and a re-raise plus delay restart whenever another popover, dialog or fullscreen element appears. The save, update and "Already saved" cards also work.
- **Only in the toolbar popup:** cards, addresses, **Search all logins** and **Show all codes**. These are not tied to the site, so a disguised click must never release them. The popup's **Cards** and **Addresses** sections appear when the page has that kind of form, and **Fill** puts the item into the form the user is working in.

The code checks for the observer, not for the browser name (`LIMITED_PAGE_UI` in `suggestions.js`). The background also refuses these requests from a page when it runs as `moz-extension:` (`LIMITED_PAGE_UI` in `background.js`).

Firefox can't turn off its own address and card autofill from an extension. The popup therefore hides that switch in Firefox. The password-saving switch works. The password page is `about:logins`, which an extension can't open, so the popup shows the address instead.

Users can take back the add-on's access to websites in `about:addons`. In that case the popup shows **Allow on HTTPS websites**.

## Native messaging on Windows

Firefox reads `HKCU\Software\Mozilla\NativeMessagingHosts\com.nuvori.desktop`. The manifest it names lists add-on IDs (`allowed_extensions`), not extension origins. Nuvori for Windows writes `%LOCALAPPDATA%\Nuvori\BrowserHost\com.nuvori.desktop.firefox.json` and that key itself. It does this when Firefox is installed (`%APPDATA%\Mozilla\Firefox`) or was registered before, at start and from **Settings > Browser extension > Connect browsers**.

Firefox starts the host with two arguments: the manifest's path and the add-on ID. The host accepts the call only when the path is Nuvori's own Firefox manifest and that manifest lists the ID (`is_registered_firefox_caller` in `nuvori-native-host.rs`).

For a development build, run `browser-host\register-native-host.ps1 -Firefox -HostExecutable .\src-tauri\target\release\nuvori-native-host.exe`.

## Steps

1. Release Nuvori for Windows with Firefox support first, or together with the add-on.
2. Run `scripts\package-extension.ps1 -Firefox`.
3. Optional, recommended: run `npx web-ext lint --source-dir <the unzipped package>`. It runs the same validator as AMO. The expected result is 0 errors and 3 warnings, which are explained in the reviewer notes below.
4. In the Developer Hub, choose **Submit a New Add-on**, then **On this site**, and upload the zip.
5. **Do you need to submit source code?** Choose **No**. The package is the source: it isn't minified, bundled or generated.
6. Fill in the listing and the reviewer notes below, then submit. The add-on is signed when the review passes.

## Listing

**Name**: Nuvori Password Fill

**Summary** (250 characters at most):

```text
Fill and save logins, cards, addresses and authenticator codes from Nuvori for Windows, the offline password vault. Needs Nuvori for Windows on the same PC.
```

**Description**:

```text
Nuvori Password Fill connects Firefox to Nuvori for Windows, the offline password vault that syncs with the Nuvori Android app.

Requires Nuvori for Windows on the same PC. The add-on has no vault of its own.

What it does
- Fills logins on HTTPS websites. Choose an account from the list under the sign-in field.
- Saves new logins and updates changed passwords after you sign in.
- Fills authenticator codes on two-step sign-in pages.
- Fills cards and addresses from the toolbar button.
- Can turn off Firefox's own password saving, so only one tool offers to save.

Private by design
- Your vault stays in Nuvori for Windows. The add-on never receives your master password, your vault key or your vault.
- It talks only to Nuvori for Windows on your PC, through Firefox's native messaging. It makes no network requests.
- It fills only the exact HTTPS website that a login is saved for.
- No account, no ads, no analytics.

Get started
1. Install Nuvori for Windows and unlock your vault.
2. Install this add-on and restart Firefox. Nuvori connects it automatically.
3. Open a sign-in page and choose an account from the Nuvori list.
```

**Categories**: Privacy & Security.

**Support site**: the page where users download Nuvori for Windows.

**License**: the license you use for the extension's code.

**Privacy policy**: the public link of `privacy-policy.html`.

## Data collection

The manifest declares `required`: `authenticationInfo`, `personallyIdentifyingInfo`, `financialAndPaymentInfo` and `websiteContent`.

Mozilla counts data "handled outside the add-on or the local browser" as transmitted. Nuvori for Windows runs outside the browser, so the logins, cards, addresses and form contents that the add-on passes to it are declared. These are the same types as in the Chrome Web Store disclosure. Nothing goes to the developer or to any server. Firefox shows these types when the user installs the add-on.

## Notes to reviewer

```text
This add-on works only with the desktop app Nuvori for Windows, which holds the user's vault. It talks to that app through native messaging (host "com.nuvori.desktop") and makes no network requests.

To test:
1. Install Nuvori for Windows from https://github.com/santoshkanumuri/vault_apk_windows/releases/latest.
2. Open Nuvori and create a vault with any master password. Add a login for an HTTPS sign-in page, for example https://the-internet.herokuapp.com/login (username tomsmith, password SuperSecretPassword!).
3. Install the add-on and restart Firefox. Nuvori registers its native messaging host for Firefox by itself.
4. Open the sign-in page, click the username field, and choose the account from the Nuvori list.

Linter warnings:
- "offscreen.* is not supported" (3): the clipboard code calls chrome.offscreen only when it exists (Chrome). In Firefox, the background page clears the clipboard with navigator.clipboard instead.

Permissions:
- nativeMessaging: the only connection to the user's vault (Nuvori for Windows on the same PC).
- https://*/*: a password manager must find sign-in fields on any HTTPS site. HTTP pages are excluded.
- scripting: fills the account chosen in the toolbar popup into the current page.
- storage, alarms: settings, and logins waiting to be saved (encrypted by Nuvori for Windows) while the vault is locked.
- clipboardWrite: Copy username, password or code in the popup. The clipboard is cleared about 30 seconds later.
- privacy (optional): asked for only when the user turns on "Use Nuvori instead of the browser's password manager".

The code is not minified, bundled or generated. The package is the source.
```

## Updates

1. Raise `version` in `extension/manifest.json`.
2. Run `scripts\package-extension.ps1 -Firefox`.
3. In the Developer Hub, open the add-on, choose **Upload New Version**, and upload the zip.
