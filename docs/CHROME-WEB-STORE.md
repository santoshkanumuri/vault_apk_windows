# Publish the browser extension in the Chrome Web Store

This guide publishes **Nuvori Password Fill** (`extension/`). Chrome and Brave install it from the Chrome Web Store. Edge can install it from the Chrome Web Store too, after the user allows extensions from other stores.

## What you need

| Item | Where |
| --- | --- |
| Chrome Web Store developer account (one-time USD 5 fee) | [Developer Dashboard](https://chrome.google.com/webstore/devconsole) |
| Store package | `artifacts/Nuvori_extension_<version>_chrome_web_store.zip`. Make it with `scripts\package-extension.ps1 -Store`. |
| Privacy policy link | The public link of `card_app/docs/privacy-policy.html`. It covers the extension in "Nuvori for Windows and the browser extension". Push it first. |
| At least 1 screenshot, 1280 x 800 or 640 x 400 | See [Screenshots](#screenshots). |
| A public download of Nuvori for Windows | The extension does nothing without it. Reviewers and users need a link. |

The 128 x 128 store icon is inside the package (`extension/icons/icon-128.png`).

## Why the store package has no `key`

`extension/manifest.json` has a `key` field. It gives the unpacked extension the fixed ID `kapellkbongejlglcengbmjnpblemmjm` on every PC. Nuvori for Windows trusts only known IDs (`src-tauri/src/browser_setup.rs`, `EXTENSION_ID`).

The Chrome Web Store refuses a new item whose manifest has a `key`. The `-Store` switch removes only that line. The store then gives the item a new ID. Nuvori for Windows must trust that ID too, so the order of steps matters.

The store item ID is `lpohaakdindhljdhpofnfmggbfllgdil`. Nuvori for Windows trusts it from 2.2.1 (`STORE_EXTENSION_ID` in `browser_setup.rs`), next to the unpacked ID.

## Steps

1. Push the privacy policy, so that its public link shows the new text.
2. Run `scripts\package-extension.ps1 -Store`.
3. In the Developer Dashboard, select **New item** and upload the store zip.
4. Copy the **Item ID** (32 letters) from the dashboard. Copy the **Public key** from the **Package** tab too.
5. Make sure that a Nuvori for Windows build trusts the new ID (done in 2.2.1). Release that build before or together with the extension. Without it, the store extension cannot reach Nuvori.
6. Fill in the tabs below.
7. Select **Submit for review**. A review usually takes a few days. Broad host access (`https://*/*`) can make it take longer.

## Store listing tab

**Name** (from the manifest): Nuvori Password Fill

**Summary** (from the manifest, 132 characters at most): Fill and save logins from Nuvori for Windows, right on the page.

**Description**:

```text
Nuvori Password Fill connects Chrome, Edge and Brave to Nuvori for Windows, the offline password vault that syncs with the Nuvori Android app.

Requires Nuvori for Windows on the same PC. The extension has no vault of its own.

What it does
- Fills logins on HTTPS websites. Choose an account from the list under the sign-in field.
- Saves new logins and updates changed passwords after you sign in.
- Fills cards, addresses and authenticator codes, also inside payment frames.
- Can turn off the browser's own password manager, so only one tool offers to save.

Private by design
- Your vault stays in Nuvori for Windows. The extension never receives your master password, your vault key or your vault.
- It talks only to Nuvori for Windows on your PC, through the browser's native messaging. It makes no network requests.
- It fills only the exact HTTPS website that a login is saved for.
- Logins waiting to be saved are encrypted by Nuvori for Windows before the extension keeps them.
- No account, no ads, no analytics.

Get started
1. Install Nuvori for Windows and unlock your vault.
2. Install this extension. Nuvori connects it automatically.
3. Open a sign-in page and choose an account from the Nuvori list.
```

**Category**: choose the closest one in the list, such as **Tools** or **Privacy & Security**.

**Language**: English.

**Icon**: comes from the package. **Screenshots**: see below. Promo tiles are optional.

**Official URL / Homepage URL**: the page where users download Nuvori for Windows.

**Support URL**: the same page, or an email address you check.

## Privacy practices tab

**Single purpose**:

```text
Fill and save the user's logins, cards, addresses and authenticator codes on HTTPS websites, using the user's own Nuvori for Windows vault on the same PC.
```

**Permission justification**:

| Permission | Justification to paste |
| --- | --- |
| `nativeMessaging` | Talks to Nuvori for Windows on the same PC, which holds the user's encrypted vault. All account lists, fills and saves go through this local connection. |
| `storage` | Stores the extension's settings, the user's "Never save" and "Don't suggest" site lists, the last 20 diagnostic events without secrets, and logins waiting to be saved, encrypted by Nuvori for Windows. |
| `scripting` | When the user selects an account in the toolbar popup, fills it into the current HTTPS page, and reads the page's form to offer a manual save. |
| `alarms` | Retries logins waiting to be saved once a minute while Nuvori for Windows is locked, and starts clearing a copied password after about 30 seconds. |
| `clipboardWrite` | Copies a username, password or authenticator code when the user selects Copy in the popup. |
| `offscreen` | Opens a hidden offscreen document to clear a copied password from the clipboard after about 30 seconds. A service worker cannot write to the clipboard. |
| Host permission `https://*/*` | Finds sign-in, card, address and code fields on the HTTPS sites the user visits, and shows Nuvori's account list there. A password manager must work on any site. HTTP pages are excluded. |
| `privacy` (optional) | Asked for only when the user turns on "Use Nuvori instead of the browser's password manager". It turns off the browser's own password saving and autofill. |

**Remote code**: No, I am not using remote code.

**Data usage**. The store asks to disclose data the extension handles, also when it stays on the device. Check:

- **Personally identifiable information** (names and addresses it fills or saves)
- **Financial and payment information** (cards it fills or saves)
- **Authentication information** (passwords and authenticator codes)
- **Website content** (the form fields it reads to fill and save)

Leave the other types unchecked: health, personal communications, location, web history and user activity.

Check all three certifications. They are true for this extension: it doesn't sell or transfer data to third parties, doesn't use it for other purposes, and doesn't use it for credit decisions.

**Privacy policy URL**: the public link of `privacy-policy.html`.

## Test instructions tab

```text
This extension works only with the desktop app Nuvori for Windows, which holds the vault.
1. Download and install Nuvori for Windows from <download link>.
2. Open Nuvori and create a vault with any master password. On the Home page, select Add, choose a login, and save one for an HTTPS sign-in page you can open.
3. Install the extension and restart the browser. Nuvori connects it automatically. Settings > Browser extension then shows a "Last contact" time.
4. Open a sign-in page on an HTTPS site. Select the username field and choose the account from the Nuvori list.
No account or sign-in is needed. The extension makes no network requests.
```

## Distribution tab

- **Visibility**: choose **Unlisted** until the Windows download is public. Change it to **Public** later.
- **Regions**: all regions.
- **Payments**: free.

## Screenshots and promo images

The images are in `store-assets/chrome-web-store/`:

| File | Size | Dashboard field |
| --- | --- | --- |
| `store-icon-128.png` | 128 x 128 | Store icon (the same file as `extension/icons/icon-128.png`) |
| `screenshot-1-fill.png` | 1280 x 800 | Screenshot 1 |
| `screenshot-2-private.png` | 1280 x 800 | Screenshot 2 |
| `screenshot-3-settings.png` | 1280 x 800 | Screenshot 3 |
| `small-promo-440x280.png` | 440 x 280 | Small promo tile |
| `marquee-1400x560.png` | 1400 x 560 | Marquee promo tile (optional) |

The popup in the screenshots is the real `popup.html`, `popup.css` and `popup.js`, rendered by headless Chrome with demo data only (Northwind and `example.com` accounts). The browser APIs and Nuvori for Windows were replaced by a small stand-in script that returns that demo data.

## Updates

1. Raise `version` in `extension/manifest.json`.
2. Run `scripts\package-extension.ps1 -Store`.
3. Upload the zip on the item's **Package** tab, then submit for review.
