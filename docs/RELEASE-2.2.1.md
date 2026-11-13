# Nuvori 2.2.1

Windows version 2.2.1. Browser extension version 0.7.2. Pairs with Android 2.2.0 (version code 58). Same Google Drive sync, Wi-Fi sync, autofill and passkey behavior as [2.2.0](RELEASE-2.2.0.md).

## Browser extension from the Chrome Web Store

- Nuvori now trusts the Chrome Web Store version of **Nuvori Password Fill** (item ID `lpohaakdindhljdhpofnfmggbfllgdil`). The store signs the extension with its own key, so its ID differs from the unpacked extension.
- The unpacked extension (ID `kapellkbongejlglcengbmjnpblemmjm`) keeps working. Nuvori registers both IDs for Chrome, Edge and Brave when it starts.
- **Settings > Browser extension > Set up the extension** now points to the Chrome Web Store first.
- Extension 0.7.2 has the same code as 0.7.1, plus icons that the store requires. See [Chrome Web Store](CHROME-WEB-STORE.md).

## Updating from 2.2.0

1. Quit Nuvori from the tray icon.
2. Run the 2.2.1 package of the same type you installed before (MSI or setup EXE). The vault is kept.
3. For the Store build test, install `Nuvori_2.2.1.0_x64.msix` too.
4. Open Nuvori once. It registers the new extension ID. Restart the browser.

To move from the unpacked extension to the store version:

1. In the extension's **Pending** tab, finish or discard any waiting logins. Settings and the pending list belong to one extension ID and do not move.
2. Install **Nuvori Password Fill** from the Chrome Web Store.
3. Remove the unpacked extension on the browser's extensions page.

## Checks

- 188 Rust unit tests passed (4 network and emulator tests ignored), 43 browser host tests and 121 extension tests passed. The frontend type check passed.
- New tests: both extension IDs are written into every host manifest, and both pass the same ID check as an ID read back from a registered manifest. Every icon that the extension manifest names exists.
- The setup EXE, the MSI and the Store test package `Nuvori_2.2.1.0_x64.msix` were built. The installed app and the Store app both hold the store extension ID and the Google OAuth client.
- The store zip `Nuvori_extension_0.7.2_chrome_web_store.zip` has no `key` field, no tests and no docs.
- Not run: the store extension against this build in a real browser. That needs the published store item.
