# Nuvori 2.2.4

Windows version 2.2.4. Browser extension version 0.7.3. Pairs with Android 2.2.4 (version code 62).

## Windows Hello unlock is bound to Hello

- Before, the Hello copy of the vault key was protected by DPAPI only. Another program that runs as the same Windows user could remove DPAPI without a Hello prompt.
- Now, enabling Hello creates a Windows Hello key named "Nuvori vault unlock". Nuvori asks it to sign a random challenge and derives the key-encryption key from the signature (HKDF-SHA256). AES-256-GCM encrypts the vault key under it, and DPAPI wraps the result as a second layer (`hello-unlock-v1.bin`, format 2).
- A copy saved by 2.2.3 or earlier is opened once at the first Hello unlock and saved again in the new format. Windows can show one extra Hello prompt for this.
- If Windows Hello is reset, Hello unlock stops with a message. Unlock with the master password, then turn Hello off and on again in More.

## Quick search shortcut

- Press **Ctrl+Shift+Space** in any Windows app to open Nuvori's search from the tray. A locked vault shows the unlock screen first.
- The shortcut never unlocks, copies, or types anything by itself.
- Change the key or turn it off in **Settings > Security > Quick search shortcut**.

## Colors

- Pick one of 16 accents and one of 8 backgrounds in **Settings > App**. The default is the same green as before. All three windows recolor, also while the vault is locked.
- The choice syncs with paired devices over Wi-Fi and Google Drive. Light or dark mode stays per device.
- **Update every device first.** A device sends a color change only after every other active device runs 2.2.4 or newer and has synced once over Wi-Fi.
- The browser extension (0.7.3) uses the colors chosen in the desktop app, in the popup and in the in-page suggestions.

## Checks

- 219 Rust unit tests passed (4 network and emulator tests ignored). 124 extension tests passed. The frontend type check and production build passed.
- New tests: Hello key wrapping (format 2) and the migration of a 2.2.3 copy, the quick search shortcut settings, appearance sync rules against the shared vector file `fixtures/appearance-v1.json` (the same file Android checks), the feature gate for older peers, and the extension colors.
- `named_pipe_releases_only_one_selected_password_and_locks` failed once in a release-mode run, as in 2.2.3. It passed in 5 separate runs and in the next full run. It does not touch the changed code.
- `nuvori.exe` and the MSI report version 2.2.4. Both MSIX packages carry version 2.2.4.0: the test package `Nuvori.Desktop.Test`, signed by `CN=Nuvori Test`, and the unsigned Store package `SantoshKanumuri.Nuvori`.
- Both extension zips report version 0.7.3, include `appearance-palette.js`, and leave out tests. The Chrome Web Store zip has no `key` field.
- Not run: Windows Hello on a real Hello reset, color sync with a real phone, and the extension colors in a live browser.

## Files

- `Nuvori_2.2.4_x64-setup.exe` and `Nuvori_2.2.4_x64_en-US.msi`: installers.
- `Nuvori_2.2.4.0_x64_store.msix`: unsigned Microsoft Store upload.
- `Nuvori_2.2.4.0_x64.msix` and `Nuvori-Test.cer`: test package, signed with a local test certificate.
- `Nuvori_extension_0.7.3.zip` and `Nuvori_extension_0.7.3_chrome_web_store.zip`: browser extension.
