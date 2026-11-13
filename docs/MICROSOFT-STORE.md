# Publish Nuvori in the Microsoft Store

This guide publishes **Nuvori for Windows** as an MSIX package. The Store signs the package, so you do not need a code-signing certificate. The Store build also adds the Windows passkey provider (see [distribution](DISTRIBUTION.md#test-the-store-build-msix)).

## What you need

| Item | Where |
| --- | --- |
| Partner Center developer account | [storedeveloper.microsoft.com](https://storedeveloper.microsoft.com). Free for individuals. |
| Reserved app name **Nuvori** | Partner Center > Apps and games > Nuvori |
| Store package | `artifacts\msix\Nuvori_<version>.0_x64_store.msix`. Make it with the command in [Build the package](#build-the-package). |
| Privacy policy link | [santoshkanumuri.github.io/vault_apk/privacy-policy.html](https://santoshkanumuri.github.io/vault_apk/privacy-policy.html). Push `card_app/docs/privacy-policy.html` first, because the live page does not yet have the section "Nuvori for Windows and the browser extension". |
| Screenshots and logos | `store-assets/microsoft-store/`. See [Images](#images). |

## Package identity

Partner Center > Product management > Product identity gives these values. Do not change them after the first upload. Each update must use the same values.

| Manifest field | Value |
| --- | --- |
| `Package/Identity/Name` | `SantoshKanumuri.Nuvori` |
| `Package/Identity/Publisher` | `CN=048504FE-BF37-40FB-AF4D-22F10F1A4D6A` |
| `Package/Properties/PublisherDisplayName` | `Santosh Kanumuri` |

The app reads its package family name at run time (`src-tauri/src/store_build.rs`). The installer build finds the Store build by that name, so no code change is necessary for this identity.

## Build the package

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-msix.ps1 -Store
```

1. The script compiles the pairing helper, the browser host and the app, and then writes `artifacts\msix\Nuvori_<version>.0_x64_store.msix`. Upload only the file that ends in `_store.msix`.
2. `-Store` puts the identity above in the manifest and leaves the package unsigned. The Store signs it after certification.
3. Add `-SkipBuild` to package the binaries that are already in `src-tauri\target\release`.
4. The fourth version part stays 0. The Store requires this.
5. Each upload needs a higher version than the last one. Change the version in the five files listed in [DISTRIBUTION.md](DISTRIBUTION.md#build-the-next-installer).

## Check the package before you upload

The Windows App Certification Kit runs most of the Store's technical checks. It must install the package, so test the test-signed build. It has the same files.

1. Run `scripts\package-msix.ps1` without parameters. It makes the test-signed package.
2. From an administrator PowerShell, run:

   ```powershell
   & "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appcert.exe" reset
   & "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appcert.exe" test `
     -appxpackagepath "artifacts\msix\Nuvori_<version>.0_x64.msix" -reportoutputpath "$env:TEMP\nuvori-wack.xml"
   ```

3. Open the report. Fix each failed test, then build the Store package again with `-Store`.

## Partner Center submission

Open Apps and games > Nuvori > Start your submission. Fill in each section.

### Pricing and availability

- **Markets**: all markets, or the markets you choose.
- **Visibility**: Public audience, discoverable.
- **Pricing**: Free.

### Properties

- **Category**: Security. (Productivity is the alternative.)
- **Privacy policy URL**: the link in [What you need](#what-you-need).
- **Website**: the page where people download Nuvori for Android and the browser extension.
- **Support contact info**: the contact email in the privacy policy.
- **Product declarations**: select "This app depends on non-Microsoft drivers or NT services" **no**. Select "This product accesses, collects, or transmits personal information" **yes**. The vault holds personal data, and sync sends encrypted data to the user's own devices and Google Drive.
- **System requirements**: Windows 10 version 2004 (build 19041) or newer, x64. Note under additional requirements: "Passkeys in Windows needs a recent Windows 11 update."

### Age ratings

Answer the IARC questionnaire. Nuvori has no violence, no user-to-user communication, no shared user content, no location sharing and no purchases. Choose the category "Utility, productivity, communication, or other". The expected rating is the lowest one (Everyone / 3+).

### Packages

Upload the unsigned `_store.msix` from [Build the package](#build-the-package). Partner Center reads the identity and the restricted capabilities from it.

### Store listing (English, United States)

Copy the text below. The Store counts characters per field, and each text below fits.

**Product name**: Nuvori

**Short description**:

```text
An offline password vault for Windows. Keep passwords, cards, authenticator codes, passkeys and notes encrypted on your PC, unlock with Windows Hello, and sync with the Nuvori Android app on your own Wi-Fi. No Nuvori account.
```

**Description**:

```text
Nuvori keeps your passwords, cards, authenticator codes, passkeys, notes and security questions in one encrypted vault on your PC. There is no Nuvori account and no Nuvori server.

Your vault, on your devices
- The vault is encrypted on your PC and opens only with your master password or Windows Hello.
- Pair Nuvori with the Nuvori Android app. Your devices send each other encrypted, signed changes directly over your local network.
- Optional Google Drive sync works when your devices are apart. Every change is encrypted before upload, and Nuvori uses only a hidden app folder in your Drive.

Everything in one place
- Passwords with websites, tags and folders.
- Cards, including the security code, behind a separate approval.
- Authenticator codes (TOTP) with a countdown on every code.
- Passkeys: Nuvori is a passkey manager in Windows, so browsers and apps on this PC can sign in with your Nuvori passkeys.
- Notes, security questions and address profiles.
- Photos of cards and receipts, stored in the vault.

Fill in your browser
- The free Nuvori Password Fill extension for Chrome, Edge and Brave fills logins, cards, addresses and codes from Nuvori.
- The extension talks only to Nuvori on your PC. It never receives your master password or your vault.

Private by design
- No ads, no analytics, no tracking.
- The clipboard clears after you copy a password, code or card number.
- The vault locks after a period of inactivity that you choose.

Nuvori cannot recover a forgotten master password. Keep it safe.
```

**What's new in this version**:

```text
First release in the Microsoft Store. The Store version also works as a passkey manager in Windows: turn it on in Settings > Security > Passkeys in Windows.
```

**Product features** (one per line):

```text
Encrypted offline vault with no Nuvori account
Unlock with Windows Hello or your master password
Passwords, cards, authenticator codes, notes and security questions
Passkey manager in Windows for browsers and apps
Sync with the Nuvori Android app over your own Wi-Fi
Optional encrypted sync through your own Google Drive
Browser filling in Chrome, Edge and Brave with the Nuvori extension
Light and dark themes
```

**Search terms** (7 at most):

```text
password manager
password vault
authenticator
passkeys
offline
2FA codes
card wallet
```

**Copyright and trademark info**: © 2026 Santosh Kanumuri

**Developed by**: Santosh Kanumuri

### Images

All files are in `store-assets/microsoft-store/`. The screenshots are 1920 x 1080 PNG files of the real app UI with sample data only. Fictitious companies (Contoso, Fabrikam, Northwind) and `.example` domains make the data. No real vault data is in them.

| File | Partner Center field | Caption |
| --- | --- | --- |
| `screenshot-1-home.png` | Screenshot 1 | Everything in one vault: passwords, cards, codes and notes. |
| `screenshot-2-passwords.png` | Screenshot 2 | Find any login fast with filters, folders and Ctrl+K search. |
| `screenshot-3-codes-passkeys.png` | Screenshot 3 | Authenticator codes and passkeys, next to your passwords. |
| `screenshot-4-detail-dark.png` | Screenshot 4 | Copy a username or password with one click. Dark theme included. |
| `screenshot-5-sync.png` | Screenshot 5 | Sync with your phone over Wi-Fi, or through your own Google Drive. |
| `screenshot-6-settings.png` | Screenshot 6 | Windows Hello, passkeys in Windows, auto-lock and clipboard clearing. |
| `screenshot-7-unlock.png` | Screenshot 7 | Unlock with Windows Hello or your master password. |
| `screenshot-8-home-dark.png` | Screenshot 8 | The full vault in the dark theme. |
| `app-tile-icon-300x300.png` | Store logos > 1:1 app tile icon (300 x 300) | |
| `box-art-1080x1080.png` | Store logos > 1:1 box art (1080 x 1080) | |
| `poster-art-720x1080.png` | Store logos > 2:3 poster art (720 x 1080) | |
| `hero-1920x1080.png` | Additional art > 16:9 Super hero art (optional) | |

The screenshots come from `npm run dev`, which uses the development stand-in backend (`src/dev/mock.ts`) in place of the Rust core. A headless Chrome window of 1280 x 720 at 150 % scale made each image. The capture replaced the stand-in's filler rows and test states (sync conflicts, a pending managing-role transfer) with tidy sample data, and hid the "Preview mode" note and toasts.

### Submission options

**Restricted capabilities**. The package declares two. Paste this text into the justification box:

```text
runFullTrust: Nuvori is a Win32 desktop app (Tauri with WebView2). Its package contains three full-trust executables: the app, a passkey provider COM server that Windows activates through webauthn.dll, and a browser native messaging host that the Nuvori extension for Chrome, Edge and Brave starts through an app execution alias.

unvirtualizedResources: Nuvori keeps its encrypted vault in %APPDATA%\com.nuvori.desktop and registers its native messaging host in HKCU for the browsers. File system and registry write virtualization are off, so that the vault is not deleted when the user uninstalls or reinstalls the app, and so that the vault stays shared with the existing installer (EXE/MSI) version of Nuvori on the same PC. A password vault that is deleted together with the app would cause data loss.
```

**Notes for certification**:

```text
No account or sign-in is needed. On first start, create a vault with any master password (at least 12 characters). Add passwords, cards and codes from the Add button.

Passkeys in Windows (Windows 11 with the latest updates): open Settings > Security > Passkeys in Windows in Nuvori and select Turn on. Windows Settings opens at Accounts > Passkeys > Advanced options; turn Nuvori on.

Device sync needs the Nuvori Android app on the same Wi-Fi network, and Google Drive sync needs a Google account. Both are optional; the app works fully without them.

Closing the window keeps Nuvori in the notification area so the browser extension can fill logins. Quit from the tray icon.
```

## After you submit

1. Certification usually takes a few business days. Partner Center sends an email with the result.
2. If a check fails, the report names the policy. Fix it and submit again.
3. After it passes, the app goes live in the markets you chose. Install it from the Store on a separate PC and test it there.

## Updates

1. Change the version in the five files listed in [DISTRIBUTION.md](DISTRIBUTION.md#build-the-next-installer).
2. Build with the command in [Build the package](#build-the-package). Use the same identity.
3. In Partner Center, select Update on the last submission. Replace the package, and change "What's new in this version".
4. Submit. Users get the update from the Store. Windows keeps the passkey provider turned on across Store updates.
