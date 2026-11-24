# Install and share Nuvori for Windows

## Use the ready-made installer

Share `Nuvori_2.3.0_x64-setup.exe` from the [latest release](https://github.com/santoshkanumuri/vault_apk_windows/releases/latest) with people using 64-bit Windows PCs. They double-click the file, complete setup, and open Nuvori from the Start menu. The setup installs for the current Windows user. Node.js, npm, Rust, and the .NET SDK are not required on their PCs.

The MSI `Nuvori_2.3.0_x64_en-US.msi` on the same Releases page is an alternative for managed installation. Choose one package. These are x64 Windows packages. Android phones need the phone APK, and other platforms need separate builds.

Setup includes the pairing helper and browser Native Messaging host. Install the browser extension **Nuvori Password Fill** from the Chrome Web Store (see [Chrome Web Store](CHROME-WEB-STORE.md)). For development, `Nuvori_extension_<version>.zip` can also be extracted to a folder that stays in place and loaded with **Load unpacked**. Nuvori connects the extension to Chrome, Edge and Brave by itself when it starts; **Settings > Browser extension > Connect** does it again on demand. Restart the browser afterward. Nuvori trusts the store extension ID and the fixed unpacked ID, so a new folder or a later update needs no new registration.

The installer checks for Microsoft WebView2 and downloads it if missing. That first installation needs internet access when WebView2 is absent. Once dependencies are present, the vault and local sync do not require a cloud account. See [Tauri's Windows installer documentation](https://v2.tauri.app/distribute/windows-installer/).

## Build the next installer

On the development PC, from the Windows project folder:

```powershell
npm run package:windows
```

This compiles the self-contained pairing helper, browser host, frontend, and desktop app, then packages both installers. It copies them to `artifacts` with a versioned SHA-256 checksum file. The development prerequisites are listed in [README.md](../README.md#run-the-project).

Keep the version consistent in `package.json`, `package-lock.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and `src-tauri/tauri.conf.json` before a release. Keep the application identifier unchanged so updates keep using the existing vault location.

## Distribute a release

1. Test installation on a separate Windows PC and test note and photo sync with a phone. Packaging and emulator tests do not cover that PC's firewall or network.
2. Upload the setup EXE, checksum file, and release notes to your download location, such as a GitHub release or your website. The MSI is optional.
3. Tell users to quit Nuvori from its tray icon, then run the new installer over their existing installation. They should not reset or erase their vault to install an update. Use the same package type as before (the setup EXE installs for the current user, the MSI for the whole PC), so the update replaces the existing copy instead of adding a second one.

For local sync, keep both devices on a network that allows them to reach each other. Allow the installed Nuvori app through Windows Firewall on your trusted local network. A firewall rule for the development executable does not cover a separately installed executable.

Publish only signed packages. Without signing, `npm run package:windows` warns that the installers are for testing only. See [Sign a release](#sign-a-release).

To compare a download with the supplied checksum:

```powershell
Get-FileHash .\Nuvori_2.3.0_x64-setup.exe -Algorithm SHA256
```

The checksum detects a changed file. It does not replace a trusted publisher signature.

## Sign a release

From the security review (M-07), a release build signs every program it ships and checks the signatures before anything is copied to `artifacts`. A signed build also refuses to talk to a pairing helper, browser host or second app copy that was not signed by one of its own certificates, so a program dropped into a folder Nuvori trusts cannot pose as part of Nuvori. An unsigned development build keeps working as before.

The certificate and its private key stay on your PC, in the Windows certificate store, on a hardware token, or in Azure. Nothing secret goes into the repository: the build reads its settings from environment variables, listed at the top of `scripts/signing.ps1`.

### What you need to supply

Pick one:

1. **A code signing certificate from a certificate authority** (an OV or EV certificate, usually on a USB token or in a cloud HSM). Install it so it shows in `certmgr.msc` under Personal > Certificates with a private key. Note its SHA-1 thumbprint and the CA's RFC 3161 timestamp address.
2. **Azure Trusted Signing.** Create an account and a public trust certificate profile, install the `Microsoft.Trusted.Signing.Client` package for `Azure.CodeSigning.Dlib.dll`, write the `metadata.json` it describes (endpoint, account name, profile name), and sign in with `az login`. Note the publisher name the profile issues (its common name).

You also need `signtool.exe` from the Windows SDK.

### Build signed installers

For a certificate:

```powershell
$env:NUVORI_SIGN_MODE = 'certificate'
$env:NUVORI_SIGN_CERT_THUMBPRINT = '<40-digit SHA-1 thumbprint>'
$env:NUVORI_SIGN_TIMESTAMP_URL = '<your CA''s timestamp address>'
$env:NUVORI_REQUIRE_SIGNING = '1'
npm run package:windows
```

For Azure Trusted Signing:

```powershell
$env:NUVORI_SIGN_MODE = 'trusted-signing'
$env:NUVORI_TRUSTED_SIGNING_DLIB = '<path>\Azure.CodeSigning.Dlib.dll'
$env:NUVORI_TRUSTED_SIGNING_METADATA = '<path>\metadata.json'
$env:NUVORI_SIGNER_NAME = '<publisher name in the certificate>'
$env:NUVORI_SIGN_TIMESTAMP_URL = 'http://timestamp.acs.microsoft.com'
$env:NUVORI_REQUIRE_SIGNING = '1'
npm run package:windows
```

The build signs the pairing helper, then Tauri signs `nuvori.exe`, `nuvori-native-host.exe`, the uninstaller and both installers through `scripts/sign-file.ps1`. Every file is signed with SHA-256 and timestamped, so it keeps verifying after the certificate expires. `NUVORI_REQUIRE_SIGNING=1` stops the build if signing is not set up or any signature fails.

### Which signers the app trusts

The build bakes its signers into the app (`src-tauri/src/signer.rs`):

- In `certificate` mode it adds the SHA-256 of your certificate. That pins one certificate, so **before you renew**, add the new certificate's SHA-256 to `NUVORI_SIGNER_SHA256` (comma separated) for one release, so the release before the switch already trusts the next certificate. Get it with `(Get-FileHash -InputStream ([IO.MemoryStream]::new($cert.RawData)) -Algorithm SHA256).Hash`.
- In `trusted-signing` mode it trusts the publisher name, because Azure issues a new short-lived certificate every few days. Windows still checks that the chain ends at a trusted root and that the signature is intact.

The MSIX for the Microsoft Store is built without pinning, because the Store signs the package and trusts it by package identity.

### Signed update channel

Nuvori does not check for updates by itself, so the release page is the update channel. To let people check a download against a key you control, as well as against the Authenticode signature:

1. Once, make a key pair: `npm run tauri -- signer generate -w "$env:USERPROFILE\.tauri\nuvori.key"`. Keep the private key and its password offline, and publish the public key in this file and on the release page.
2. Before each release build, set `TAURI_SIGNING_PRIVATE_KEY` (the key or its path) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
3. `npm run package:windows` then writes `SHA256SUMS-<version>.txt.sig` next to the checksum list. Upload both.

If Nuvori later gets the Tauri updater, the same key pair signs its update files, and its public key goes into `tauri.conf.json` under `plugins.updater.pubkey`. That adds a network check, so the privacy policy needs updating first.

SmartScreen warnings can still depend on reputation after signing. See [Tauri's Windows signing guide](https://v2.tauri.app/distribute/sign/windows/).

## Test the Store build (MSIX)

The MSIX is the future Microsoft Store package. It adds the Windows passkey provider. It is for testing on your own PC; the Store signs the real one.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-msix.ps1
powershell -ExecutionPolicy Bypass -File scripts\install-test-msix.ps1
```

1. `package-msix.ps1` builds the app and writes `artifacts\msix\Nuvori_<version>_x64.msix`, signed with a local test certificate (`CN=Nuvori Test`) in your user certificate store.
2. Quit Nuvori from the tray first. `install-test-msix.ps1` copies `%APPDATA%\com.nuvori.desktop` to a dated backup, then installs. With Developer Mode on (Settings > System > For developers) it needs no administrator rights; otherwise run it from an administrator PowerShell, which trusts the test certificate on this PC.
3. Open Nuvori from the Start menu and unlock it. In Nuvori, open **Settings > Security > Passkeys in Windows** and choose **Turn on**. Windows Settings opens at Accounts > Passkeys > Advanced options; turn Nuvori on under passkey managers. The row in Nuvori then shows **On**.
4. Remove it with `install-test-msix.ps1 -Uninstall`. The vault and the installer build stay.

### Store build and installer build on one PC

Both builds use the same vault folder, and one Nuvori runs at a time. From 2.1.9, the Store build always wins, because only it can answer passkey requests:

- When the Store build starts, it records its app ID in `%APPDATA%\com.nuvori.desktop\store-build.json`.
- When the installer build starts and that Store package is installed, it opens the Store build and closes. So the old Start menu entry, the browser extension and sign-in at startup all end up in the Store build.
- When the Store build starts while an installer-build copy runs, it asks that copy to close and takes its place. The copy agrees only when the request comes from the recorded Store package. An installer build 2.1.8 or earlier does not know this request; quit it from the tray once.
- The Store build points the browser registrations at its own browser host when it starts.
- Nuvori's **Settings > About** names the build. A Store build also shows **Installer build also installed** with a link to Installed apps. You can keep the installer build or uninstall it. The vault stays either way.

To return to the installer build, uninstall the MSIX. The installer build then deletes the stale `store-build.json`, runs itself, and connects the browsers to its own host.

For a Store release, build with `package-msix.ps1 -Store`. It uses the Partner Center identity, leaves the package unsigned for the Store to sign, and writes `Nuvori_<version>_x64_store.msix`. See [Microsoft Store](MICROSOFT-STORE.md). The Store reviews the `unvirtualizedResources` capability, which keeps the vault outside the package so it survives an uninstall and stays shared with the installer build. On Windows 11 the manifest unvirtualizes only the vault folder, the `Nuvori\BrowserHost` folder (manifests, plus a real copy of the host for Firefox-based browsers, which reject the execution alias) and the five `NativeMessagingHosts\com.nuvori.desktop` keys: Chrome, Edge, Brave, Chromium and Mozilla (flexible virtualization). Nuvori detects installed browsers from `StartMenuInternet` and profile folders, and writes the keys of each browser family the user kept connected. Windows 10 turns off AppData and HKCU virtualization as a whole. A unit test in `browser_setup.rs` keeps the manifest lists equal to the paths in the code.
