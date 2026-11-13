# Nuvori 2.2.3

Windows version 2.2.3. Browser extension version 0.7.2 (unchanged). Pairs with Android 2.2.3 (version code 61). Same features as [2.2.2](RELEASE-2.2.2.md), plus one change.

## Leaving the sync group also works through Google Drive

- Before, a PC that left the group told the managing phone only over Wi-Fi. A phone that was never on the same Wi-Fi again kept the PC on its device list.
- Now, with Google Drive connected, the PC also uploads its signed leave request to Google Drive. It seals the request with the group's cloud key while leaving, because it no longer has that key afterwards.
- The PC uploads the file from its background loop. A failed upload retries every 5 minutes for up to 30 days, the same as the Wi-Fi request.
- The managing phone (Android 2.2.3) checks the request and signs the removal. Every device then learns the removal through Google Drive or Wi-Fi.
- See [Cloud sync through Google Drive](CLOUD-SYNC.md) for the `l.` file and the checks.

## Checks

- 189 Rust unit tests passed (4 network and emulator tests ignored), 43 browser host tests and 121 extension tests passed. The frontend type check passed.
- New tests: the leave file name and body match the shared values in `fixtures/cloud-sync-v1.json` byte for byte (the same values Android checks). A leaving PC stores a sealed leave file only with Google Drive connected, retries the upload after 5 minutes, drops it after 30 days, and forgets it after the upload.
- `named_pipe_releases_only_one_selected_password_and_locks` failed once in a full host test run with Windows error 233 and passed in 3 separate runs. It does not touch the changed code.
- Not run: a real leave between a PC and a phone through Google Drive.
