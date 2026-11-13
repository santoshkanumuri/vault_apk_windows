# Nuvori 2.2.2

Windows version 2.2.2. Browser extension version 0.7.2 (unchanged). Pairs with Android 2.2.2 (version code 60).

## Choose how often Nuvori checks

- **Sync** page, **Connection**: new row **Check devices every**: 30 s, 1 min (default), 5 min or 15 min. It shows while **Sync automatically** is on. These are the same choices as the phone.
- **Google Drive** card: new row **Check Google Drive every**: 15 s (default), 1 min, 5 min or **Sync now only**.
- Your own changes still go out about 2 seconds after you save them, with every choice.
- **Sync now only** checks Google Drive when this PC unlocks, after your own changes, and when you select **Sync now**.

## Wi-Fi and Google Drive have their own timers

- Before, one timer ran Wi-Fi and Google Drive together, every 60 seconds.
- Now each way has its own interval and its own retry delay. A phone that is away from this Wi-Fi no longer slows down the Google Drive checks.
- Google Drive checks run when Google Drive is connected, also when **Sync automatically** (Wi-Fi) is off. The phone already worked this way.
- With Google Drive connected, an automatic Wi-Fi check that finds no device is not shown as a sync failure. A PC away from its phone is normal then.

## Updating from 2.2.1

1. Quit Nuvori from the tray icon.
2. Run the 2.2.2 package of the same type you installed before (MSI or setup EXE). The vault is kept.
3. Open **Sync** and check the two new rows.

## Checks

- 188 Rust unit tests passed (4 network and emulator tests ignored), 43 browser host tests and 121 extension tests passed. The frontend type check passed.
- New tests: each way keeps its own interval and retry delay, and a change still runs a pass about 2 seconds later with **Sync now only** (`each_way_keeps_its_own_interval_and_retry_delay`). Only the listed intervals can be saved, and an unknown saved value falls back to its default (`the_check_schedule_keeps_only_listed_intervals`).
- The setup EXE, the MSI and the Store test package `Nuvori_2.2.2.0_x64.msix` were built. Both apps hold the Google OAuth client and the store extension ID.
- Not run: the new timers against a real Google Drive and a real phone.
