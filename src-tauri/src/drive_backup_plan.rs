//! The naming and scheduling rules of Google Drive backups, as Nuvori for Android has them
//! (`DriveBackupNames` and `DriveBackupPlan`). Pure: no database, no network and no clock of its
//! own, so the tests cover every rule.
//!
//! A backup is named `nvbak1.<backup ID: 16 hex>.<created: 13-digit Unix milliseconds>`. The
//! backup ID names the device that wrote the file, so each device replaces only its own copies.
//! Sync on both platforms reads only names that start with `nv1.<group>.`, so sync leaves these
//! files alone and the two kinds share the one hidden Drive folder.

/// The prefix of every backup file name.
pub const PREFIX: &str = "nvbak1.";

pub const HOUR: i64 = 3_600_000;
pub const DAY: i64 = 86_400_000;
pub const WEEK: i64 = 7 * DAY;
pub const MONTH: i64 = 30 * DAY;

/// The intervals the app offers, as on Android.
pub const INTERVALS: [i64; 4] = [HOUR, DAY, WEEK, MONTH];
pub const DEFAULT_INTERVAL: i64 = DAY;

/// Each device keeps its newest backup and the one before it.
pub const KEEP: usize = 2;

/// After a failed attempt, this long before the next automatic try.
pub const RETRY_AFTER: i64 = 15 * 60_000;

/// The largest time a name can hold: 13 digits.
const MAX_CREATED_AT: i64 = 9_999_999_999_999;

/// One backup file in the Drive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupFile {
    pub file_id: String,
    /// The device that wrote it.
    pub backup_id: String,
    pub created_at: i64,
    pub size: u64,
}

/// A file in the Drive folder, as the cloud store lists it. `CloudFile` implements it; the tests
/// use a struct of their own, which keeps this file free of the rest of the app.
pub trait Listed {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn size(&self) -> u64;
}

/// True for a 16-character lower-case hexadecimal backup ID.
pub fn valid_backup_id(backup_id: &str) -> bool {
    backup_id.len() == 16 && backup_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn valid_interval(interval: i64) -> bool {
    INTERVALS.contains(&interval)
}

/// The file name for a backup `backup_id` writes at `created_at`. `None` for an ID or a time that
/// could not be read back.
pub fn name(backup_id: &str, created_at: i64) -> Option<String> {
    if !valid_backup_id(backup_id) || !(0..=MAX_CREATED_AT).contains(&created_at) {
        return None;
    }
    Some(format!("{PREFIX}{backup_id}.{created_at:013}"))
}

/// The backup a file name describes, or `None` for any other name, this app's sync files included.
pub fn parse<F: Listed>(file: &F) -> Option<BackupFile> {
    let rest = file.name().strip_prefix(PREFIX)?;
    let (backup_id, created_at) = rest.split_once('.')?;
    if !valid_backup_id(backup_id) || created_at.len() != 13 || !created_at.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(BackupFile {
        file_id: file.id().to_owned(),
        backup_id: backup_id.to_owned(),
        created_at: created_at.parse().ok()?,
        size: file.size(),
    })
}

/// Every backup in the folder, newest first. The file ID breaks a tie, so the order is stable.
pub fn available<F: Listed>(files: &[F]) -> Vec<BackupFile> {
    let mut backups: Vec<BackupFile> = files.iter().filter_map(parse).collect();
    backups.sort_by(|left, right| right.created_at.cmp(&left.created_at).then_with(|| left.file_id.cmp(&right.file_id)));
    backups
}

/// A backup is due when none was made, the interval passed, or the clock moved backwards. A failed
/// attempt holds the next automatic try for [`RETRY_AFTER`].
pub fn due(now: i64, last_backup_at: i64, last_attempt_at: i64, interval: i64) -> bool {
    let retry_waits = last_attempt_at > last_backup_at && now >= last_attempt_at && now - last_attempt_at < RETRY_AFTER;
    if retry_waits {
        return false;
    }
    last_backup_at <= 0 || now < last_backup_at || now - last_backup_at >= interval
}

/// This device's backups beyond the newest [`KEEP`], and its backups made before
/// `password_changed_at`, which open with the master password of before the change. `keep` is the
/// backup just uploaded, which stays even when the clock went backwards. Another device's backups
/// are never touched.
pub fn obsolete<F: Listed>(files: &[F], backup_id: &str, password_changed_at: i64, keep: Option<&str>) -> Vec<BackupFile> {
    available(files)
        .into_iter()
        .filter(|file| file.backup_id == backup_id)
        .enumerate()
        .filter(|(index, file)| {
            Some(file.file_id.as_str()) != keep && (*index >= KEEP || file.created_at < password_changed_at)
        })
        .map(|(_, file)| file)
        .collect()
}

/// True while this device still has a backup made before `password_changed_at`, other than `keep`.
/// The app stops reporting an old master password once this is false.
pub fn old_password_backups_left<F: Listed>(files: &[F], backup_id: &str, password_changed_at: i64, keep: Option<&str>) -> bool {
    password_changed_at > 0
        && available(files).into_iter().any(|file| {
            file.backup_id == backup_id && Some(file.file_id.as_str()) != keep && file.created_at < password_changed_at
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct File {
        id: String,
        name: String,
        size: u64,
    }

    impl Listed for File {
        fn id(&self) -> &str {
            &self.id
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn size(&self) -> u64 {
            self.size
        }
    }

    const THIS: &str = "0123456789abcdef";
    const OTHER: &str = "fedcba9876543210";

    fn file(id: &str, name: &str) -> File {
        File { id: id.to_owned(), name: name.to_owned(), size: 10 }
    }

    /// A backup of `backup_id` made at `created_at`, with `id` as its Drive file ID.
    fn backup(id: &str, backup_id: &str, created_at: i64) -> File {
        file(id, &name(backup_id, created_at).unwrap())
    }

    #[test]
    fn a_name_holds_the_device_and_the_time_in_13_digits() {
        assert_eq!(name(THIS, 1_764_000_000_000).unwrap(), "nvbak1.0123456789abcdef.1764000000000");
        assert_eq!(name(THIS, 5).unwrap(), "nvbak1.0123456789abcdef.0000000000005");
        assert_eq!(name(THIS, MAX_CREATED_AT).unwrap(), "nvbak1.0123456789abcdef.9999999999999");
    }

    #[test]
    fn a_name_that_could_not_be_read_back_is_refused() {
        for (backup_id, created_at) in [
            (THIS, -1),
            (THIS, MAX_CREATED_AT + 1),
            ("0123456789ABCDEF", 1),
            ("0123456789abcde", 1),
            ("0123456789abcdef0", 1),
            ("0123456789abcdeg", 1),
            ("", 1),
        ] {
            assert_eq!(name(backup_id, created_at), None, "{backup_id} at {created_at}");
        }
    }

    #[test]
    fn a_backup_name_is_read_back_whole() {
        let listed = File { id: "drive-1".into(), name: name(THIS, 1_764_000_000_000).unwrap(), size: 4096 };
        assert_eq!(
            parse(&listed),
            Some(BackupFile {
                file_id: "drive-1".into(),
                backup_id: THIS.into(),
                created_at: 1_764_000_000_000,
                size: 4096
            })
        );
    }

    #[test]
    fn sync_files_and_other_names_are_not_backups() {
        for name in [
            "nv1.group.device.1.2",
            "nv1.0123456789abcdef.1764000000000",
            "nvbak1.0123456789abcdef",
            "nvbak1.0123456789abcdef.176400000000",
            "nvbak1.0123456789abcdef.17640000000000",
            "nvbak1.0123456789abcdef.abcdefghijklm",
            "nvbak1.0123456789ABCDEF.1764000000000",
            "nvbak1.0123456789abcdef.1764000000000.extra",
            "nvbak2.0123456789abcdef.1764000000000",
            "Nuvori backup 2026-11-25.pvault",
            "",
        ] {
            assert_eq!(parse(&file("id", name)), None, "{name}");
        }
    }

    #[test]
    fn every_devices_backups_are_listed_newest_first() {
        let files = [
            backup("a", THIS, 300),
            backup("b", OTHER, 400),
            file("c", "nv1.group.device.1.2"),
            backup("d", THIS, 100),
        ];
        let listed = available(&files);
        assert_eq!(
            listed.iter().map(|file| (file.file_id.as_str(), file.created_at)).collect::<Vec<_>>(),
            [("b", 400), ("a", 300), ("d", 100)]
        );
    }

    #[test]
    fn two_backups_made_in_the_same_millisecond_keep_a_stable_order() {
        let files = [backup("z", THIS, 100), backup("a", THIS, 100)];
        assert_eq!(available(&files).iter().map(|file| file.file_id.as_str()).collect::<Vec<_>>(), ["a", "z"]);
    }

    #[test]
    fn the_first_backup_is_due_at_once() {
        assert!(due(1_000, 0, 0, DAY));
    }

    #[test]
    fn a_backup_is_due_once_the_interval_has_passed() {
        let last = 1_000_000;
        assert!(!due(last + DAY - 1, last, 0, DAY));
        assert!(due(last + DAY, last, 0, DAY));
        assert!(due(last + HOUR, last, 0, HOUR));
        assert!(!due(last + DAY, last, 0, WEEK));
        assert!(due(last + MONTH, last, 0, MONTH));
    }

    #[test]
    fn a_clock_that_moved_backwards_makes_one_due() {
        let last = 1_000_000;
        assert!(due(last - 1, last, 0, WEEK), "a backup in the future is not waited for");
    }

    #[test]
    fn a_failed_attempt_waits_a_quarter_of_an_hour() {
        let (last_backup, attempt) = (1_000_000, 1_000_000 + DAY);
        assert!(!due(attempt, last_backup, attempt, DAY), "just failed");
        assert!(!due(attempt + RETRY_AFTER - 1, last_backup, attempt, DAY));
        assert!(due(attempt + RETRY_AFTER, last_backup, attempt, DAY));
    }

    #[test]
    fn an_attempt_stamped_in_the_future_does_not_hold_backups_for_ever() {
        let (last_backup, attempt) = (1_000_000, 1_000_000 + 10 * DAY);
        // The clock was ahead when the attempt failed and has since been put right.
        assert!(due(last_backup + 2 * DAY, last_backup, attempt, DAY));
    }

    #[test]
    fn an_attempt_that_finished_does_not_hold_the_next_one() {
        let at = 1_000_000;
        assert!(due(at + DAY, at, at, DAY), "the attempt is the backup that succeeded");
    }

    #[test]
    fn only_this_devices_backups_beyond_the_newest_two_are_removed() {
        let files = [
            backup("newest", THIS, 400),
            backup("second", THIS, 300),
            backup("third", THIS, 200),
            backup("fourth", THIS, 100),
            backup("theirs", OTHER, 100),
        ];
        let stale = obsolete(&files, THIS, 0, Some("newest"));
        assert_eq!(stale.iter().map(|file| file.file_id.as_str()).collect::<Vec<_>>(), ["third", "fourth"]);
    }

    #[test]
    fn the_backup_just_uploaded_is_never_removed() {
        let files = [backup("older", THIS, 400), backup("just-made", THIS, 100)];
        // The clock went backwards, so the new file sorts last, but it stays.
        let stale = obsolete(&files, THIS, 0, Some("just-made"));
        assert!(stale.is_empty(), "{stale:?}");
    }

    #[test]
    fn backups_that_open_with_the_old_master_password_are_removed() {
        let files = [backup("new", THIS, 500), backup("old", THIS, 300), backup("theirs", OTHER, 100)];
        let stale = obsolete(&files, THIS, 400, Some("new"));
        assert_eq!(stale.iter().map(|file| file.file_id.as_str()).collect::<Vec<_>>(), ["old"]);
        assert!(obsolete(&files, THIS, 0, Some("new")).is_empty(), "without a password change both are kept");
    }

    #[test]
    fn an_old_password_is_reported_until_its_last_backup_is_gone() {
        let files = [backup("new", THIS, 500), backup("old", THIS, 300)];
        assert!(old_password_backups_left(&files, THIS, 400, Some("new")));
        assert!(!old_password_backups_left(&files[..1], THIS, 400, Some("new")), "only the new one is left");
        assert!(!old_password_backups_left(&files, THIS, 0, Some("new")), "no password change");
        assert!(!old_password_backups_left(&files, OTHER, 400, None), "another device's backups are not ours to judge");
    }

    #[test]
    fn only_the_intervals_the_app_offers_are_valid() {
        assert!(INTERVALS.iter().copied().all(valid_interval));
        assert!(valid_interval(DEFAULT_INTERVAL));
        for interval in [0, -DAY, 1, DAY + 1, 365 * DAY] {
            assert!(!valid_interval(interval), "{interval}");
        }
    }
}
