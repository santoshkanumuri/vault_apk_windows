//! Backoff after wrong master passwords on the unlock screen, as Android's `UnlockThrottle`
//! (security review L-03). The first [`FREE_ATTEMPTS`] tries are free; after that each failure waits
//! twice as long as the one before, from 30 seconds up to [`MAX_DELAY_MILLIS`]. The count is kept in
//! a small file next to the vault so that it survives a restart, and times are wall-clock: a clock
//! moved back counts as no time passed. Windows Hello is not throttled, as Android's fingerprint
//! unlock is not, and only a correct master password clears the count.
//!
//! Standard library only, so these tests also run without the app's other crates.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub const FREE_ATTEMPTS: u32 = 5;
pub const MAX_DELAY_MILLIS: i64 = 15 * 60_000;
pub const FILE_NAME: &str = "unlock-throttle-v1.txt";
/// Android caps its counter at 1000 as well.
const MAX_FAILURES: u32 = 1000;

/// The wait that `failures` wrong passwords in a row impose before the next try.
pub fn delay_after(failures: u32) -> i64 {
    if failures < FREE_ATTEMPTS {
        return 0;
    }
    let step = (failures - FREE_ATTEMPTS).min(10);
    (30_000_i64 << step).min(MAX_DELAY_MILLIS)
}

/// Milliseconds left before another try, after `failures` in a row, the last at `last_failure_at`.
pub fn wait_millis(failures: u32, last_failure_at: i64, now: i64) -> i64 {
    let delay = delay_after(failures);
    if delay == 0 {
        return 0;
    }
    let elapsed = now.saturating_sub(last_failure_at);
    if elapsed < 0 {
        return delay;
    }
    (delay - elapsed).max(0)
}

/// "45 seconds", "1 minute", "15 minutes": a wait rounded up.
pub fn describe(millis: i64) -> String {
    let seconds = ((millis + 999) / 1000).max(1);
    if seconds < 60 {
        return if seconds == 1 { "1 second".to_owned() } else { format!("{seconds} seconds") };
    }
    let minutes = (seconds + 59) / 60;
    if minutes == 1 { "1 minute".to_owned() } else { format!("{minutes} minutes") }
}

/// The message the unlock screen shows while it waits (Android's wording).
pub fn message(wait: i64) -> String {
    format!("Too many wrong passwords. Try again in {}.", describe(wait))
}

/// Wrong passwords in a row, kept in the vault folder.
pub struct UnlockThrottle {
    path: PathBuf,
}

impl UnlockThrottle {
    pub fn new(directory: &Path) -> Self {
        Self { path: directory.join(FILE_NAME) }
    }

    /// Failures in a row and when the last one happened. A missing or unreadable file is no failures.
    pub fn load(&self) -> (u32, i64) {
        let Ok(text) = fs::read_to_string(&self.path) else { return (0, 0) };
        let mut parts = text.split_ascii_whitespace();
        match (parts.next(), parts.next().map(str::parse::<u32>), parts.next().map(str::parse::<i64>)) {
            (Some("1"), Some(Ok(failures)), Some(Ok(at))) => (failures.min(MAX_FAILURES), at),
            _ => (0, 0),
        }
    }

    /// Milliseconds before the next master password may be tried.
    pub fn wait(&self, now: i64) -> i64 {
        let (failures, at) = self.load();
        wait_millis(failures, at, now)
    }

    /// Counts one more wrong password at `now`.
    pub fn record_failure(&self, now: i64) -> io::Result<()> {
        let (failures, _) = self.load();
        let next = failures.saturating_add(1).min(MAX_FAILURES);
        fs::write(&self.path, format!("1 {next} {now}\n"))
    }

    /// A correct master password starts the count again.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: i64 = 60_000;

    #[test]
    fn five_tries_are_free_then_the_wait_doubles_up_to_fifteen_minutes() {
        for failures in 0..FREE_ATTEMPTS {
            assert_eq!(delay_after(failures), 0);
        }
        assert_eq!(delay_after(5), 30_000);
        assert_eq!(delay_after(6), MINUTE);
        assert_eq!(delay_after(7), 2 * MINUTE);
        assert_eq!(delay_after(9), 8 * MINUTE);
        assert_eq!(delay_after(10), 15 * MINUTE, "16 minutes is capped");
        assert_eq!(delay_after(1000), 15 * MINUTE);
    }

    #[test]
    fn the_wait_counts_down_from_the_last_failure_and_a_clock_moved_back_restarts_it() {
        let at = 1_800_000_000_000;
        assert_eq!(wait_millis(4, at, at), 0);
        assert_eq!(wait_millis(5, at, at), 30_000);
        assert_eq!(wait_millis(5, at, at + 20_000), 10_000);
        assert_eq!(wait_millis(5, at, at + 31_000), 0);
        assert_eq!(wait_millis(6, at, at - 1), MINUTE, "a clock moved back counts as no time passed");
    }

    #[test]
    fn waits_read_like_android() {
        assert_eq!(describe(1), "1 second");
        assert_eq!(describe(30_000), "30 seconds");
        assert_eq!(describe(59_001), "1 minute");
        assert_eq!(describe(60_000), "1 minute");
        assert_eq!(describe(61_000), "2 minutes");
        assert_eq!(describe(15 * MINUTE), "15 minutes");
        assert_eq!(message(30_000), "Too many wrong passwords. Try again in 30 seconds.");
    }

    #[test]
    fn the_count_survives_a_restart_and_a_correct_password_clears_it() {
        let directory = std::env::temp_dir().join(format!("nuvori-throttle-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let throttle = UnlockThrottle::new(&directory);
        throttle.clear().unwrap();
        let now = 1_800_000_000_000;
        for _ in 0..5 {
            assert_eq!(throttle.wait(now), 0);
            throttle.record_failure(now).unwrap();
        }
        let restarted = UnlockThrottle::new(&directory);
        assert_eq!(restarted.load(), (5, now));
        assert_eq!(restarted.wait(now + 5_000), 25_000);
        restarted.record_failure(now + 40_000).unwrap();
        assert_eq!(restarted.wait(now + 40_000), MINUTE);
        restarted.clear().unwrap();
        restarted.clear().unwrap();
        assert_eq!(restarted.wait(now + 40_000), 0);

        fs::write(directory.join(FILE_NAME), "garbage").unwrap();
        assert_eq!(restarted.load(), (0, 0), "an unreadable file is no failures");
        fs::write(directory.join(FILE_NAME), "1 999999 5").unwrap();
        assert_eq!(restarted.load(), (1000, 5));
        fs::remove_dir_all(&directory).unwrap();
    }
}
