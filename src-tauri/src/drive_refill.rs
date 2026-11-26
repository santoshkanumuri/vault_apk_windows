//! Keeping the drive's copy of every author's changes readable (audit C1 and M6). Shared with
//! Android `DriveRefill.kt`; both apps make the same choices from the same facts.
//!
//! - Refill marker (C1): the drive holds an author's changes up to `reach`, and the oldest change this
//!   PC still holds is `oldest`, with a gap between them (history was trimmed here while Drive was off,
//!   or the drive lost files). When every active member already applied everything below `oldest`
//!   (this PC's own floor(A), the same floor drive cleanup uses), a floor marker at `oldest - 1` lets
//!   every device go on from `oldest`. It is the marker that cleanup writes, so readers need nothing
//!   new, and an existing marker is never lowered. Otherwise the gap stays until a device that still
//!   holds the missing changes uploads them.
//! - Re-upload (M6): an active device keeps reporting less of an author than the drive holds, well
//!   after the drive got the file it needs: that file may be unreadable for it. A device that holds
//!   the range uploads it again as a new file, at most once a day per author.

/// A device counts as stuck on a file it reported this long after the file reached the drive.
pub const STUCK_AFTER_MS: i64 = 6 * 60 * 60 * 1000;
/// At most one re-upload per author in this long.
pub const REUPLOAD_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    None,
    Mark,
    Stuck,
}

/// What to do about the start of an author's range on the drive.
pub fn plan(reach: u64, oldest: Option<u64>, own_floor: u64, marker: u64) -> Step {
    match oldest {
        None => Step::None,
        Some(oldest) if oldest <= reach + 1 => Step::None,
        Some(oldest) if oldest - 1 <= own_floor && oldest - 1 > marker => Step::Mark,
        Some(_) => Step::Stuck,
    }
}

/// One file of an author's changes on the drive, with when it got there (Unix milliseconds, 0 if unknown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub first: u64,
    pub last: u64,
    pub modified_at: i64,
}

/// What another device's signed progress report says it received of an author, and when it wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerReport {
    pub received: u64,
    pub reported_at: i64,
}

/// The range to upload again for one author, as (after, through): from right after the lowest
/// sequence an active device stays stuck at, through the end of the files it can't get past.
/// None when no device is stuck, or the last re-upload was less than a day ago.
pub fn reupload(covered: u64, peers: &[PeerReport], segments: &[Segment], last_reupload: i64, now: i64) -> Option<(u64, u64)> {
    if (0..REUPLOAD_INTERVAL_MS).contains(&(now - last_reupload)) {
        return None;
    }
    peers
        .iter()
        .filter_map(|peer| {
            if peer.received >= covered {
                return None;
            }
            let next: Vec<&Segment> =
                segments.iter().filter(|segment| segment.first <= peer.received + 1 && segment.last > peer.received).collect();
            // No file holds its next change: a gap that a device holding the changes fills, not a stuck read.
            if next.is_empty() {
                return None;
            }
            next.iter()
                .all(|segment| segment.modified_at > 0 && peer.reported_at - segment.modified_at >= STUCK_AFTER_MS)
                .then(|| (peer.received, covered.min(next.iter().map(|segment| segment.last).max().unwrap_or(covered))))
        })
        .min_by_key(|(after, _)| *after)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors as Android `CloudSyncPassTest.driveRefillPlansAndReuploadsByTheSharedRules`.
    #[test]
    fn drive_refill_plans_and_reuploads_by_the_shared_rules() {
        assert_eq!(plan(10, Some(11), 20, 0), Step::None);
        assert_eq!(plan(10, None, 20, 0), Step::None);
        assert_eq!(plan(0, Some(11), 10, 0), Step::Mark);
        assert_eq!(plan(0, Some(11), 9, 0), Step::Stuck);
        // An existing marker is never lowered.
        assert_eq!(plan(0, Some(11), 20, 10), Step::Stuck);
        assert_eq!(plan(5, Some(11), 20, 5), Step::Mark);
        let file = Segment { first: 1, last: 10, modified_at: 1_000 };
        let day = REUPLOAD_INTERVAL_MS;
        let stuck = PeerReport { received: 0, reported_at: 1_000 + STUCK_AFTER_MS };
        assert_eq!(reupload(15, &[stuck], &[file], 0, 10 * day), Some((0, 10)));
        // Not yet stuck long enough, already re-uploaded today, a gap rather than a file, or nobody behind.
        assert_eq!(reupload(15, &[PeerReport { reported_at: 2_000, ..stuck }], &[file], 0, 10 * day), None);
        assert_eq!(reupload(15, &[stuck], &[file], 10 * day - 1, 10 * day), None);
        assert_eq!(reupload(15, &[stuck], &[Segment { first: 2, ..file }], 0, 10 * day), None);
        assert_eq!(reupload(15, &[PeerReport { received: 15, ..stuck }], &[file], 0, 10 * day), None);
    }
}
