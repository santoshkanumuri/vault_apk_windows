//! Limits for LAN sync connections that have not yet proved they belong to the vault group
//! (security review L-20). Android has the same limits in `sync/PreAuthLimiter.kt`.

use std::{
    collections::HashMap,
    net::{IpAddr, Shutdown, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// Time a connecting device has, in total, to answer the challenge. Each read already has its own
/// timeout, but a device sending one byte at a time could otherwise keep a connection open for hours.
pub(crate) const PRE_AUTH_DEADLINE: Duration = Duration::from_secs(20);

/// Closes `stream` after `limit` unless the returned guard is dropped first. Drop the guard once
/// the peer has proved its membership; an early return drops it too.
pub(crate) fn close_after(stream: TcpStream, limit: Duration) -> DeadlineGuard {
    let (cancel, wait) = mpsc::channel::<()>();
    thread::spawn(move || {
        if let Err(mpsc::RecvTimeoutError::Timeout) = wait.recv_timeout(limit) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    DeadlineGuard { _cancel: cancel }
}

/// Dropping it disconnects the channel, so the watcher thread ends without closing the socket.
pub(crate) struct DeadlineGuard {
    _cancel: mpsc::Sender<()>,
}

/// M7: the key a source is limited by. An IPv6 host usually holds a whole /64, so its addresses
/// count as one source; an IPv4-mapped IPv6 address counts as its IPv4 address.
pub(crate) fn source_key(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(_) => source,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        },
    }
}

/// Unproved connections checked at once, from all sources together and from one source (Android
/// `PreAuthLimiter`: 8 and 2). The last [RESERVED] are kept for sources that proved membership
/// before (M7), so strangers cannot fill them.
const TOTAL: usize = 8;
const PER_SOURCE: usize = 2;
const RESERVED: usize = 2;
/// How long a source that proved membership counts as a known device.
const KNOWN_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Whether a new connection may start its membership check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Start,
    /// Too many checks are running: answer busy, so a paired device retries soon.
    Full,
    /// The source keeps failing the proof: close without a reply.
    Blocked,
}

/// Turns away an address whose connections keep failing the membership proof, and limits how many
/// connections are checked at once.
pub(crate) struct PreAuthLimiter {
    max_failures: usize,
    window: Duration,
    block: Duration,
    failures: HashMap<IpAddr, Vec<Instant>>,
    blocked_until: HashMap<IpAddr, Instant>,
    active: HashMap<IpAddr, usize>,
    known: HashMap<IpAddr, Instant>,
}

impl Default for PreAuthLimiter {
    fn default() -> Self { Self::new(5, Duration::from_secs(120), Duration::from_secs(120)) }
}

impl PreAuthLimiter {
    pub(crate) fn new(max_failures: usize, window: Duration, block: Duration) -> Self {
        Self { max_failures, window, block, failures: HashMap::new(), blocked_until: HashMap::new(),
            active: HashMap::new(), known: HashMap::new() }
    }

    /// Starts the check of a connection from `source`, within the limits. Call [Self::finish] or
    /// [Self::release] once for each [Admit::Start].
    pub(crate) fn try_start(&mut self, source: IpAddr, now: Instant) -> Admit {
        if !self.allow(source, now) { return Admit::Blocked; }
        let source = source_key(source);
        let known = self.known.get(&source).is_some_and(|at| now.saturating_duration_since(*at) < KNOWN_FOR);
        let total: usize = self.active.values().sum();
        let mine = self.active.get(&source).copied().unwrap_or(0);
        if mine >= PER_SOURCE || total >= TOTAL || (!known && total >= TOTAL - RESERVED) { return Admit::Full; }
        self.active.insert(source, mine + 1);
        Admit::Start
    }

    /// Ends a check without counting it as a failure (a busy reply before the check).
    pub(crate) fn release(&mut self, source: IpAddr) {
        let source = source_key(source);
        match self.active.get(&source).copied().unwrap_or(0) {
            0 | 1 => { self.active.remove(&source); }
            left => { self.active.insert(source, left - 1); }
        }
    }

    /// False while `source` is turned away. The caller then closes the connection without a reply.
    pub(crate) fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        let source = source_key(source);
        match self.blocked_until.get(&source) {
            Some(until) if now < *until => false,
            Some(_) => { self.blocked_until.remove(&source); true }
            None => true,
        }
    }

    /// Records how a connection from `source` ended. A proved connection clears its failures and
    /// makes the source a known device.
    pub(crate) fn finish(&mut self, source: IpAddr, proved: bool, now: Instant) {
        self.release(source);
        let source = source_key(source);
        if proved {
            self.failures.remove(&source);
            if self.known.len() >= 256 { self.known.retain(|_, at| now.saturating_duration_since(*at) < KNOWN_FOR); }
            if self.known.len() < 256 || self.known.contains_key(&source) { self.known.insert(source, now); }
            return;
        }
        let window = self.window;
        let recent = self.failures.entry(source).or_default();
        recent.retain(|at| now.saturating_duration_since(*at) < window);
        recent.push(now);
        if recent.len() >= self.max_failures {
            self.failures.remove(&source);
            self.blocked_until.insert(source, now + self.block);
        }
        // Keep the maps small on a busy network.
        if self.failures.len() > 256 {
            self.failures.retain(|_, times| times.iter().any(|at| now.saturating_duration_since(*at) < window));
        }
        self.blocked_until.retain(|_, until| now < *until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn ip(last: u8) -> IpAddr { IpAddr::from([192, 168, 1, last]) }

    #[test]
    fn repeated_failures_turn_an_address_away_for_a_while() {
        let start = Instant::now();
        let mut limiter = PreAuthLimiter::default();
        for _ in 0..4 { assert!(limiter.allow(ip(9), start)); limiter.finish(ip(9), false, start); }
        assert!(limiter.allow(ip(9), start));
        limiter.finish(ip(9), false, start);
        assert!(!limiter.allow(ip(9), start + Duration::from_secs(60)));
        assert!(limiter.allow(ip(10), start), "other addresses are not affected");
        assert!(limiter.allow(ip(9), start + Duration::from_secs(121)));
    }

    #[test]
    fn checks_at_once_are_limited_and_known_devices_keep_a_reserve() {
        let start = Instant::now();
        let mut limiter = PreAuthLimiter::default();
        // A known device proved earlier.
        assert_eq!(limiter.try_start(ip(50), start), Admit::Start);
        limiter.finish(ip(50), true, start);
        // Two per source.
        assert_eq!(limiter.try_start(ip(1), start), Admit::Start);
        assert_eq!(limiter.try_start(ip(1), start), Admit::Start);
        assert_eq!(limiter.try_start(ip(1), start), Admit::Full);
        // Strangers fill 6 of the 8 checks; the last 2 stay for known devices.
        for last in 2..=5 { assert_eq!(limiter.try_start(ip(last), start), Admit::Start); }
        assert_eq!(limiter.try_start(ip(6), start), Admit::Full, "a stranger cannot take the reserve");
        assert_eq!(limiter.try_start(ip(50), start), Admit::Start, "the known device still gets in");
        assert_eq!(limiter.try_start(ip(50), start), Admit::Start);
        assert_eq!(limiter.try_start(ip(50), start), Admit::Full, "8 at most");
        // A busy reply frees the slot without counting a failure.
        limiter.release(ip(2));
        assert_eq!(limiter.try_start(ip(6), start), Admit::Full, "still 7 running, inside the reserve");
        limiter.release(ip(3));
        assert_eq!(limiter.try_start(ip(6), start), Admit::Full);
        limiter.release(ip(4));
        assert_eq!(limiter.try_start(ip(6), start), Admit::Start, "5 running: a stranger fits again");
    }

    #[test]
    fn ipv6_addresses_of_one_network_count_as_one_source() {
        let a: IpAddr = "2001:db8:1:2::10".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:abcd::99".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::10".parse().unwrap();
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(other));
        let mapped: IpAddr = "::ffff:192.168.1.7".parse().unwrap();
        assert_eq!(source_key(mapped), ip(7));
        let start = Instant::now();
        let mut limiter = PreAuthLimiter::default();
        assert_eq!(limiter.try_start(a, start), Admit::Start);
        assert_eq!(limiter.try_start(b, start), Admit::Start);
        assert_eq!(limiter.try_start("2001:db8:1:2::77".parse().unwrap(), start), Admit::Full);
        for _ in 0..5 { limiter.finish(a, false, start); }
        assert!(!limiter.allow(b, start), "a block covers the whole /64");
        assert!(limiter.allow(other, start));
    }

    #[test]
    fn old_failures_and_a_proved_connection_reset_the_count() {
        let start = Instant::now();
        let mut limiter = PreAuthLimiter::default();
        for _ in 0..4 { limiter.finish(ip(2), false, start); }
        limiter.finish(ip(2), false, start + Duration::from_secs(130));
        assert!(limiter.allow(ip(2), start + Duration::from_secs(130)));
        for _ in 0..3 { limiter.finish(ip(2), false, start + Duration::from_secs(131)); }
        limiter.finish(ip(2), true, start + Duration::from_secs(132));
        limiter.finish(ip(2), false, start + Duration::from_secs(133));
        assert!(limiter.allow(ip(2), start + Duration::from_secs(133)));
    }

    fn loopback() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (listener.accept().unwrap().0, client)
    }

    #[test]
    fn an_unproved_connection_is_closed_at_the_deadline() {
        let (server, mut client) = loopback();
        let _guard = close_after(server.try_clone().unwrap(), Duration::from_millis(200));
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let started = Instant::now();
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0, "the server side closed");
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn a_dropped_guard_leaves_the_connection_open() {
        let (server, mut client) = loopback();
        drop(close_after(server.try_clone().unwrap(), Duration::from_millis(200)));
        thread::sleep(Duration::from_millis(400));
        client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let error = client.read(&mut [0; 1]).unwrap_err();
        assert!(matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
    }
}
