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

/// Turns away an address whose connections keep failing the membership proof.
pub(crate) struct PreAuthLimiter {
    max_failures: usize,
    window: Duration,
    block: Duration,
    failures: HashMap<IpAddr, Vec<Instant>>,
    blocked_until: HashMap<IpAddr, Instant>,
}

impl Default for PreAuthLimiter {
    fn default() -> Self { Self::new(5, Duration::from_secs(120), Duration::from_secs(120)) }
}

impl PreAuthLimiter {
    pub(crate) fn new(max_failures: usize, window: Duration, block: Duration) -> Self {
        Self { max_failures, window, block, failures: HashMap::new(), blocked_until: HashMap::new() }
    }

    /// False while `source` is turned away. The caller then closes the connection without a reply.
    pub(crate) fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        match self.blocked_until.get(&source) {
            Some(until) if now < *until => false,
            Some(_) => { self.blocked_until.remove(&source); true }
            None => true,
        }
    }

    /// Records how a connection from `source` ended. A proved connection clears its failures.
    pub(crate) fn finish(&mut self, source: IpAddr, proved: bool, now: Instant) {
        if proved { self.failures.remove(&source); return; }
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
