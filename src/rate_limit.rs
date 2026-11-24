// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::warn;

/// Fixed-window per-IP limiter shared by the TFTP and HTTP ingress paths.
pub struct PerIpRateLimiter {
    /// Map of IP -> (window_start, request_count)
    counters: DashMap<std::net::IpAddr, (Instant, u32)>,
    /// One candidate per tracked address; hot counter updates never take this lock.
    expiry_candidates: Mutex<VecDeque<std::net::IpAddr>>,
    /// Maximum requests per IP per second
    max_per_sec: u32,
    /// Label for log messages (e.g. "TFTP", "API")
    label: &'static str,
    /// Hard cardinality bound for addresses controlled by remote traffic.
    max_entries: usize,
    /// Exact number of entries for which insertion capacity is reserved.
    tracked_entries: AtomicUsize,
    /// Total requests rejected by this limiter (for Prometheus exposure)
    rejected_total: AtomicU64,
}

impl PerIpRateLimiter {
    /// Creates a one-second per-IP limiter with at most 100,000 tracked IPs.
    ///
    /// `label` is retained for security log attribution and must have static lifetime.
    pub fn new(max_per_sec: u32, label: &'static str) -> Self {
        Self::with_max_entries(max_per_sec, label, 100_000)
    }

    fn with_max_entries(max_per_sec: u32, label: &'static str, max_entries: usize) -> Self {
        Self {
            counters: DashMap::new(),
            expiry_candidates: Mutex::new(VecDeque::new()),
            max_per_sec,
            label,
            max_entries,
            tracked_entries: AtomicUsize::new(0),
            rejected_total: AtomicU64::new(0),
        }
    }

    /// Returns true if the request should be allowed.
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    pub(crate) fn check_at(&self, ip: std::net::IpAddr, now: Instant) -> bool {
        // Zero is an explicit operator opt-out for trusted benchmark networks.
        // The secure default remains enabled and no address state is retained.
        if self.max_per_sec == 0 {
            return true;
        }
        if let Some(mut entry) = self.counters.get_mut(&ip) {
            return self.update_counter(ip, &mut entry, now);
        }

        if self.tracked_entries.load(Ordering::Acquire) >= self.max_entries {
            self.reclaim_expired(64, now);
        }
        #[allow(
            deprecated,
            reason = "try_update requires Rust 1.95; retain fetch_update for MSRV 1.85"
        )]
        let reservation =
            self.tracked_entries
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < self.max_entries).then_some(current + 1)
                });
        if reservation.is_err() {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let mut inserted = false;
        let mut entry = match self.counters.entry(ip) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                self.tracked_entries.fetch_sub(1, Ordering::AcqRel);
                entry.into_ref()
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                inserted = true;
                entry.insert((now, 0))
            }
        };
        let allowed = self.update_counter(ip, &mut entry, now);
        drop(entry); // Reclamation takes the queue lock before a map shard.
        if inserted {
            self.expiry_candidates.lock().push_back(ip);
        }
        allowed
    }

    fn update_counter(
        &self,
        ip: std::net::IpAddr,
        entry: &mut (Instant, u32),
        now: Instant,
    ) -> bool {
        if now.saturating_duration_since(entry.0) >= Duration::from_secs(1) {
            entry.0 = now;
            entry.1 = 1;
            true
        } else {
            entry.1 = entry.1.saturating_add(1);
            if self.max_per_sec < u32::MAX && entry.1 == self.max_per_sec + 1 {
                warn!(client_ip = %ip, layer = self.label, "Rate limit exceeded — sustained abuse detected");
            }
            let allowed = entry.1 <= self.max_per_sec;
            if !allowed {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
            }
            allowed
        }
    }

    /// Total requests rejected by this limiter since startup.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }

    /// Reclaims expired one-second windows, subject to the maintenance threshold.
    pub fn cleanup_stale(&self, threshold: usize) {
        self.cleanup_stale_at(threshold, Instant::now());
    }

    fn cleanup_stale_at(&self, threshold: usize, now: Instant) {
        if self.tracked_entries.load(Ordering::Acquire) >= threshold {
            // Release the insertion queue lock between bounded maintenance
            // batches instead of holding it across a full-capacity map.
            let candidates = self.tracked_entries.load(Ordering::Acquire);
            for _ in (0..candidates).step_by(64) {
                self.reclaim_expired(64, now);
            }
        }
    }

    fn reclaim_expired(&self, maximum: usize, now: Instant) {
        // Never queue ingress behind another reclamation pass or scan the full
        // map at capacity. Rotating live candidates makes subsequent scans advance.
        let Some(mut candidates) = self.expiry_candidates.try_lock() else {
            return;
        };
        let cutoff = now - Duration::from_secs(1);
        for _ in 0..maximum.min(candidates.len()) {
            let ip = candidates.pop_front().unwrap();
            if self
                .counters
                .remove_if(&ip, |_, value| value.0 <= cutoff)
                .is_some()
            {
                self.tracked_entries.fetch_sub(1, Ordering::AcqRel);
            } else {
                candidates.push_back(ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn capacity_reclaims_expired_windows_without_resetting_live_quotas() {
        let now = Instant::now();
        let limiter = PerIpRateLimiter::with_max_entries(1, "test", 2);
        let old = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let new = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        assert!(limiter.check_at(old, now));
        assert!(limiter.check_at(live, now));
        assert!(!limiter.check_at(new, now));
        limiter.counters.get_mut(&old).unwrap().0 = now - Duration::from_secs(2);
        assert!(limiter.check_at(new, now));
        assert!(!limiter.check_at(live, now));
        assert_eq!(limiter.counters.len(), 2);
        assert_eq!(limiter.expiry_candidates.lock().len(), 2);
        assert_eq!(limiter.tracked_entries.load(Ordering::Acquire), 2);
    }

    #[test]
    fn capacity_reclamation_rotates_live_candidates_and_bounds_work() {
        let now = Instant::now();
        let limiter = PerIpRateLimiter::with_max_entries(1, "test", 128);
        for suffix in 0..128 {
            assert!(limiter.check_at(Ipv4Addr::new(192, 0, 2, suffix).into(), now));
        }
        let old = Ipv4Addr::new(192, 0, 2, 127).into();
        limiter.counters.get_mut(&old).unwrap().0 = now - Duration::from_secs(2);
        let new = Ipv4Addr::new(192, 0, 2, 128).into();
        assert!(!limiter.check_at(new, now));
        assert!(limiter.check_at(new, now));
        for suffix in 0..127 {
            assert!(!limiter.check_at(Ipv4Addr::new(192, 0, 2, suffix).into(), now));
        }
        assert_eq!(limiter.expiry_candidates.lock().len(), 128);
    }

    #[test]
    fn test_allows_under_limit() {
        let rl = PerIpRateLimiter::new(5, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..5 {
            assert!(rl.check(ip));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::new(2, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(rl.check_at(ip, now));
        assert!(rl.check_at(ip, now));
        assert!(!rl.check_at(ip, now));
    }

    #[test]
    fn zero_disables_limiting_without_tracking_addresses() {
        let rl = PerIpRateLimiter::new(0, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..10_000 {
            assert!(rl.check(ip));
        }
        assert!(rl.counters.is_empty());
        assert_eq!(rl.tracked_entries.load(Ordering::Acquire), 0);
        assert_eq!(rl.rejected_count(), 0);
    }

    #[test]
    fn test_cleanup_stale_skips_small() {
        let rl = PerIpRateLimiter::new(10, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        rl.check(ip);
        rl.cleanup_stale(100);
        assert_eq!(rl.counters.len(), 1);
    }

    #[test]
    fn test_rate_limiter_bounded_entries() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::with_max_entries(1000, "test", 32);
        for suffix in 0..32 {
            assert!(rl.check_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, suffix)), now));
        }
        assert!(!rl.check_at(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), now));
        assert_eq!(rl.tracked_entries.load(Ordering::Acquire), 32);
        assert_eq!(rl.counters.len(), 32);
    }

    #[test]
    fn concurrent_new_ips_cannot_exceed_capacity() {
        use std::sync::{Arc, Barrier};

        let now = Instant::now();
        let limiter = Arc::new(PerIpRateLimiter::with_max_entries(1000, "test", 64));
        let barrier = Arc::new(Barrier::new(256));
        let handles: Vec<_> = (0..256u16)
            .map(|suffix| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let octets = suffix.to_be_bytes();
                    limiter.check_at(IpAddr::V4(Ipv4Addr::new(10, 1, octets[0], octets[1])), now)
                })
            })
            .collect();
        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|admitted| *admitted)
            .count();

        assert_eq!(admitted, 64);
        assert_eq!(limiter.tracked_entries.load(Ordering::Acquire), 64);
        assert_eq!(limiter.counters.len(), 64);
    }

    #[test]
    fn test_rate_limiter_blocks_after_quota_exhausted() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::new(1, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(rl.check_at(ip, now));
        assert!(!rl.check_at(ip, now));
    }

    #[test]
    fn test_rate_limiter_per_ip_isolation() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::new(2, "test");
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.check_at(ip1, now));
        assert!(rl.check_at(ip1, now));
        assert!(!rl.check_at(ip1, now));
        assert!(rl.check_at(ip2, now));
        assert!(rl.check_at(ip2, now));
        assert!(!rl.check_at(ip2, now));
    }

    #[test]
    fn test_rate_limiter_rejected_count() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::new(1, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(rl.rejected_count(), 0);
        assert!(rl.check_at(ip, now));
        assert!(!rl.check_at(ip, now));
        assert_eq!(rl.rejected_count(), 1);
        assert!(!rl.check_at(ip, now));
        assert_eq!(rl.rejected_count(), 2);
    }

    #[test]
    fn test_rate_limiter_counter_saturates_under_sustained_abuse() {
        let rl = PerIpRateLimiter::new(10, "test");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let now = Instant::now();
        rl.counters.insert(ip, (now, u32::MAX - 1));

        assert!(!rl.check_at(ip, now));
        assert_eq!(rl.counters.get(&ip).unwrap().1, u32::MAX);
        assert!(!rl.check_at(ip, now));
        assert_eq!(rl.counters.get(&ip).unwrap().1, u32::MAX);
    }

    #[test]
    fn test_rate_limiter_rejects_at_max_entries() {
        // An injected small cap exercises the production capacity branch cheaply.
        let now = Instant::now();
        let rl_small = PerIpRateLimiter::with_max_entries(1000, "test", 3);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

        assert!(rl_small.check_at(ip1, now));
        assert!(rl_small.check_at(ip2, now));
        assert!(rl_small.check_at(ip3, now));
        assert!(!rl_small.check_at(ip4, now));
        assert_eq!(rl_small.rejected_count(), 1);
        assert!(rl_small.check_at(ip1, now));
    }

    #[test]
    fn test_rate_limiter_cleanup_removes_old() {
        let now = Instant::now();
        let rl = PerIpRateLimiter::new(100, "test");
        for i in 0..10u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            rl.check_at(ip, now);
        }
        assert_eq!(rl.counters.len(), 10);
        rl.cleanup_stale_at(5, now);
        assert_eq!(rl.counters.len(), 10);
        rl.cleanup_stale_at(5, now + Duration::from_secs(1));
        assert!(rl.counters.is_empty());
    }
}
