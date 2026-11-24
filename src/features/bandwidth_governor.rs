// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

/// Idle time can accumulate at most this many refill ticks of burst credit.
const MAX_BURST_MULTIPLIER: u64 = 10;

/// Global bandwidth governor using a token-bucket algorithm.
///
/// Callers acquire byte permits before sending. A finite burst cap limits idle
/// credit, while ten-millisecond refill and remainder accounting preserve the
/// configured long-run rate. The semaphore retains FIFO waiter ordering.
pub struct BandwidthGovernor {
    /// Available byte permits with FIFO waiter ordering.
    tokens: Semaphore,
    /// Configured rate in bytes per second.
    rate_bps: u64,
    /// Maximum tokens that can accumulate (burst cap).
    burst_cap: u64,
    /// Whole tokens added per 10ms refill tick.
    refill_per_tick: u64,
    /// Fractional hundredths of one token carried between refills.
    refill_remainder: AtomicU64,
    /// Whether the governor is enabled.
    enabled: AtomicBool,
    /// Parked or acquiring tasks; immediate grants must not bypass them.
    waiters: AtomicUsize,
}

impl BandwidthGovernor {
    /// Create a governor for `rate_bps` bytes per second.
    ///
    /// # Panics
    /// Panics if `rate_bps` is 0 (callers must validate at config parse time).
    pub fn new(rate_bps: u64, enabled: bool) -> Self {
        assert!(rate_bps > 0, "BandwidthGovernor: rate_bps must be > 0");

        // Ten-millisecond ticks avoid timer churn. Remainder accounting keeps
        // rates below 100 B/s accurate without manufacturing a token per tick.
        let refill_per_tick = rate_bps / 100;
        // Idle credit is limited to MAX_BURST_MULTIPLIER refill ticks.
        let burst_cap = rate_bps
            .div_ceil(100)
            .saturating_mul(MAX_BURST_MULTIPLIER)
            .clamp(1, u64::from(u32::MAX));

        Self {
            tokens: Semaphore::new(burst_cap as usize),
            rate_bps,
            burst_cap,
            refill_per_tick,
            refill_remainder: AtomicU64::new(0),
            enabled: AtomicBool::new(enabled),
            waiters: AtomicUsize::new(0),
        }
    }

    /// Acquire `n_bytes`, waiting for refill unless the governor is disabled.
    pub async fn acquire(&self, n_bytes: usize) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let mut remaining = n_bytes as u64;
        while remaining > 0 {
            let needed = remaining.min(self.burst_cap);
            self.acquire_chunk(needed).await;
            remaining = remaining.saturating_sub(needed);
        }
    }

    /// Consumes a burst-sized grant without allocating or parking a waiter.
    pub fn try_acquire(&self, n_bytes: usize) -> bool {
        if !self.enabled.load(Ordering::Relaxed) || n_bytes == 0 {
            return true;
        }
        if self.waiters.load(Ordering::Acquire) != 0 {
            return false;
        }
        let Ok(needed) = u32::try_from(n_bytes) else {
            return false;
        };
        if u64::from(needed) > self.burst_cap {
            return false;
        }
        let Ok(permit) = self.tokens.try_acquire_many(needed) else {
            return false;
        };
        permit.forget();
        true
    }

    /// Acquires one burst-bounded token chunk, waiting for refill when needed.
    async fn acquire_chunk(&self, needed: u64) {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        let _waiter = WaiterGuard(&self.waiters);
        if let Ok(permit) = self.tokens.acquire_many(needed as u32).await {
            // Consumed bandwidth is not returned when the guard is dropped.
            permit.forget();
        }
    }

    /// Refill tokens without allowing idle credit to exceed the burst cap.
    fn refill(&self) {
        let remainder = self.refill_remainder.load(Ordering::Relaxed);
        let fractional = remainder.saturating_add(self.rate_bps % 100);
        let add = self.refill_per_tick.saturating_add(fractional / 100);
        self.refill_remainder
            .store(fractional % 100, Ordering::Relaxed);
        let available = self.tokens.available_permits() as u64;
        let add = add.min(self.burst_cap.saturating_sub(available));
        if add > 0 {
            self.tokens.add_permits(add as usize);
        }
    }

    /// Returns the configured rate in bytes per second.
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// Returns the current available tokens (for metrics/debugging).
    pub fn available_tokens(&self) -> u64 {
        self.tokens.available_permits() as u64
    }

    /// Returns the burst cap.
    pub fn burst_cap(&self) -> u64 {
        self.burst_cap
    }

    /// Check if the governor is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

struct WaiterGuard<'a>(&'a AtomicUsize);

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Spawn the background refill task. Returns a handle that can be used to abort it.
/// The task adds tokens every 10ms at the configured rate.
pub fn spawn_refill_task(governor: Arc<BandwidthGovernor>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if governor.is_enabled() {
                governor.refill();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_governor_creation() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        assert_eq!(gov.rate_bps(), 1_000_000);
        assert!(gov.is_enabled());
        assert!(gov.burst_cap() > 0);
        assert!(gov.available_tokens() > 0);
    }

    #[test]
    #[should_panic(expected = "rate_bps must be > 0")]
    fn test_zero_rate_panics() {
        let _gov = BandwidthGovernor::new(0, true);
    }

    #[tokio::test]
    async fn test_disabled_governor_returns_immediately() {
        let gov = BandwidthGovernor::new(1, false);
        // Completing on the first poll proves no wait, independent of host load.
        let mut acquire = tokio_test::task::spawn(gov.acquire(1_000_000));
        assert!(acquire.poll().is_ready());
    }

    #[tokio::test]
    async fn test_acquire_consumes_tokens() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        let initial = gov.available_tokens();
        gov.acquire(100).await;
        let after = gov.available_tokens();
        assert!(after < initial, "Tokens should decrease after acquire");
    }

    #[test]
    fn immediate_grant_consumes_tokens_without_waiting() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        let initial = gov.available_tokens();
        assert!(gov.try_acquire(100));
        assert_eq!(gov.available_tokens(), initial - 100);
        assert!(!gov.try_acquire(gov.burst_cap() as usize + 1));
    }

    #[tokio::test]
    async fn test_refill_adds_tokens() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        let cap = gov.burst_cap();
        gov.acquire(cap as usize).await;
        let after_drain = gov.available_tokens();
        assert_eq!(after_drain, 0);

        gov.refill();
        let after_refill = gov.available_tokens();
        assert!(after_refill > 0, "Tokens should increase after refill");
        assert_eq!(after_refill, gov.refill_per_tick);
    }

    #[tokio::test]
    async fn test_burst_cap_prevents_unbounded_accumulation() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        let cap = gov.burst_cap();
        for _ in 0..1000 {
            gov.refill();
        }
        assert!(
            gov.available_tokens() <= cap,
            "Tokens {} exceeded burst cap {}",
            gov.available_tokens(),
            cap
        );
    }

    #[tokio::test]
    async fn test_acquire_blocks_until_tokens_available() {
        let gov = BandwidthGovernor::new(1_000_000, true);
        let cap = gov.burst_cap();
        gov.acquire(cap as usize).await;

        let mut acquire = tokio_test::task::spawn(gov.acquire(100));
        assert!(acquire.poll().is_pending());
        assert!(acquire.poll().is_pending());

        gov.refill();
        assert!(acquire.is_woken());
        assert!(acquire.poll().is_ready());
    }

    // Paused time makes refill ticks deterministic under host load.
    #[tokio::test(start_paused = true)]
    async fn test_acquire_larger_than_burst_cap_completes() {
        let gov = Arc::new(BandwidthGovernor::new(200_000, true));
        let request = gov.burst_cap() + 1;
        let refill_handle = spawn_refill_task(gov.clone());

        let result =
            tokio::time::timeout(Duration::from_secs(1), gov.acquire(request as usize)).await;

        refill_handle.abort();
        assert!(
            result.is_ok(),
            "acquire should complete even when request exceeds burst cap"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_concurrent_acquirers_bounded_by_ceiling() {
        let gov = Arc::new(BandwidthGovernor::new(10_000_000, true)); // 10 MB/s
        let refill_handle = spawn_refill_task(gov.clone());

        let mut handles = Vec::new();

        for _ in 0..10 {
            let g = gov.clone();
            handles.push(tokio::spawn(async move {
                g.acquire(1_000).await;
            }));
        }

        // Paused time: this bound is in virtual refill time, not host scheduling.
        tokio::time::timeout(Duration::from_secs(5), async {
            for h in handles {
                h.await.unwrap();
            }
        })
        .await
        .expect("concurrent acquirers exceeded the virtual-time ceiling");

        refill_handle.abort();
    }

    // Paused time runs every refill tick; a starved real-time interval skips
    // missed ticks and under-refills.
    #[tokio::test(start_paused = true)]
    async fn test_refill_rate_matches_configured_bps() {
        let rate_bps: u64 = 500_000;
        let gov = Arc::new(BandwidthGovernor::new(rate_bps, true));

        gov.acquire(gov.burst_cap() as usize).await;

        let refill_handle = spawn_refill_task(gov.clone());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tokens = gov.available_tokens();
        let expected_raw = rate_bps / 1000 * 100;
        let expected = expected_raw.min(gov.burst_cap());

        let lower = (expected as f64 * 0.7) as u64;
        let upper = gov.burst_cap();
        assert!(
            tokens >= lower && tokens <= upper,
            "tokens={tokens}, expected ~{expected} (range [{lower}, {upper}])",
        );

        refill_handle.abort();
    }

    #[test]
    fn test_large_acquire_no_overflow() {
        let gov = BandwidthGovernor::new(u64::MAX / 2, true);
        assert!(gov.burst_cap() > 0);
        assert!(gov.rate_bps() > 0);
    }
}
