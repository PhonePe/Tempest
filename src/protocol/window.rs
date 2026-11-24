// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

/// Server retransmission timing for one TFTP transfer.
///
/// An adaptive policy starts conservatively, then uses unambiguous RTT samples
/// within explicit lower and upper bounds. A fixed policy is used when the peer
/// negotiates RFC 2349 `timeout`, because Tempest must not retransmit earlier
/// than the interval it acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmissionPolicy {
    initial_rto: Duration,
    min_rto: Duration,
    max_rto: Duration,
    adaptive: bool,
}

impl RetransmissionPolicy {
    /// Create a bounded adaptive policy.
    pub fn adaptive(initial_rto: Duration, min_rto: Duration, max_rto: Duration) -> Self {
        let min_rto = min_rto.max(Duration::from_millis(1));
        let max_rto = max_rto.max(min_rto);
        Self {
            initial_rto: initial_rto.clamp(min_rto, max_rto),
            min_rto,
            max_rto,
            adaptive: true,
        }
    }

    /// Create a fixed policy for an explicitly negotiated RFC 2349 timeout.
    pub fn fixed(timeout: Duration) -> Self {
        let timeout = timeout.max(Duration::from_millis(1));
        Self {
            initial_rto: timeout,
            min_rto: timeout,
            max_rto: timeout,
            adaptive: false,
        }
    }

    /// Return the initial retransmission timeout.
    pub fn initial_rto(self) -> Duration {
        self.initial_rto
    }

    /// Return the smallest adaptive retransmission timeout.
    pub fn min_rto(self) -> Duration {
        self.min_rto
    }

    /// Return the largest adaptive retransmission timeout.
    pub fn max_rto(self) -> Duration {
        self.max_rto
    }

    /// Return whether valid RTT samples may adjust the timeout.
    pub fn is_adaptive(self) -> bool {
        self.adaptive
    }

    /// Return the timeout for a zero-based retry attempt before RTT sampling.
    pub fn retry_rto(self, retry: u8) -> Duration {
        if !self.adaptive {
            return self.initial_rto;
        }
        let mut timeout = self.initial_rto;
        for _ in 0..retry {
            let next = timeout.saturating_mul(2).min(self.max_rto);
            if next == timeout {
                break;
            }
            timeout = next;
        }
        timeout
    }
}

/// Implements RFC 7440 windowed transfer with ACK processing
pub struct WindowState {
    /// Negotiated window size
    window_size: u16,
    /// Current window start (first unacknowledged block)
    window_start: u16,
    /// Next block to send
    next_block: u16,
    /// Absolute 1-based window start, used for file offsets across u16 wire wrap.
    absolute_window_start: u64,
    /// Absolute 1-based next block, used for file offsets across u16 wire wrap.
    absolute_next_block: u64,
    /// Total blocks sent in current window
    blocks_in_flight: u16,
    /// Timestamp of last ACK received
    last_ack_time: Instant,
    /// Retransmission timeout
    rto: Duration,
    /// Smoothed RTT for adaptive RTO (microseconds)
    srtt_us: f64,
    /// RTT variance for adaptive RTO (microseconds)
    rttvar_us: f64,
    /// Configured RTO floor
    min_rto: Duration,
    /// Maximum RTO
    max_rto: Duration,
    /// Whether unambiguous RTT samples may update the current RTO.
    adaptive_rto: bool,
    /// Number of retransmissions for current window
    retransmit_count: u8,
    /// Maximum retries allowed
    max_retries: u8,
    /// Whether the current window can provide an unambiguous RTT sample.
    rtt_sample_valid: bool,
}

impl WindowState {
    /// Creates a window with size clamped to `1..=64` and an adaptive RTO.
    ///
    /// `timeout` is both the initial RTO and the adaptive floor.
    /// `max_retries` is the number of retransmissions allowed before
    /// [`TimeoutAction::Abort`].
    pub fn new(window_size: u16, timeout: Duration, max_retries: u8) -> Self {
        Self::with_policy(
            window_size,
            RetransmissionPolicy::adaptive(timeout, timeout, timeout.saturating_mul(2)),
            max_retries,
        )
    }

    /// Creates a window using an explicit retransmission policy.
    pub fn with_policy(window_size: u16, policy: RetransmissionPolicy, max_retries: u8) -> Self {
        let window_size = window_size.clamp(1, 64);
        Self {
            window_size,
            window_start: 1,
            next_block: 1,
            absolute_window_start: 1,
            absolute_next_block: 1,
            blocks_in_flight: 0,
            last_ack_time: Instant::now(),
            rto: policy.initial_rto,
            srtt_us: 0.0,
            rttvar_us: 0.0,
            min_rto: policy.min_rto,
            max_rto: policy.max_rto,
            adaptive_rto: policy.adaptive,
            retransmit_count: 0,
            max_retries,
            rtt_sample_valid: false,
        }
    }

    /// Return whether another DATA block fits in the current window.
    #[inline]
    pub fn can_send(&self) -> bool {
        self.blocks_in_flight < self.window_size
    }

    /// Returns the number of DATA packets that still fit in this window.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        usize::from(self.window_size.saturating_sub(self.blocks_in_flight))
    }

    /// Record one sent block and advance the next wire block number.
    #[inline]
    pub fn block_sent(&mut self) {
        if self.blocks_in_flight == 0 {
            self.last_ack_time = Instant::now();
            self.rtt_sample_valid = self.retransmit_count == 0;
        }
        self.next_block = self.next_block.wrapping_add(1);
        self.absolute_next_block = self.absolute_next_block.saturating_add(1);
        self.blocks_in_flight = self.blocks_in_flight.saturating_add(1);
    }

    /// Advance over an extension-owned block that requires no DATA or ACK.
    ///
    /// Skipping is valid only when no earlier DATA packet is awaiting an ACK;
    /// sparse resume implementations should therefore negotiate a window of
    /// one. Returns `false` without mutating state when DATA is in flight.
    pub fn block_skipped(&mut self) -> bool {
        if self.blocks_in_flight != 0 || self.next_block != self.window_start {
            return false;
        }
        self.next_block = self.next_block.wrapping_add(1);
        self.window_start = self.next_block;
        self.absolute_next_block = self.absolute_next_block.saturating_add(1);
        self.absolute_window_start = self.absolute_next_block;
        true
    }

    /// Process an incoming ACK, returns true if the window advanced
    #[inline]
    pub fn process_ack(&mut self, ack_block: u16) -> WindowAdvance {
        self.process_ack_at(ack_block, Instant::now())
    }

    #[inline]
    fn process_ack_at(&mut self, ack_block: u16, now: Instant) -> WindowAdvance {
        // Combine is_valid_ack + block_ge into a single range check.
        // An ACK is valid if it falls within [window_start, window_start + blocks_in_flight).
        let in_window = self.block_ge(ack_block, self.window_start)
            && self.block_ge(
                self.window_start
                    .wrapping_add(self.blocks_in_flight)
                    .wrapping_sub(1),
                ack_block,
            );
        if !in_window {
            return WindowAdvance::Duplicate;
        }

        // Karn's algorithm excludes ACKs for retransmitted data because their
        // RTT cannot be attributed to a particular send attempt.
        if self.adaptive_rto && self.rtt_sample_valid {
            let rtt_us = now
                .saturating_duration_since(self.last_ack_time)
                .as_micros() as f64;
            if self.srtt_us == 0.0 {
                self.srtt_us = rtt_us;
                self.rttvar_us = rtt_us / 2.0;
            } else {
                // RFC 6298 algorithm
                self.rttvar_us = 0.75 * self.rttvar_us + 0.25 * (self.srtt_us - rtt_us).abs();
                self.srtt_us = 0.875 * self.srtt_us + 0.125 * rtt_us;
            }
            let rto_us = self.srtt_us + 4.0 * self.rttvar_us;
            self.rto = Duration::from_micros(rto_us as u64)
                .max(self.min_rto)
                .min(self.max_rto);
        }

        if ack_block
            == self
                .window_start
                .wrapping_add(self.blocks_in_flight)
                .wrapping_sub(1)
        {
            // Full window acknowledged
            let acked_count = self.blocks_in_flight;
            self.window_start = ack_block.wrapping_add(1);
            self.absolute_window_start = self
                .absolute_window_start
                .saturating_add(acked_count as u64);
            self.next_block = self.window_start;
            self.absolute_next_block = self.absolute_window_start;
            self.blocks_in_flight = 0;
            self.retransmit_count = 0;
            self.last_ack_time = now;
            WindowAdvance::FullWindow { acked: acked_count }
        } else if self.block_ge(ack_block, self.window_start) {
            // Partial window ACK — slide window forward
            let acked = ack_block.wrapping_sub(self.window_start).wrapping_add(1);
            self.blocks_in_flight = self.blocks_in_flight.saturating_sub(acked);
            self.window_start = ack_block.wrapping_add(1);
            self.absolute_window_start = self.absolute_window_start.saturating_add(acked as u64);
            self.retransmit_count = 0;
            self.last_ack_time = now;
            WindowAdvance::Partial { acked }
        } else {
            WindowAdvance::Duplicate
        }
    }

    /// Return whether the current retransmission deadline has elapsed.
    pub fn is_timed_out(&self) -> bool {
        self.last_ack_time.elapsed() > self.rto
    }

    /// Advance timeout state and choose retransmission or abort.
    pub fn handle_timeout(&mut self) -> TimeoutAction {
        if self.retransmit_count >= self.max_retries {
            return TimeoutAction::Abort;
        }
        self.retransmit_count = self.retransmit_count.saturating_add(1);
        self.rtt_sample_valid = false;
        if self.adaptive_rto {
            self.rto = self.rto.saturating_mul(2).min(self.max_rto);
        }
        // Retransmission resumes at the first unacknowledged absolute block.
        self.next_block = self.window_start;
        self.absolute_next_block = self.absolute_window_start;
        self.blocks_in_flight = 0;
        self.last_ack_time = Instant::now();
        TimeoutAction::Retransmit {
            from_block: self.window_start,
            from_block_index: self.absolute_window_start,
        }
    }

    /// Returns the first unacknowledged 16-bit wire block number.
    pub fn window_start(&self) -> u16 {
        self.window_start
    }

    /// Returns the next 16-bit wire block number to send.
    pub fn next_block(&self) -> u16 {
        self.next_block
    }

    /// Returns the absolute one-based next block index across wire wraparound.
    pub fn next_block_index(&self) -> u64 {
        self.absolute_next_block
    }

    /// Returns the absolute one-based first unacknowledged block index.
    pub fn window_start_index(&self) -> u64 {
        self.absolute_window_start
    }

    /// Returns the current RFC 6298-derived retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Compare block numbers accounting for u16 wraparound
    #[inline]
    fn block_ge(&self, a: u16, b: u16) -> bool {
        let diff = a.wrapping_sub(b);
        diff < 32768
    }

    /// Returns whether an ACK belongs to the current in-flight window.
    #[cfg(test)]
    #[inline]
    fn is_valid_ack(&self, ack_block: u16) -> bool {
        self.block_ge(ack_block, self.window_start)
            && self.block_ge(
                self.window_start
                    .wrapping_add(self.blocks_in_flight)
                    .wrapping_sub(1),
                ack_block,
            )
    }
}

/// Result of applying an ACK to the current send window.
#[derive(Debug)]
pub enum WindowAdvance {
    /// The ACK covered every in-flight block.
    FullWindow {
        /// Number of newly acknowledged blocks.
        acked: u16,
    },
    /// The ACK advanced only part of the current window.
    Partial {
        /// Number of newly acknowledged blocks.
        acked: u16,
    },
    /// The ACK was outside the current in-flight range and changed no state.
    Duplicate,
}

/// Action selected when the retransmission timer expires.
#[derive(Debug)]
pub enum TimeoutAction {
    /// Rewind and resend the current unacknowledged window.
    Retransmit {
        /// First 16-bit wire block to resend.
        from_block: u16,
        /// Absolute one-based block index used for the file offset.
        from_block_index: u64,
    },
    /// Stop because the configured retry budget is exhausted.
    Abort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_basic_flow() {
        let mut ws = WindowState::new(4, Duration::from_secs(5), 3);
        assert!(ws.can_send());

        for _ in 0..4 {
            assert!(ws.can_send());
            ws.block_sent();
        }
        assert!(!ws.can_send());

        // ACK all 4 blocks
        let result = ws.process_ack(4);
        assert!(matches!(result, WindowAdvance::FullWindow { acked: 4 }));
        assert!(ws.can_send());
        assert_eq!(ws.window_start(), 5);
    }

    #[test]
    fn test_block_skipped_advances_only_without_inflight_data() {
        let mut state = WindowState::new(1, Duration::from_secs(1), 3);
        assert!(state.block_skipped());
        assert_eq!(state.next_block(), 2);
        assert_eq!(state.next_block_index(), 2);
        assert_eq!(state.window_start(), 2);

        state.block_sent();
        assert!(!state.block_skipped());
        assert_eq!(state.next_block(), 3);
        assert_eq!(state.window_start(), 2);
    }

    #[test]
    fn test_window_partial_ack() {
        let mut ws = WindowState::new(4, Duration::from_secs(5), 3);
        for _ in 0..4 {
            ws.block_sent();
        }

        let result = ws.process_ack(2);
        assert!(matches!(result, WindowAdvance::Partial { acked: 2 }));
        assert_eq!(ws.window_start(), 3);
    }

    #[test]
    fn test_adaptive_rto_updates() {
        let mut ws = WindowState::new(4, Duration::from_secs(5), 3);
        for _ in 0..4 {
            ws.block_sent();
        }

        assert_eq!(ws.rto(), Duration::from_secs(5));

        std::thread::sleep(Duration::from_millis(10));
        ws.process_ack(4);

        let rto = ws.rto();
        assert!(rto >= ws.min_rto);
        assert!(rto <= ws.max_rto);
    }

    #[test]
    fn test_adaptive_rto_respects_configured_floor() {
        let configured_floor = Duration::from_secs(2);
        let mut ws = WindowState::new(1, configured_floor, 3);
        ws.block_sent();

        // A fast LAN sample must not silently turn the operator's two-second
        // retransmission interval into an aggressive subsecond deadline.
        let sampled_at = ws.last_ack_time + Duration::from_millis(10);
        assert!(matches!(
            ws.process_ack_at(1, sampled_at),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert_eq!(ws.rto(), configured_floor);
        assert_eq!(ws.min_rto, configured_floor);
    }

    #[test]
    fn adaptive_policy_can_recover_below_its_initial_rto() {
        let policy = RetransmissionPolicy::adaptive(
            Duration::from_secs(1),
            Duration::from_millis(250),
            Duration::from_secs(4),
        );
        let mut window = WindowState::with_policy(8, policy, 3);
        window.block_sent();
        let sampled_at = window.last_ack_time + Duration::from_millis(10);

        assert!(matches!(
            window.process_ack_at(1, sampled_at),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert_eq!(window.rto(), Duration::from_millis(250));
    }

    #[test]
    fn negotiated_timeout_policy_remains_fixed() {
        let policy = RetransmissionPolicy::fixed(Duration::from_secs(2));
        let mut window = WindowState::with_policy(1, policy, 3);
        window.block_sent();
        window.last_ack_time = Instant::now() - Duration::from_millis(10);
        assert!(matches!(
            window.process_ack(1),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert_eq!(window.rto(), Duration::from_secs(2));

        window.block_sent();
        assert!(matches!(
            window.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert_eq!(window.rto(), Duration::from_secs(2));
    }

    #[test]
    fn retry_rto_is_bounded_and_fixed_when_negotiated() {
        let adaptive = RetransmissionPolicy::adaptive(
            Duration::from_millis(250),
            Duration::from_millis(100),
            Duration::from_secs(1),
        );
        assert_eq!(adaptive.retry_rto(0), Duration::from_millis(250));
        assert_eq!(adaptive.retry_rto(1), Duration::from_millis(500));
        assert_eq!(adaptive.retry_rto(8), Duration::from_secs(1));

        let fixed = RetransmissionPolicy::fixed(Duration::from_secs(3));
        assert_eq!(fixed.retry_rto(8), Duration::from_secs(3));
    }

    #[test]
    fn test_window_timeout_retransmit() {
        let mut ws = WindowState::new(4, Duration::from_secs(1), 3);
        for _ in 0..4 {
            ws.block_sent();
        }

        let action = ws.handle_timeout();
        assert!(matches!(
            action,
            TimeoutAction::Retransmit { from_block: 1, .. }
        ));
    }

    #[test]
    fn test_timeout_backoff_is_exponential_and_bounded() {
        let mut ws = WindowState::new(1, Duration::from_millis(200), 4);
        ws.max_rto = Duration::from_millis(800);
        ws.block_sent();

        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert_eq!(ws.rto(), Duration::from_millis(400));
        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert_eq!(ws.rto(), Duration::from_millis(800));
        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert_eq!(ws.rto(), Duration::from_millis(800));
    }

    #[test]
    fn test_retransmitted_ack_is_not_used_as_rtt_sample() {
        let mut ws = WindowState::new(1, Duration::from_millis(200), 2);
        ws.block_sent();
        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert_eq!(ws.rto(), Duration::from_millis(400));

        ws.block_sent();
        std::thread::sleep(Duration::from_millis(1));
        assert!(matches!(
            ws.process_ack(1),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert_eq!(ws.srtt_us, 0.0);
        assert_eq!(ws.rttvar_us, 0.0);
        assert_eq!(ws.rto(), Duration::from_millis(400));

        ws.block_sent();
        std::thread::sleep(Duration::from_millis(1));
        assert!(matches!(
            ws.process_ack(2),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert!(ws.srtt_us > 0.0);
        assert!(ws.rttvar_us > 0.0);
    }

    #[test]
    fn test_window_timeout_abort() {
        let mut ws = WindowState::new(4, Duration::from_secs(1), 2);
        for _ in 0..4 {
            ws.block_sent();
        }

        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));
        assert!(matches!(
            ws.handle_timeout(),
            TimeoutAction::Retransmit { .. }
        ));

        assert!(matches!(ws.handle_timeout(), TimeoutAction::Abort));
    }

    #[test]
    fn test_window_timeout_saturates_at_u8_max() {
        let mut ws = WindowState::new(4, Duration::from_secs(1), u8::MAX);
        ws.retransmit_count = u8::MAX;
        assert!(matches!(ws.handle_timeout(), TimeoutAction::Abort));
        assert_eq!(ws.retransmit_count, u8::MAX);
    }

    #[test]
    fn test_window_size_clamped_to_valid_range() {
        let mut min = WindowState::new(0, Duration::from_secs(1), 1);
        assert_eq!(min.window_size, 1);
        assert_eq!(min.remaining_capacity(), 1);
        min.block_sent();
        assert_eq!(min.remaining_capacity(), 0);
        let max = WindowState::new(u16::MAX, Duration::from_secs(1), 1);
        assert_eq!(max.window_size, 64);
        assert_eq!(max.remaining_capacity(), 64);
    }

    #[test]
    fn test_absolute_block_index_survives_wire_wrap() {
        let mut ws = WindowState::new(1, Duration::from_secs(1), 1);
        ws.window_start = u16::MAX;
        ws.next_block = u16::MAX;
        ws.absolute_window_start = u16::MAX as u64;
        ws.absolute_next_block = u16::MAX as u64;

        assert_eq!(ws.next_block(), u16::MAX);
        assert_eq!(ws.next_block_index(), 65_535);
        ws.block_sent();
        assert_eq!(ws.next_block(), 0);
        assert_eq!(ws.next_block_index(), 65_536);

        assert!(matches!(
            ws.process_ack(u16::MAX),
            WindowAdvance::FullWindow { acked: 1 }
        ));
        assert_eq!(ws.window_start(), 0);
        assert_eq!(ws.window_start_index(), 65_536);
        assert_eq!(ws.next_block(), 0);
        assert_eq!(ws.next_block_index(), 65_536);
    }

    #[test]
    fn test_timeout_reports_absolute_retransmit_index() {
        let mut ws = WindowState::new(1, Duration::from_secs(1), 2);
        ws.window_start = 0;
        ws.next_block = 1;
        ws.absolute_window_start = 65_536;
        ws.absolute_next_block = 65_537;
        ws.blocks_in_flight = 1;

        match ws.handle_timeout() {
            TimeoutAction::Retransmit {
                from_block,
                from_block_index,
            } => {
                assert_eq!(from_block, 0);
                assert_eq!(from_block_index, 65_536);
            }
            TimeoutAction::Abort => panic!("expected retransmit"),
        }
        assert_eq!(ws.next_block(), 0);
        assert_eq!(ws.next_block_index(), 65_536);
    }

    #[test]
    fn test_window_duplicate_ack() {
        let mut ws = WindowState::new(4, Duration::from_secs(5), 3);
        for _ in 0..4 {
            ws.block_sent();
        }

        // ACK block 2
        ws.process_ack(2);
        // ACK block 1 (now behind window_start=3 -> duplicate)
        let result = ws.process_ack(1);
        assert!(matches!(result, WindowAdvance::Duplicate));
    }

    #[test]
    fn test_can_send_stops_at_window_boundary() {
        let mut ws = WindowState::new(1, Duration::from_secs(5), 3);
        assert!(ws.can_send());
        ws.block_sent();
        assert!(!ws.can_send()); // window of 1,after sending 1 block
    }

    #[test]
    fn test_block_order_handles_wraparound() {
        let ws = WindowState::new(4, Duration::from_secs(5), 3);
        assert!(ws.block_ge(1, 1)); // equal
        assert!(ws.block_ge(65535, 65534)); // near max
        assert!(ws.block_ge(0, 65535)); // wraparound: 0 is "after" 65535
    }

    #[test]
    fn test_is_valid_ack_empty_window() {
        let ws = WindowState::new(4, Duration::from_secs(5), 3);
        // No blocks sent yet, no valid ACK
        assert!(!ws.is_valid_ack(1));
    }
}
