// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::protocol::window::RetransmissionPolicy;

/// Negotiated TFTP options from RFC 2347/2348/2349/7440.
#[derive(Debug, Clone)]
pub struct NegotiatedOptions {
    /// Block size (RFC 2348): 8–65464
    pub block_size: u16,
    /// Window size (RFC 7440): 1–65535
    pub window_size: u16,
    /// Timeout in seconds (RFC 2349)
    pub timeout: u8,
    /// Whether the peer explicitly requested `timeout`, controlling OACK emission.
    pub timeout_requested: bool,
    /// Fixed negotiated or bounded internal server retransmission policy.
    pub retransmission_policy: RetransmissionPolicy,
    /// Maximum timeout retransmissions before the transfer is aborted.
    pub max_retries: u8,
    /// Transfer size (RFC 2349)
    pub transfer_size: Option<u64>,
}

/// TFTP request direction used to interpret the RFC 2349 `tsize` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionRequestKind {
    /// A read request, for which only `tsize=0` is a valid size query.
    Read,
    /// A write request, for which `tsize` declares upload bytes.
    Write,
}

impl Default for NegotiatedOptions {
    fn default() -> Self {
        Self {
            block_size: 512,
            window_size: 1,
            timeout: 5,
            timeout_requested: false,
            retransmission_policy: RetransmissionPolicy::adaptive(
                Duration::from_secs(1),
                Duration::from_millis(250),
                Duration::from_secs(4),
            ),
            max_retries: 5,
            transfer_size: None,
        }
    }
}

/// Negotiate read options using the small bounded option list directly.
pub fn negotiate_options(
    requested: &[(String, String)],
    defaults: &OptionDefaults,
) -> (NegotiatedOptions, Vec<(String, String)>) {
    negotiate_options_for_request(requested, defaults, OptionRequestKind::Read)
}

/// Negotiates requested options for an RRQ or WRQ.
///
/// Invalid values are ignored or clamped to RFC and configured resource limits;
/// the returned list contains only options that may be emitted in an OACK.
pub fn negotiate_options_for_request(
    requested: &[(String, String)],
    defaults: &OptionDefaults,
    request_kind: OptionRequestKind,
) -> (NegotiatedOptions, Vec<(String, String)>) {
    let mut acknowledged = Vec::new();
    let negotiated = negotiate_options_inner(
        requested,
        defaults,
        request_kind,
        true,
        255,
        Some(&mut acknowledged),
    );
    (negotiated, acknowledged)
}

/// Negotiates server state without allocating an acknowledgement list.
///
/// The transfer path serializes its final OACK after filesystem resolution,
/// when the authoritative `tsize` and extension values are available.
pub(crate) fn negotiate_options_only_for_request(
    requested: &[(String, String)],
    defaults: &OptionDefaults,
    request_kind: OptionRequestKind,
    accept_client_timeout: bool,
    max_client_timeout_secs: u8,
) -> NegotiatedOptions {
    negotiate_options_inner(
        requested,
        defaults,
        request_kind,
        accept_client_timeout,
        max_client_timeout_secs,
        None,
    )
}

fn negotiate_options_inner(
    requested: &[(String, String)],
    defaults: &OptionDefaults,
    request_kind: OptionRequestKind,
    accept_client_timeout: bool,
    max_client_timeout_secs: u8,
    mut acknowledged: Option<&mut Vec<(String, String)>>,
) -> NegotiatedOptions {
    let max_block_size = defaults.max_block_size.clamp(8, 65464);
    let max_window_size = defaults.max_window_size.clamp(1, 64);
    let min_rto = defaults.min_retransmit_interval_ms.max(1);
    let max_rto = defaults
        .max_retransmit_interval_ms
        .max(min_rto)
        .max(defaults.retransmit_interval_ms);
    let mut negotiated = NegotiatedOptions {
        retransmission_policy: RetransmissionPolicy::adaptive(
            Duration::from_millis(defaults.retransmit_interval_ms.max(1)),
            Duration::from_millis(min_rto),
            Duration::from_millis(max_rto),
        ),
        max_retries: defaults.max_retries.max(1),
        ..Default::default()
    };
    // The packet parser already bounds this list, so a scan avoids another map.
    let find_option = |key: &str| -> Option<&str> {
        requested
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    };

    // RFC 2348: blksize
    // Enforce minimum block size of 8 bytes per RFC 2348
    if let Some(bs) = find_option("blksize").and_then(|value| value.parse::<u16>().ok()) {
        let bs = bs.clamp(8, max_block_size);
        negotiated.block_size = bs;
        if let Some(options) = acknowledged.as_mut() {
            options.push(("blksize".into(), bs.to_string()));
        }
    }

    // RFC 7440 windowsize, capped by both protocol and phase policy.
    if let Some(ws) = find_option("windowsize").and_then(|value| value.parse::<u16>().ok()) {
        let ws = ws.clamp(1, max_window_size);
        negotiated.window_size = ws;
        if let Some(options) = acknowledged.as_mut() {
            options.push(("windowsize".into(), ws.to_string()));
        }
    }

    // RFC 2349: timeout
    if accept_client_timeout {
        if let Some(t) = find_option("timeout")
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|&t| t != 0 && t <= max_client_timeout_secs)
        {
            negotiated.timeout = t;
            negotiated.timeout_requested = true;
            negotiated.retransmission_policy =
                RetransmissionPolicy::fixed(Duration::from_secs(u64::from(t)));
            if let Some(options) = acknowledged.as_mut() {
                options.push(("timeout".into(), t.to_string()));
            }
        }
    }

    // RFC 2349: tsize. RRQ uses 0 as a query; WRQ carries the upload size.
    if let Some(tsize) = find_option("tsize").and_then(|value| value.parse::<u64>().ok()) {
        if request_kind == OptionRequestKind::Write || tsize == 0 {
            negotiated.transfer_size = Some(tsize);
        }
    }

    negotiated
}

/// Defaults used during option negotiation — may be overridden by boot phase
pub struct OptionDefaults {
    /// Largest permitted RFC 2348 payload size in bytes, clamped to `8..=65464`.
    pub max_block_size: u16,
    /// Largest permitted RFC 7440 window, clamped to `1..=64`.
    pub max_window_size: u16,
    /// Initial and minimum retry interval used without an RFC timeout request.
    pub retransmit_interval_ms: u64,
    /// Adaptive retry floor used without an RFC timeout request.
    pub min_retransmit_interval_ms: u64,
    /// Adaptive retry ceiling used without an RFC timeout request.
    pub max_retransmit_interval_ms: u64,
    /// Number of retransmissions permitted before aborting a transfer.
    pub max_retries: u8,
}

impl Default for OptionDefaults {
    fn default() -> Self {
        Self {
            max_block_size: 65464,
            max_window_size: 64,
            retransmit_interval_ms: 1_000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            max_retries: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_tftp_client_policy(
        value: &str,
        accept: bool,
        ceiling: u8,
        expected_timeout: Option<u8>,
    ) {
        let defaults = OptionDefaults {
            retransmit_interval_ms: 750,
            min_retransmit_interval_ms: 125,
            max_retransmit_interval_ms: 6_000,
            max_retries: 9,
            ..Default::default()
        };
        for kind in [OptionRequestKind::Read, OptionRequestKind::Write] {
            let size = if kind == OptionRequestKind::Read {
                0
            } else {
                4096
            };
            let requested = vec![
                ("blksize".into(), "1468".into()),
                ("windowsize".into(), "8".into()),
                ("TiMeOuT".into(), value.into()),
                ("tsize".into(), size.to_string()),
            ];
            let context =
                format!("{kind:?}: timeout={value:?}, accept={accept}, ceiling={ceiling}");
            let mut expected_ack = vec![
                ("blksize".into(), "1468".into()),
                ("windowsize".into(), "8".into()),
            ];
            if let Some(timeout) = expected_timeout {
                expected_ack.push(("timeout".into(), timeout.to_string()));
            }
            let mut ack = Vec::new();
            let options = negotiate_options_inner(
                &requested,
                &defaults,
                kind,
                accept,
                ceiling,
                Some(&mut ack),
            );
            assert_eq!(ack, expected_ack, "{context}");
            let no_ack =
                negotiate_options_only_for_request(&requested, &defaults, kind, accept, ceiling);
            let mut results = vec![options, no_ack];
            if accept && ceiling == 255 {
                let (public, ack) = negotiate_options_for_request(&requested, &defaults, kind);
                assert_eq!(ack, expected_ack, "public: {context}");
                results.push(public);
                if kind == OptionRequestKind::Read {
                    let (public, ack) = negotiate_options(&requested, &defaults);
                    assert_eq!(ack, expected_ack, "read wrapper: {context}");
                    results.push(public);
                }
            }
            for options in results {
                assert_eq!(options.block_size, 1468, "{context}");
                assert_eq!(options.window_size, 8, "{context}");
                assert_eq!(options.transfer_size, Some(size), "{context}");
                assert_eq!(options.max_retries, 9, "{context}");
                assert_eq!(
                    options.timeout_requested,
                    expected_timeout.is_some(),
                    "{context}"
                );
                assert_eq!(
                    options.timeout,
                    expected_timeout.unwrap_or(NegotiatedOptions::default().timeout),
                    "{context}"
                );
                let expected_policy = match expected_timeout {
                    Some(timeout) => {
                        RetransmissionPolicy::fixed(Duration::from_secs(timeout.into()))
                    }
                    None => RetransmissionPolicy::adaptive(
                        Duration::from_millis(750),
                        Duration::from_millis(125),
                        Duration::from_secs(6),
                    ),
                };
                assert_eq!(options.retransmission_policy, expected_policy, "{context}");
                for retry in 0..=u8::MAX {
                    let expected_rto = match expected_timeout {
                        Some(timeout) => Duration::from_secs(timeout.into()),
                        None => Duration::from_millis(match retry {
                            0 => 750,
                            1 => 1_500,
                            2 => 3_000,
                            _ => 6_000,
                        }),
                    };
                    assert_eq!(
                        options.retransmission_policy.retry_rto(retry),
                        expected_rto,
                        "{context}, retry={retry}"
                    );
                }
            }
        }
    }

    #[test]
    fn tftp_client_policy_timeout_ceiling_preserves_other_options() {
        for ceiling in [1, 5, 255] {
            for timeout in 1..=u8::MAX {
                for value in [timeout.to_string(), format!("{timeout:03}")] {
                    assert_tftp_client_policy(
                        &value,
                        true,
                        ceiling,
                        (timeout <= ceiling).then_some(timeout),
                    );
                }
            }
        }
    }

    #[test]
    fn tftp_client_policy_disabled_overrides_timeout_ceiling() {
        for ceiling in [1, 5, 255] {
            for timeout in 1..=u8::MAX {
                assert_tftp_client_policy(&timeout.to_string(), false, ceiling, None);
            }
        }
    }

    #[test]
    fn tftp_client_policy_malformed_timeouts_are_omitted() {
        for ceiling in [1, 5, 255] {
            for accept in [false, true] {
                for value in [
                    "0",
                    "00",
                    "256",
                    "65536",
                    "18446744073709551616",
                    "+1",
                    "-1",
                    "-255",
                    "text",
                    "",
                    " ",
                    " 1",
                    "1 ",
                    "\t1",
                    "1\n",
                    "1.0",
                    "1e0",
                    "0x01",
                    "1\0",
                    "١",
                    "１",
                ] {
                    assert_tftp_client_policy(value, accept, ceiling, None);
                }
            }
        }
    }

    #[test]
    fn tftp_client_policy_retries_are_not_client_negotiable() {
        let defaults = OptionDefaults {
            max_retries: 9,
            ..Default::default()
        };
        for kind in [OptionRequestKind::Read, OptionRequestKind::Write] {
            for accept in [false, true] {
                for ceiling in [1, 5, 255] {
                    for key in ["retry", "retries", "max_retries", "MAX_RETRIES"] {
                        for value in ["0", "1", "255", "invalid"] {
                            let requested = vec![(key.into(), value.into())];
                            let mut ack = Vec::new();
                            let options = negotiate_options_inner(
                                &requested,
                                &defaults,
                                kind,
                                accept,
                                ceiling,
                                Some(&mut ack),
                            );
                            assert!(ack.is_empty(), "{key}={value}");
                            let no_ack = negotiate_options_only_for_request(
                                &requested, &defaults, kind, accept, ceiling,
                            );
                            for options in [options, no_ack] {
                                assert_eq!(options.max_retries, 9, "{key}={value}");
                                assert!(!options.timeout_requested);
                                assert!(options.retransmission_policy.is_adaptive());
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_negotiate_blksize() {
        let requested = vec![("blksize".into(), "1468".into())];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.block_size, 1468);
        assert_eq!(ack.len(), 1);
    }

    #[test]
    fn test_negotiate_clamps_blksize() {
        let requested = vec![("blksize".into(), "65535".into())];
        let defaults = OptionDefaults::default();
        let (opts, _) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.block_size, 65464);
    }

    #[test]
    fn test_negotiate_clamps_window_size() {
        let requested = vec![("windowsize".into(), "0".into())];
        let defaults = OptionDefaults::default();
        let (opts, _) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.window_size, 1); // Clamped to minimum 1
    }

    fn assert_timeout_ignored(value: &str) {
        let defaults = OptionDefaults {
            retransmit_interval_ms: 750,
            min_retransmit_interval_ms: 125,
            max_retransmit_interval_ms: 6_000,
            max_retries: 9,
            ..Default::default()
        };
        let expected_policy = RetransmissionPolicy::adaptive(
            Duration::from_millis(750),
            Duration::from_millis(125),
            Duration::from_secs(6),
        );
        let requested = vec![("timeout".into(), value.into())];
        for kind in [OptionRequestKind::Read, OptionRequestKind::Write] {
            let (options, ack) = negotiate_options_for_request(&requested, &defaults, kind);
            assert!(ack.is_empty(), "{kind:?}: timeout={value:?}, ack={ack:?}");
            let no_ack = negotiate_options_only_for_request(&requested, &defaults, kind, true, 255);
            let mut results = vec![options, no_ack];
            if kind == OptionRequestKind::Read {
                let (options, ack) = negotiate_options(&requested, &defaults);
                assert!(ack.is_empty(), "read wrapper: timeout={value:?}");
                results.push(options);
            }
            for options in results {
                assert!(!options.timeout_requested, "{kind:?}: timeout={value:?}");
                assert_eq!(options.timeout, NegotiatedOptions::default().timeout);
                assert_eq!(options.retransmission_policy, expected_policy);
                assert_eq!(options.max_retries, defaults.max_retries);
                for retry in 0..=u8::MAX {
                    assert_eq!(
                        options.retransmission_policy.retry_rto(retry),
                        expected_policy.retry_rto(retry)
                    );
                }
            }
        }
    }

    #[test]
    fn test_negotiate_ignores_out_of_range_timeout() {
        for value in ["0", "00", "256", "65536", "18446744073709551616"] {
            assert_timeout_ignored(value);
        }
    }

    #[test]
    fn test_negotiate_ignores_malformed_timeout() {
        for value in [
            "+1", "-1", "-255", "text", "", " ", " 1", "1 ", "\t1", "1\n", "1.0", "1e0", "0x01",
            "1\0", "١", "１",
        ] {
            assert_timeout_ignored(value);
        }
    }

    #[test]
    fn test_negotiate_accepts_every_valid_timeout_exactly() {
        let defaults = OptionDefaults {
            max_retries: 9,
            ..Default::default()
        };
        for timeout in 1..=u8::MAX {
            // RFC values are numeric: leading zeroes do not change the timeout.
            for value in [timeout.to_string(), format!("{timeout:03}")] {
                let requested = vec![("timeout".into(), value.clone())];
                let expected_ack = vec![("timeout".into(), timeout.to_string())];
                let expected_rto = Duration::from_secs(u64::from(timeout));
                for kind in [OptionRequestKind::Read, OptionRequestKind::Write] {
                    let (options, ack) = negotiate_options_for_request(&requested, &defaults, kind);
                    assert_eq!(ack, expected_ack, "{kind:?}: timeout={value:?}");
                    let no_ack =
                        negotiate_options_only_for_request(&requested, &defaults, kind, true, 255);
                    let mut results = vec![options, no_ack];
                    if kind == OptionRequestKind::Read {
                        let (options, ack) = negotiate_options(&requested, &defaults);
                        assert_eq!(ack, expected_ack, "read wrapper: timeout={value:?}");
                        results.push(options);
                    }
                    for options in results {
                        assert!(options.timeout_requested, "{kind:?}: timeout={value:?}");
                        assert_eq!(options.timeout, timeout);
                        assert_eq!(options.max_retries, defaults.max_retries);
                        assert_eq!(
                            options.retransmission_policy,
                            RetransmissionPolicy::fixed(expected_rto)
                        );
                        for retry in 0..=u8::MAX {
                            assert_eq!(
                                options.retransmission_policy.retry_rto(retry),
                                expected_rto,
                                "{kind:?}: timeout={value:?}, retry={retry}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_negotiate_case_insensitive_keys() {
        let requested = vec![("BLKSIZE".into(), "1024".into())];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.block_size, 1024);
        assert_eq!(ack.len(), 1);
    }

    #[test]
    fn test_negotiate_multiple_options() {
        let requested = vec![
            ("blksize".into(), "8192".into()),
            ("windowsize".into(), "16".into()),
            ("timeout".into(), "10".into()),
        ];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.block_size, 8192);
        assert_eq!(opts.window_size, 16);
        assert_eq!(opts.timeout, 10);
        assert_eq!(ack.len(), 3);
    }

    #[test]
    fn test_negotiate_tsize() {
        let requested = vec![("tsize".into(), "0".into())];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.transfer_size, Some(0));
        // tsize doesn't generate an ACK option (filled in by caller)
        assert!(ack.is_empty());
    }

    #[test]
    fn test_negotiate_write_tsize_accepts_declared_size() {
        let requested = vec![("tsize".into(), "4096".into())];
        let defaults = OptionDefaults::default();
        let (opts, ack) =
            negotiate_options_for_request(&requested, &defaults, OptionRequestKind::Write);

        assert_eq!(opts.transfer_size, Some(4096));
        assert!(ack.is_empty());
    }

    #[test]
    fn test_negotiate_read_tsize_ignores_nonzero_size() {
        let requested = vec![("tsize".into(), "4096".into())];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);

        assert_eq!(opts.transfer_size, None);
        assert!(ack.is_empty());
    }

    #[test]
    fn test_negotiate_empty_request() {
        let requested = vec![];
        let defaults = OptionDefaults::default();
        let (opts, ack) = negotiate_options(&requested, &defaults);
        assert_eq!(opts.block_size, 512);
        assert_eq!(opts.window_size, 1);
        assert_eq!(opts.timeout, 5);
        assert!(ack.is_empty());
    }

    #[test]
    fn test_negotiate_sanitizes_zero_option_defaults() {
        let requested = vec![
            ("blksize".into(), "1024".into()),
            ("windowsize".into(), "8".into()),
        ];
        let defaults = OptionDefaults {
            max_block_size: 0,
            max_window_size: 0,
            ..Default::default()
        };
        let (opts, ack) = negotiate_options(&requested, &defaults);

        assert_eq!(opts.block_size, 8);
        assert_eq!(opts.window_size, 1);
        assert_eq!(opts.timeout, 5);
        assert_eq!(ack.len(), 2);
    }

    #[test]
    fn test_transfer_policy_controls_timeout_and_retries() {
        let requested = vec![("timeout".into(), "2".into())];
        let defaults = OptionDefaults {
            retransmit_interval_ms: 250,
            max_retries: 9,
            ..Default::default()
        };
        let (options, ack) = negotiate_options(&requested, &defaults);
        assert!(options.timeout_requested);
        assert_eq!(
            options.retransmission_policy.initial_rto(),
            Duration::from_secs(2)
        );
        assert!(!options.retransmission_policy.is_adaptive());
        assert_eq!(options.max_retries, 9);
        assert_eq!(ack, vec![("timeout".into(), "2".into())]);
    }

    #[test]
    fn declined_timeout_is_omitted_and_uses_internal_policy() {
        let defaults = OptionDefaults {
            retransmit_interval_ms: 1_000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            ..Default::default()
        };
        for kind in [OptionRequestKind::Read, OptionRequestKind::Write] {
            let size = if kind == OptionRequestKind::Read {
                0
            } else {
                4096
            };
            let requested = vec![
                ("blksize".into(), "1468".into()),
                ("windowsize".into(), "8".into()),
                ("timeout".into(), "255".into()),
                ("tsize".into(), size.to_string()),
            ];
            let mut acknowledged = Vec::new();
            let options = negotiate_options_inner(
                &requested,
                &defaults,
                kind,
                false,
                255,
                Some(&mut acknowledged),
            );
            assert_eq!(
                acknowledged,
                vec![
                    ("blksize".into(), "1468".into()),
                    ("windowsize".into(), "8".into()),
                ]
            );
            let no_ack =
                negotiate_options_only_for_request(&requested, &defaults, kind, false, 255);
            for options in [options, no_ack] {
                let policy = options.retransmission_policy;
                assert_eq!(options.block_size, 1468);
                assert_eq!(options.window_size, 8);
                assert_eq!(options.transfer_size, Some(size));
                assert_eq!(options.timeout, NegotiatedOptions::default().timeout);
                assert_eq!(options.max_retries, defaults.max_retries);
                assert!(!options.timeout_requested);
                assert!(policy.is_adaptive());
                assert_eq!(policy.initial_rto(), Duration::from_secs(1));
                assert_eq!(policy.min_rto(), Duration::from_millis(250));
                assert_eq!(policy.max_rto(), Duration::from_secs(4));
                for retry in 0..=u8::MAX {
                    let seconds = match retry {
                        0 => 1,
                        1 => 2,
                        _ => 4,
                    };
                    assert_eq!(policy.retry_rto(retry), Duration::from_secs(seconds));
                }
            }
        }
    }

    #[test]
    fn internal_retransmission_policy_is_adaptive_and_bounded() {
        let defaults = OptionDefaults {
            retransmit_interval_ms: 1_000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            ..Default::default()
        };
        let (options, ack) = negotiate_options(&[], &defaults);

        assert!(ack.is_empty());
        assert!(!options.timeout_requested);
        assert!(options.retransmission_policy.is_adaptive());
        assert_eq!(
            options.retransmission_policy.initial_rto(),
            Duration::from_secs(1)
        );
        assert_eq!(
            options.retransmission_policy.min_rto(),
            Duration::from_millis(250)
        );
        assert_eq!(
            options.retransmission_policy.max_rto(),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn test_window_size_is_capped_at_64() {
        let requested = vec![("windowsize".into(), "65535".into())];
        let defaults = OptionDefaults::default();
        let (opts, _) = negotiate_options(&requested, &defaults);
        assert!(opts.window_size <= 64, "Window size should be capped at 64");
    }

    #[test]
    fn test_block_size_has_protocol_minimum() {
        let requested = vec![("blksize".into(), "4".into())];
        let defaults = OptionDefaults::default();
        let (opts, _) = negotiate_options(&requested, &defaults);
        assert!(opts.block_size >= 8, "Block size minimum should be 8");
    }
}
