// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use tempest::protocol::options::{
    OptionDefaults, OptionRequestKind, negotiate_options_for_request,
};

fuzz_target!(|data: &[u8]| {
    let mut fields = data
        .split(|byte| *byte == 0)
        .take(40)
        .map(|field| String::from_utf8_lossy(&field[..field.len().min(64)]).into_owned());
    let mut requested = Vec::with_capacity(20);
    while let (Some(name), Some(value)) = (fields.next(), fields.next()) {
        requested.push((name, value));
    }

    let selector = data.first().copied().unwrap_or_default();
    let defaults = OptionDefaults {
        max_block_size: u16::from_be_bytes([selector, data.get(1).copied().unwrap_or_default()]),
        max_window_size: u16::from_be_bytes([
            data.get(2).copied().unwrap_or_default(),
            data.get(3).copied().unwrap_or_default(),
        ]),
        retransmit_interval_ms: u64::from(data.get(4).copied().unwrap_or_default()),
        min_retransmit_interval_ms: u64::from(data.get(5).copied().unwrap_or_default()),
        max_retransmit_interval_ms: u64::from(data.get(6).copied().unwrap_or_default()),
        max_retries: data.get(7).copied().unwrap_or_default(),
    };
    let request_kind = if selector & 1 == 0 {
        OptionRequestKind::Read
    } else {
        OptionRequestKind::Write
    };
    let (negotiated, acknowledged) =
        negotiate_options_for_request(&requested, &defaults, request_kind);

    assert!((8..=65_464).contains(&negotiated.block_size));
    assert!((1..=64).contains(&negotiated.window_size));
    assert!(negotiated.timeout >= 1);
    assert!(negotiated.retransmission_policy.initial_rto().as_millis() >= 1);
    assert!(negotiated.max_retries >= 1);
    assert!(acknowledged.len() <= 3);
});
