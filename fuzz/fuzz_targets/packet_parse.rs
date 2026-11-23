// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use tempest::protocol::packet::TftpPacket;

fuzz_target!(|data: &[u8]| {
    let peer = SocketAddr::from(([192, 0, 2, 1], 49_152));
    let _ = TftpPacket::parse(data, peer);
});
