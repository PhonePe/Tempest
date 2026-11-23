// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

/// RFC 2347 option negotiation with server-enforced resource bounds.
pub mod options;
/// Parsing and serialization of TFTP wire packets.
pub mod packet;
/// Read/write transfer execution and artifact verification.
pub mod transfer;
/// RFC 7440 window and retransmission state.
pub mod window;
