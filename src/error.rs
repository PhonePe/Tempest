// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use thiserror::Error;

/// Errors returned by Tempest configuration, control-plane, and data-plane APIs.
#[derive(Debug, Error)]
pub enum TempestError {
    /// A filesystem, socket, or other operating-system I/O operation failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A TFTP packet or transfer violated protocol or security requirements.
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Configuration loading or validation failed.
    #[error("Config error: {0}")]
    Config(String),

    /// Release registration, resolution, pinning, or cutover failed.
    #[error("Version error: {0}")]
    Version(String),

    /// Durable audit admission or JSONL persistence failed.
    #[error("Audit error: {0}")]
    Audit(String),

    /// An optional payload compression operation failed.
    #[error("Compression error: {0}")]
    Compression(String),

    /// An HTTP API operation could not be completed.
    #[error("API error: {0}")]
    Api(String),

    /// Durable control-state access failed.
    #[error("Persistence error: {0}")]
    Persistence(String),

    /// Ordinary SQL serving state has not been validated within its configured age.
    #[error("Persistent serving snapshot is stale")]
    PersistenceSnapshotStale,

    /// Durable SQL coordination is temporarily saturated or timed out; retry.
    #[error("Persistence busy: {0}")]
    PersistenceBusy(String),

    /// A compare-and-swap or concurrent control-plane mutation conflicted.
    #[error("Conflict: {0}")]
    Conflict(String),
}

/// TFTP parsing and transfer failures that can be mapped to wire errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The packet opcode is not defined by the supported TFTP RFCs.
    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u16),

    /// A packet from `addr` failed bounded structural or encoding validation.
    #[error("Malformed packet from {addr}: {reason}")]
    MalformedPacket {
        /// Source address of the malformed datagram.
        addr: SocketAddr,
        /// Non-sensitive validation failure description.
        reason: String,
    },

    /// The request named a transfer mode that Tempest cannot parse or serve.
    #[error("Unsupported transfer mode: {0}")]
    UnsupportedMode(String),

    /// The requested artifact does not exist in the permitted namespace.
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Artifact access was denied, including root-containment violations.
    #[error("Access violation: {0}")]
    AccessViolation(String),

    /// Requested RFC options could not be negotiated safely.
    #[error("Option negotiation failed: {0}")]
    OptionNegotiation(String),

    /// The peer did not acknowledge `block` before the retry budget expired.
    #[error("Transfer timeout for {addr} block {block}")]
    Timeout {
        /// Address of the timed-out transfer peer.
        addr: SocketAddr,
        /// Last relevant 16-bit TFTP wire block number.
        block: u16,
    },

    /// The server's absolute TFTP lifetime expired, regardless of peer progress.
    #[error("Transfer lifetime exceeded for {addr}")]
    TransferDeadline {
        /// Address of the timed-out transfer peer.
        addr: SocketAddr,
    },

    /// The named peer explicitly or implicitly terminated its transfer.
    #[error("Transfer aborted by client: {addr}")]
    ClientAbort {
        /// Address of the peer that aborted the transfer.
        addr: SocketAddr,
    },

    /// Open-time artifact bytes did not match the release pin.
    #[error("File version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// SHA-256 digest recorded in the pinned release manifest.
        expected: String,
        /// SHA-256 digest observed after securely opening the artifact.
        actual: String,
    },
}

/// TFTP error codes defined by RFC 1350.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpErrorCode {
    /// Unclassified failure; the accompanying message carries detail.
    NotDefined = 0,
    /// The requested file is unavailable.
    FileNotFound = 1,
    /// Filesystem policy or authorization denied access.
    AccessViolation = 2,
    /// Storage cannot accept more data.
    DiskFull = 3,
    /// The packet or operation is not legal for this transfer.
    IllegalOperation = 4,
    /// The datagram was sent to an unrelated transfer ID.
    UnknownTransferId = 5,
    /// A write request would overwrite an existing file.
    FileAlreadyExists = 6,
    /// The protocol-specific user identity is unknown.
    NoSuchUser = 7,
    /// RFC 2347 option negotiation failed.
    OptionNegotiation = 8,
}

impl From<TftpErrorCode> for u16 {
    fn from(code: TftpErrorCode) -> Self {
        code as u16
    }
}

/// Crate result type using [`TempestError`].
pub type Result<T> = std::result::Result<T, TempestError>;
