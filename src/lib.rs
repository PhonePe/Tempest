// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Release-coherent TFTP and HTTP boot artifact serving.
//!
//! Tempest provides the RFC data plane, boot-session and version-group control
//! plane, observability, and public, versioned contracts used by optional
//! extension crates.
//!
//! # Core ownership
//!
//! The core owns request validation, release and boot-session resolution, path
//! confinement, artifact verification, TFTP transfer identifiers, window and
//! retransmission state, HTTP control routes, metrics, and lifecycle cleanup.
//! Start with [`config::TempestConfig`] and [`server::TftpServer`].
//!
//! # Extension composition
//!
//! Optional in-process capabilities implement the typed contracts in
//! [`extension`] and are installed through
//! [`server::TftpServer::builder`]. They are statically linked Rust components,
//! not dynamically loaded plugins or a general request-middleware chain. The
//! default binary remains fully usable without them.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// HTTP control, artifact-download, health, and metrics endpoints.
pub mod api;
mod artifact_cache;
mod artifact_root;
/// Deserializable server configuration and validation.
pub mod config;
/// Crate-wide error types and TFTP error codes.
pub mod error;
pub mod extension;
/// Boot-phase, release-versioning, audit, bandwidth, and QoS features.
pub mod features;
/// Optional PostgreSQL/MySQL durable control-plane repository.
#[cfg(feature = "sql-persistence")]
pub mod persistence;
/// Disabled-feature persistence stub that reports unsupported operations.
#[cfg(not(feature = "sql-persistence"))]
#[path = "persistence_disabled.rs"]
pub mod persistence;
/// TFTP packet, option-negotiation, transfer, and window primitives.
pub mod protocol;
/// Bounded per-client request rate limiting.
pub mod rate_limit;
/// Shared supervised lifecycle for core and downstream server compositions.
pub mod runtime;
/// Runtime server state and TFTP service orchestration.
pub mod server;
#[cfg(feature = "sql-persistence")]
mod sqlx_instrumentation;
mod timestamp;
