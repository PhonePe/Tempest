// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Disabled SQL persistence surface for default Tempest builds.
//!
//! Keeping the type surface available lets the release/session code compile
//! without conditional branches. Configuration rejects persistence before any
//! method here can be reached in a correctly constructed default binary.

use std::net::IpAddr;

use crate::error::TempestError;
use crate::features::versioning::{BootChainPin, VersionGroup};
use crate::server::BootSessionEntry;

/// Placeholder control-state store used when `sql-persistence` is not compiled.
pub struct PersistenceStore;

/// Unconstructible placeholder for durable reader lifetimes in SQL-free builds.
#[derive(Debug)]
pub struct ReaderRegistration;

pub(crate) struct ControlSnapshot {
    pub(crate) revision: i64,
    pub(crate) groups: Vec<(VersionGroup, bool)>,
    pub(crate) sessions: Vec<(IpAddr, BootSessionEntry)>,
}

impl PersistenceStore {
    /// Rejects offline reader recovery because SQL support is not compiled.
    pub async fn recover_abandoned_readers(
        _database_url: &str,
        _all_servers_stopped: bool,
    ) -> Result<u64, TempestError> {
        Err(disabled())
    }

    pub(crate) async fn ensure_serving_mode(&self, _exclusive: bool) -> Result<(), TempestError> {
        Err(disabled())
    }

    pub(crate) async fn ensure_serving_admission(
        &self,
        _exclusive: bool,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    pub(crate) async fn register_reader(
        &self,
        _pin: &BootChainPin,
    ) -> Result<std::sync::Arc<ReaderRegistration>, TempestError> {
        Err(disabled())
    }

    pub(crate) async fn check_unmanaged_admission(
        &self,
        _profile: &str,
        _name: &str,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    pub(crate) async fn preview_sql_group_deletion(
        &self,
        _group: &VersionGroup,
    ) -> Result<(), crate::features::versioning::deletion::DeleteError> {
        Err(coordination_unavailable())
    }

    pub(crate) async fn delete_sql_group(
        &self,
        _group: &VersionGroup,
        _revision: i64,
    ) -> Result<(), crate::features::versioning::deletion::DeleteError> {
        Err(coordination_unavailable())
    }

    pub(crate) fn serving_lease_lost(&self) -> bool {
        false
    }

    pub(crate) async fn load_control_snapshot(
        &self,
        _max_sessions: usize,
    ) -> Result<ControlSnapshot, TempestError> {
        Err(disabled())
    }
    /// Reject connection attempts in builds without SQL support.
    pub async fn connect(_database_url: &str) -> Result<Self, TempestError> {
        Err(disabled())
    }

    /// Rejects revision reads because no durable repository is compiled.
    pub async fn version_revision(&self, _boot_profile: &str) -> Result<i64, TempestError> {
        Err(disabled())
    }

    /// Rejects snapshot revision reads because no durable repository is compiled.
    pub async fn state_revision(&self) -> Result<i64, TempestError> {
        Err(disabled())
    }

    /// Rejects release persistence because no durable repository is compiled.
    pub async fn persist_version_group(
        &self,
        _group: &VersionGroup,
        _expected_revision: i64,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects durable rollback because no durable repository is compiled.
    pub async fn rollback_version_group(
        &self,
        _boot_profile: &str,
        _group_id: &str,
        _manifest_digest: Option<&str>,
        _expected_revision: i64,
        _expected_active_group: Option<&str>,
        _expected_active_manifest_digest: Option<&str>,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects durable release withdrawal because no repository is compiled.
    pub async fn withdraw_version_group(
        &self,
        _boot_profile: &str,
        _group_id: &str,
        _manifest_digest: Option<&str>,
        _expected_revision: i64,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects release hydration because no durable repository is compiled.
    pub async fn load_version_groups(&self) -> Result<Vec<(VersionGroup, bool)>, TempestError> {
        Err(disabled())
    }

    /// Rejects boot-session persistence because no repository is compiled.
    pub async fn persist_boot_session(
        &self,
        _client_ip: IpAddr,
        _entry: &BootSessionEntry,
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    pub(crate) async fn persist_boot_sessions_if_unchanged(
        &self,
        _entries: &[(IpAddr, BootSessionEntry)],
        _expected: &[(IpAddr, Option<BootSessionEntry>)],
    ) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects durable session pinning because no repository is compiled.
    pub async fn pin_boot_session(
        &self,
        _client_ip: IpAddr,
        _boot_epoch: u64,
        _pin: &BootChainPin,
    ) -> Result<bool, TempestError> {
        Err(disabled())
    }

    /// Rejects durable session deletion because no repository is compiled.
    pub async fn delete_boot_session(&self, _client_ip: IpAddr) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects durable token-matched deletion because no repository is compiled.
    pub async fn delete_boot_session_with_token(
        &self,
        _client_ip: IpAddr,
        _token_hash: &[u8; 32],
    ) -> Result<bool, TempestError> {
        Err(disabled())
    }

    /// Rejects durable expiry pruning because no repository is compiled.
    pub async fn prune_expired_boot_sessions(&self) -> Result<(), TempestError> {
        Err(disabled())
    }

    /// Rejects boot-session hydration because no repository is compiled.
    pub async fn load_boot_sessions(
        &self,
        _max_sessions: usize,
    ) -> Result<Vec<(IpAddr, BootSessionEntry)>, TempestError> {
        Err(disabled())
    }
}

/// Returns the standard error for operations unavailable without SQL support.
fn disabled() -> TempestError {
    TempestError::Persistence(
        "SQL persistence is not compiled; enable the sql-persistence feature".into(),
    )
}

fn coordination_unavailable() -> crate::features::versioning::deletion::DeleteError {
    crate::features::versioning::deletion::DeleteError::Blocked(vec![
        crate::features::versioning::deletion::DeleteBlocker::PersistenceCoordinationUnavailable,
    ])
}
