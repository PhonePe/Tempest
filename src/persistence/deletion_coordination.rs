// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Internal SQL reader/fence primitives used by coordinated metadata deletion.
//!
//! All operations serialize with durable writers on the existing state-revision
//! row, but do not change that revision: these rows are not control snapshots.
//! Registrations and reservations never expire or evict. A lost acknowledgement
//! may leave a durable blocker; retry with the SAME opaque ID, never infer absence
//! from a timeout. Release only after the actual reader has stopped. Unknown or
//! crashed readers require future fenced recovery, not TTL-based cleanup.
//! Each call has a five-second total deadline, including pool and lock waits.
//! Timeout/cancellation drops the transaction; cancellation during commit can
//! still leave a committed blocker and must be treated as an uncertain result.
//!
//! Runtime admission, lifetime namespace locking, atomic removal and ownership
//! tombstones are implemented in `runtime`. Every updated serving process must
//! participate; pre-protocol binaries require a stopped upgrade. Metadata
//! coordination never authorizes byte deletion. Reservation rows block admission
//! regardless of identity, and committed deletion keeps its reservation forever.

use super::{DatabaseDialect, PersistenceStore, TempestError, persistence_error, row_text};
use crate::features::versioning::{BootChainPin, is_valid_boot_profile};
use crate::sqlx_instrumentation::TracedTransaction;
use sqlx::Row;

mod runtime;
pub use runtime::ReaderRegistration;
pub(super) use runtime::ServingLease;

const MAX_READERS: i64 = 4096;
const MAX_RESERVATIONS: i64 = 100;
const COORDINATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A canonical opaque operation ID; callers generate fresh UUID-v4 simple IDs.
/// Persist it across ambiguous retries. Sharing an ID between live readers is unsafe.
/// Never reuse an ID for a new operation after releasing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoordinationId(String);

impl CoordinationId {
    pub(crate) fn new(value: &str) -> Result<Self, CoordinationError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CoordinationError::InvalidInput);
        }
        Ok(Self(value.to_owned()))
    }
}

/// Validated exact durable identity; fields cannot be mutated after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GroupIdentity {
    profile: String,
    group: String,
    version: i64,
    digest: String,
}

impl GroupIdentity {
    pub(crate) fn new(pin: &BootChainPin) -> Result<Self, CoordinationError> {
        if !is_valid_boot_profile(&pin.boot_profile)
            || pin.group_id.is_empty()
            || pin.group_id.len() > 128
            || !pin
                .group_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || pin.manifest_digest.len() != 64
            || !pin
                .manifest_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CoordinationError::InvalidInput);
        }
        Ok(Self {
            profile: pin.boot_profile.clone(),
            group: pin.group_id.clone(),
            version: i64::try_from(pin.version_id).map_err(|_| CoordinationError::InvalidInput)?,
            digest: pin.manifest_digest.clone(),
        })
    }
}

/// Distinguishes safety/capacity refusals from database or decoding failures.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CoordinationError {
    #[error("invalid coordination identity or opaque ID")]
    InvalidInput,
    #[error("durable release identity is missing or changed")]
    IdentityChanged,
    #[error("group has a durable deletion reservation or tombstone")]
    Reserved,
    #[error("opaque ID belongs to another operation or identity")]
    IdConflict,
    #[error("group is durably active")]
    Active,
    #[error("group has a live durable session")]
    LiveSession,
    #[error("group has durable readers (including unknown or abandoned readers)")]
    ReadersPresent,
    #[error("durable coordination capacity exhausted; no rows were evicted")]
    Capacity,
    #[error("coordination deadline exceeded; outcome uncertain, retry with the same ID")]
    DeadlineExceeded,
    #[error(transparent)]
    Persistence(#[from] TempestError),
}

impl PersistenceStore {
    /// Called only under the existing serialized schema migration lock.
    pub(super) async fn migrate_deletion_coordination(&self) -> Result<(), TempestError> {
        self.migrate_serving_coordination().await?;
        // Binary ASCII keys avoid MySQL's default case-insensitive ID aliasing.
        let suffix = match self.dialect {
            DatabaseDialect::Postgres => "",
            DatabaseDialect::MySql => " ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin",
        };
        for (table, key) in [
            ("tempest_group_readers", "PRIMARY KEY (operation_id)"),
            (
                "tempest_group_deletion_reservations",
                "PRIMARY KEY (boot_profile, group_id), UNIQUE (operation_id)",
            ),
        ] {
            sqlx::query(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    operation_id VARCHAR(32) NOT NULL,
                    boot_profile VARCHAR(64) NOT NULL,
                    group_id VARCHAR(128) NOT NULL,
                    version_id BIGINT NOT NULL,
                    manifest_digest VARCHAR(64) NOT NULL,
                    {key}
                ){suffix}"
            ))
            .execute(&self.pool)
            .await
            .map_err(|e| persistence_error("migrate deletion coordination", e))?;
        }
        // Bounded point lookups rather than scanning unrelated readers/sessions.
        for (table, index, columns) in [
            (
                "tempest_group_readers",
                "tempest_readers_group_idx",
                "boot_profile, group_id",
            ),
            (
                "tempest_boot_sessions",
                "tempest_sessions_group_idx",
                "boot_profile, pinned_group_id",
            ),
        ] {
            let statement = match self.dialect {
                DatabaseDialect::Postgres => {
                    format!("CREATE INDEX IF NOT EXISTS {index} ON {table} ({columns})")
                }
                DatabaseDialect::MySql => {
                    let exists: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM information_schema.statistics
                         WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
                    )
                    .bind(table)
                    .bind(index)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| persistence_error("inspect coordination index", e))?;
                    if exists != 0 {
                        continue;
                    }
                    format!("CREATE INDEX {index} ON {table} ({columns})")
                }
            };
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(|e| persistence_error("migrate coordination index", e))?;
        }
        self.migrate_ownership_index().await?;
        Ok(())
    }

    fn coordination_sql(&self, postgres: &'static str, mysql: &'static str) -> &'static str {
        match self.dialect {
            DatabaseDialect::Postgres => postgres,
            DatabaseDialect::MySql => mysql,
        }
    }

    async fn begin_coordination(&self) -> Result<TracedTransaction<'_>, CoordinationError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin coordination", e))?;
        self.lock_state_revision(&mut tx).await?;
        Ok(tx)
    }

    /// Current locking read: never accept a stale MySQL consistent snapshot.
    async fn coordination_group(
        &self,
        tx: &mut TracedTransaction<'_>,
        identity: &GroupIdentity,
    ) -> Result<bool, CoordinationError> {
        let row = sqlx::query(self.coordination_sql(
            "SELECT boot_profile, group_id, version_id, manifest_digest, CAST(active AS INTEGER) AS is_active FROM tempest_version_groups WHERE boot_profile = $1 AND group_id = $2 FOR UPDATE",
            "SELECT boot_profile, group_id, version_id, manifest_digest, CAST(active AS SIGNED) AS is_active FROM tempest_version_groups WHERE boot_profile = ? AND group_id = ? FOR UPDATE",
        )).bind(&identity.profile).bind(&identity.group).fetch_optional(tx.executor()).await
            .map_err(|e| persistence_error("read coordination group", e))?
            .ok_or(CoordinationError::IdentityChanged)?;
        if !matches_identity(&row, identity)? {
            return Err(CoordinationError::IdentityChanged);
        }
        let active: i64 = row
            .try_get("is_active")
            .map_err(|e| persistence_error("read coordination active state", e))?;
        Ok(active != 0)
    }

    async fn coordination_reservation(
        &self,
        tx: &mut TracedTransaction<'_>,
        identity: &GroupIdentity,
    ) -> Result<Option<sqlx::any::AnyRow>, CoordinationError> {
        sqlx::query(self.coordination_sql(
            "SELECT operation_id, boot_profile, group_id, version_id, manifest_digest FROM tempest_group_deletion_reservations WHERE boot_profile = $1 AND group_id = $2 FOR UPDATE",
            "SELECT operation_id, boot_profile, group_id, version_id, manifest_digest FROM tempest_group_deletion_reservations WHERE boot_profile = ? AND group_id = ? FOR UPDATE",
        )).bind(&identity.profile).bind(&identity.group).fetch_optional(tx.executor()).await
            .map_err(|e| persistence_error("read deletion reservation", e).into())
    }

    /// Register BEFORE using cached metadata or opening bytes. Retry an ambiguous
    /// commit with the same ID. Success alone does not fence legacy readers.
    pub(crate) async fn acquire_group_reader(
        &self,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        coordination_deadline(async {
            let mut tx = self.begin_coordination().await?;
            self.acquire_reader_in_tx(&mut tx, identity, id).await?;
            tx.commit()
                .await
                .map_err(|e| persistence_error("commit reader registration", e))?;
            Ok(())
        })
        .await
    }

    async fn acquire_reader_in_tx(
        &self,
        tx: &mut TracedTransaction<'_>,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        self.coordination_group(tx, identity).await?;
        if self.coordination_reservation(tx, identity).await?.is_some() {
            return Err(CoordinationError::Reserved);
        }
        let existing = sqlx::query(self.coordination_sql(
            "SELECT boot_profile, group_id, version_id, manifest_digest FROM tempest_group_readers WHERE operation_id = $1 FOR UPDATE",
            "SELECT boot_profile, group_id, version_id, manifest_digest FROM tempest_group_readers WHERE operation_id = ? FOR UPDATE",
        )).bind(&id.0).fetch_optional(tx.executor()).await.map_err(|e| persistence_error("read reader registration", e))?;
        if let Some(row) = existing {
            return if matches_identity(&row, identity)? {
                Ok(())
            } else {
                Err(CoordinationError::IdConflict)
            };
        }
        match self.check_coordination_capacity(tx, false).await {
            Ok(()) => {}
            Err(CoordinationError::Capacity) => {
                sqlx::query(
                    "UPDATE tempest_deletion_safety SET reader_tracking_exhausted = 1 WHERE id = 1",
                )
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("disable deletion after reader exhaustion", e))?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.insert_coordination(tx, identity, id, false).await
    }

    /// Idempotent exact release, including after legacy retention removed a group.
    /// Do not call until the actual reader has finished. No TTL cleanup exists.
    pub(crate) async fn release_group_reader(
        &self,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        coordination_deadline(self.release_coordination(identity, id, false)).await
    }

    /// Primitive test entry point; runtime deletion reserves in its transaction.
    /// Durable admission fence only, never permission to delete. Refuses active
    /// groups, live pinned sessions and ALL readers regardless of age/identity.
    #[cfg(test)]
    pub(crate) async fn reserve_group_deletion(
        &self,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        coordination_deadline(async {
            let mut tx = self.begin_coordination().await?;
            self.reserve_deletion_in_tx(&mut tx, identity, id).await?;
            tx.commit()
                .await
                .map_err(|e| persistence_error("commit deletion reservation", e))?;
            Ok(())
        })
        .await
    }

    async fn reserve_deletion_in_tx(
        &self,
        tx: &mut TracedTransaction<'_>,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        if self.reader_tracking_exhausted(tx).await? {
            return Err(CoordinationError::Capacity);
        }
        if self.coordination_group(tx, identity).await? {
            return Err(CoordinationError::Active);
        }
        let session = sqlx::query(self.coordination_sql(
            "SELECT client_ip FROM tempest_boot_sessions WHERE boot_profile = $1 AND pinned_group_id = $2 AND expires_at > $3 LIMIT 1 FOR UPDATE",
            "SELECT client_ip FROM tempest_boot_sessions WHERE boot_profile = ? AND pinned_group_id = ? AND expires_at > ? LIMIT 1 FOR UPDATE",
        )).bind(&identity.profile).bind(&identity.group).bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .fetch_optional(tx.executor()).await.map_err(|e| persistence_error("check deletion sessions", e))?;
        if session.is_some() {
            return Err(CoordinationError::LiveSession);
        }
        let reader = sqlx::query(self.coordination_sql(
            "SELECT operation_id FROM tempest_group_readers WHERE boot_profile = $1 AND group_id = $2 LIMIT 1 FOR UPDATE",
            "SELECT operation_id FROM tempest_group_readers WHERE boot_profile = ? AND group_id = ? LIMIT 1 FOR UPDATE",
        )).bind(&identity.profile).bind(&identity.group).fetch_optional(tx.executor()).await
            .map_err(|e| persistence_error("check deletion readers", e))?;
        if reader.is_some() {
            return Err(CoordinationError::ReadersPresent);
        }
        if let Some(row) = self.coordination_reservation(tx, identity).await? {
            return if row_text(&row, "operation_id")? == id.0 && matches_identity(&row, identity)? {
                Ok(())
            } else {
                Err(CoordinationError::Reserved)
            };
        }
        // A token cannot be rebound to a different group, even after an uncertain commit.
        let existing = sqlx::query(self.coordination_sql(
            "SELECT operation_id FROM tempest_group_deletion_reservations WHERE operation_id = $1 FOR UPDATE",
            "SELECT operation_id FROM tempest_group_deletion_reservations WHERE operation_id = ? FOR UPDATE",
        )).bind(&id.0).fetch_optional(tx.executor()).await.map_err(|e| persistence_error("check reservation ID", e))?;
        if existing.is_some() {
            return Err(CoordinationError::IdConflict);
        }
        self.check_coordination_capacity(tx, true).await?;
        self.insert_coordination(tx, identity, id, true).await
    }

    pub(super) async fn reader_tracking_exhausted(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<bool, TempestError> {
        let exhausted: i32 = sqlx::query_scalar(
            "SELECT reader_tracking_exhausted FROM tempest_deletion_safety WHERE id = 1",
        )
        .fetch_one(tx.executor())
        .await
        .map_err(|e| persistence_error("check deletion safety", e))?;
        Ok(exhausted != 0)
    }

    /// Cancel an uncommitted reservation only. Committed tombstones are permanent.
    #[cfg(test)]
    pub(crate) async fn release_group_deletion(
        &self,
        identity: &GroupIdentity,
        id: &CoordinationId,
    ) -> Result<(), CoordinationError> {
        coordination_deadline(self.release_coordination(identity, id, true)).await
    }

    async fn check_coordination_capacity(
        &self,
        tx: &mut TracedTransaction<'_>,
        reservation: bool,
    ) -> Result<(), CoordinationError> {
        if !reservation {
            let count: i64 = sqlx::query_scalar(
                "SELECT registered_count FROM tempest_reader_capacity WHERE id = 1 FOR UPDATE",
            )
            .fetch_one(tx.executor())
            .await
            .map_err(|e| persistence_error("check durable reader capacity", e))?;
            if !(0..=MAX_READERS).contains(&count) {
                return Err(
                    TempestError::Persistence("durable reader capacity is invalid".into()).into(),
                );
            }
            return if count == MAX_READERS {
                Err(CoordinationError::Capacity)
            } else {
                Ok(())
            };
        }
        let table = "tempest_group_deletion_reservations";
        let limit = MAX_RESERVATIONS;
        let cast = if self.dialect == DatabaseDialect::Postgres {
            "BIGINT"
        } else {
            "SIGNED"
        };
        // Limit even on an oversized/corrupt legacy table; never hydrate all rows.
        let count: i64 = sqlx::query_scalar(&format!("SELECT CAST(COUNT(*) AS {cast}) FROM (SELECT operation_id FROM {table} LIMIT {limit}) AS bounded_rows"))
            .fetch_one(tx.executor()).await.map_err(|e| persistence_error("check coordination capacity", e))?;
        if count >= limit {
            return Err(CoordinationError::Capacity);
        }
        Ok(())
    }

    async fn insert_coordination(
        &self,
        tx: &mut TracedTransaction<'_>,
        identity: &GroupIdentity,
        id: &CoordinationId,
        reservation: bool,
    ) -> Result<(), CoordinationError> {
        let table = if reservation {
            "tempest_group_deletion_reservations"
        } else {
            "tempest_group_readers"
        };
        let values = self.coordination_sql("$1, $2, $3, $4, $5", "?, ?, ?, ?, ?");
        sqlx::query(&format!("INSERT INTO {table} (operation_id, boot_profile, group_id, version_id, manifest_digest) VALUES ({values})"))
            .bind(&id.0).bind(&identity.profile).bind(&identity.group).bind(identity.version).bind(&identity.digest)
            .execute(tx.executor()).await.map_err(|e| persistence_error("insert coordination row", e))?;
        if !reservation {
            let updated = sqlx::query(
                "UPDATE tempest_reader_capacity SET registered_count = registered_count + 1
                 WHERE id = 1 AND registered_count >= 0 AND registered_count < 4096",
            )
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("increment reader capacity", e))?;
            if updated.rows_affected() != 1 {
                return Err(TempestError::Persistence(
                    "durable reader capacity increment failed".into(),
                )
                .into());
            }
        }
        Ok(())
    }

    async fn release_coordination(
        &self,
        identity: &GroupIdentity,
        id: &CoordinationId,
        reservation: bool,
    ) -> Result<(), CoordinationError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin coordination cleanup", e))?;
        self.lock_state_revision_unchecked(&mut tx).await?;
        if reservation {
            self.reject_deleted_group(&mut tx, &identity.profile, &identity.group)
                .await?;
        }
        let table = if reservation {
            "tempest_group_deletion_reservations"
        } else {
            "tempest_group_readers"
        };
        let parameter = self.coordination_sql("$1", "?");
        let row = sqlx::query(&format!("SELECT boot_profile, group_id, version_id, manifest_digest FROM {table} WHERE operation_id = {parameter} FOR UPDATE"))
            .bind(&id.0).fetch_optional(tx.executor()).await.map_err(|e| persistence_error("check coordination release", e))?;
        if let Some(row) = row {
            if !matches_identity(&row, identity)? {
                return Err(CoordinationError::IdConflict);
            }
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE operation_id = {parameter}"
            ))
            .bind(&id.0)
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("release coordination row", e))?;
            if !reservation {
                let updated = sqlx::query(
                    "UPDATE tempest_reader_capacity SET registered_count = registered_count - 1
                     WHERE id = 1 AND registered_count > 0 AND registered_count <= 4096",
                )
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("decrement reader capacity", e))?;
                if updated.rows_affected() != 1 {
                    return Err(TempestError::Persistence(
                        "durable reader capacity decrement failed".into(),
                    )
                    .into());
                }
            }
        }
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit coordination release", e))?;
        Ok(())
    }
}

async fn coordination_deadline<T>(
    operation: impl std::future::Future<Output = Result<T, CoordinationError>>,
) -> Result<T, CoordinationError> {
    tokio::time::timeout(COORDINATION_TIMEOUT, operation)
        .await
        .map_err(|_| CoordinationError::DeadlineExceeded)?
}

fn matches_identity(
    row: &sqlx::any::AnyRow,
    identity: &GroupIdentity,
) -> Result<bool, CoordinationError> {
    let version: i64 = row
        .try_get("version_id")
        .map_err(|e| persistence_error("read coordination version", e))?;
    Ok(row_text(row, "boot_profile")? == identity.profile
        && row_text(row, "group_id")? == identity.group
        && version == identity.version
        && row_text(row, "manifest_digest")? == identity.digest)
}

#[cfg(test)]
#[path = "deletion_coordination_tests.rs"]
mod tests;
