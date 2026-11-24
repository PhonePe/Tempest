// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::any::{AnyConnectOptions, AnyPoolOptions, AnyRow};

use crate::error::TempestError;
use crate::features::versioning::{
    BootChainManifest, BootChainPin, FileVersion, ManifestArtifact, VersionGroup, VersionId,
    is_valid_boot_profile,
};
use crate::server::BootSessionEntry;
use crate::sqlx_instrumentation::{TracedPool, TracedTransaction};

const MAX_PERSISTED_GROUPS: usize = 100;
const MAX_PERSISTED_FILES_PER_GROUP: usize = 100;
const MAX_PERSISTED_JSON_BYTES: usize = 1024 * 1024;
const MAX_PERSISTED_SNAPSHOT_JSON_BYTES: usize = 16 * 1024 * 1024;

pub(crate) mod deletion_coordination;
pub use deletion_coordination::ReaderRegistration;

#[derive(Clone)]
/// PostgreSQL or MySQL repository for release groups and boot sessions.
///
/// Clones share an eight-connection SQLx pool. Version mutations use per-profile
/// revision compare-and-swap transactions to detect concurrent writers.
pub struct PersistenceStore {
    pool: TracedPool,
    dialect: DatabaseDialect,
    serving: std::sync::Arc<tokio::sync::OnceCell<deletion_coordination::ServingLease>>,
    reader_budget: std::sync::Arc<tokio::sync::Semaphore>,
}

/// One committed revision, read while durable writers are excluded.
pub(crate) struct ControlSnapshot {
    pub(crate) revision: i64,
    pub(crate) groups: Vec<(VersionGroup, bool)>,
    pub(crate) sessions: Vec<(IpAddr, BootSessionEntry)>,
}

/// Selects PostgreSQL or MySQL query and migration syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseDialect {
    Postgres,
    MySql,
}

impl DatabaseDialect {
    const fn system_name(self) -> &'static str {
        match self {
            Self::Postgres => "postgresql",
            Self::MySql => "mysql",
        }
    }
}

fn version_group_table_sql(dialect: DatabaseDialect) -> String {
    let json_type = match dialect {
        DatabaseDialect::Postgres => "TEXT",
        DatabaseDialect::MySql => "MEDIUMTEXT",
    };
    format!(
        "CREATE TABLE IF NOT EXISTS tempest_version_groups (
            boot_profile VARCHAR(64) NOT NULL,
            group_id VARCHAR(128) NOT NULL,
            version_id BIGINT NOT NULL,
            created_at TEXT NOT NULL,
            manifest_digest VARCHAR(128) NOT NULL,
            manifest_signature TEXT NULL,
            manifest_json {json_type} NOT NULL,
            files_json {json_type} NOT NULL,
            active BOOLEAN NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (boot_profile, group_id)
        )"
    )
}

/// Serializable manifest representation stored in the control database.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedManifest {
    boot_profile: String,
    group_id: String,
    version_id: VersionId,
    #[serde(with = "crate::timestamp")]
    created_at: jiff::Timestamp,
    artifacts: Vec<ManifestArtifact>,
    manifest_digest: String,
    signature: Option<String>,
}

impl From<&BootChainManifest> for PersistedManifest {
    fn from(manifest: &BootChainManifest) -> Self {
        Self {
            boot_profile: manifest.boot_profile.clone(),
            group_id: manifest.group_id.clone(),
            version_id: manifest.version_id,
            created_at: manifest.created_at,
            artifacts: manifest.artifacts.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            signature: manifest.signature.clone(),
        }
    }
}

impl From<PersistedManifest> for BootChainManifest {
    fn from(manifest: PersistedManifest) -> Self {
        Self {
            boot_profile: manifest.boot_profile,
            group_id: manifest.group_id,
            version_id: manifest.version_id,
            created_at: manifest.created_at,
            artifacts: manifest.artifacts,
            manifest_digest: manifest.manifest_digest,
            signature: manifest.signature,
        }
    }
}

/// Serializable artifact-version representation stored with a release group.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedFileVersion {
    boot_profile: String,
    logical_name: String,
    path: String,
    version_id: VersionId,
    content_hash: String,
    size: u64,
}

impl From<&FileVersion> for PersistedFileVersion {
    fn from(file: &FileVersion) -> Self {
        Self {
            boot_profile: file.boot_profile.clone(),
            logical_name: file.logical_name.clone(),
            path: file.path.display().to_string(),
            version_id: file.version_id,
            content_hash: file.content_hash.clone(),
            size: file.size,
        }
    }
}

impl From<PersistedFileVersion> for FileVersion {
    fn from(file: PersistedFileVersion) -> Self {
        Self {
            boot_profile: file.boot_profile,
            logical_name: file.logical_name,
            path: PathBuf::from(file.path),
            version_id: file.version_id,
            content_hash: file.content_hash,
            size: file.size,
        }
    }
}

/// Adds operation context to a database persistence error.
fn persistence_error(context: &str, error: impl std::fmt::Display) -> TempestError {
    TempestError::Persistence(format!("{context}: {error}"))
}

/// Detects serialization, deadlock, and lock-timeout errors that require retry.
fn is_transaction_conflict(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(error) = error else {
        return false;
    };
    matches!(
        error.code().as_deref(),
        Some("40001" | "40P01" | "1205" | "1213")
    )
}

/// Decodes a typed JSON value read from a database row.
fn parse_json<T: serde::de::DeserializeOwned>(
    context: &str,
    value: &str,
) -> Result<T, TempestError> {
    serde_json::from_str(value).map_err(|e| persistence_error(context, e))
}

/// Reads a text column with a binary fallback for SQLx `Any` compatibility.
fn row_text(row: &AnyRow, column: &str) -> Result<String, TempestError> {
    if let Ok(value) = row.try_get(column) {
        return Ok(value);
    }
    String::from_utf8(
        row.try_get(column)
            .map_err(|e| persistence_error(&format!("read {column}"), e))?,
    )
    .map_err(|e| persistence_error(&format!("decode {column}"), e))
}

impl PersistenceStore {
    /// Closed pool fixture: deletion must fail closed without attempting SQL or
    /// falling back to memory-only mutation when persistence is unavailable.
    #[cfg(test)]
    pub(crate) async fn unavailable_for_deletion_test() -> Self {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/unused")
            .unwrap();
        pool.close().await;
        Self {
            pool: TracedPool::new(pool, "postgresql"),
            dialect: DatabaseDialect::Postgres,
            serving: Default::default(),
            reader_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::config::COORDINATED_DELETION_READER_LIMIT,
            )),
        }
    }

    /// Connects to a supported database and applies serialized, idempotent schema migrations.
    ///
    /// URLs must use `postgres://`, `postgresql://`, or `mysql://`; credentials
    /// remain owned by SQLx and are not included in returned errors.
    ///
    /// # Errors
    ///
    /// Returns [`TempestError::Persistence`] for invalid schemes/URLs,
    /// connection, migration, or retention failures.
    pub async fn connect(database_url: &str) -> Result<Self, TempestError> {
        let store = Self::connect_unmigrated(database_url).await?;
        store.migrate().await?;
        store.enforce_version_group_retention().await?;
        Ok(store)
    }

    async fn connect_unmigrated(database_url: &str) -> Result<Self, TempestError> {
        sqlx::any::install_default_drivers();
        let dialect = if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            DatabaseDialect::Postgres
        } else if database_url.starts_with("mysql://") {
            DatabaseDialect::MySql
        } else {
            return Err(TempestError::Persistence(
                "database_url must start with postgres://, postgresql://, or mysql://".to_string(),
            ));
        };
        let options = AnyConnectOptions::from_str(database_url)
            .map_err(|e| persistence_error("invalid database URL", e))?;
        let pool = AnyPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(|e| persistence_error("connect database", e))?;
        Ok(Self {
            pool: TracedPool::new(pool, dialect.system_name()),
            dialect,
            serving: Default::default(),
            reader_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::config::COORDINATED_DELETION_READER_LIMIT,
            )),
        })
    }

    /// Returns dialect-specific SQL for deactivating a profile's groups.
    fn deactivate_groups_sql(&self) -> &'static str {
        match self.dialect {
            DatabaseDialect::Postgres => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = $1 WHERE boot_profile = $2"
            }
            DatabaseDialect::MySql => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = ? WHERE boot_profile = ?"
            }
        }
    }

    /// Returns dialect-specific SQL for activating one release group.
    fn activate_group_sql(&self, match_digest: bool) -> &'static str {
        match (self.dialect, match_digest) {
            (DatabaseDialect::Postgres, false) => {
                "UPDATE tempest_version_groups SET active = TRUE, updated_at = $1
             WHERE boot_profile = $2 AND group_id = $3"
            }
            (DatabaseDialect::MySql, false) => {
                "UPDATE tempest_version_groups SET active = TRUE, updated_at = ?
             WHERE boot_profile = ? AND group_id = ?"
            }
            (DatabaseDialect::Postgres, true) => {
                "UPDATE tempest_version_groups SET active = TRUE, updated_at = $1
                 WHERE boot_profile = $2 AND group_id = $3 AND manifest_digest = $4"
            }
            (DatabaseDialect::MySql, true) => {
                "UPDATE tempest_version_groups SET active = TRUE, updated_at = ?
                 WHERE boot_profile = ? AND group_id = ? AND manifest_digest = ?"
            }
        }
    }

    /// Returns dialect-specific SQL for withdrawing the matching active group.
    fn withdraw_group_sql(&self, match_digest: bool) -> &'static str {
        match (self.dialect, match_digest) {
            (DatabaseDialect::Postgres, false) => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = $1
                 WHERE boot_profile = $2 AND group_id = $3 AND active = TRUE"
            }
            (DatabaseDialect::MySql, false) => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = ?
                 WHERE boot_profile = ? AND group_id = ? AND active = TRUE"
            }
            (DatabaseDialect::Postgres, true) => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = $1
                 WHERE boot_profile = $2 AND group_id = $3 AND manifest_digest = $4
                   AND active = TRUE"
            }
            (DatabaseDialect::MySql, true) => {
                "UPDATE tempest_version_groups SET active = FALSE, updated_at = ?
                 WHERE boot_profile = ? AND group_id = ? AND manifest_digest = ?
                   AND active = TRUE"
            }
        }
    }

    /// Loads the profile mutation revision, returning zero before first mutation.
    pub async fn version_revision(&self, boot_profile: &str) -> Result<i64, TempestError> {
        let sql = match self.dialect {
            DatabaseDialect::Postgres => {
                "SELECT revision FROM tempest_profile_revisions WHERE boot_profile = $1"
            }
            DatabaseDialect::MySql => {
                "SELECT revision FROM tempest_profile_revisions WHERE boot_profile = ?"
            }
        };
        sqlx::query_scalar(sql)
            .bind(boot_profile)
            .fetch_optional(&self.pool)
            .await
            .map(|revision| revision.unwrap_or(0))
            .map_err(|e| persistence_error("load version revision", e))
    }

    /// Returns the revision shared by release and boot-session snapshots.
    pub async fn state_revision(&self) -> Result<i64, TempestError> {
        sqlx::query_scalar("SELECT revision FROM tempest_state_revision WHERE singleton_id = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| persistence_error("load state revision", e))
    }

    /// Locks, validates serving admission, and advances the snapshot revision.
    async fn bump_state_revision(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<(), TempestError> {
        self.lock_state_revision(tx).await?;
        self.bump_locked_state_revision(tx).await
    }

    /// Advances the revision after this transaction already called
    /// `lock_state_revision`, avoiding a second serving-lease probe.
    async fn bump_locked_state_revision(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<(), TempestError> {
        let result = sqlx::query(
            "UPDATE tempest_state_revision SET revision = revision + 1 WHERE singleton_id = 1",
        )
        .execute(tx.executor())
        .await
        .map_err(|e| persistence_error("advance state revision", e))?;
        if result.rows_affected() != 1 {
            return Err(TempestError::Persistence(
                "state revision singleton is missing; rerun migrations".into(),
            ));
        }
        Ok(())
    }

    /// Serializes mutations that participate in coherent durable snapshots.
    async fn lock_state_revision(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<i64, TempestError> {
        let revision = self.lock_state_revision_unchecked(tx).await?;
        self.validate_serving_generation(tx).await?;
        Ok(revision)
    }

    /// Startup and exact reader cleanup must remain possible after lease loss.
    async fn lock_state_revision_unchecked(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<i64, TempestError> {
        sqlx::query_scalar(
            "SELECT revision FROM tempest_state_revision WHERE singleton_id = 1 FOR UPDATE",
        )
        .fetch_one(tx.executor())
        .await
        .map_err(|e| persistence_error("lock state revision", e))
    }

    /// Reads one committed view while excluding cooperating durable writers.
    /// Artifact hashing happens after this short, bounded read transaction.
    pub(crate) async fn load_control_snapshot(
        &self,
        max_sessions: usize,
    ) -> Result<ControlSnapshot, TempestError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin control snapshot", e))?;
        let revision = self.lock_state_revision(&mut tx).await?;
        let groups = self.load_version_groups_from(tx.executor()).await?;
        let sessions = self
            .load_boot_sessions_from(tx.executor(), max_sessions)
            .await?;
        tx.commit()
            .await
            .map_err(|e| persistence_error("finish control snapshot", e))?;
        Ok(ControlSnapshot {
            revision,
            groups,
            sessions,
        })
    }

    /// Begins a transaction and claims the expected profile revision.
    async fn begin_version_mutation(
        &self,
        boot_profile: &str,
        expected_revision: i64,
    ) -> Result<TracedTransaction<'_>, TempestError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin version mutation", e))?;
        self.lock_state_revision(&mut tx).await?;
        let (insert_sql, claim_sql) = match self.dialect {
            DatabaseDialect::Postgres => (
                "INSERT INTO tempest_profile_revisions (boot_profile, revision) VALUES ($1, 0)
                 ON CONFLICT (boot_profile) DO NOTHING",
                "UPDATE tempest_profile_revisions SET revision = revision + 1
                 WHERE boot_profile = $1 AND revision = $2",
            ),
            DatabaseDialect::MySql => (
                "INSERT IGNORE INTO tempest_profile_revisions (boot_profile, revision) VALUES (?, 0)",
                "UPDATE tempest_profile_revisions SET revision = revision + 1
                 WHERE boot_profile = ? AND revision = ?",
            ),
        };
        sqlx::query(insert_sql)
            .bind(boot_profile)
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("initialize version revision", e))?;
        let claimed = sqlx::query(claim_sql)
            .bind(boot_profile)
            .bind(expected_revision)
            .execute(tx.executor())
            .await
            .map_err(|error| {
                if is_transaction_conflict(&error) {
                    TempestError::Conflict(format!(
                        "version state changed for profile {boot_profile}; retry against the latest revision"
                    ))
                } else {
                    persistence_error("claim version revision", error)
                }
            })?;
        if claimed.rows_affected() != 1 {
            return Err(TempestError::Conflict(format!(
                "version state changed for profile {boot_profile}; retry against the latest revision"
            )));
        }
        self.bump_locked_state_revision(&mut tx).await?;
        Ok(tx)
    }

    /// Deactivates a profile's groups inside an existing mutation transaction.
    async fn deactivate_groups_in_tx(
        &self,
        tx: &mut TracedTransaction<'_>,
        boot_profile: &str,
    ) -> Result<(), TempestError> {
        sqlx::query(self.deactivate_groups_sql())
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .bind(boot_profile)
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("deactivate old version groups", e))?;

        Ok(())
    }

    /// Removes oldest inactive, unpinned rows until hydration bounds hold.
    async fn prune_version_groups_in_tx(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<bool, TempestError> {
        let (summary_sql, candidate_sql) = match self.dialect {
            DatabaseDialect::Postgres => (
                "SELECT CAST(COUNT(*) AS BIGINT) AS group_count,
                        CAST(COALESCE(SUM(OCTET_LENGTH(manifest_json) + OCTET_LENGTH(files_json)), 0) AS BIGINT) AS json_bytes,
                        CAST(COALESCE(SUM(CASE WHEN OCTET_LENGTH(manifest_json) > $1 OR OCTET_LENGTH(files_json) > $1 THEN 1 ELSE 0 END), 0) AS BIGINT) AS oversized_count
                 FROM tempest_version_groups",
                "SELECT g.boot_profile, g.group_id FROM tempest_version_groups g
                 WHERE g.active = FALSE
                                     AND NOT EXISTS (SELECT 1 FROM tempest_group_readers r WHERE r.boot_profile = g.boot_profile AND r.group_id = g.group_id)
                                     AND NOT EXISTS (SELECT 1 FROM tempest_group_deletion_reservations d WHERE d.boot_profile = g.boot_profile AND d.group_id = g.group_id)
                   AND ($2 = FALSE OR OCTET_LENGTH(g.manifest_json) > $3 OR OCTET_LENGTH(g.files_json) > $3)
                   AND NOT EXISTS (
                       SELECT 1 FROM tempest_boot_sessions s
                       WHERE s.expires_at > $1 AND s.boot_profile = g.boot_profile
                         AND s.pinned_group_id = g.group_id
                         AND s.pinned_version_id = g.version_id
                         AND s.pinned_manifest_digest = g.manifest_digest)
                 ORDER BY g.created_at ASC, g.boot_profile ASC, g.group_id ASC LIMIT 1",
            ),
            DatabaseDialect::MySql => (
                "SELECT CAST(COUNT(*) AS SIGNED) AS group_count,
                        CAST(COALESCE(SUM(OCTET_LENGTH(manifest_json) + OCTET_LENGTH(files_json)), 0) AS SIGNED) AS json_bytes,
                        CAST(COALESCE(SUM(CASE WHEN OCTET_LENGTH(manifest_json) > ? OR OCTET_LENGTH(files_json) > ? THEN 1 ELSE 0 END), 0) AS SIGNED) AS oversized_count
                 FROM tempest_version_groups",
                "SELECT g.boot_profile, g.group_id FROM tempest_version_groups g
                 WHERE g.active = FALSE
                                     AND NOT EXISTS (SELECT 1 FROM tempest_group_readers r WHERE r.boot_profile = g.boot_profile AND r.group_id = g.group_id)
                                     AND NOT EXISTS (SELECT 1 FROM tempest_group_deletion_reservations d WHERE d.boot_profile = g.boot_profile AND d.group_id = g.group_id)
                   AND (? = 0 OR OCTET_LENGTH(g.manifest_json) > ? OR OCTET_LENGTH(g.files_json) > ?)
                   AND NOT EXISTS (
                       SELECT 1 FROM tempest_boot_sessions s
                       WHERE s.expires_at > ? AND s.boot_profile = g.boot_profile
                         AND s.pinned_group_id = g.group_id
                         AND s.pinned_version_id = g.version_id
                         AND s.pinned_manifest_digest = g.manifest_digest)
                 ORDER BY g.created_at ASC, g.boot_profile ASC, g.group_id ASC LIMIT 1",
            ),
        };
        let json_limit = i64::try_from(MAX_PERSISTED_JSON_BYTES)
            .map_err(|_| TempestError::Persistence("JSON byte limit is invalid".into()))?;
        let mut pruned = false;
        loop {
            let mut summary = sqlx::query(summary_sql).bind(json_limit);
            if self.dialect == DatabaseDialect::MySql {
                summary = summary.bind(json_limit);
            }
            let summary = summary
                .fetch_one(tx.executor())
                .await
                .map_err(|e| persistence_error("inspect version group retention", e))?;
            let group_count: i64 = summary
                .try_get("group_count")
                .map_err(|e| persistence_error("read persisted group count", e))?;
            let json_bytes: i64 = summary
                .try_get("json_bytes")
                .map_err(|e| persistence_error("read persisted JSON bytes", e))?;
            let oversized_count: i64 = summary
                .try_get("oversized_count")
                .map_err(|e| persistence_error("read oversized group count", e))?;
            if group_count <= MAX_PERSISTED_GROUPS as i64
                && json_bytes <= MAX_PERSISTED_SNAPSHOT_JSON_BYTES as i64
                && oversized_count == 0
            {
                return Ok(pruned);
            }
            if self.reader_tracking_exhausted(tx).await? {
                return Err(TempestError::Conflict(
                    "durable reader tracking exhausted; release retention requires offline reader recovery"
                        .into(),
                ));
            }

            let now = crate::timestamp::to_rfc3339(jiff::Timestamp::now());
            let require_oversized = oversized_count != 0;
            let candidate = match self.dialect {
                DatabaseDialect::Postgres => sqlx::query(candidate_sql)
                    .bind(&now)
                    .bind(require_oversized)
                    .bind(json_limit),
                DatabaseDialect::MySql => sqlx::query(candidate_sql)
                    .bind(i32::from(require_oversized))
                    .bind(json_limit)
                    .bind(json_limit)
                    .bind(&now),
            };
            let Some(candidate) = candidate
                .fetch_optional(tx.executor())
                .await
                .map_err(|e| persistence_error("select version group for pruning", e))?
            else {
                return Err(TempestError::Persistence(
                    "active or pinned release history exceeds durable hydration bounds".into(),
                ));
            };
            let profile: String = candidate
                .try_get("boot_profile")
                .map_err(|e| persistence_error("read pruned boot profile", e))?;
            let group_id: String = candidate
                .try_get("group_id")
                .map_err(|e| persistence_error("read pruned group id", e))?;
            let delete_sql = match self.dialect {
                DatabaseDialect::Postgres => {
                    "DELETE FROM tempest_version_groups WHERE boot_profile = $1 AND group_id = $2 AND active = FALSE"
                }
                DatabaseDialect::MySql => {
                    "DELETE FROM tempest_version_groups WHERE boot_profile = ? AND group_id = ? AND active = FALSE"
                }
            };
            let removed = sqlx::query(delete_sql)
                .bind(profile)
                .bind(group_id)
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("prune version group", e))?
                .rows_affected();
            if removed != 1 {
                return Err(TempestError::Conflict(
                    "version group retention changed concurrently; retry".into(),
                ));
            }
            pruned = true;
        }
    }

    /// Repairs legacy durable history before hydration.
    async fn enforce_version_group_retention(&self) -> Result<(), TempestError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin version retention", e))?;
        self.lock_state_revision(&mut tx).await?;
        if self.prune_version_groups_in_tx(&mut tx).await? {
            self.bump_locked_state_revision(&mut tx).await?;
        }
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit version retention", e))
    }

    /// Serializes schema migration with a database-scoped advisory lock.
    async fn migrate(&self) -> Result<(), TempestError> {
        let mut lock_connection = self
            .pool
            .acquire()
            .await
            .map_err(|e| persistence_error("acquire migration lock connection", e))?;
        match self.dialect {
            DatabaseDialect::Postgres => {
                sqlx::query(
                    "SELECT pg_advisory_lock(hashtext('tempest_schema_migration')::bigint)",
                )
                .execute(lock_connection.executor())
                .await
                .map_err(|e| persistence_error("acquire PostgreSQL migration lock", e))?;
            }
            DatabaseDialect::MySql => {
                let acquired: Option<i64> =
                    sqlx::query_scalar("SELECT GET_LOCK('tempest_schema_migration', 30)")
                        .fetch_one(lock_connection.executor())
                        .await
                        .map_err(|e| persistence_error("acquire MySQL migration lock", e))?;
                if acquired != Some(1) {
                    return Err(TempestError::Persistence(
                        "timed out acquiring MySQL migration lock".into(),
                    ));
                }
            }
        }

        let migration_result = self.migrate_locked().await;
        let unlock_result = match self.dialect {
            DatabaseDialect::Postgres => sqlx::query(
                "SELECT pg_advisory_unlock(hashtext('tempest_schema_migration')::bigint)",
            )
            .execute(lock_connection.executor())
            .await
            .map(|_| ())
            .map_err(|e| persistence_error("release PostgreSQL migration lock", e)),
            DatabaseDialect::MySql => {
                sqlx::query("SELECT RELEASE_LOCK('tempest_schema_migration')")
                    .execute(lock_connection.executor())
                    .await
                    .map(|_| ())
                    .map_err(|e| persistence_error("release MySQL migration lock", e))
            }
        };

        migration_result?;
        unlock_result
    }

    /// Creates or upgrades schema objects while the migration lock is held.
    async fn migrate_locked(&self) -> Result<(), TempestError> {
        sqlx::query(&version_group_table_sql(self.dialect))
            .execute(&self.pool)
            .await
            .map_err(|e| persistence_error("migrate tempest_version_groups", e))?;
        if self.dialect == DatabaseDialect::MySql
            && self
                .mysql_version_group_json_columns_need_widening()
                .await?
        {
            sqlx::query(
                "ALTER TABLE tempest_version_groups
                 MODIFY COLUMN manifest_json MEDIUMTEXT NOT NULL,
                 MODIFY COLUMN files_json MEDIUMTEXT NOT NULL",
            )
            .execute(&self.pool)
            .await
            .map_err(|e| persistence_error("widen version group JSON columns", e))?;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tempest_boot_sessions (
                client_ip VARCHAR(64) NOT NULL PRIMARY KEY,
                boot_profile VARCHAR(64) NOT NULL,
                client_mac VARCHAR(32) NULL,
                serial VARCHAR(128) NULL,
                trace_id VARCHAR(128) NULL,
                boot_epoch BIGINT NOT NULL DEFAULT 1,
                pinned_group_id VARCHAR(128) NULL,
                pinned_version_id BIGINT NULL,
                pinned_manifest_digest VARCHAR(128) NULL,
                artifact_token_hash VARCHAR(64) NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("migrate tempest_boot_sessions", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tempest_profile_revisions (
                boot_profile VARCHAR(64) NOT NULL PRIMARY KEY,
                revision BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("migrate tempest_profile_revisions", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tempest_state_revision (
                singleton_id INTEGER NOT NULL PRIMARY KEY,
                revision BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("migrate tempest_state_revision", e))?;
        let initialize_revision = match self.dialect {
            DatabaseDialect::Postgres => {
                "INSERT INTO tempest_state_revision (singleton_id, revision) VALUES (1, 0)
                 ON CONFLICT (singleton_id) DO NOTHING"
            }
            DatabaseDialect::MySql => {
                "INSERT IGNORE INTO tempest_state_revision (singleton_id, revision) VALUES (1, 0)"
            }
        };
        sqlx::query(initialize_revision)
            .execute(&self.pool)
            .await
            .map_err(|e| persistence_error("initialize tempest_state_revision", e))?;

        self.ensure_boot_session_columns().await?;
        self.migrate_deletion_coordination().await?;

        Ok(())
    }

    async fn mysql_version_group_json_columns_need_widening(&self) -> Result<bool, TempestError> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS count FROM information_schema.columns
             WHERE table_schema = DATABASE()
               AND table_name = 'tempest_version_groups'
               AND column_name IN ('manifest_json', 'files_json')
               AND data_type = 'mediumtext'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| persistence_error("inspect version group JSON columns", e))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|e| persistence_error("read version group JSON column count", e))?;
        Ok(count != 2)
    }

    /// Adds boot-session pin columns missing from an older schema.
    async fn ensure_boot_session_columns(&self) -> Result<(), TempestError> {
        let columns = [
            ("boot_epoch", "BIGINT NOT NULL DEFAULT 1"),
            ("pinned_group_id", "VARCHAR(128) NULL"),
            ("pinned_version_id", "BIGINT NULL"),
            ("pinned_manifest_digest", "VARCHAR(128) NULL"),
            ("artifact_token_hash", "VARCHAR(64) NULL"),
        ];

        for (column, definition) in columns {
            if !self.boot_session_column_exists(column).await? {
                let sql =
                    format!("ALTER TABLE tempest_boot_sessions ADD COLUMN {column} {definition}");
                sqlx::query(&sql).execute(&self.pool).await.map_err(|e| {
                    persistence_error(format!("add boot session column {column}").as_str(), e)
                })?;
            }
        }

        Ok(())
    }

    /// Checks schema metadata for one boot-session column.
    async fn boot_session_column_exists(&self, column: &str) -> Result<bool, TempestError> {
        let sql = match self.dialect {
            DatabaseDialect::Postgres => {
                "SELECT COUNT(*) AS count FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'tempest_boot_sessions'
                   AND column_name = $1"
            }
            DatabaseDialect::MySql => {
                "SELECT COUNT(*) AS count FROM information_schema.columns
                 WHERE table_schema = DATABASE()
                   AND table_name = 'tempest_boot_sessions'
                   AND column_name = ?"
            }
        };

        let row = sqlx::query(sql)
            .bind(column)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| persistence_error("check boot session column", e))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|e| persistence_error("read boot session column count", e))?;
        Ok(count > 0)
    }

    /// Atomically deactivates prior groups and inserts `group` as active.
    ///
    /// # Errors
    ///
    /// Returns [`TempestError::Conflict`] if `expected_revision` is stale, or a
    /// persistence error for serialization, query, or commit failure.
    pub async fn persist_version_group(
        &self,
        group: &VersionGroup,
        expected_revision: i64,
    ) -> Result<(), TempestError> {
        let manifest = PersistedManifest::from(&group.manifest);
        let files: Vec<PersistedFileVersion> = group.files.iter().map(Into::into).collect();
        let manifest_json = serde_json::to_string(&manifest)
            .map_err(|e| persistence_error("serialize manifest", e))?;
        let files_json =
            serde_json::to_string(&files).map_err(|e| persistence_error("serialize files", e))?;
        if manifest_json.len() > MAX_PERSISTED_JSON_BYTES
            || files_json.len() > MAX_PERSISTED_JSON_BYTES
        {
            return Err(TempestError::Persistence(format!(
                "version group JSON exceeds {MAX_PERSISTED_JSON_BYTES} bytes"
            )));
        }

        let mut tx = self
            .begin_version_mutation(&group.boot_profile, expected_revision)
            .await?;
        self.reject_reserved_group(&mut tx, &group.boot_profile, &group.group_id)
            .await?;
        self.remember_managed_names(
            &mut tx,
            &group
                .files
                .iter()
                .map(|file| file.logical_name.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        self.deactivate_groups_in_tx(&mut tx, &group.boot_profile)
            .await?;

        let insert_sql = match self.dialect {
            DatabaseDialect::Postgres => {
                "INSERT INTO tempest_version_groups
                (boot_profile, group_id, version_id, created_at, manifest_digest,
                 manifest_signature, manifest_json, files_json, active, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9)"
            }
            DatabaseDialect::MySql => {
                "INSERT INTO tempest_version_groups
                (boot_profile, group_id, version_id, created_at, manifest_digest,
                 manifest_signature, manifest_json, files_json, active, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?)"
            }
        };

        sqlx::query(insert_sql)
            .bind(&group.boot_profile)
            .bind(&group.group_id)
            .bind(group.version_id as i64)
            .bind(crate::timestamp::to_rfc3339(group.created_at))
            .bind(&group.manifest.manifest_digest)
            .bind(&group.manifest.signature)
            .bind(manifest_json)
            .bind(files_json)
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .execute(tx.executor())
            .await
            .map_err(|error| match &error {
                sqlx::Error::Database(error) if error.is_unique_violation() => {
                    TempestError::Conflict(format!(
                        "group ID already exists for profile {}: {}",
                        group.boot_profile, group.group_id
                    ))
                }
                _ => persistence_error("persist version group", error),
            })?;

        self.prune_version_groups_in_tx(&mut tx).await?;

        tx.commit()
            .await
            .map_err(|e| persistence_error("commit version group transaction", e))?;

        Ok(())
    }

    /// Atomically activates a historical group under revision CAS protection.
    ///
    /// `expected_active_group`, when supplied, must still be active in the same
    /// transaction; otherwise a conflict is returned.
    pub async fn rollback_version_group(
        &self,
        boot_profile: &str,
        group_id: &str,
        manifest_digest: Option<&str>,
        expected_revision: i64,
        expected_active_group: Option<&str>,
        expected_active_manifest_digest: Option<&str>,
    ) -> Result<(), TempestError> {
        let mut tx = self
            .begin_version_mutation(boot_profile, expected_revision)
            .await?;

        self.reject_reserved_group(&mut tx, boot_profile, group_id)
            .await?;
        if let Some(active_group) = expected_active_group {
            let mut query =
                sqlx::query(self.withdraw_group_sql(expected_active_manifest_digest.is_some()))
                    .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
                    .bind(boot_profile)
                    .bind(active_group);
            if let Some(digest) = expected_active_manifest_digest {
                query = query.bind(digest);
            }
            let result = query
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("verify active version group", e))?;
            if result.rows_affected() != 1 {
                return Err(TempestError::Conflict(format!(
                    "active version changed for profile {boot_profile}; retry against durable state"
                )));
            }
        }

        self.deactivate_groups_in_tx(&mut tx, boot_profile).await?;

        let mut query = sqlx::query(self.activate_group_sql(manifest_digest.is_some()))
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .bind(boot_profile)
            .bind(group_id);
        if let Some(digest) = manifest_digest {
            query = query.bind(digest);
        }
        let result = query
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("persist rollback", e))?;

        if result.rows_affected() == 0 {
            return Err(TempestError::Persistence(format!(
                "cannot persist rollback; group not found for profile {boot_profile}: {group_id}"
            )));
        }

        tx.commit()
            .await
            .map_err(|e| persistence_error("commit rollback transaction", e))?;

        Ok(())
    }

    /// Atomically deactivates the named active group under revision CAS protection.
    pub async fn withdraw_version_group(
        &self,
        boot_profile: &str,
        group_id: &str,
        manifest_digest: Option<&str>,
        expected_revision: i64,
    ) -> Result<(), TempestError> {
        let mut tx = self
            .begin_version_mutation(boot_profile, expected_revision)
            .await?;
        self.reject_reserved_group(&mut tx, boot_profile, group_id)
            .await?;
        let mut query = sqlx::query(self.withdraw_group_sql(manifest_digest.is_some()))
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .bind(boot_profile)
            .bind(group_id);
        if let Some(digest) = manifest_digest {
            query = query.bind(digest);
        }
        let result = query
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("withdraw version group", e))?;
        if result.rows_affected() == 0 {
            return Err(TempestError::Conflict(format!(
                "active version changed for profile {boot_profile}; retry against durable state"
            )));
        }
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit version withdrawal", e))?;
        Ok(())
    }

    /// Loads a bounded persisted group snapshot in profile/version order.
    ///
    /// Cryptographic and filesystem validation is performed by the receiving
    /// [`crate::features::versioning::VersionStore`] before activation.
    pub async fn load_version_groups(&self) -> Result<Vec<(VersionGroup, bool)>, TempestError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|e| persistence_error("acquire version snapshot connection", e))?;
        self.load_version_groups_from(connection.executor()).await
    }

    async fn load_version_groups_from<'e, E>(
        &self,
        connection: E,
    ) -> Result<Vec<(VersionGroup, bool)>, TempestError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Any>,
    {
        let sql = match self.dialect {
            DatabaseDialect::Postgres => {
                "SELECT boot_profile, group_id, version_id, created_at,
                        LEFT(manifest_json, $1) AS manifest_json,
                        LEFT(files_json, $1) AS files_json,
                        CASE WHEN active THEN CAST(1 AS BIGINT) ELSE CAST(0 AS BIGINT) END AS active
                 FROM tempest_version_groups
                 ORDER BY active DESC, updated_at DESC LIMIT $2"
            }
            DatabaseDialect::MySql => {
                "SELECT boot_profile, group_id, version_id, created_at,
                        LEFT(manifest_json, ?) AS manifest_json,
                        LEFT(files_json, ?) AS files_json,
                        CAST(active AS SIGNED) AS active
                 FROM tempest_version_groups
                 ORDER BY active DESC, updated_at DESC LIMIT ?"
            }
        };
        let json_fetch_bytes = i32::try_from(MAX_PERSISTED_JSON_BYTES + 1)
            .map_err(|_| TempestError::Persistence("JSON byte limit is invalid".into()))?;
        let group_fetch_limit = i64::try_from(MAX_PERSISTED_GROUPS + 1)
            .map_err(|_| TempestError::Persistence("group limit is invalid".into()))?;
        let mut query = sqlx::query(sql).bind(json_fetch_bytes);
        if self.dialect == DatabaseDialect::MySql {
            query = query.bind(json_fetch_bytes);
        }
        let rows = query
            .bind(group_fetch_limit)
            .fetch_all(connection)
            .await
            .map_err(|e| persistence_error("load version groups", e))?;
        if rows.len() > MAX_PERSISTED_GROUPS {
            return Err(TempestError::Persistence(format!(
                "durable version groups exceed supported limit {MAX_PERSISTED_GROUPS}"
            )));
        }

        let mut total_json_bytes = 0usize;
        let mut groups = Vec::with_capacity(rows.len());
        for row in rows {
            let manifest_json = row_text(&row, "manifest_json")?;
            let files_json = row_text(&row, "files_json")?;
            if manifest_json.len() > MAX_PERSISTED_JSON_BYTES
                || files_json.len() > MAX_PERSISTED_JSON_BYTES
            {
                return Err(TempestError::Persistence(format!(
                    "persisted group JSON exceeds {MAX_PERSISTED_JSON_BYTES} bytes"
                )));
            }
            total_json_bytes = total_json_bytes
                .checked_add(manifest_json.len())
                .and_then(|value| value.checked_add(files_json.len()))
                .ok_or_else(|| TempestError::Persistence("snapshot byte count overflow".into()))?;
            if total_json_bytes > MAX_PERSISTED_SNAPSHOT_JSON_BYTES {
                return Err(TempestError::Persistence(format!(
                    "persisted group snapshot exceeds {MAX_PERSISTED_SNAPSHOT_JSON_BYTES} JSON bytes"
                )));
            }
            groups.push(Self::version_group_from_row(
                row,
                manifest_json,
                files_json,
            )?);
        }
        groups.sort_by(|(left, _), (right, _)| {
            left.boot_profile
                .cmp(&right.boot_profile)
                .then_with(|| left.version_id.cmp(&right.version_id))
        });
        Ok(groups)
    }

    /// Hydrates one persisted group row and its active-state flag.
    fn version_group_from_row(
        row: AnyRow,
        manifest_json: String,
        files_json: String,
    ) -> Result<(VersionGroup, bool), TempestError> {
        let boot_profile: String = row
            .try_get("boot_profile")
            .map_err(|e| persistence_error("read boot_profile", e))?;
        let group_id: String = row
            .try_get("group_id")
            .map_err(|e| persistence_error("read group_id", e))?;
        let version_id: i64 = row
            .try_get("version_id")
            .map_err(|e| persistence_error("read version_id", e))?;
        let created_at = row_text(&row, "created_at")?;
        let active: i64 = row
            .try_get("active")
            .map_err(|e| persistence_error("read active", e))?;

        let manifest: BootChainManifest =
            parse_json::<PersistedManifest>("parse manifest_json", &manifest_json)?.into();
        let persisted_files =
            parse_json::<Vec<PersistedFileVersion>>("parse files_json", &files_json)?;
        if persisted_files.len() > MAX_PERSISTED_FILES_PER_GROUP
            || manifest.artifacts.len() > MAX_PERSISTED_FILES_PER_GROUP
        {
            return Err(TempestError::Persistence(format!(
                "persisted group exceeds {MAX_PERSISTED_FILES_PER_GROUP} artifacts"
            )));
        }
        let files: Vec<FileVersion> = persisted_files.into_iter().map(Into::into).collect();
        let created_at = created_at
            .parse::<jiff::Timestamp>()
            .map_err(|e| persistence_error("parse created_at", e))?;

        Ok((
            VersionGroup {
                boot_profile,
                group_id,
                version_id: u64::try_from(version_id).map_err(|_| {
                    persistence_error("load version groups", "version id must be non-negative")
                })?,
                files,
                created_at,
                manifest,
            },
            active != 0,
        ))
    }

    /// Upserts a source-IP boot session, translating monotonic TTL to UTC expiry.
    ///
    /// The entire session, including any release pin, replaces the prior row.
    pub async fn persist_boot_session(
        &self,
        client_ip: IpAddr,
        entry: &BootSessionEntry,
    ) -> Result<(), TempestError> {
        self.persist_boot_sessions(&[(client_ip, entry.clone())])
            .await
    }

    /// One bounded, atomic upsert and revision increment for independently validated clients.
    pub(crate) async fn persist_boot_sessions(
        &self,
        entries: &[(IpAddr, BootSessionEntry)],
    ) -> Result<(), TempestError> {
        self.persist_boot_sessions_inner(entries, None).await
    }

    /// Rejects stale issuers before replacing any session in the batch.
    pub(crate) async fn persist_boot_sessions_if_unchanged(
        &self,
        entries: &[(IpAddr, BootSessionEntry)],
        expected: &[(IpAddr, Option<BootSessionEntry>)],
    ) -> Result<(), TempestError> {
        self.persist_boot_sessions_inner(entries, Some(expected))
            .await
    }

    async fn persist_boot_sessions_inner(
        &self,
        entries: &[(IpAddr, BootSessionEntry)],
        expected: Option<&[(IpAddr, Option<BootSessionEntry>)]>,
    ) -> Result<(), TempestError> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries.len() > 32
            || entries
                .iter()
                .map(|(ip, _)| ip)
                .collect::<std::collections::HashSet<_>>()
                .len()
                != entries.len()
        {
            return Err(TempestError::Persistence(
                "Session batch must contain at most 32 unique clients".into(),
            ));
        }
        let template = match self.dialect {
            DatabaseDialect::Postgres => {
                "INSERT INTO tempest_boot_sessions
                (client_ip, boot_profile, client_mac, serial, trace_id, boot_epoch,
                 pinned_group_id, pinned_version_id, pinned_manifest_digest, artifact_token_hash,
                 expires_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (client_ip) DO UPDATE SET
                boot_profile = excluded.boot_profile,
                client_mac = excluded.client_mac,
                serial = excluded.serial,
                trace_id = excluded.trace_id,
                boot_epoch = excluded.boot_epoch,
                pinned_group_id = excluded.pinned_group_id,
                pinned_version_id = excluded.pinned_version_id,
                pinned_manifest_digest = excluded.pinned_manifest_digest,
                artifact_token_hash = excluded.artifact_token_hash,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at"
            }
            DatabaseDialect::MySql => {
                "INSERT INTO tempest_boot_sessions
                (client_ip, boot_profile, client_mac, serial, trace_id, boot_epoch,
                 pinned_group_id, pinned_version_id, pinned_manifest_digest, artifact_token_hash,
                 expires_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                boot_profile = VALUES(boot_profile),
                client_mac = VALUES(client_mac),
                serial = VALUES(serial),
                trace_id = VALUES(trace_id),
                boot_epoch = VALUES(boot_epoch),
                pinned_group_id = VALUES(pinned_group_id),
                pinned_version_id = VALUES(pinned_version_id),
                pinned_manifest_digest = VALUES(pinned_manifest_digest),
                artifact_token_hash = VALUES(artifact_token_hash),
                expires_at = VALUES(expires_at),
                updated_at = VALUES(updated_at)"
            }
        };
        let values = (0..entries.len())
            .map(|row| {
                let columns = (1..=12)
                    .map(|column| match self.dialect {
                        DatabaseDialect::Postgres => format!("${}", row * 12 + column),
                        DatabaseDialect::MySql => "?".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("({columns})")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let first_row = match self.dialect {
            DatabaseDialect::Postgres => "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            DatabaseDialect::MySql => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        };
        // Only generated placeholders are interpolated; every value remains bound.
        let upsert_sql = template.replacen(first_row, &values, 1);
        let pinned_groups: Vec<_> = entries
            .iter()
            .filter_map(|(_, entry)| entry.pinned_boot_chain.as_ref())
            .map(|pin| (pin.boot_profile.as_str(), pin.group_id.as_str()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut query = sqlx::query(&upsert_sql);
        let now = jiff::Timestamp::now();
        for (client_ip, entry) in entries {
            let ttl = entry.expires_at.saturating_duration_since(Instant::now());
            let expires_at = now + ttl;
            let epoch = i64::try_from(entry.boot_epoch).map_err(|_| {
                TempestError::Persistence("boot epoch exceeds database range".into())
            })?;
            let pin = entry.pinned_boot_chain.as_ref();
            let version = pin
                .map(|pin| i64::try_from(pin.version_id))
                .transpose()
                .map_err(|_| {
                    TempestError::Persistence("pinned version exceeds database range".into())
                })?;
            query = query
                .bind(client_ip.to_string())
                .bind(&entry.boot_profile)
                .bind(&entry.client_mac)
                .bind(&entry.serial)
                .bind(&entry.trace_id)
                .bind(epoch)
                .bind(pin.map(|pin| pin.group_id.as_str()))
                .bind(version)
                .bind(pin.map(|pin| pin.manifest_digest.as_str()))
                .bind(entry.artifact_token_hash.map(hex::encode))
                .bind(crate::timestamp::to_rfc3339(expires_at))
                .bind(crate::timestamp::to_rfc3339(now));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin boot session mutation", e))?;
        self.bump_state_revision(&mut tx).await?;
        self.reject_reserved_groups(&mut tx, &pinned_groups).await?;
        if let Some(expected) = expected {
            self.check_session_preconditions(&mut tx, entries, expected)
                .await?;
        }
        query
            .execute(tx.executor())
            .await
            .map_err(|error| persistence_error("persist boot session batch", error))?;
        tx.commit()
            .await
            .map_err(|error| persistence_error("commit boot session mutation", error))?;
        Ok(())
    }

    /// The revision update already holds the global durable mutation lock.
    /// Use current reads on MySQL too, so an older transaction snapshot cannot
    /// authorize an overwrite after another issuer has committed.
    async fn check_session_preconditions(
        &self,
        tx: &mut TracedTransaction<'_>,
        entries: &[(IpAddr, BootSessionEntry)],
        expected: &[(IpAddr, Option<BootSessionEntry>)],
    ) -> Result<(), TempestError> {
        if entries.len() != expected.len()
            || entries
                .iter()
                .zip(expected)
                .any(|((ip, _), (expected_ip, _))| ip != expected_ip)
        {
            return Err(TempestError::Persistence(
                "invalid session preconditions".into(),
            ));
        }
        let (session_sql, release_sql) = match self.dialect {
            DatabaseDialect::Postgres => (
                "SELECT boot_profile, boot_epoch, artifact_token_hash, pinned_group_id,
                 pinned_version_id, pinned_manifest_digest FROM tempest_boot_sessions
                 WHERE client_ip = $1 AND expires_at > $2 FOR UPDATE",
                "SELECT group_id, version_id, manifest_digest FROM tempest_version_groups
                 WHERE boot_profile = $1 AND active = TRUE FOR UPDATE",
            ),
            DatabaseDialect::MySql => (
                "SELECT boot_profile, boot_epoch, artifact_token_hash, pinned_group_id,
                 pinned_version_id, pinned_manifest_digest FROM tempest_boot_sessions
                 WHERE client_ip = ? AND expires_at > ? FOR UPDATE",
                "SELECT group_id, version_id, manifest_digest FROM tempest_version_groups
                 WHERE boot_profile = ? AND active = TRUE FOR UPDATE",
            ),
        };
        let now = crate::timestamp::to_rfc3339(jiff::Timestamp::now());
        for ((ip, entry), (_, previous)) in entries.iter().zip(expected) {
            let current = sqlx::query(session_sql)
                .bind(ip.to_string())
                .bind(&now)
                .fetch_optional(tx.executor())
                .await
                .map_err(|e| persistence_error("check session identity", e))?;
            let matches = match (current.as_ref(), previous.as_ref()) {
                (None, None) => true,
                (Some(row), Some(previous)) => {
                    let profile: String = row
                        .try_get("boot_profile")
                        .map_err(|e| persistence_error("read session profile", e))?;
                    let epoch: i64 = row
                        .try_get("boot_epoch")
                        .map_err(|e| persistence_error("read session epoch", e))?;
                    let token: Option<String> = row
                        .try_get("artifact_token_hash")
                        .map_err(|e| persistence_error("read session token", e))?;
                    let group: Option<String> = row
                        .try_get("pinned_group_id")
                        .map_err(|e| persistence_error("read session group", e))?;
                    let version: Option<i64> = row
                        .try_get("pinned_version_id")
                        .map_err(|e| persistence_error("read session version", e))?;
                    let digest: Option<String> = row
                        .try_get("pinned_manifest_digest")
                        .map_err(|e| persistence_error("read session digest", e))?;
                    let pin = previous.pinned_boot_chain.as_ref();
                    profile == previous.boot_profile
                        && u64::try_from(epoch).ok() == Some(previous.boot_epoch)
                        && token == previous.artifact_token_hash.map(hex::encode)
                        && group.as_deref() == pin.map(|pin| pin.group_id.as_str())
                        && version.and_then(|v| u64::try_from(v).ok())
                            == pin.map(|pin| pin.version_id)
                        && digest.as_deref() == pin.map(|pin| pin.manifest_digest.as_str())
                }
                _ => false,
            };
            if !matches {
                return Err(TempestError::Conflict(
                    "durable boot session changed".into(),
                ));
            }
            let retains_pin = previous.as_ref().is_some_and(|previous| {
                previous.boot_epoch == entry.boot_epoch
                    && previous.boot_profile == entry.boot_profile
                    && previous.pinned_boot_chain.is_some()
                    && previous.pinned_boot_chain == entry.pinned_boot_chain
            });
            if retains_pin {
                continue;
            }
            let active = sqlx::query(release_sql)
                .bind(&entry.boot_profile)
                .fetch_optional(tx.executor())
                .await
                .map_err(|e| persistence_error("check active session release", e))?;
            let matches = match (active, entry.pinned_boot_chain.as_ref()) {
                (None, None) => true,
                (Some(row), Some(pin)) => {
                    let group: String = row
                        .try_get("group_id")
                        .map_err(|e| persistence_error("read active group", e))?;
                    let version: i64 = row
                        .try_get("version_id")
                        .map_err(|e| persistence_error("read active version", e))?;
                    let digest: String = row
                        .try_get("manifest_digest")
                        .map_err(|e| persistence_error("read active digest", e))?;
                    group == pin.group_id
                        && u64::try_from(version).ok() == Some(pin.version_id)
                        && digest == pin.manifest_digest
                }
                _ => false,
            };
            if !matches {
                return Err(TempestError::Conflict(
                    "durable active release changed".into(),
                ));
            }
        }
        Ok(())
    }

    /// Sets a live session's first pin to an exact, durably active release.
    ///
    /// The shared revision mutation lock serializes release validation and the
    /// session CAS with cooperating durable writers. This does not coordinate
    /// node-local transfer pins or authorize SQL-backed deletion.
    /// Returns `false` when the release changed, or the session changed, expired,
    /// was already pinned, or vanished. Rejections do not advance the revision.
    pub async fn pin_boot_session(
        &self,
        client_ip: IpAddr,
        boot_epoch: u64,
        pin: &BootChainPin,
    ) -> Result<bool, TempestError> {
        let (release_sql, sql) = match self.dialect {
            DatabaseDialect::Postgres => (
                "SELECT group_id FROM tempest_version_groups
                 WHERE boot_profile = $1 AND group_id = $2 AND version_id = $3
                   AND manifest_digest = $4 AND active = TRUE FOR UPDATE",
                "UPDATE tempest_boot_sessions SET pinned_group_id = $1,
                 pinned_version_id = $2, pinned_manifest_digest = $3, updated_at = $4
                 WHERE client_ip = $5 AND boot_profile = $6 AND boot_epoch = $7
                   AND pinned_group_id IS NULL AND pinned_version_id IS NULL
                   AND pinned_manifest_digest IS NULL AND expires_at > $4",
            ),
            DatabaseDialect::MySql => (
                "SELECT group_id FROM tempest_version_groups
                 WHERE boot_profile = ? AND group_id = ? AND version_id = ?
                   AND manifest_digest = ? AND active = TRUE FOR UPDATE",
                "UPDATE tempest_boot_sessions SET pinned_group_id = ?,
                 pinned_version_id = ?, pinned_manifest_digest = ?, updated_at = ?
                 WHERE client_ip = ? AND boot_profile = ? AND boot_epoch = ?
                   AND pinned_group_id IS NULL AND pinned_version_id IS NULL
                   AND pinned_manifest_digest IS NULL AND expires_at > ?",
            ),
        };
        let epoch = i64::try_from(boot_epoch)
            .map_err(|_| TempestError::Persistence("boot epoch exceeds database range".into()))?;
        let version = i64::try_from(pin.version_id).map_err(|_| {
            TempestError::Persistence("pinned version exceeds database range".into())
        })?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin boot session pin", e))?;
        self.bump_state_revision(&mut tx).await?;
        self.reject_reserved_group(&mut tx, &pin.boot_profile, &pin.group_id)
            .await?;
        // A locking/current read also avoids an older MySQL repeatable-read
        // snapshot authorizing a stale selection after waiting for a writer.
        if sqlx::query(release_sql)
            .bind(&pin.boot_profile)
            .bind(&pin.group_id)
            .bind(version)
            .bind(&pin.manifest_digest)
            .fetch_optional(tx.executor())
            .await
            .map_err(|e| persistence_error("check first pin release identity", e))?
            .is_none()
        {
            return Ok(false);
        }
        // Sample time after acquiring the mutation lock, not before waiting.
        let now = crate::timestamp::to_rfc3339(jiff::Timestamp::now());
        let mut query = sqlx::query(sql)
            .bind(&pin.group_id)
            .bind(version)
            .bind(&pin.manifest_digest)
            .bind(&now)
            .bind(client_ip.to_string())
            .bind(&pin.boot_profile)
            .bind(epoch);
        if self.dialect == DatabaseDialect::MySql {
            query = query.bind(&now);
        }
        let pinned = query
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("pin boot session", e))?
            .rows_affected()
            == 1;
        if pinned {
            tx.commit()
                .await
                .map_err(|e| persistence_error("commit boot session pin", e))?;
        }
        Ok(pinned)
    }

    /// Deletes the boot session keyed by source IP; absence is not an error.
    pub async fn delete_boot_session(&self, client_ip: IpAddr) -> Result<(), TempestError> {
        let sql = match self.dialect {
            DatabaseDialect::Postgres => "DELETE FROM tempest_boot_sessions WHERE client_ip = $1",
            DatabaseDialect::MySql => "DELETE FROM tempest_boot_sessions WHERE client_ip = ?",
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin boot session deletion", e))?;
        self.lock_state_revision(&mut tx).await?;
        let removed = sqlx::query(sql)
            .bind(client_ip.to_string())
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("delete boot session", e))?
            .rows_affected();
        if removed != 0 {
            self.bump_locked_state_revision(&mut tx).await?;
        }
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit boot session deletion", e))?;
        Ok(())
    }

    /// Revokes a matching capability under the same durable lock as registration.
    /// Returns false for a replacement token; absence is an idempotent success.
    pub async fn delete_boot_session_with_token(
        &self,
        client_ip: IpAddr,
        token_hash: &[u8; 32],
    ) -> Result<bool, TempestError> {
        let (select_sql, delete_sql) = match self.dialect {
            DatabaseDialect::Postgres => (
                "SELECT artifact_token_hash FROM tempest_boot_sessions WHERE client_ip = $1",
                "DELETE FROM tempest_boot_sessions WHERE client_ip = $1 AND artifact_token_hash = $2",
            ),
            DatabaseDialect::MySql => (
                "SELECT artifact_token_hash FROM tempest_boot_sessions WHERE client_ip = ? FOR UPDATE",
                "DELETE FROM tempest_boot_sessions WHERE client_ip = ? AND artifact_token_hash = ?",
            ),
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin token-matched session deletion", e))?;
        self.lock_state_revision(&mut tx).await?;
        let current = sqlx::query(select_sql)
            .bind(client_ip.to_string())
            .fetch_optional(tx.executor())
            .await
            .map_err(|e| persistence_error("read session deletion identity", e))?;
        let Some(current) = current else {
            return Ok(true);
        };
        let current_hash: Option<String> = current
            .try_get("artifact_token_hash")
            .map_err(|e| persistence_error("read session deletion token", e))?;
        let expected_hash = hex::encode(token_hash);
        if current_hash.as_deref() != Some(expected_hash.as_str()) {
            return Ok(false);
        }
        let removed = sqlx::query(delete_sql)
            .bind(client_ip.to_string())
            .bind(expected_hash)
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("delete matching boot session", e))?
            .rows_affected();
        if removed != 1 {
            return Ok(false);
        }
        self.bump_locked_state_revision(&mut tx).await?;
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit matching boot session deletion", e))?;
        Ok(true)
    }

    /// Deletes sessions whose stored UTC expiration is not later than now.
    pub async fn prune_expired_boot_sessions(&self) -> Result<(), TempestError> {
        let sql = match self.dialect {
            DatabaseDialect::Postgres => "DELETE FROM tempest_boot_sessions WHERE expires_at <= $1",
            DatabaseDialect::MySql => "DELETE FROM tempest_boot_sessions WHERE expires_at <= ?",
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin boot session pruning", e))?;
        self.lock_state_revision(&mut tx).await?;
        let removed = sqlx::query(sql)
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("prune boot sessions", e))?
            .rows_affected();
        if removed != 0 {
            self.bump_locked_state_revision(&mut tx).await?;
        }
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit boot session pruning", e))?;
        Ok(())
    }

    /// Loads unexpired sessions and reconstructs remaining monotonic TTLs.
    ///
    /// Malformed addresses, timestamps, epochs, or partial release pins fail the
    /// complete load rather than hydrating ambiguous authorization state.
    pub async fn load_boot_sessions(
        &self,
        max_sessions: usize,
    ) -> Result<Vec<(IpAddr, BootSessionEntry)>, TempestError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|e| persistence_error("acquire session snapshot connection", e))?;
        self.load_boot_sessions_from(connection.executor(), max_sessions)
            .await
    }

    async fn load_boot_sessions_from<'e, E>(
        &self,
        connection: E,
        max_sessions: usize,
    ) -> Result<Vec<(IpAddr, BootSessionEntry)>, TempestError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Any>,
    {
        let max_sessions = max_sessions.max(1);
        let fetch_limit = i64::try_from(max_sessions.saturating_add(1)).map_err(|_| {
            TempestError::Persistence("boot session limit exceeds database range".into())
        })?;
        let sql = match self.dialect {
            DatabaseDialect::Postgres => {
                "SELECT client_ip, boot_profile, client_mac, serial, trace_id, boot_epoch,
                    pinned_group_id, pinned_version_id, pinned_manifest_digest,
                    artifact_token_hash, expires_at
             FROM tempest_boot_sessions
             WHERE expires_at > $1
             ORDER BY expires_at DESC
             LIMIT $2"
            }
            DatabaseDialect::MySql => {
                "SELECT client_ip, boot_profile, client_mac, serial, trace_id, boot_epoch,
                    pinned_group_id, pinned_version_id, pinned_manifest_digest,
                    artifact_token_hash, expires_at
             FROM tempest_boot_sessions
             WHERE expires_at > ?
             ORDER BY expires_at DESC
             LIMIT ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(crate::timestamp::to_rfc3339(jiff::Timestamp::now()))
            .bind(fetch_limit)
            .fetch_all(connection)
            .await
            .map_err(|e| persistence_error("load boot sessions", e))?;
        if rows.len() > max_sessions {
            return Err(TempestError::Persistence(format!(
                "durable boot sessions exceed configured limit {max_sessions}"
            )));
        }

        rows.into_iter()
            .map(|row| {
                let client_ip: String = row
                    .try_get("client_ip")
                    .map_err(|e| persistence_error("read client_ip", e))?;
                let client_ip = client_ip
                    .parse()
                    .map_err(|e| persistence_error("parse client_ip", e))?;
                let boot_profile: String = row
                    .try_get("boot_profile")
                    .map_err(|e| persistence_error("read session boot_profile", e))?;
                if !is_valid_boot_profile(&boot_profile) {
                    return Err(persistence_error(
                        "load boot sessions",
                        "invalid boot profile",
                    ));
                }
                let client_mac: Option<String> = row
                    .try_get("client_mac")
                    .map_err(|e| persistence_error("read client_mac", e))?;
                let serial: Option<String> = row
                    .try_get("serial")
                    .map_err(|e| persistence_error("read serial", e))?;
                let trace_id: Option<String> = row
                    .try_get("trace_id")
                    .map_err(|e| persistence_error("read trace_id", e))?;
                let boot_epoch: i64 = row
                    .try_get("boot_epoch")
                    .map_err(|e| persistence_error("read boot_epoch", e))?;
                let pinned_group_id: Option<String> = row
                    .try_get("pinned_group_id")
                    .map_err(|e| persistence_error("read pinned_group_id", e))?;
                let pinned_version_id: Option<i64> = row
                    .try_get("pinned_version_id")
                    .map_err(|e| persistence_error("read pinned_version_id", e))?;
                let pinned_manifest_digest: Option<String> = row
                    .try_get("pinned_manifest_digest")
                    .map_err(|e| persistence_error("read pinned_manifest_digest", e))?;
                let artifact_token_hash: Option<String> = row
                    .try_get("artifact_token_hash")
                    .map_err(|e| persistence_error("read artifact_token_hash", e))?;
                let artifact_token_hash = artifact_token_hash
                    .map(|encoded| {
                        let decoded = hex::decode(encoded).map_err(|error| {
                            persistence_error("decode artifact_token_hash", error)
                        })?;
                        decoded.try_into().map_err(|_| {
                            persistence_error(
                                "decode artifact_token_hash",
                                "digest must contain exactly 32 bytes",
                            )
                        })
                    })
                    .transpose()?;
                let expires_at = row_text(&row, "expires_at")?;
                let expires_at = expires_at
                    .parse::<jiff::Timestamp>()
                    .map_err(|e| persistence_error("parse expires_at", e))?;
                let ttl = Duration::try_from(expires_at.duration_since(jiff::Timestamp::now()))
                    .unwrap_or_default();

                let pinned_boot_chain =
                    match (pinned_group_id, pinned_version_id, pinned_manifest_digest) {
                        (Some(group_id), Some(version_id), Some(manifest_digest)) => {
                            let version_id = u64::try_from(version_id).map_err(|_| {
                                persistence_error(
                                    "load boot sessions",
                                    "pinned version must be non-negative",
                                )
                            })?;
                            Some(BootChainPin {
                                boot_profile: boot_profile.clone(),
                                group_id,
                                version_id,
                                manifest_digest,
                            })
                        }
                        (None, None, None) => None,
                        _ => {
                            return Err(persistence_error(
                                "load boot sessions",
                                "incomplete pinned boot-chain identity",
                            ));
                        }
                    };

                let boot_epoch = u64::try_from(boot_epoch).map_err(|_| {
                    persistence_error("load boot sessions", "boot epoch must be positive")
                })?;
                if boot_epoch == 0 {
                    return Err(persistence_error(
                        "load boot sessions",
                        "boot epoch must be positive",
                    ));
                }

                Ok((
                    client_ip,
                    BootSessionEntry {
                        trace_id,
                        boot_profile,
                        client_mac,
                        serial,
                        boot_epoch,
                        artifact_token_hash,
                        pinned_boot_chain,
                        expires_at: Instant::now() + ttl,
                    },
                ))
            })
            .collect()
    }
}

/// Returns the disposable test database URL, or `None` to skip a database test.
///
/// With `TEMPEST_REQUIRE_TEST_DATABASE=1` (set by CI database jobs), a missing
/// URL fails instead, so a misconfigured job can never pass vacuously.
#[cfg(test)]
pub(crate) fn test_database_url() -> Option<String> {
    let required = std::env::var("TEMPEST_REQUIRE_TEST_DATABASE").is_ok_and(|value| value == "1");
    match std::env::var("TEMPEST_TEST_DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ if required => panic!(
            "TEMPEST_REQUIRE_TEST_DATABASE=1 but TEMPEST_TEST_DATABASE_URL is unset or empty"
        ),
        _ => None,
    }
}

/// Bounds concurrently running database-backed tests across the test binary.
///
/// A fixture can hold about 30 server connections (several stores with eight
/// pooled connections each), and the harness runs one test per CPU by default,
/// so large runners would exceed default server limits (PostgreSQL 100, MySQL
/// 151). Hold the returned permit for the whole test, including cleanup.
/// `TEMPEST_TEST_DATABASE_CONCURRENCY` overrides the default of 3.
#[cfg(test)]
pub(crate) async fn test_database_slot() -> tokio::sync::SemaphorePermit<'static> {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| {
            let slots = std::env::var("TEMPEST_TEST_DATABASE_CONCURRENCY")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|slots| *slots > 0)
                .unwrap_or(3);
            tokio::sync::Semaphore::new(slots)
        })
        .acquire()
        .await
        .expect("test database semaphore is never closed")
}

/// Runs `test` against a fresh sibling database that is dropped afterwards.
///
/// Use it for tests whose effects are global to a database (revisions,
/// retention pruning, snapshot limits), so they cannot disturb concurrently
/// running tests that share the base test database.
#[cfg(test)]
pub(crate) async fn with_isolated_test_database<F, Fut>(test: F)
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = test_database_url() else {
        return;
    };
    let _database_slot = test_database_slot().await;
    sqlx::any::install_default_drivers();
    let admin = sqlx::AnyPool::connect(&url).await.unwrap();
    let database = format!("tempest_isolated_{}", uuid::Uuid::new_v4().simple());
    // The identifier is generated locally from a fixed prefix and UUID hex.
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .expect("isolated database tests require CREATE DATABASE permission on the disposable test server");
    let mut options: sqlx::any::AnyConnectOptions = url.parse().unwrap();
    options.database_url.set_path(&format!("/{database}"));
    let isolated_url = options.database_url.to_string();
    // Joining a child task lets cleanup run even when an assertion panics.
    let result = tokio::spawn(test(isolated_url)).await;
    if !url.starts_with("mysql:") {
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()")
            .bind(&database).execute(&admin).await.unwrap();
    }
    sqlx::query(&format!("DROP DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    if let Err(error) = result {
        if error.is_panic() {
            std::panic::resume_unwind(error.into_panic());
        }
        panic!("isolated database test task was cancelled: {error}");
    }
}

#[cfg(test)]
#[path = "persistence/pin_tests.rs"]
mod pin_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// CI reruns only the `SQL_TEST_MODULES` named in the Makefile against the
    /// second database, so a database-backed test elsewhere would silently run
    /// against PostgreSQL alone.
    #[test]
    fn database_tests_stay_in_sql_test_modules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Packaged crates ship without the Makefile and its CI entry points.
        let Ok(makefile) = std::fs::read_to_string(root.join("Makefile")) else {
            return;
        };
        let modules: Vec<&str> = makefile
            .lines()
            .find_map(|line| line.strip_prefix("SQL_TEST_MODULES"))
            .and_then(|line| line.trim_start().strip_prefix(":="))
            .expect("Makefile defines SQL_TEST_MODULES")
            .split_whitespace()
            .collect();
        assert!(!modules.is_empty());

        let mut pending = vec![root.join("src")];
        let mut database_modules = Vec::new();
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap_or_default();
                if path.extension().is_some_and(|ext| ext == "rs")
                    && (source.contains("test_database_url()")
                        || source.contains("test_database_slot()"))
                {
                    let relative = path.strip_prefix(root.join("src")).unwrap();
                    let module = relative
                        .with_extension("")
                        .components()
                        .map(|part| part.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("::");
                    database_modules.push(format!("{module}::"));
                }
            }
        }
        assert!(
            database_modules
                .iter()
                .any(|module| module == "persistence::")
        );
        for module in database_modules {
            assert!(
                modules.iter().any(|prefix| module.starts_with(prefix)),
                "{module} uses the test database but no Makefile SQL_TEST_MODULES entry covers it"
            );
        }
    }

    #[test]
    fn legacy_manifest_json_preserves_timestamp_precision() {
        let value = serde_json::json!({
            "boot_profile": "default",
            "group_id": "legacy",
            "version_id": 7,
            "created_at": "2026-11-17T12:34:56.123450Z",
            "artifacts": [],
            "manifest_digest": "00".repeat(32),
            "signature": null,
        });
        let persisted: PersistedManifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&persisted).unwrap(), value);
        let manifest: BootChainManifest = persisted.into();
        assert_eq!(
            crate::timestamp::to_rfc3339(manifest.created_at),
            "2026-11-17T12:34:56.123450+00:00"
        );
    }

    #[test]
    fn mysql_version_group_schema_uses_wide_json_columns() {
        let mysql = version_group_table_sql(DatabaseDialect::MySql);
        assert!(mysql.contains("manifest_json MEDIUMTEXT NOT NULL"));
        assert!(mysql.contains("files_json MEDIUMTEXT NOT NULL"));
        assert!(
            version_group_table_sql(DatabaseDialect::Postgres)
                .contains("manifest_json TEXT NOT NULL")
        );
    }

    pub(super) fn version_group(
        boot_profile: &str,
        group_id: &str,
        version_id: u64,
    ) -> VersionGroup {
        let created_at = jiff::Timestamp::now();
        let file = FileVersion {
            boot_profile: boot_profile.into(),
            logical_name: "artifact.bin".into(),
            path: PathBuf::from("/tmp/artifact.bin"),
            version_id,
            content_hash: "00".repeat(32),
            size: 1,
        };
        VersionGroup {
            boot_profile: boot_profile.into(),
            group_id: group_id.into(),
            version_id,
            files: vec![file.clone()],
            created_at,
            manifest: BootChainManifest {
                boot_profile: boot_profile.into(),
                group_id: group_id.into(),
                version_id,
                created_at,
                artifacts: vec![ManifestArtifact {
                    logical_name: file.logical_name,
                    path: file.path.display().to_string(),
                    content_hash: file.content_hash,
                    size: file.size,
                }],
                manifest_digest: "00".repeat(32),
                signature: None,
            },
        }
    }

    #[tokio::test]
    async fn control_snapshot_waits_for_the_complete_mutation() {
        super::with_isolated_test_database(assert_control_snapshot_waits_for_the_complete_mutation)
            .await;
    }

    async fn assert_control_snapshot_waits_for_the_complete_mutation(database_url: String) {
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let profile = format!("snapshot-{}", uuid::Uuid::new_v4());
        let group = version_group(&profile, "release", 1);
        store.persist_version_group(&group, 0).await.unwrap();
        let client_ip = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: profile.clone(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        store.persist_boot_session(client_ip, &entry).await.unwrap();

        let mut tx = store.pool.begin().await.unwrap();
        store.bump_state_revision(&mut tx).await.unwrap();
        store
            .deactivate_groups_in_tx(&mut tx, &profile)
            .await
            .unwrap();
        // A snapshot must not expose the release change before the corresponding
        // session change commits, even though its first SELECT could already run.
        let snapshot = store.load_control_snapshot(100_000);
        tokio::pin!(snapshot);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut snapshot)
                .await
                .is_err()
        );
        let delete_sql = match store.dialect {
            DatabaseDialect::Postgres => "DELETE FROM tempest_boot_sessions WHERE client_ip = $1",
            DatabaseDialect::MySql => "DELETE FROM tempest_boot_sessions WHERE client_ip = ?",
        };
        sqlx::query(delete_sql)
            .bind(client_ip.to_string())
            .execute(tx.executor())
            .await
            .unwrap();
        let revision = store.lock_state_revision(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        let snapshot = tokio::time::timeout(Duration::from_secs(30), snapshot)
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.revision >= revision);
        assert!(!snapshot.sessions.iter().any(|(ip, _)| *ip == client_ip));
        assert!(
            snapshot
                .groups
                .iter()
                .any(|(candidate, active)| candidate == &group && !active)
        );
    }

    #[tokio::test]
    async fn test_concurrent_version_writers_reject_stale_revision() {
        super::with_isolated_test_database(assert_concurrent_version_writers_reject_stale_revision)
            .await;
    }

    async fn assert_concurrent_version_writers_reject_stale_revision(database_url: String) {
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let profile = format!(
            "cas-{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_microsecond()
        );
        let fallback = version_group(&profile, "fallback", 1);
        store.persist_version_group(&fallback, 0).await.unwrap();
        let left = version_group(&profile, "left", 2);
        let right = version_group(&profile, "right", 3);
        let (left_result, right_result) = tokio::join!(
            store.persist_version_group(&left, 1),
            store.persist_version_group(&right, 1)
        );

        assert_eq!(left_result.is_ok() as u8 + right_result.is_ok() as u8, 1);
        assert!(
            matches!(left_result, Err(TempestError::Conflict(_)))
                || matches!(right_result, Err(TempestError::Conflict(_))),
            "left={left_result:?}, right={right_result:?}"
        );
        let active = store
            .load_version_groups()
            .await
            .unwrap()
            .into_iter()
            .filter(|(group, active)| group.boot_profile == profile && *active)
            .map(|(group, _)| group)
            .collect::<Vec<_>>();
        assert_eq!(active.len(), 1);
        assert_eq!(store.version_revision(&profile).await.unwrap(), 2);

        let newer = version_group(&profile, "newer", 4);
        store.persist_version_group(&newer, 2).await.unwrap();
        assert!(matches!(
            store
                .rollback_version_group(
                    &profile,
                    "fallback",
                    None,
                    3,
                    Some(&active[0].group_id),
                    None,
                )
                .await,
            Err(TempestError::Conflict(_))
        ));
        let active = store
            .load_version_groups()
            .await
            .unwrap()
            .into_iter()
            .filter(|(group, active)| group.boot_profile == profile && *active)
            .map(|(group, _)| group.group_id)
            .collect::<Vec<_>>();
        assert_eq!(active, ["newer"]);
        assert_eq!(store.version_revision(&profile).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_durable_group_retention_preserves_pins_and_loader_bounds() {
        // Retention prunes the oldest inactive groups of every profile, so this
        // test would delete groups that concurrent tests still assert on.
        super::with_isolated_test_database(assert_durable_group_retention).await;
    }

    async fn assert_durable_group_retention(database_url: String) {
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let profile = format!(
            "retention-{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_microsecond()
        );
        let mut pinned = version_group(&profile, "pinned", 1);
        let old = jiff::Timestamp::now() - Duration::from_secs(86_400);
        pinned.created_at = old;
        pinned.manifest.created_at = old;
        store.persist_version_group(&pinned, 0).await.unwrap();

        let duplicate = version_group(&profile, "pinned", 2);
        assert!(matches!(
            store.persist_version_group(&duplicate, 1).await,
            Err(TempestError::Conflict(_))
        ));
        let client_ip = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        store
            .persist_boot_session(
                client_ip,
                &BootSessionEntry {
                    trace_id: None,
                    boot_profile: profile.clone(),
                    client_mac: None,
                    serial: None,
                    boot_epoch: 1,
                    artifact_token_hash: None,
                    pinned_boot_chain: Some(BootChainPin {
                        boot_profile: profile.clone(),
                        group_id: pinned.group_id.clone(),
                        version_id: pinned.version_id,
                        manifest_digest: pinned.manifest.manifest_digest.clone(),
                    }),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            )
            .await
            .unwrap();

        for version_id in 2..=101 {
            store
                .persist_version_group(
                    &version_group(&profile, &format!("release-{version_id}"), version_id),
                    (version_id - 1) as i64,
                )
                .await
                .unwrap();
        }
        let groups = store.load_version_groups().await.unwrap();
        assert!(groups.len() <= MAX_PERSISTED_GROUPS);
        assert!(groups.iter().any(|(group, _)| {
            group.boot_profile == profile && group.group_id == "pinned" && group.version_id == 1
        }));
        assert!(groups.iter().any(|(group, active)| {
            group.boot_profile == profile && group.group_id == "release-101" && *active
        }));

        let mut oversized = version_group(&profile, "oversized", 102);
        let path = "x".repeat(MAX_PERSISTED_JSON_BYTES + 1);
        oversized.files[0].path = PathBuf::from(&path);
        oversized.manifest.artifacts[0].path = path;
        assert!(matches!(
            store.persist_version_group(&oversized, 101).await,
            Err(TempestError::Persistence(_))
        ));
        assert_eq!(store.version_revision(&profile).await.unwrap(), 101);
    }

    #[tokio::test]
    async fn test_boot_session_pin_rejects_stale_epoch() {
        super::with_isolated_test_database(assert_boot_session_pin_rejects_stale_epoch).await;
    }

    async fn assert_boot_session_pin_rejects_stale_epoch(database_url: String) {
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let client_ip = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        let profile = format!("epoch-{}", uuid::Uuid::new_v4());
        let group = version_group(&profile, "release-a", 1);
        store.persist_version_group(&group, 0).await.unwrap();
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: profile.clone(),
            client_mac: None,
            serial: None,
            boot_epoch: 2,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        store.persist_boot_session(client_ip, &entry).await.unwrap();
        let pin = BootChainPin {
            boot_profile: profile,
            group_id: "release-a".into(),
            version_id: 1,
            manifest_digest: group.manifest.manifest_digest,
        };

        assert!(!store.pin_boot_session(client_ip, 1, &pin).await.unwrap());
        assert!(store.pin_boot_session(client_ip, 2, &pin).await.unwrap());
        assert_eq!(
            store
                .load_boot_sessions(100)
                .await
                .unwrap()
                .into_iter()
                .find(|(ip, _)| *ip == client_ip)
                .unwrap()
                .1
                .pinned_boot_chain,
            Some(pin)
        );
        store.delete_boot_session(client_ip).await.unwrap();
    }

    #[tokio::test]
    async fn test_session_revocation_preserves_durable_replacement() {
        let Some(database_url) = super::test_database_url() else {
            return;
        };
        let _database_slot = super::test_database_slot().await;
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let ip = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: "default".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 2,
            artifact_token_hash: Some([2; 32]),
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        store.persist_boot_session(ip, &entry).await.unwrap();
        assert!(
            !store
                .delete_boot_session_with_token(ip, &[1; 32])
                .await
                .unwrap()
        );
        assert!(
            store
                .delete_boot_session_with_token(ip, &[2; 32])
                .await
                .unwrap()
        );
        assert!(
            store
                .delete_boot_session_with_token(ip, &[2; 32])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_load_boot_sessions_enforces_limit() {
        let Some(database_url) = super::test_database_url() else {
            return;
        };
        let _database_slot = super::test_database_slot().await;
        let store = PersistenceStore::connect(&database_url).await.unwrap();
        let first = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        let second = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: "capacity-test".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        store.persist_boot_session(first, &entry).await.unwrap();
        store.persist_boot_session(second, &entry).await.unwrap();

        assert!(matches!(
            store.load_boot_sessions(1).await,
            Err(TempestError::Persistence(message)) if message.contains("configured limit 1")
        ));

        store.delete_boot_session(first).await.unwrap();
        store.delete_boot_session(second).await.unwrap();
    }
}
