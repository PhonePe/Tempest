// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Durable ordinary/deletion mode selection. Ordinary nodes cache startup admission;
//! deletion-enabled nodes require an exclusive namespace lock for their lifetime.
//! Old binaries must be stopped before migration: no SQL protocol can observe a
//! reader that never participates. Reader rows and tombstones have no expiry.

use super::{
    BootChainPin, COORDINATION_TIMEOUT, CoordinationError, CoordinationId, DatabaseDialect,
    GroupIdentity, MAX_READERS, PersistenceStore, TempestError, TracedTransaction,
    coordination_deadline, persistence_error, row_text,
};
use crate::features::versioning::VersionGroup;
use crate::features::versioning::deletion::{DeleteBlocker, DeleteError};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedSemaphorePermit};

const LEGACY_PROTOCOL: i32 = 1;
const ORDINARY_PROTOCOL: i32 = 2;
const DELETION_PROTOCOL: i32 = 3;

fn serving_protocol(protocol: i32, exclusive: bool) -> Result<i32, TempestError> {
    let expected = if exclusive {
        DELETION_PROTOCOL
    } else {
        ORDINARY_PROTOCOL
    };
    if protocol == LEGACY_PROTOCOL || protocol == expected {
        Ok(expected)
    } else {
        Err(TempestError::Persistence(
            "SQL serving mode differs from the durable namespace; stop every serving node before an explicit mode migration".into(),
        ))
    }
}

pub(in crate::persistence) struct ServingLease {
    exclusive: bool,
    generation: i64,
    #[cfg(test)]
    probe_count: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    probe_delay_ms: std::sync::atomic::AtomicU64,
    // Never reacquire a lost connection. An error permanently poisons admission.
    transaction: Mutex<Option<TracedTransaction<'static>>>,
    // Mirrors a poisoned `transaction` so readiness can report it without SQL.
    lost: std::sync::atomic::AtomicBool,
}

impl ServingLease {
    fn poison(&self, transaction: &mut Option<TracedTransaction<'static>>) {
        *transaction = None;
        self.lost.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Durable managed-reader lifetime. Clones of the enclosing Arc retain admission
/// until the last response/body/transfer owner drops it. Failed cleanup leaves a
/// permanent SQL blocker, never a lease that expires while bytes are in flight.
pub struct ReaderRegistration {
    store: PersistenceStore,
    identity: GroupIdentity,
    id: CoordinationId,
    permit: Option<OwnedSemaphorePermit>,
}

impl std::fmt::Debug for ReaderRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderRegistration").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl ReaderRegistration {
    pub(super) fn id_for_test(&self) -> CoordinationId {
        self.id.clone()
    }
}

impl Drop for ReaderRegistration {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let store = self.store.clone();
        let identity = self.identity.clone();
        let id = self.id.clone();
        // The permit follows cleanup, bounding outstanding work to 4096 even
        // under cancellation. Exact release is idempotent, so transient failures
        // retry briefly; a dead runtime or exhausted retries retain the row.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _permit = permit;
                let result = retry_reader_release(READER_RELEASE_BACKOFF, || {
                    store.release_group_reader(&identity, &id)
                })
                .await;
                if let Err(error) = result {
                    tracing::error!(%error, "durable reader cleanup failed after retries; SQL deletion remains blocked");
                }
            });
        }
    }
}

/// Delays before each retry of an exact reader release, bounding cleanup to
/// six attempts over roughly 15.5 seconds of backoff plus per-attempt deadlines.
const READER_RELEASE_BACKOFF: [std::time::Duration; 5] = [
    std::time::Duration::from_millis(500),
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(4),
    std::time::Duration::from_secs(8),
];

async fn retry_reader_release<F, Fut>(
    backoff: impl IntoIterator<Item = std::time::Duration>,
    mut release: F,
) -> Result<(), CoordinationError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), CoordinationError>>,
{
    let mut delays = backoff.into_iter();
    loop {
        match release().await {
            Ok(()) => return Ok(()),
            // Invalid identity or ID conflicts cannot succeed on retry.
            Err(error @ (CoordinationError::InvalidInput | CoordinationError::IdConflict)) => {
                return Err(error);
            }
            Err(error) => match delays.next() {
                Some(delay) => {
                    tracing::warn!(%error, ?delay, "durable reader cleanup failed; retrying");
                    tokio::time::sleep(delay).await;
                }
                None => return Err(error),
            },
        }
    }
}

impl PersistenceStore {
    /// Recover abandoned reader bookkeeping after every serving process is stopped.
    ///
    /// This offline operation opens its own store and requires the exclusive
    /// deletion namespace in an existing coordination schema. It does not run
    /// startup migrations or release retention. The confirmation is an operator
    /// assertion, not proof that a disconnected process has stopped sending bytes. Tombstones,
    /// reservations, releases, sessions and artifact bytes are never removed.
    ///
    /// # Errors
    ///
    /// Refuses missing confirmation, ordinary namespaces, a live namespace owner,
    /// oversized reader state, and database failures. An uncertain result may be
    /// retried only while all serving processes remain stopped.
    pub async fn recover_abandoned_readers(
        database_url: &str,
        all_servers_stopped: bool,
    ) -> Result<u64, TempestError> {
        if !all_servers_stopped {
            return Err(TempestError::Config(
                "reader recovery requires confirmation that every serving process is stopped"
                    .into(),
            ));
        }
        let store = Self::connect_unmigrated(database_url).await?;
        store.recover_reader_bookkeeping().await
    }

    pub(super) async fn recover_reader_bookkeeping(&self) -> Result<u64, TempestError> {
        self.ensure_serving_admission(true).await?;
        coordination_deadline(async {
            let mut tx = self.begin_coordination().await?;
            let rows = sqlx::query("SELECT operation_id FROM tempest_group_readers LIMIT 4097")
                .fetch_all(tx.executor())
                .await
                .map_err(|error| persistence_error("inspect abandoned readers", error))?;
            if rows.len() > MAX_READERS as usize {
                return Err(CoordinationError::Capacity);
            }
            sqlx::query("DELETE FROM tempest_group_readers")
                .execute(tx.executor())
                .await
                .map_err(|error| persistence_error("recover abandoned readers", error))?;
            let updated =
                sqlx::query("UPDATE tempest_reader_capacity SET registered_count = 0 WHERE id = 1")
                    .execute(tx.executor())
                    .await
                    .map_err(|error| persistence_error("recover reader capacity", error))?;
            // MySQL reports changed rows, so an already-zero count is valid too.
            if updated.rows_affected() == 0 {
                let count: i64 = sqlx::query_scalar(
                    "SELECT registered_count FROM tempest_reader_capacity WHERE id = 1",
                )
                .fetch_one(tx.executor())
                .await
                .map_err(|error| persistence_error("verify recovered reader capacity", error))?;
                if count != 0 {
                    return Err(TempestError::Persistence(
                        "reader capacity recovery failed".into(),
                    )
                    .into());
                }
            }
            sqlx::query(
                "UPDATE tempest_deletion_safety SET reader_tracking_exhausted = 0 WHERE id = 1",
            )
            .execute(tx.executor())
            .await
            .map_err(|error| persistence_error("restore deletion tracking", error))?;
            tx.commit()
                .await
                .map_err(|error| persistence_error("commit reader recovery", error))?;
            Ok(rows.len() as u64)
        })
        .await
        .map_err(coordination_error)
    }

    pub(super) async fn migrate_ownership_index(&self) -> Result<(), TempestError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tempest_managed_names (name_hash VARCHAR(64) PRIMARY KEY)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("migrate managed names", e))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS tempest_deletion_safety (id INTEGER PRIMARY KEY, reader_tracking_exhausted INTEGER NOT NULL, ownership_ready INTEGER NOT NULL)")
            .execute(&self.pool).await.map_err(|e| persistence_error("migrate deletion safety", e))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS tempest_reader_capacity (id INTEGER PRIMARY KEY, registered_count BIGINT NOT NULL)")
            .execute(&self.pool).await.map_err(|e| persistence_error("migrate reader capacity", e))?;
        sqlx::query(self.coordination_sql(
            "INSERT INTO tempest_deletion_safety VALUES (1, 0, 0) ON CONFLICT (id) DO NOTHING",
            "INSERT IGNORE INTO tempest_deletion_safety VALUES (1, 0, 0)",
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("initialize deletion safety", e))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| persistence_error("begin ownership migration", e))?;
        self.lock_state_revision_unchecked(&mut tx).await?;
        let capacity: Option<i64> = sqlx::query_scalar(
            "SELECT registered_count FROM tempest_reader_capacity WHERE id = 1 FOR UPDATE",
        )
        .fetch_optional(tx.executor())
        .await
        .map_err(|e| persistence_error("inspect reader capacity migration", e))?;
        if capacity.is_none() {
            let count: i64 = sqlx::query_scalar(self.coordination_sql(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM (SELECT operation_id FROM tempest_group_readers LIMIT 4097) AS readers",
                "SELECT CAST(COUNT(*) AS SIGNED) FROM (SELECT operation_id FROM tempest_group_readers LIMIT 4097) AS readers",
            )).fetch_one(tx.executor()).await.map_err(|e| persistence_error("initialize reader capacity", e))?;
            if count > MAX_READERS {
                return Err(TempestError::Persistence(
                    "legacy durable reader state exceeds capacity".into(),
                ));
            }
            sqlx::query(self.coordination_sql(
                "INSERT INTO tempest_reader_capacity (id, registered_count) VALUES (1, $1)",
                "INSERT INTO tempest_reader_capacity (id, registered_count) VALUES (1, ?)",
            ))
            .bind(count)
            .execute(tx.executor())
            .await
            .map_err(|e| persistence_error("persist reader capacity", e))?;
        } else if !matches!(capacity, Some(0..=MAX_READERS)) {
            return Err(TempestError::Persistence(
                "durable reader capacity is invalid".into(),
            ));
        }
        self.backfill_ownership_index(&mut tx).await?;
        tx.commit()
            .await
            .map_err(|e| persistence_error("commit ownership migration", e))
    }

    async fn backfill_ownership_index(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<(), TempestError> {
        let protocol: i32 =
            sqlx::query_scalar("SELECT protocol FROM tempest_serving_namespace WHERE id = 1")
                .fetch_one(tx.executor())
                .await
                .map_err(|e| persistence_error("inspect ownership mode", e))?;
        if protocol != DELETION_PROTOCOL {
            return Ok(());
        }
        let ready: i32 =
            sqlx::query_scalar("SELECT ownership_ready FROM tempest_deletion_safety WHERE id = 1")
                .fetch_one(tx.executor())
                .await
                .map_err(|e| persistence_error("inspect ownership migration", e))?;
        if ready == 0 {
            for (table, column, files) in [
                ("tempest_version_groups", "files_json", true),
                ("tempest_group_tombstones", "names_json", false),
            ] {
                let rows = sqlx::query(&format!("SELECT {column} FROM {table} LIMIT 101"))
                    .fetch_all(tx.executor())
                    .await
                    .map_err(|e| persistence_error("load ownership migration", e))?;
                if rows.len() > 100 {
                    return Err(TempestError::Persistence(
                        "ownership migration exceeds supported metadata bounds".into(),
                    ));
                }
                for row in rows {
                    let json = row_text(&row, column)?;
                    if json.len() > super::super::MAX_PERSISTED_JSON_BYTES {
                        return Err(TempestError::Persistence(
                            "ownership migration JSON exceeds bounds".into(),
                        ));
                    }
                    let names: Vec<String> = if files {
                        super::super::parse_json::<Vec<super::super::PersistedFileVersion>>(
                            "decode ownership files",
                            &json,
                        )?
                        .into_iter()
                        .map(|file| file.logical_name)
                        .collect()
                    } else {
                        super::super::parse_json("decode ownership tombstone", &json)?
                    };
                    if names.len() > 100 {
                        return Err(TempestError::Persistence(
                            "ownership migration member count exceeds bounds".into(),
                        ));
                    }
                    self.remember_managed_names(tx, &names).await?;
                }
            }
            sqlx::query("UPDATE tempest_deletion_safety SET ownership_ready = 1 WHERE id = 1")
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("complete ownership migration", e))?;
        }
        Ok(())
    }

    pub(in crate::persistence) async fn remember_managed_names(
        &self,
        tx: &mut TracedTransaction<'_>,
        names: &[String],
    ) -> Result<(), TempestError> {
        let protocol: i32 =
            sqlx::query_scalar("SELECT protocol FROM tempest_serving_namespace WHERE id = 1")
                .fetch_one(tx.executor())
                .await
                .map_err(|e| persistence_error("inspect managed ownership mode", e))?;
        if protocol != DELETION_PROTOCOL {
            // A later stopped migration must include names published in ordinary mode.
            sqlx::query("UPDATE tempest_deletion_safety SET ownership_ready = 0 WHERE id = 1")
                .execute(tx.executor())
                .await
                .map_err(|e| persistence_error("defer managed ownership backfill", e))?;
            return Ok(());
        }
        for name in names {
            sqlx::query(self.coordination_sql(
                "INSERT INTO tempest_managed_names (name_hash) VALUES ($1) ON CONFLICT (name_hash) DO NOTHING",
                "INSERT IGNORE INTO tempest_managed_names (name_hash) VALUES (?)",
            )).bind(hex::encode(Sha256::digest(name.as_bytes()))).execute(tx.executor()).await
                .map_err(|e| persistence_error("retain managed ownership", e))?;
        }
        let count: i64 = sqlx::query_scalar(self.coordination_sql(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM (SELECT name_hash FROM tempest_managed_names LIMIT 20001) AS names",
            "SELECT CAST(COUNT(*) AS SIGNED) FROM (SELECT name_hash FROM tempest_managed_names LIMIT 20001) AS names",
        )).fetch_one(tx.executor()).await.map_err(|e| persistence_error("check managed ownership capacity", e))?;
        if count > 20_000 {
            return Err(TempestError::Conflict(
                "durable managed-name capacity exhausted; release mutation refused".into(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn serving_snapshot_for_test(&self) -> (String, i64) {
        let lease = self.serving.get().unwrap();
        let mut connection = lease.transaction.lock().await;
        let tx = connection.as_mut().unwrap();
        let isolation = sqlx::query_scalar("SELECT @@transaction_isolation")
            .fetch_one(tx.executor())
            .await
            .unwrap();
        // Deliberately establish the first consistent read only AFTER probes
        // and a peer commit. An earlier snapshot would return a stale value.
        let generation =
            sqlx::query_scalar("SELECT generation FROM tempest_serving_generation WHERE id = 1")
                .fetch_one(tx.executor())
                .await
                .unwrap();
        (isolation, generation)
    }

    #[cfg(test)]
    pub(super) async fn serving_connection_id(&self) -> i64 {
        let lease = self.serving.get().unwrap();
        let mut connection = lease.transaction.lock().await;
        sqlx::query_scalar(self.coordination_sql(
            "SELECT CAST(pg_backend_pid() AS BIGINT)",
            "SELECT CAST(CONNECTION_ID() AS SIGNED)",
        ))
        .fetch_one(connection.as_mut().unwrap().executor())
        .await
        .unwrap()
    }

    #[cfg(test)]
    pub(super) async fn serving_transaction_for_test(
        &self,
    ) -> tokio::sync::MutexGuard<'_, Option<TracedTransaction<'static>>> {
        self.serving.get().unwrap().transaction.lock().await
    }

    /// Ends the lifetime lease and waits for the database to release its lock,
    /// as owner shutdown would. Dropping the store releases it asynchronously,
    /// which races a peer's immediate NOWAIT admission.
    #[cfg(test)]
    pub(super) async fn stop_serving_for_test(self) {
        let lease = self.serving.get().unwrap();
        let transaction = lease.transaction.lock().await.take().unwrap();
        transaction.rollback().await.unwrap();
    }

    #[cfg(test)]
    pub(super) fn set_serving_probe_delay_for_test(&self, delay: std::time::Duration) {
        self.serving.get().unwrap().probe_delay_ms.store(
            delay.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    #[cfg(test)]
    pub(super) fn serving_probe_count_for_test(&self) -> usize {
        self.serving
            .get()
            .unwrap()
            .probe_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(in crate::persistence) async fn migrate_serving_coordination(
        &self,
    ) -> Result<(), TempestError> {
        let suffix = match self.dialect {
            DatabaseDialect::Postgres => "",
            DatabaseDialect::MySql => " ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin",
        };
        let exists = if self.dialect == DatabaseDialect::MySql {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.tables
                 WHERE table_schema = DATABASE() AND table_name = 'tempest_serving_namespace'",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| persistence_error("inspect serving namespace table", e))?;
            count != 0
        } else {
            false
        };
        if !exists {
            sqlx::query(&format!("CREATE TABLE IF NOT EXISTS tempest_serving_namespace (id INTEGER PRIMARY KEY, protocol INTEGER NOT NULL){suffix}"))
                .execute(&self.pool).await.map_err(|e| persistence_error("migrate serving namespace", e))?;
        }
        // Do not write an existing namespace row: serving nodes hold it locked
        // for their lifetime, and a new connection must reach admission refusal.
        let initialized =
            sqlx::query("SELECT protocol FROM tempest_serving_namespace WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| persistence_error("inspect serving protocol", e))?;
        if initialized.is_none() {
            sqlx::query("INSERT INTO tempest_serving_namespace (id, protocol) VALUES (1, 1)")
                .execute(&self.pool)
                .await
                .map_err(|e| persistence_error("initialize serving protocol", e))?;
        }
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS tempest_group_tombstones (
            boot_profile VARCHAR(64) NOT NULL, group_id VARCHAR(128) NOT NULL,
            names_json {} NOT NULL, PRIMARY KEY (boot_profile, group_id)){suffix}",
            if self.dialect == DatabaseDialect::MySql {
                "TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
            } else {
                "TEXT"
            }
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| persistence_error("migrate ownership tombstones", e))?;
        if self.dialect == DatabaseDialect::MySql {
            let charset: String = sqlx::query_scalar(
                "SELECT character_set_name FROM information_schema.columns
                 WHERE table_schema = DATABASE() AND table_name = 'tempest_group_tombstones'
                   AND column_name = 'names_json'",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| persistence_error("inspect tombstone encoding", e))?;
            if charset != "utf8mb4" {
                sqlx::query("ALTER TABLE tempest_group_tombstones MODIFY COLUMN names_json TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL")
                    .execute(&self.pool).await
                    .map_err(|e| persistence_error("upgrade tombstone encoding", e))?;
            }
        }
        // Separate from the lifetime-locked namespace row. Changes serialize
        // with admissions and control mutations on the state revision row.
        sqlx::query("CREATE TABLE IF NOT EXISTS tempest_serving_generation (id INTEGER PRIMARY KEY, generation BIGINT NOT NULL)")
            .execute(&self.pool).await.map_err(|e| persistence_error("migrate serving generation", e))?;
        sqlx::query(self.coordination_sql(
            "INSERT INTO tempest_serving_generation (id, generation) VALUES (1, 0) ON CONFLICT (id) DO NOTHING",
            "INSERT IGNORE INTO tempest_serving_generation (id, generation) VALUES (1, 0)",
        )).execute(&self.pool).await.map_err(|e| persistence_error("initialize serving generation", e))?;
        Ok(())
    }

    /// Whether the deletion-mode lifetime lease was lost. Never performs SQL.
    pub(crate) fn serving_lease_lost(&self) -> bool {
        self.serving
            .get()
            .is_some_and(|lease| lease.lost.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Validates the selected mode without duplicating transactional lease checks.
    pub(crate) async fn ensure_serving_mode(&self, exclusive: bool) -> Result<(), TempestError> {
        match self.serving.get() {
            Some(lease) if lease.exclusive == exclusive => Ok(()),
            Some(_) => Err(TempestError::Persistence(
                "SQL serving mode cannot change within a process".into(),
            )),
            None => self.ensure_serving_admission(exclusive).await,
        }
    }

    /// Acquires the serving namespace before reconciliation or first admission.
    /// Ordinary servers cache a durable mode selection. Deletion requires exclusive
    /// ownership; competing modes cannot coexist or switch during serving.
    pub(crate) async fn ensure_serving_admission(
        &self,
        exclusive: bool,
    ) -> Result<(), TempestError> {
        let deadline = tokio::time::Instant::now() + COORDINATION_TIMEOUT;
        let statement =
            "SELECT protocol FROM tempest_serving_namespace WHERE id = 1 FOR UPDATE NOWAIT";
        let lease = tokio::time::timeout_at(deadline, self.serving.get_or_try_init(|| async {
            let mut mode_tx = self.pool.begin().await.map_err(|e| persistence_error("begin serving mode", e))?;
            let protocol: i32 = sqlx::query_scalar(statement).fetch_one(mode_tx.executor()).await
                .map_err(|e| persistence_error("acquire serving namespace (another server may own it)", e))?;
            let selected = serving_protocol(protocol, exclusive)?;
            if !exclusive && protocol == LEGACY_PROTOCOL {
                for table in ["tempest_group_readers", "tempest_group_deletion_reservations", "tempest_group_tombstones"] {
                    let row = sqlx::query(&format!("SELECT 1 FROM {table} LIMIT 1"))
                        .fetch_optional(mode_tx.executor()).await.map_err(|e| persistence_error("inspect prior deletion state", e))?;
                    if row.is_some() {
                        return Err(TempestError::Persistence("namespace contains deletion history; coordinated deletion mode is required".into()));
                    }
                }
            }
            if protocol != selected {
                sqlx::query(self.coordination_sql(
                    "UPDATE tempest_serving_namespace SET protocol = $1 WHERE id = 1",
                    "UPDATE tempest_serving_namespace SET protocol = ? WHERE id = 1",
                )).bind(selected).execute(mode_tx.executor()).await.map_err(|e| persistence_error("persist serving mode", e))?;
            }
            mode_tx.commit().await.map_err(|e| persistence_error("commit serving mode", e))?;
            if !exclusive {
                return Ok(ServingLease { exclusive, generation: 0, transaction: Mutex::new(None),
                    #[cfg(test)]
                    probe_count: std::sync::atomic::AtomicUsize::new(0),
                    #[cfg(test)]
                    probe_delay_ms: std::sync::atomic::AtomicU64::new(0),
                    lost: std::sync::atomic::AtomicBool::new(false),
                });
            }
            let mut tx = self.pool.begin().await.map_err(|e| persistence_error("begin serving lease", e))?;
            let protocol: i32 = sqlx::query_scalar(statement).fetch_one(tx.executor()).await
                .map_err(|e| persistence_error("acquire exclusive serving lease", e))?;
            serving_protocol(protocol, true)?;
            let mut generation_tx = self.pool.begin().await.map_err(|e| persistence_error("begin serving generation", e))?;
            self.lock_state_revision_unchecked(&mut generation_tx).await?;
            self.backfill_ownership_index(&mut generation_tx).await?;
            sqlx::query("UPDATE tempest_serving_generation SET generation = generation + 1 WHERE id = 1")
                .execute(generation_tx.executor()).await.map_err(|e| persistence_error("advance serving generation", e))?;
            let generation: i64 = sqlx::query_scalar("SELECT generation FROM tempest_serving_generation WHERE id = 1 FOR UPDATE")
                .fetch_one(generation_tx.executor()).await.map_err(|e| persistence_error("capture serving generation", e))?;
            generation_tx.commit().await.map_err(|e| persistence_error("commit serving generation", e))?;
            Ok(ServingLease { exclusive, generation, transaction: Mutex::new(Some(tx)),
                #[cfg(test)]
                probe_count: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                probe_delay_ms: std::sync::atomic::AtomicU64::new(0),
                lost: std::sync::atomic::AtomicBool::new(false),
            })
        })).await.map_err(|_| TempestError::PersistenceBusy("serving namespace deadline exceeded".into()))??;
        if lease.exclusive != exclusive {
            return Err(TempestError::Persistence(
                "SQL serving mode cannot change within a process".into(),
            ));
        }
        if !exclusive {
            return Ok(());
        }
        // Probe the SAME transaction/connection, never the pool. Reconnection
        // would falsely claim ownership of a lock that was already released.
        // Repeat the original locking read: it checks the supported namespace
        // under the required lock without committing or changing lock mode.
        // InnoDB treats this as a current read. An ordinary table SELECT would
        // pin a REPEATABLE READ snapshot (and undo history) for the node lifetime,
        // including normal/shared mode. Generation stays in its separate tx.
        let mut transaction = tokio::time::timeout_at(deadline, lease.transaction.lock())
            .await
            .map_err(|_| {
                TempestError::PersistenceBusy(
                    "serving namespace deadline exceeded while waiting for the lease probe".into(),
                )
            })?;
        let tx = transaction.as_mut().ok_or_else(|| {
            TempestError::Persistence("SQL serving lease lost; restart required".into())
        })?;
        #[cfg(test)]
        lease
            .probe_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        let probe_delay = std::time::Duration::from_millis(
            lease
                .probe_delay_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        // A fresh budget: time spent queued behind other probes is not evidence
        // that this connection failed, but a timeout here poisons the lease.
        let probe = tokio::time::timeout(COORDINATION_TIMEOUT, async {
            // Server-side latency, so cancellation can interrupt an in-flight query.
            #[cfg(test)]
            if !probe_delay.is_zero() {
                let seconds = probe_delay.as_secs_f64();
                let sleep = match self.dialect {
                    DatabaseDialect::Postgres => format!("SELECT 1 FROM pg_sleep({seconds})"),
                    DatabaseDialect::MySql => format!("SELECT SLEEP({seconds})"),
                };
                sqlx::query(&sleep).execute(tx.executor()).await?;
            }
            sqlx::query_scalar::<_, i32>(statement)
                .fetch_one(tx.executor())
                .await
        })
        .await;
        if !matches!(probe, Ok(Ok(DELETION_PROTOCOL))) {
            lease.poison(&mut transaction);
            return Err(TempestError::Persistence(
                "SQL serving lease lost; admission stopped, reader rows retained".into(),
            ));
        }
        Ok(())
    }

    /// Called only AFTER taking the durable revision lock, in the transaction
    /// that admits a reader or mutates control state. A standalone public store
    /// writer has no serving lease and remains a legitimate control-plane client.
    pub(in crate::persistence) async fn validate_serving_generation(
        &self,
        tx: &mut TracedTransaction<'_>,
    ) -> Result<(), TempestError> {
        let Some(lease) = self.serving.get() else {
            return Ok(());
        };
        if !lease.exclusive {
            return Ok(());
        }
        self.ensure_serving_admission(lease.exclusive).await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT generation FROM tempest_serving_generation WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(tx.executor())
        .await
        .map_err(|e| persistence_error("check serving generation", e))?;
        if current != lease.generation {
            lease.poison(&mut *lease.transaction.lock().await);
            return Err(TempestError::Persistence(
                "SQL serving generation changed; restart required".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn register_reader(
        &self,
        pin: &BootChainPin,
    ) -> Result<Arc<ReaderRegistration>, TempestError> {
        let identity = GroupIdentity::new(pin).map_err(coordination_error)?;
        let id = CoordinationId::new(&uuid::Uuid::new_v4().simple().to_string())
            .map_err(coordination_error)?;
        let permit = self
            .reader_budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                TempestError::PersistenceBusy("durable reader cleanup capacity exhausted".into())
            })?;
        // Construct before the first await: cancellation/ambiguous commit also
        // attempts exact release once the registration transaction has stopped.
        let registration = Arc::new(ReaderRegistration {
            store: self.clone(),
            identity,
            id,
            permit: Some(permit),
        });
        self.acquire_group_reader(&registration.identity, &registration.id)
            .await
            .map_err(reader_admission_error)?;
        Ok(registration)
    }

    pub(in crate::persistence) async fn reject_deleted_group(
        &self,
        tx: &mut TracedTransaction<'_>,
        profile: &str,
        group: &str,
    ) -> Result<(), TempestError> {
        let row = sqlx::query(self.coordination_sql(
            "SELECT group_id FROM tempest_group_tombstones WHERE boot_profile = $1 AND group_id = $2 FOR UPDATE",
            "SELECT group_id FROM tempest_group_tombstones WHERE boot_profile = ? AND group_id = ? FOR UPDATE",
        )).bind(profile).bind(group).fetch_optional(tx.executor()).await
            .map_err(|e| persistence_error("check deletion tombstone", e))?;
        if row.is_some() {
            return Err(TempestError::Conflict(
                "group was deleted; its identity cannot be reused".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::persistence) async fn reject_reserved_group(
        &self,
        tx: &mut TracedTransaction<'_>,
        profile: &str,
        group: &str,
    ) -> Result<(), TempestError> {
        self.reject_reserved_groups(tx, &[(profile, group)]).await
    }

    pub(in crate::persistence) async fn reject_reserved_groups(
        &self,
        tx: &mut TracedTransaction<'_>,
        groups: &[(&str, &str)],
    ) -> Result<(), TempestError> {
        if groups.is_empty() {
            return Ok(());
        }
        if groups.len() > 32 {
            return Err(TempestError::Persistence(
                "deletion fence batch exceeds 32 groups".into(),
            ));
        }
        let predicates = (0..groups.len())
            .map(|index| match self.dialect {
                DatabaseDialect::Postgres => format!(
                    "(boot_profile = ${} AND group_id = ${})",
                    index * 2 + 1,
                    index * 2 + 2
                ),
                DatabaseDialect::MySql => "(boot_profile = ? AND group_id = ?)".into(),
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        for (table, message) in [
            (
                "tempest_group_tombstones",
                "group was deleted; its identity cannot be reused",
            ),
            (
                "tempest_group_deletion_reservations",
                "group has a durable deletion reservation",
            ),
        ] {
            let statement =
                format!("SELECT group_id FROM {table} WHERE {predicates} LIMIT 1 FOR UPDATE");
            let mut query = sqlx::query(&statement);
            for (profile, group) in groups {
                query = query.bind(*profile).bind(*group);
            }
            if query
                .fetch_optional(tx.executor())
                .await
                .map_err(|e| persistence_error("check batched deletion fences", e))?
                .is_some()
            {
                return Err(TempestError::Conflict(message.into()));
            }
        }
        Ok(())
    }

    /// Durable ownership check for the HTTP unmanaged compatibility path. A stale
    /// in-memory snapshot must never reopen a deleted managed logical name.
    pub(crate) async fn check_unmanaged_admission(
        &self,
        _profile: &str,
        name: &str,
    ) -> Result<(), TempestError> {
        if !crate::features::versioning::is_canonical_artifact_name(name) {
            return Err(TempestError::Conflict("noncanonical logical name".into()));
        }
        tokio::time::timeout(COORDINATION_TIMEOUT, async {
            let mut tx = self
                .begin_coordination()
                .await
                .map_err(coordination_error)?;
            let owned = sqlx::query(self.coordination_sql(
                "SELECT name_hash FROM tempest_managed_names WHERE name_hash = $1",
                "SELECT name_hash FROM tempest_managed_names WHERE name_hash = ?",
            ))
            .bind(hex::encode(Sha256::digest(name.as_bytes())))
            .fetch_optional(tx.executor())
            .await
            .map_err(|e| persistence_error("check indexed managed ownership", e))?;
            if owned.is_some() {
                return Err(crate::error::ProtocolError::FileNotFound(name.into()).into());
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            TempestError::PersistenceBusy("ownership admission deadline exceeded".into())
        })?
    }

    /// Advisory SQL eligibility: executes the real checks, but rolls back the
    /// provisional reservation. Confirmation must repeat them under revision CAS.
    pub(crate) async fn preview_sql_group_deletion(
        &self,
        group: &VersionGroup,
    ) -> Result<(), DeleteError> {
        let identity = group_identity(group).map_err(|error| deletion_refusal(error.into()))?;
        let id = CoordinationId::new(&uuid::Uuid::new_v4().simple().to_string())
            .map_err(deletion_refusal)?;
        coordination_deadline(async {
            let mut tx = self.begin_coordination().await?;
            self.reserve_deletion_in_tx(&mut tx, &identity, &id).await
        })
        .await
        .map_err(deletion_refusal)
    }

    /// Reservation, exact identity CAS, ownership tombstone and deletion commit
    /// together. Cancellation before commit rolls back; after commit, stale local
    /// metadata cannot pass reader admission or writer tombstone checks.
    pub(crate) async fn delete_sql_group(
        &self,
        group: &VersionGroup,
        revision: i64,
    ) -> Result<(), DeleteError> {
        self.ensure_serving_admission(true)
            .await
            .map_err(|error| deletion_refusal(error.into()))?;
        let identity = group_identity(group).map_err(|error| deletion_refusal(error.into()))?;
        let id = CoordinationId::new(&uuid::Uuid::new_v4().simple().to_string())
            .map_err(deletion_refusal)?;
        coordination_deadline(async {
            // Mutation conflicts here are revision CAS failures: the caller is stale.
            let mut tx = self
                .begin_version_mutation(&identity.profile, revision)
                .await
                .map_err(|error| match error {
                    TempestError::Conflict(_) => CoordinationError::IdentityChanged,
                    other => other.into(),
                })?;
            self.reserve_deletion_in_tx(&mut tx, &identity, &id).await?;
            let names: Vec<_> = group.files.iter().map(|f| f.logical_name.as_str()).collect();
            self.remember_managed_names(&mut tx, &group.files.iter().map(|file| file.logical_name.clone()).collect::<Vec<_>>()).await?;
            let names = serde_json::to_string(&names).map_err(|e| persistence_error("encode deleted names", e))?;
            if group.files.len() > 100 || names.len() > 32 * 1024 {
                return Err(CoordinationError::Capacity);
            }
            sqlx::query(self.coordination_sql(
                "INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES ($1, $2, $3)",
                "INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES (?, ?, ?)",
            )).bind(&identity.profile).bind(&identity.group).bind(names).execute(tx.executor()).await
                .map_err(|e| persistence_error("persist ownership tombstone", e))?;
            let removed = sqlx::query(self.coordination_sql(
                "DELETE FROM tempest_version_groups WHERE boot_profile = $1 AND group_id = $2 AND version_id = $3 AND manifest_digest = $4 AND active = FALSE",
                "DELETE FROM tempest_version_groups WHERE boot_profile = ? AND group_id = ? AND version_id = ? AND manifest_digest = ? AND active = FALSE",
            )).bind(&identity.profile).bind(&identity.group).bind(identity.version).bind(&identity.digest)
                .execute(tx.executor()).await.map_err(|e| persistence_error("delete retained SQL group", e))?;
            if removed.rows_affected() != 1 { return Err(CoordinationError::IdentityChanged); }
            tx.commit().await.map_err(|e| persistence_error("commit SQL group deletion", e))?;
            Ok(())
        }).await.map_err(deletion_refusal)
    }
}

fn group_identity(group: &VersionGroup) -> Result<GroupIdentity, TempestError> {
    GroupIdentity::new(&BootChainPin {
        boot_profile: group.boot_profile.clone(),
        group_id: group.group_id.clone(),
        version_id: group.version_id,
        manifest_digest: group.manifest.manifest_digest.clone(),
    })
    .map_err(coordination_error)
}

fn coordination_error(error: CoordinationError) -> TempestError {
    match error {
        CoordinationError::Persistence(error) => error,
        CoordinationError::DeadlineExceeded | CoordinationError::Capacity => {
            TempestError::PersistenceBusy(error.to_string())
        }
        other => TempestError::Conflict(other.to_string()),
    }
}

/// Download admission: a removed or reserved release is simply not served,
/// without disclosing deletion state; transient limits are retryable.
fn reader_admission_error(error: CoordinationError) -> TempestError {
    match error {
        CoordinationError::IdentityChanged | CoordinationError::Reserved => {
            crate::error::ProtocolError::FileNotFound("release no longer available".into()).into()
        }
        other => coordination_error(other),
    }
}

/// Keeps the specific reason an SQL deletion was refused for operators.
fn deletion_refusal(error: CoordinationError) -> DeleteError {
    let blocker = match error {
        CoordinationError::IdentityChanged | CoordinationError::Reserved => {
            return DeleteError::Stale;
        }
        CoordinationError::Active => DeleteBlocker::ActiveRelease,
        CoordinationError::LiveSession => DeleteBlocker::BootSessionPinned,
        CoordinationError::ReadersPresent => DeleteBlocker::TransferPinned,
        CoordinationError::InvalidInput
        | CoordinationError::IdConflict
        | CoordinationError::Capacity
        | CoordinationError::DeadlineExceeded
        | CoordinationError::Persistence(_) => {
            tracing::warn!(%error, "SQL metadata deletion coordination unavailable");
            DeleteBlocker::PersistenceCoordinationUnavailable
        }
    };
    DeleteError::Blocked(vec![blocker])
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn reader_release_retries_transient_failures_with_bounded_backoff() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        retry_reader_release(READER_RELEASE_BACKOFF, || async {
            match attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
                0 | 1 => Err(CoordinationError::DeadlineExceeded),
                _ => Ok(()),
            }
        })
        .await
        .unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(started.elapsed(), std::time::Duration::from_millis(1500));

        attempts.store(0, std::sync::atomic::Ordering::Relaxed);
        let error = retry_reader_release(READER_RELEASE_BACKOFF, || async {
            attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(CoordinationError::Persistence(TempestError::Persistence(
                "database unavailable".into(),
            )))
        })
        .await
        .unwrap_err();
        assert!(matches!(error, CoordinationError::Persistence(_)));
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Relaxed),
            READER_RELEASE_BACKOFF.len() + 1
        );

        attempts.store(0, std::sync::atomic::Ordering::Relaxed);
        let error = retry_reader_release(READER_RELEASE_BACKOFF, || async {
            attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(CoordinationError::IdConflict)
        })
        .await
        .unwrap_err();
        assert!(matches!(error, CoordinationError::IdConflict));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn transient_coordination_failures_are_retryable_and_removed_releases_are_absent() {
        for error in [
            CoordinationError::DeadlineExceeded,
            CoordinationError::Capacity,
        ] {
            assert!(matches!(
                coordination_error(error),
                TempestError::PersistenceBusy(_)
            ));
        }
        for error in [
            CoordinationError::IdentityChanged,
            CoordinationError::Reserved,
        ] {
            assert!(matches!(
                reader_admission_error(error),
                TempestError::Protocol(crate::error::ProtocolError::FileNotFound(_))
            ));
        }
        assert!(matches!(
            reader_admission_error(CoordinationError::DeadlineExceeded),
            TempestError::PersistenceBusy(_)
        ));
    }

    #[test]
    fn sql_deletion_refusals_keep_their_specific_reason() {
        for (error, blocker) in [
            (CoordinationError::Active, DeleteBlocker::ActiveRelease),
            (
                CoordinationError::LiveSession,
                DeleteBlocker::BootSessionPinned,
            ),
            (
                CoordinationError::ReadersPresent,
                DeleteBlocker::TransferPinned,
            ),
            (
                CoordinationError::Capacity,
                DeleteBlocker::PersistenceCoordinationUnavailable,
            ),
            (
                CoordinationError::DeadlineExceeded,
                DeleteBlocker::PersistenceCoordinationUnavailable,
            ),
        ] {
            assert!(matches!(
                deletion_refusal(error),
                DeleteError::Blocked(blockers) if blockers == [blocker]
            ));
        }
        for error in [
            CoordinationError::IdentityChanged,
            CoordinationError::Reserved,
        ] {
            assert!(matches!(deletion_refusal(error), DeleteError::Stale));
        }
    }

    #[test]
    fn serving_modes_require_an_explicit_stopped_transition() {
        assert_eq!(
            serving_protocol(LEGACY_PROTOCOL, false).unwrap(),
            ORDINARY_PROTOCOL
        );
        assert_eq!(
            serving_protocol(LEGACY_PROTOCOL, true).unwrap(),
            DELETION_PROTOCOL
        );
        assert!(serving_protocol(ORDINARY_PROTOCOL, false).is_ok());
        assert!(serving_protocol(DELETION_PROTOCOL, true).is_ok());
        assert!(serving_protocol(ORDINARY_PROTOCOL, true).is_err());
        assert!(serving_protocol(DELETION_PROTOCOL, false).is_err());
        assert!(serving_protocol(99, true).is_err());
    }
}
