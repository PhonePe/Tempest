// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::fs::{File, Metadata};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::error::TempestError;

pub(crate) const HOT_ARTIFACT_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const HOT_ARTIFACT_CACHE_MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const HOT_ARTIFACT_CACHE_MAX_ENTRIES: usize = 4096;
const BACKGROUND_FILL_MIN_BYTES: usize = 4 * 1024 * 1024;
const MAX_BACKGROUND_FILLS: usize = 4;

/// Stable identity derived from metadata on the same handle used for reading.
#[derive(Clone, Debug, Eq)]
pub(crate) struct ArtifactIdentity {
    #[cfg(not(unix))]
    nonce: u64,
    len: u64,
    modified_ns: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl ArtifactIdentity {
    pub(crate) fn new(path: &Path, metadata: &Metadata) -> Self {
        #[cfg(unix)]
        let _ = path;
        #[cfg(not(unix))]
        static NEXT_NON_UNIX_IDENTITY: AtomicU64 = AtomicU64::new(1);
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        Self {
            #[cfg(not(unix))]
            nonce: NEXT_NON_UNIX_IDENTITY.fetch_add(1, Ordering::Relaxed),
            len: metadata.len(),
            modified_ns,
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(metadata),
            #[cfg(unix)]
            changed_seconds: std::os::unix::fs::MetadataExt::ctime(metadata),
            #[cfg(unix)]
            changed_nanoseconds: std::os::unix::fs::MetadataExt::ctime_nsec(metadata),
        }
    }

    pub(crate) fn shared_cache_key(&self) -> String {
        #[cfg(unix)]
        {
            format!(
                "file:{}:{}:{}:{}:{}:{}",
                self.device,
                self.inode,
                self.len,
                self.modified_ns,
                self.changed_seconds,
                self.changed_nanoseconds
            )
        }
        #[cfg(not(unix))]
        {
            format!("uncached:{}:{}:{}", self.nonce, self.len, self.modified_ns)
        }
    }
}

impl PartialEq for ArtifactIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.modified_ns == other.modified_ns && {
            #[cfg(unix)]
            {
                self.device == other.device
                    && self.inode == other.inode
                    && self.changed_seconds == other.changed_seconds
                    && self.changed_nanoseconds == other.changed_nanoseconds
            }
            #[cfg(not(unix))]
            {
                self.nonce == other.nonce
            }
        }
    }
}

impl Hash for ArtifactIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        #[cfg(not(unix))]
        self.nonce.hash(state);
        self.len.hash(state);
        self.modified_ns.hash(state);
        #[cfg(unix)]
        {
            self.device.hash(state);
            self.inode.hash(state);
            self.changed_seconds.hash(state);
            self.changed_nanoseconds.hash(state);
        }
    }
}

enum EntryState {
    Loading,
    Ready(Arc<Bytes>),
    Failed(String),
}

pub(crate) struct CacheEntry {
    state: Mutex<EntryState>,
    verified_content_hash: Mutex<Option<String>>,
    ready: Notify,
    reserved_bytes: usize,
    path: Arc<Path>,
    metadata: Metadata,
    last_validated_ms: AtomicU64,
    background_fill: bool,
}

impl CacheEntry {
    fn loading(
        reserved_bytes: usize,
        path: Arc<Path>,
        metadata: Metadata,
        validated_at_ms: u64,
        background_fill: bool,
    ) -> Self {
        Self {
            state: Mutex::new(EntryState::Loading),
            verified_content_hash: Mutex::new(None),
            ready: Notify::new(),
            reserved_bytes,
            path,
            metadata,
            last_validated_ms: AtomicU64::new(validated_at_ms),
            background_fill,
        }
    }

    fn publish(&self, bytes: Arc<Bytes>) {
        *self.state.lock() = EntryState::Ready(bytes);
        self.ready.notify_waiters();
    }

    fn fail(&self, error: &TempestError) {
        *self.state.lock() = EntryState::Failed(error.to_string());
        self.ready.notify_waiters();
    }

    fn ready_bytes(&self) -> Option<Arc<Bytes>> {
        match &*self.state.lock() {
            EntryState::Ready(bytes) => Some(bytes.clone()),
            EntryState::Loading | EntryState::Failed(_) => None,
        }
    }

    fn mark_verified(&self, content_hash: &str) {
        *self.verified_content_hash.lock() = Some(content_hash.to_owned());
    }

    fn verified_bytes(&self, content_hash: &str, size: u64) -> Option<Arc<Bytes>> {
        if self.verified_content_hash.lock().as_deref() != Some(content_hash) {
            return None;
        }
        let bytes = self.ready_bytes()?;
        (u64::try_from(bytes.len()).ok()? == size).then_some(bytes)
    }

    fn evictable(&self) -> bool {
        match &*self.state.lock() {
            EntryState::Ready(bytes) => Arc::strong_count(bytes) == 1,
            EntryState::Loading | EntryState::Failed(_) => false,
        }
    }

    async fn wait(&self) -> Result<Arc<Bytes>, TempestError> {
        loop {
            let notified = self.ready.notified();
            match &*self.state.lock() {
                EntryState::Ready(bytes) => return Ok(bytes.clone()),
                EntryState::Failed(error) => {
                    return Err(TempestError::Io(std::io::Error::other(error.clone())));
                }
                EntryState::Loading => {}
            }
            notified.await;
        }
    }
}

struct CacheState {
    entries: HashMap<ArtifactIdentity, Arc<CacheEntry>>,
    insertion_order: VecDeque<(ArtifactIdentity, Arc<CacheEntry>)>,
    resident_bytes: usize,
}

#[derive(Clone)]
struct HotPath {
    identity: ArtifactIdentity,
    entry: Arc<CacheEntry>,
}

/// Result of opening and optionally retaining one small artifact.
pub(crate) enum PreparedArtifact {
    File(File),
    BackgroundFill(File, BackgroundFill),
    Memory(Arc<Bytes>),
    Pending(Arc<CacheEntry>),
}

struct BackgroundFillPermit(Arc<AtomicUsize>);

impl BackgroundFillPermit {
    fn try_acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        #[allow(
            deprecated,
            reason = "try_update requires Rust 1.95; retain fetch_update for MSRV 1.85"
        )]
        let reservation = active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_BACKGROUND_FILLS).then(|| current + 1)
        });
        reservation.ok().map(|_| Self(active.clone()))
    }
}

impl Drop for BackgroundFillPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct BackgroundFill {
    file: File,
    identity: ArtifactIdentity,
    entry: Arc<CacheEntry>,
    state: Arc<Mutex<CacheState>>,
    hot_paths: Arc<DashMap<Arc<Path>, HotPath>>,
    fills: Arc<AtomicU64>,
    _permit: BackgroundFillPermit,
}

impl BackgroundFill {
    fn run(self) {
        match read_stable_bytes_at(
            &self.file,
            self.entry.path.as_ref(),
            &self.entry.metadata,
            self.entry.reserved_bytes,
        ) {
            Ok(bytes) => {
                self.entry.publish(Arc::new(bytes));
                self.fills.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.entry.fail(&error);
                remove_failed_entry(
                    self.state.as_ref(),
                    self.hot_paths.as_ref(),
                    &self.identity,
                    &self.entry,
                );
                tracing::debug!(
                    path = %self.entry.path.display(),
                    error = %error,
                    "Background hot-artifact fill failed"
                );
            }
        }
    }
}

/// Retains the expected identity and cache entry across capability validation.
///
/// Holding the entry prevents bounded eviction until capability validation has
/// selected retained bytes or fallen back to the opened file.
pub(crate) struct HotPathTicket {
    identity: ArtifactIdentity,
    entry: Arc<CacheEntry>,
}

impl PreparedArtifact {
    pub(crate) async fn resolve(self) -> Result<ArtifactContent, TempestError> {
        match self {
            Self::File(file) => Ok(ArtifactContent::File(file)),
            Self::BackgroundFill(file, fill) => {
                tokio::task::spawn_blocking(move || fill.run());
                Ok(ArtifactContent::File(file))
            }
            Self::Memory(bytes) => Ok(ArtifactContent::Memory(bytes)),
            Self::Pending(entry) => entry.wait().await.map(ArtifactContent::Memory),
        }
    }
}

/// Transfer source after any coalesced cache fill has completed.
pub(crate) enum ArtifactContent {
    File(File),
    Memory(Arc<Bytes>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HotArtifactCacheStats {
    pub hits: u64,
    pub verified_hits: u64,
    pub freshness_hits: u64,
    pub misses: u64,
    pub coalesced: u64,
    pub bypasses: u64,
    pub fills: u64,
    pub resident_bytes: usize,
    pub entries: usize,
}

/// Byte-bounded FIFO cache for small immutable artifact snapshots.
///
/// Unmanaged lookups follow a capability-open of the requested name and key
/// bytes from metadata on that exact handle. Managed lookups may skip that open
/// only after the retained bytes have matched the pinned size and SHA-256.
pub(crate) struct HotArtifactCache {
    max_bytes: usize,
    max_file_bytes: usize,
    max_entries: usize,
    state: Arc<Mutex<CacheState>>,
    hot_paths: Arc<DashMap<Arc<Path>, HotPath>>,
    hits: AtomicU64,
    verified_hits: AtomicU64,
    misses: AtomicU64,
    coalesced: AtomicU64,
    bypasses: AtomicU64,
    fills: Arc<AtomicU64>,
    freshness_hits: AtomicU64,
    background_fills: Arc<AtomicUsize>,
    started_at: Instant,
}

impl HotArtifactCache {
    #[cfg(test)]
    pub(crate) fn with_default_limits() -> Self {
        Self::with_limits(
            HOT_ARTIFACT_CACHE_MAX_BYTES,
            HOT_ARTIFACT_CACHE_MAX_FILE_BYTES,
        )
    }

    pub(crate) fn with_limits(max_bytes: usize, max_file_bytes: usize) -> Self {
        Self::new(max_bytes, max_file_bytes, HOT_ARTIFACT_CACHE_MAX_ENTRIES)
    }

    fn new(max_bytes: usize, max_file_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_file_bytes,
            max_entries,
            state: Arc::new(Mutex::new(CacheState {
                entries: HashMap::new(),
                insertion_order: VecDeque::new(),
                resident_bytes: 0,
            })),
            hot_paths: Arc::new(DashMap::new()),
            hits: AtomicU64::new(0),
            verified_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
            bypasses: AtomicU64::new(0),
            fills: Arc::new(AtomicU64::new(0)),
            freshness_hits: AtomicU64::new(0),
            background_fills: Arc::new(AtomicUsize::new(0)),
            started_at: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Returns a retained ticket for the capability-validation handoff.
    pub(crate) fn hot_path_ticket(&self, path: &Path) -> Option<HotPathTicket> {
        let hot = self.hot_paths.get(path)?;
        Some(HotPathTicket {
            identity: hot.identity.clone(),
            entry: hot.entry.clone(),
        })
    }

    /// Returns a previously verified immutable snapshot for a managed release.
    ///
    /// The bytes, not the mutable directory entry, are the trust boundary here.
    /// A path replacement cannot change the retained allocation, and the exact
    /// pinned digest and size must match before the filesystem open is skipped.
    pub(crate) fn verified_path(
        &self,
        path: &Path,
        content_hash: &str,
        size: u64,
    ) -> Option<(Arc<Bytes>, Metadata)> {
        let hot = self.hot_paths.get(path)?;
        let bytes = hot.entry.verified_bytes(content_hash, size)?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.verified_hits.fetch_add(1, Ordering::Relaxed);
        Some((bytes, hot.entry.metadata.clone()))
    }

    /// Returns a recently capability-validated unmanaged snapshot.
    ///
    /// This optimization is disabled when `validation_interval_ms` is zero.
    /// Callers explicitly accept that a rename or deletion can remain invisible
    /// until the bounded interval elapses; retained bytes remain path-confined.
    pub(crate) fn recent_unmanaged_path(
        &self,
        path: &Path,
        validation_interval_ms: u64,
    ) -> Option<(Arc<Bytes>, Metadata)> {
        if validation_interval_ms == 0 {
            return None;
        }
        self.recent_unmanaged_path_at(path, validation_interval_ms, self.now_ms())
    }

    fn recent_unmanaged_path_at(
        &self,
        path: &Path,
        validation_interval_ms: u64,
        now_ms: u64,
    ) -> Option<(Arc<Bytes>, Metadata)> {
        let hot = self.hot_paths.get(path)?;
        let validated_at = hot.entry.last_validated_ms.load(Ordering::Acquire);
        if now_ms.saturating_sub(validated_at) > validation_interval_ms {
            return None;
        }
        let bytes = hot.entry.ready_bytes()?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.freshness_hits.fetch_add(1, Ordering::Relaxed);
        Some((bytes, hot.entry.metadata.clone()))
    }

    /// Records that the retained bytes for this exact opened identity matched
    /// the managed release digest.
    pub(crate) fn mark_verified(&self, path: &Path, metadata: &Metadata, content_hash: &str) {
        let identity = ArtifactIdentity::new(path, metadata);
        let Some(hot) = self.hot_paths.get(path) else {
            return;
        };
        if hot.identity == identity {
            hot.entry.mark_verified(content_hash);
        }
    }

    /// Looks up a previously admitted identity without populating on a miss.
    ///
    /// The transfer path uses this after deciding to validate a known-hot path
    /// inline. An eviction or replacement between that decision and the open
    /// must not turn into a cold filesystem read on an async runtime worker.
    pub(crate) fn prepare_ticket(
        &self,
        ticket: HotPathTicket,
        file: File,
        path: &Path,
        metadata: &Metadata,
    ) -> PreparedArtifact {
        let identity = ArtifactIdentity::new(path, metadata);
        if identity == ticket.identity {
            ticket
                .entry
                .last_validated_ms
                .store(self.now_ms(), Ordering::Release);
            if let Some(bytes) = ticket.entry.ready_bytes() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return PreparedArtifact::Memory(bytes);
            }
            if ticket.entry.background_fill {
                return PreparedArtifact::File(file);
            }
            self.coalesced.fetch_add(1, Ordering::Relaxed);
            return PreparedArtifact::Pending(ticket.entry);
        }

        self.hot_paths.remove_if(path, |_, hot| {
            hot.identity == ticket.identity && Arc::ptr_eq(&hot.entry, &ticket.entry)
        });
        self.bypasses.fetch_add(1, Ordering::Relaxed);
        PreparedArtifact::File(file)
    }

    pub(crate) fn prepare(
        &self,
        file: File,
        path: &Path,
        metadata: &Metadata,
    ) -> Result<PreparedArtifact, TempestError> {
        // Stable file identity is not exposed by Rust's portable metadata API.
        // A path/size/mtime tuple can alias a same-name replacement, so retain
        // correctness by disabling identity reuse on non-Unix platforms.
        if cfg!(not(unix)) {
            let _ = (path, metadata);
            self.bypasses.fetch_add(1, Ordering::Relaxed);
            return Ok(PreparedArtifact::File(file));
        }

        let mut file = file;
        let file_bytes = match usize::try_from(metadata.len()) {
            Ok(bytes)
                if bytes <= self.max_file_bytes
                    && bytes <= self.max_bytes
                    && self.max_entries > 0 =>
            {
                bytes
            }
            _ => {
                self.bypasses.fetch_add(1, Ordering::Relaxed);
                return Ok(PreparedArtifact::File(file));
            }
        };
        let identity = ArtifactIdentity::new(path, metadata);
        let background_fill = file_bytes >= BACKGROUND_FILL_MIN_BYTES;
        let (entry, background_permit) = {
            let mut state = self.state.lock();
            if let Some(entry) = state.entries.get(&identity) {
                entry
                    .last_validated_ms
                    .store(self.now_ms(), Ordering::Release);
                if let Some(bytes) = entry.ready_bytes() {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(PreparedArtifact::Memory(bytes));
                }
                if entry.background_fill {
                    return Ok(PreparedArtifact::File(file));
                }
                self.coalesced.fetch_add(1, Ordering::Relaxed);
                return Ok(PreparedArtifact::Pending(entry.clone()));
            }

            let background_permit = background_fill
                .then(|| BackgroundFillPermit::try_acquire(&self.background_fills))
                .flatten();
            if background_fill && background_permit.is_none() {
                self.bypasses.fetch_add(1, Ordering::Relaxed);
                return Ok(PreparedArtifact::File(file));
            }

            if !reserve_entry(
                &mut state,
                &self.hot_paths,
                file_bytes,
                self.max_bytes,
                self.max_entries,
            ) {
                self.bypasses.fetch_add(1, Ordering::Relaxed);
                return Ok(PreparedArtifact::File(file));
            }
            let cached_path: Arc<Path> = Arc::from(path);
            let entry = Arc::new(CacheEntry::loading(
                file_bytes,
                cached_path.clone(),
                metadata.clone(),
                self.now_ms(),
                background_fill,
            ));
            state.resident_bytes += file_bytes;
            state.entries.insert(identity.clone(), entry.clone());
            self.hot_paths.insert(
                cached_path,
                HotPath {
                    identity: identity.clone(),
                    entry: entry.clone(),
                },
            );
            state
                .insertion_order
                .push_back((identity.clone(), entry.clone()));
            self.misses.fetch_add(1, Ordering::Relaxed);
            (entry, background_permit)
        };

        if let Some(permit) = background_permit {
            let transfer_file = match file.try_clone() {
                Ok(file) => file,
                Err(error) => {
                    let error = TempestError::Io(error);
                    entry.fail(&error);
                    self.remove_failed(&identity, &entry);
                    return Err(error);
                }
            };
            return Ok(PreparedArtifact::BackgroundFill(
                transfer_file,
                BackgroundFill {
                    file,
                    identity,
                    entry,
                    state: self.state.clone(),
                    hot_paths: self.hot_paths.clone(),
                    fills: self.fills.clone(),
                    _permit: permit,
                },
            ));
        }

        match read_stable_bytes(&mut file, path, metadata, file_bytes) {
            Ok(bytes) => {
                let bytes = Arc::new(bytes);
                entry.publish(bytes.clone());
                self.fills.fetch_add(1, Ordering::Relaxed);
                Ok(PreparedArtifact::Memory(bytes))
            }
            Err(error) => {
                entry.fail(&error);
                self.remove_failed(&identity, &entry);
                Err(error)
            }
        }
    }

    fn remove_failed(&self, identity: &ArtifactIdentity, failed: &Arc<CacheEntry>) {
        remove_failed_entry(
            self.state.as_ref(),
            self.hot_paths.as_ref(),
            identity,
            failed,
        );
    }

    pub(crate) fn stats(&self) -> HotArtifactCacheStats {
        let state = self.state.lock();
        HotArtifactCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            verified_hits: self.verified_hits.load(Ordering::Relaxed),
            freshness_hits: self.freshness_hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            bypasses: self.bypasses.load(Ordering::Relaxed),
            fills: self.fills.load(Ordering::Relaxed),
            resident_bytes: state.resident_bytes,
            entries: state.entries.len(),
        }
    }
}

fn remove_failed_entry(
    state: &Mutex<CacheState>,
    hot_paths: &DashMap<Arc<Path>, HotPath>,
    identity: &ArtifactIdentity,
    failed: &Arc<CacheEntry>,
) {
    let mut state = state.lock();
    if state
        .entries
        .get(identity)
        .is_some_and(|current| Arc::ptr_eq(current, failed))
    {
        state.entries.remove(identity);
        hot_paths.remove_if(failed.path.as_ref(), |_, hot| {
            hot.identity == *identity && Arc::ptr_eq(&hot.entry, failed)
        });
        state.resident_bytes = state.resident_bytes.saturating_sub(failed.reserved_bytes);
    }
}

fn reserve_entry(
    state: &mut CacheState,
    hot_paths: &DashMap<Arc<Path>, HotPath>,
    incoming_bytes: usize,
    max_bytes: usize,
    max_entries: usize,
) -> bool {
    while state.resident_bytes.saturating_add(incoming_bytes) > max_bytes
        || state.entries.len() >= max_entries
    {
        // Bound lock hold time when live transfers lease most of the cache.
        let candidates = state.insertion_order.len().min(64);
        let mut evicted = false;
        for _ in 0..candidates {
            let Some((identity, entry)) = state.insertion_order.pop_front() else {
                break;
            };
            let is_current = state
                .entries
                .get(&identity)
                .is_some_and(|current| Arc::ptr_eq(current, &entry));
            if is_current && !entry.evictable() {
                state.insertion_order.push_back((identity, entry));
                continue;
            }
            // Remove the discoverable path first. `remove_if` waits for active
            // map guards, so any ticket or byte lease acquired before removal
            // is reflected in the strong counts below and no new lease can
            // race the decision. Restore the path if the entry remains in use.
            let removed_hot_path = if is_current {
                hot_paths.remove_if(entry.path.as_ref(), |_, hot| {
                    hot.identity == identity && Arc::ptr_eq(&hot.entry, &entry)
                })
            } else {
                None
            };
            let index_references = 2 + usize::from(removed_hot_path.is_some());
            let has_external_reference = Arc::strong_count(&entry) > index_references;
            if is_current && entry.evictable() && !has_external_reference {
                state.entries.remove(&identity);
                state.resident_bytes = state.resident_bytes.saturating_sub(entry.reserved_bytes);
                evicted = true;
                break;
            }
            if is_current {
                if let Some((path, hot_path)) = removed_hot_path {
                    hot_paths.insert(path, hot_path);
                }
                state.insertion_order.push_back((identity, entry));
            }
        }
        if !evicted {
            return false;
        }
    }
    true
}

fn read_stable_bytes(
    file: &mut File,
    path: &Path,
    metadata: &Metadata,
    expected_bytes: usize,
) -> Result<Bytes, TempestError> {
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(expected_bytes)
        .map_err(|error| {
            TempestError::Io(std::io::Error::other(format!(
                "failed to reserve hot-artifact buffer: {error}"
            )))
        })?;
    contents.resize(expected_bytes, 0);
    file.read_exact(&mut contents)?;
    let after = file.metadata()?;
    if ArtifactIdentity::new(path, metadata) != ArtifactIdentity::new(path, &after) {
        return Err(TempestError::Io(std::io::Error::other(
            "artifact identity changed while populating hot cache",
        )));
    }
    Ok(Bytes::from(contents))
}

#[cfg(unix)]
fn read_stable_bytes_at(
    file: &File,
    path: &Path,
    metadata: &Metadata,
    expected_bytes: usize,
) -> Result<Bytes, TempestError> {
    use std::os::unix::fs::FileExt;

    let mut contents = Vec::new();
    contents
        .try_reserve_exact(expected_bytes)
        .map_err(|error| {
            TempestError::Io(std::io::Error::other(format!(
                "failed to reserve background hot-artifact buffer: {error}"
            )))
        })?;
    contents.resize(expected_bytes, 0);
    let mut offset = 0usize;
    while offset < expected_bytes {
        let read = match file.read_at(
            &mut contents[offset..],
            u64::try_from(offset).unwrap_or(u64::MAX),
        ) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return Err(TempestError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "artifact was truncated while populating hot cache",
            )));
        }
        offset += read;
    }
    let after = file.metadata()?;
    if ArtifactIdentity::new(path, metadata) != ArtifactIdentity::new(path, &after) {
        return Err(TempestError::Io(std::io::Error::other(
            "artifact identity changed while populating hot cache",
        )));
    }
    Ok(Bytes::from(contents))
}

#[cfg(not(unix))]
fn read_stable_bytes_at(
    file: &File,
    path: &Path,
    metadata: &Metadata,
    expected_bytes: usize,
) -> Result<Bytes, TempestError> {
    let mut file = file.try_clone()?;
    read_stable_bytes(&mut file, path, metadata, expected_bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    fn open(path: &Path) -> (File, Metadata) {
        let file = File::open(path).unwrap();
        let metadata = file.metadata().unwrap();
        (file, metadata)
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn non_unix_bypasses_cache_without_stable_file_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("tiny.img");
        fs::write(&path, b"cached bytes").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);
        for _ in 0..2 {
            let (file, metadata) = open(&path);
            let content = cache
                .prepare(file, &path, &metadata)
                .unwrap()
                .resolve()
                .await
                .unwrap();
            assert!(matches!(content, ArtifactContent::File(_)));
        }
        assert!(cache.hot_path_ticket(&path).is_none());
        assert!(cache.recent_unmanaged_path(&path, 1_000).is_none());
        let stats = cache.stats();
        assert_eq!((stats.fills, stats.entries, stats.bypasses), (0, 0, 2));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hot_artifact_hit_reuses_one_retained_allocation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("tiny.img");
        fs::write(&path, b"cached bytes").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);
        assert!(cache.hot_path_ticket(&path).is_none());

        let (file, metadata) = open(&path);
        let first = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        let first = match first {
            ArtifactContent::Memory(bytes) => bytes,
            ArtifactContent::File(_) => panic!("small artifact bypassed cache"),
        };
        let (file, metadata) = open(&path);
        let second = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        let second = match second {
            ArtifactContent::Memory(bytes) => bytes,
            ArtifactContent::File(_) => panic!("small artifact bypassed cache"),
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert!(cache.hot_path_ticket(&path).is_some());
        assert_eq!(cache.stats().fills, 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_file_limit_admits_artifact_above_the_default_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("large-managed.img");
        let artifact_len = HOT_ARTIFACT_CACHE_MAX_FILE_BYTES + 1;
        fs::write(&path, vec![0xa5; artifact_len]).unwrap();

        let defaults = HotArtifactCache::with_default_limits();
        let (file, metadata) = open(&path);
        assert!(matches!(
            defaults.prepare(file, &path, &metadata).unwrap(),
            PreparedArtifact::File(_)
        ));

        let configured = HotArtifactCache::with_limits(4 * 1024 * 1024, 3 * 1024 * 1024);
        let (file, metadata) = open(&path);
        let ArtifactContent::Memory(bytes) = configured
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap()
        else {
            panic!("artifact within configured limits bypassed cache");
        };
        assert_eq!(bytes.len(), artifact_len);
        assert_eq!(configured.stats().resident_bytes, artifact_len);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_fill_streams_immediately_and_publishes_in_background() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("large.img");
        fs::write(&path, vec![0x5a; BACKGROUND_FILL_MIN_BYTES]).unwrap();
        let cache =
            HotArtifactCache::new(2 * BACKGROUND_FILL_MIN_BYTES, BACKGROUND_FILL_MIN_BYTES, 8);

        let (first_file, metadata) = open(&path);
        let first = cache.prepare(first_file, &path, &metadata).unwrap();
        assert!(matches!(&first, PreparedArtifact::BackgroundFill(_, _)));

        // A request arriving during the fill must use its independently opened
        // handle instead of waiting behind the full-artifact memory copy.
        let (second_file, second_metadata) = open(&path);
        let second = cache.prepare(second_file, &path, &second_metadata).unwrap();
        assert!(matches!(&second, PreparedArtifact::File(_)));

        assert!(matches!(
            first.resolve().await.unwrap(),
            ArtifactContent::File(_)
        ));
        assert!(matches!(
            second.resolve().await.unwrap(),
            ArtifactContent::File(_)
        ));

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while cache.stats().fills == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background cache fill did not complete");

        let (third_file, third_metadata) = open(&path);
        let third = cache
            .prepare(third_file, &path, &third_metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        let ArtifactContent::Memory(bytes) = third else {
            panic!("completed background fill was not reused");
        };
        assert_eq!(bytes.len(), BACKGROUND_FILL_MIN_BYTES);
        assert_eq!(cache.stats().fills, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn same_size_replacement_cannot_inherit_cached_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("tiny.img");
        fs::write(&path, b"old!").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);

        let (file, metadata) = open(&path);
        let old = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"new!").unwrap();
        fs::rename(&replacement, &path).unwrap();
        let (file, metadata) = open(&path);
        let ticket = cache.hot_path_ticket(&path).unwrap();
        let changed = cache.prepare_ticket(ticket, file, &path, &metadata);
        assert!(matches!(changed, PreparedArtifact::File(_)));
        assert!(cache.hot_path_ticket(&path).is_none());

        let (file, metadata) = open(&path);
        let new = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();

        let ArtifactContent::Memory(old) = old else {
            panic!("old artifact bypassed cache");
        };
        let ArtifactContent::Memory(new) = new else {
            panic!("new artifact bypassed cache");
        };
        assert_eq!(old.as_ref().as_ref(), b"old!");
        assert_eq!(new.as_ref().as_ref(), b"new!");
        assert!(!Arc::ptr_eq(&old, &new));
        assert_eq!(cache.stats().fills, 2);
        assert_eq!(cache.stats().bypasses, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_snapshot_requires_exact_verified_digest_and_size() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("managed.img");
        fs::write(&path, b"verified bytes").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);
        let (file, metadata) = open(&path);
        let prepared = cache.prepare(file, &path, &metadata).unwrap();
        let ArtifactContent::Memory(expected) = prepared.resolve().await.unwrap() else {
            panic!("small artifact bypassed cache");
        };

        assert!(cache.verified_path(&path, "digest-a", 14).is_none());
        cache.mark_verified(&path, &metadata, "digest-a");
        assert!(cache.verified_path(&path, "digest-b", 14).is_none());
        assert!(cache.verified_path(&path, "digest-a", 13).is_none());

        let (actual, cached_metadata) = cache.verified_path(&path, "digest-a", 14).unwrap();
        assert!(Arc::ptr_eq(&expected, &actual));
        assert_eq!(cached_metadata.len(), 14);
        assert_eq!(cache.stats().verified_hits, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unmanaged_freshness_window_is_explicit_and_bounded() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unmanaged.img");
        fs::write(&path, b"cached").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);
        let (file, metadata) = open(&path);
        cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();

        assert!(cache.recent_unmanaged_path(&path, 0).is_none());
        let validated_at = {
            cache
                .hot_paths
                .get(path.as_path())
                .unwrap()
                .entry
                .last_validated_ms
                .load(Ordering::Acquire)
        };
        assert!(
            cache
                .recent_unmanaged_path_at(&path, 10, validated_at.saturating_add(10))
                .is_some()
        );
        assert!(
            cache
                .recent_unmanaged_path_at(&path, 10, validated_at.saturating_add(11))
                .is_none()
        );
        assert_eq!(cache.stats().freshness_hits, 1);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unmanaged_recent_hits_share_bytes_under_concurrency() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unmanaged.img");
        fs::write(&path, b"cached").unwrap();
        let cache = Arc::new(HotArtifactCache::new(1024, 1024, 8));
        let (file, metadata) = open(&path);
        let ArtifactContent::Memory(expected) = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap()
        else {
            panic!("small artifact bypassed cache");
        };

        let mut tasks = Vec::new();
        for _ in 0..64 {
            let cache = cache.clone();
            let path = path.clone();
            let expected = expected.clone();
            tasks.push(tokio::spawn(async move {
                let (actual, _) = cache.recent_unmanaged_path(&path, 1_000).unwrap();
                assert!(Arc::ptr_eq(&expected, &actual));
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(cache.stats().freshness_hits, 64);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_snapshot_is_immutable_after_same_name_replacement() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("managed.img");
        fs::write(&path, b"trusted").unwrap();
        let cache = HotArtifactCache::new(1024, 1024, 8);
        let (file, metadata) = open(&path);
        cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        cache.mark_verified(&path, &metadata, "trusted-digest");

        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"hostile").unwrap();
        fs::rename(replacement, &path).unwrap();

        let (bytes, cached_metadata) = cache.verified_path(&path, "trusted-digest", 7).unwrap();
        assert_eq!(bytes.as_ref().as_ref(), b"trusted");
        assert_eq!(
            ArtifactIdentity::new(&path, &cached_metadata),
            ArtifactIdentity::new(&path, &metadata)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_budget_is_exact_and_in_use_entries_are_not_evicted() {
        let directory = tempdir().unwrap();
        let first_path = directory.path().join("first");
        let second_path = directory.path().join("second");
        fs::write(&first_path, b"12345678").unwrap();
        fs::write(&second_path, b"abcdefgh").unwrap();
        let cache = HotArtifactCache::new(8, 8, 1);

        let (file, metadata) = open(&first_path);
        let retained = cache
            .prepare(file, &first_path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        let (file, metadata) = open(&second_path);
        let bypassed = cache
            .prepare(file, &second_path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();

        assert!(matches!(retained, ArtifactContent::Memory(_)));
        assert!(matches!(bypassed, ArtifactContent::File(_)));
        assert!(cache.hot_path_ticket(&first_path).is_some());
        assert!(cache.hot_path_ticket(&second_path).is_none());
        assert_eq!(cache.stats().resident_bytes, 8);
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().bypasses, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hot_path_ticket_keeps_retained_bytes_charged_to_budget() {
        let directory = tempdir().unwrap();
        let first_path = directory.path().join("first");
        let second_path = directory.path().join("second");
        fs::write(&first_path, b"12345678").unwrap();
        fs::write(&second_path, b"abcdefgh").unwrap();
        let cache = HotArtifactCache::new(8, 8, 1);

        let (file, metadata) = open(&first_path);
        drop(
            cache
                .prepare(file, &first_path, &metadata)
                .unwrap()
                .resolve()
                .await
                .unwrap(),
        );
        let ticket = cache.hot_path_ticket(&first_path).unwrap();

        let (file, metadata) = open(&second_path);
        let while_ticketed = cache
            .prepare(file, &second_path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        assert!(matches!(while_ticketed, ArtifactContent::File(_)));
        assert_eq!(cache.stats().resident_bytes, 8);
        assert_eq!(cache.stats().entries, 1);

        drop(ticket);
        let (file, metadata) = open(&second_path);
        let after_release = cache
            .prepare(file, &second_path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        assert!(matches!(after_release, ArtifactContent::Memory(_)));
        assert!(cache.hot_path_ticket(&first_path).is_none());
        assert!(cache.hot_path_ticket(&second_path).is_some());
        assert_eq!(cache.stats().resident_bytes, 8);
        assert_eq!(cache.stats().entries, 1);
    }

    #[tokio::test]
    async fn oversize_artifact_bypasses_without_allocation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("large");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[0x5a; 9]).unwrap();
        drop(file);
        let cache = HotArtifactCache::new(8, 8, 1);
        let (file, metadata) = open(&path);

        let prepared = cache
            .prepare(file, &path, &metadata)
            .unwrap()
            .resolve()
            .await
            .unwrap();
        assert!(matches!(prepared, ArtifactContent::File(_)));
        assert_eq!(cache.stats().resident_bytes, 0);
        assert_eq!(cache.stats().bypasses, 1);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_reads_fill_one_identity_once() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("shared.img");
        fs::write(&path, vec![0x5a; 1024 * 1024]).unwrap();
        let cache = Arc::new(HotArtifactCache::new(2 * 1024 * 1024, 2 * 1024 * 1024, 8));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let prepared = tokio::task::spawn_blocking(move || {
                    let (file, metadata) = open(&path);
                    barrier.wait();
                    cache.prepare(file, &path, &metadata)
                })
                .await
                .unwrap()
                .unwrap();
                let ArtifactContent::Memory(bytes) = prepared.resolve().await.unwrap() else {
                    panic!("small artifact bypassed cache");
                };
                assert_eq!(bytes.len(), 1024 * 1024);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        let stats = cache.stats();
        assert_eq!(stats.fills, 1);
        assert_eq!(stats.hits + stats.coalesced, 15);
        assert_eq!(stats.resident_bytes, 1024 * 1024);
    }
}
