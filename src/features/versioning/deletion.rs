// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, identity-checked retained metadata removal. No filesystem mutation.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{VersionGroup, VersionStore, artifact_identity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeleteBlocker {
    ActiveRelease,
    BootSessionPinned,
    TransferPinned,
    CutoverInProgress,
    PersistenceCoordinationUnavailable,
    ByteDeletionUnavailable,
    RetainedReference,
    ReferenceCheckIncomplete,
    OwnershipFenceRequired,
}

#[derive(Debug)]
pub(crate) enum DeleteError {
    Missing,
    Stale,
    Blocked(Vec<DeleteBlocker>),
}

impl VersionStore {
    /// Publish only after the durable identity-checked deletion committed. New
    /// local resolvers may hold a provisional pin, but cannot pass SQL admission.
    pub(crate) fn commit_durable_group_deletion(&self, profile: &str, id: &str, digest: &str) {
        self.groups.write().retain(|group| {
            group.boot_profile != profile
                || group.group_id != id
                || group.manifest.manifest_digest != digest
        });
    }

    /// Caller holds the server control lock; this is advisory, not a reservation.
    pub(crate) fn preview_group_deletion(
        &self,
        profile: &str,
        id: &str,
    ) -> Result<(VersionGroup, Vec<DeleteBlocker>), DeleteError> {
        let groups = self.groups.read();
        let group = groups
            .iter()
            .find(|group| group.boot_profile == profile && group.group_id == id)
            .ok_or(DeleteError::Missing)?;
        Ok((group.clone(), self.group_deletion_blockers(group, &groups)))
    }

    fn group_deletion_blockers(
        &self,
        group: &VersionGroup,
        groups: &[VersionGroup],
    ) -> Vec<DeleteBlocker> {
        let mut blockers = Vec::new();
        // Metadata removal must not turn a managed logical name into an
        // unmanaged HTTP fallback. Until durable bounded ownership tombstones
        // exist, another retained group must preserve every name's fence.
        let remaining_names: HashSet<_> = groups
            .iter()
            .filter(|other| {
                other.boot_profile != group.boot_profile || other.group_id != group.group_id
            })
            .flat_map(|other| {
                other
                    .files
                    .iter()
                    .map(|file| (file.boot_profile.as_str(), file.logical_name.as_str()))
            })
            .collect();
        if group.files.iter().any(|file| {
            !remaining_names.contains(&(file.boot_profile.as_str(), file.logical_name.as_str()))
        }) {
            blockers.push(DeleteBlocker::OwnershipFenceRequired);
        }
        if self
            .active_releases
            .load()
            .chains
            .get(&group.boot_profile)
            .is_some_and(|pin| pin.manifest_digest == group.manifest.manifest_digest)
        {
            blockers.push(DeleteBlocker::ActiveRelease);
        }
        if self
            .pinned_boot_chains
            .contains_key(&group.manifest.manifest_digest)
        {
            blockers.push(DeleteBlocker::BootSessionPinned);
        }
        if group.files.iter().any(|file| {
            self.pinned_count_for_profile(&group.boot_profile, &file.logical_name, group.version_id)
                > 0
        }) {
            blockers.push(DeleteBlocker::TransferPinned);
        }
        if self.cutover_in_progress(&group.boot_profile) {
            blockers.push(DeleteBlocker::CutoverInProgress);
        }
        blockers
    }

    /// SQL-free only. Caller holds the server control lock through removal.
    pub(crate) fn delete_retained_group(
        &self,
        profile: &str,
        id: &str,
        digest: &str,
    ) -> Result<(), DeleteError> {
        let mut groups = self.groups.write();
        let index = groups
            .iter()
            .position(|group| group.boot_profile == profile && group.group_id == id)
            .ok_or(DeleteError::Missing)?;
        let group = &groups[index];
        if group.manifest.manifest_digest != digest {
            return Err(DeleteError::Stale);
        }
        let blockers = self.group_deletion_blockers(group, &groups);
        if !blockers.is_empty() {
            return Err(DeleteError::Blocked(blockers));
        }
        // No await or filesystem work between revalidation and metadata removal.
        // Prepared rollback must reacquire groups and find this identity.
        groups.remove(index);
        // Every owned name remains backed by another group, so the active
        // snapshot (including its ownership fence) remains unchanged.
        Ok(())
    }
}

pub(crate) fn file_delete_identity(path: &Path, metadata: &fs::Metadata, hash: &str) -> String {
    let identity = artifact_identity(path, metadata);
    let mut digest = Sha256::new();
    digest.update(b"tempest-file-delete-v1\0");
    digest.update(identity.as_bytes());
    digest.update(b"\0");
    digest.update(hash.as_bytes());
    hex::encode(digest.finalize())
}

pub(crate) fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> Option<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        None
    }
}
