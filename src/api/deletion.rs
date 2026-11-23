// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Preview/confirm deletion, deliberately failing closed for unsupported lifecycles.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, TempestError};
use crate::features::versioning::deletion::{
    DeleteBlocker, DeleteError, file_delete_identity, same_file,
};
use crate::features::versioning::{
    VersionGroup, hash_stable_open_file, is_valid_boot_profile, is_valid_group_id,
    is_valid_logical_name,
};
use crate::server::ServerState;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum DeleteTarget {
    RetainedGroup {
        boot_profile: String,
        group_id: String,
    },
    File {
        path: String,
    },
}

impl DeleteTarget {
    fn valid(&self) -> bool {
        match self {
            Self::RetainedGroup {
                boot_profile,
                group_id,
            } => is_valid_boot_profile(boot_profile) && is_valid_group_id(group_id),
            Self::File { path } => is_valid_logical_name(path),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviewDeleteRequest {
    target: DeleteTarget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmDeleteRequest {
    target: DeleteTarget,
    expected_identity: String,
}

#[derive(Serialize)]
struct GroupReference {
    boot_profile: String,
    group_id: String,
    manifest_digest: String,
}

impl From<&VersionGroup> for GroupReference {
    fn from(group: &VersionGroup) -> Self {
        Self {
            boot_profile: group.boot_profile.clone(),
            group_id: group.group_id.clone(),
            manifest_digest: group.manifest.manifest_digest.clone(),
        }
    }
}

#[derive(Serialize)]
struct DeletePreview {
    target: DeleteTarget,
    expected_identity: String,
    can_delete: bool,
    blockers: Vec<DeleteBlocker>,
    referring_groups: Vec<GroupReference>,
}

fn deletion_error(error: DeleteError) -> Response {
    match error {
        DeleteError::Missing => (StatusCode::NOT_FOUND, "Delete target not found").into_response(),
        DeleteError::Stale => (
            StatusCode::CONFLICT,
            "Delete identity changed; preview again",
        )
            .into_response(),
        DeleteError::Blocked(blockers) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "blockers": blockers
            })),
        )
            .into_response(),
    }
}

/// Advisory preview; no token storage, filesystem mutation, or reservation.
pub(super) async fn preview_delete(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<PreviewDeleteRequest>,
) -> Response {
    if !request.target.valid() {
        return (StatusCode::BAD_REQUEST, "Invalid delete target").into_response();
    }
    match build_preview(state, request.target).await {
        Ok(preview) => Json(preview).into_response(),
        Err(response) => *response,
    }
}

async fn build_preview(
    state: Arc<ServerState>,
    target: DeleteTarget,
) -> Result<DeletePreview, Box<Response>> {
    // Do not accumulate an unbounded waiter queue behind control mutations.
    let guard = state.control_plane_lock.try_lock().map_err(|_| {
        Box::new(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Control mutation busy; retry preview",
            )
                .into_response(),
        )
    })?;
    match &target {
        DeleteTarget::RetainedGroup {
            boot_profile,
            group_id,
        } => {
            let (group, mut blockers) = state
                .version_store
                .preview_group_deletion(boot_profile, group_id)
                .map_err(|error| Box::new(deletion_error(error)))?;
            if let Some(store) = &state.persistence {
                if !state.config.persistence.coordinated_deletion
                    || store.ensure_serving_admission(true).await.is_err()
                {
                    blockers.push(DeleteBlocker::PersistenceCoordinationUnavailable);
                } else {
                    match store.preview_sql_group_deletion(&group).await {
                        Ok(()) => {}
                        Err(DeleteError::Blocked(durable)) => {
                            for blocker in durable {
                                if !blockers.contains(&blocker) {
                                    blockers.push(blocker);
                                }
                            }
                        }
                        Err(error) => return Err(Box::new(deletion_error(error))),
                    }
                }
            } else if state.config.persistence.enabled
                || state.config.persistence.coordinated_deletion
            {
                blockers.push(DeleteBlocker::PersistenceCoordinationUnavailable);
            }
            Ok(DeletePreview {
                target,
                expected_identity: group.manifest.manifest_digest,
                can_delete: blockers.is_empty(),
                blockers,
                referring_groups: Vec::new(),
            })
        }
        DeleteTarget::File { path } => {
            let snapshot = state.version_store.release_snapshot().map_err(|_| {
                Box::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Release snapshot capacity exceeded",
                    )
                        .into_response(),
                )
            })?;
            let permit = state
                .artifact_hash_budget
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    Box::new(
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "File preview capacity exceeded",
                        )
                            .into_response(),
                    )
                })?;
            let path = path.clone();
            drop(guard);
            let worker_state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let root = worker_state.artifact_root()?;
                let opened = root.open_delete_inspection(Path::new(&path))?;
                let (hash, metadata) = hash_stable_open_file(
                    opened.file,
                    &opened.path,
                    opened.metadata,
                    Some(4 * 1024 * 1024 * 1024),
                )?;
                let identity = file_delete_identity(&opened.path, &metadata, &hash);
                let mut references = Vec::new();
                let mut incomplete =
                    worker_state.persistence.is_some() || worker_state.config.persistence.enabled;
                // At most 100 groups / 10,000 members; no byte reads for references.
                for group in &snapshot.groups {
                    let mut refers = false;
                    for file in &group.files {
                        match root.open_delete_inspection(&file.path) {
                            Ok(other) => match same_file(&metadata, &other.metadata) {
                                Some(true) => refers = true,
                                Some(false) => {}
                                None => incomplete = true,
                            },
                            Err(_) => incomplete = true,
                        }
                    }
                    if refers {
                        references.push(GroupReference::from(group));
                    }
                }
                Ok::<_, TempestError>((identity, references, incomplete))
            })
            .await;
            let (expected_identity, referring_groups, incomplete) = match result {
                Ok(Ok(result)) => result,
                Ok(Err(TempestError::Protocol(ProtocolError::FileNotFound(_)))) => {
                    return Err(Box::new(deletion_error(DeleteError::Missing)));
                }
                Ok(Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))) => {
                    return Err(Box::new(
                        (StatusCode::BAD_REQUEST, "Unsafe file target").into_response(),
                    ));
                }
                _ => {
                    return Err(Box::new(
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "File identity could not be proven within preview bounds",
                        )
                            .into_response(),
                    ));
                }
            };
            let mut blockers = vec![DeleteBlocker::ByteDeletionUnavailable];
            if !referring_groups.is_empty() {
                blockers.push(DeleteBlocker::RetainedReference);
            }
            if incomplete {
                blockers.push(DeleteBlocker::ReferenceCheckIncomplete);
            }
            if state.persistence.is_some() || state.config.persistence.enabled {
                blockers.push(DeleteBlocker::PersistenceCoordinationUnavailable);
            }
            Ok(DeletePreview {
                target,
                expected_identity,
                can_delete: false,
                blockers,
                referring_groups,
            })
        }
    }
}

/// Confirm exactly one target, revalidating all executable preconditions at commit.
pub(super) async fn confirm_delete(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ConfirmDeleteRequest>,
) -> Response {
    if !request.target.valid()
        || request.expected_identity.len() != 64
        || !request
            .expected_identity
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return (StatusCode::BAD_REQUEST, "Invalid delete confirmation").into_response();
    }
    if let DeleteTarget::File { .. } = &request.target {
        return match build_preview(state, request.target).await {
            Ok(preview) if preview.expected_identity != request.expected_identity => {
                deletion_error(DeleteError::Stale)
            }
            Ok(preview) => deletion_error(DeleteError::Blocked(preview.blockers)),
            Err(response) => *response,
        };
    }
    let Ok(_guard) = state.control_plane_lock.try_lock() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control mutation busy; preview again",
        )
            .into_response();
    };
    if (state.persistence.is_some()
        || state.config.persistence.enabled
        || state.config.persistence.coordinated_deletion)
        && (!state.config.persistence.coordinated_deletion || state.persistence.is_none())
    {
        return deletion_error(DeleteError::Blocked(vec![
            DeleteBlocker::PersistenceCoordinationUnavailable,
        ]));
    }
    let DeleteTarget::RetainedGroup {
        boot_profile,
        group_id,
    } = &request.target
    else {
        unreachable!()
    };
    if let Some(store) = &state.persistence {
        let (group, blockers) = match state
            .version_store
            .preview_group_deletion(boot_profile, group_id)
        {
            Ok(value) => value,
            Err(error) => return deletion_error(error),
        };
        if group.manifest.manifest_digest != request.expected_identity {
            return deletion_error(DeleteError::Stale);
        }
        if !blockers.is_empty() {
            return deletion_error(DeleteError::Blocked(blockers));
        }
        let revision = match store.version_revision(boot_profile).await {
            Ok(revision) => revision,
            Err(error) => {
                tracing::warn!(%error, "SQL metadata deletion could not read the revision");
                return deletion_error(DeleteError::Blocked(vec![
                    DeleteBlocker::PersistenceCoordinationUnavailable,
                ]));
            }
        };
        if let Err(error) = store.delete_sql_group(&group, revision).await {
            tracing::warn!(
                ?error,
                "SQL metadata deletion refused or uncertain; reconcile before retry"
            );
            return deletion_error(error);
        }
        state.version_store.commit_durable_group_deletion(
            boot_profile,
            group_id,
            &request.expected_identity,
        );
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "deleted": request.target,
                "expected_identity": request.expected_identity,
                "bytes_deleted": false
            })),
        )
            .into_response();
    }
    match state.version_store.delete_retained_group(
        boot_profile,
        group_id,
        &request.expected_identity,
    ) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "deleted": request.target,
                "expected_identity": request.expected_identity,
                "bytes_deleted": false
            })),
        )
            .into_response(),
        Err(error) => deletion_error(error),
    }
}

#[cfg(test)]
mod tests;
