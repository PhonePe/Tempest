// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Bounded group commits for concurrent session registration; no schema changes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use super::RegisterSessionResponse;
use crate::server::{BootSessionEntry, ServerState, active_boot_session};

const MAX_BATCH: usize = 32;
const QUEUE_CAPACITY: usize = 256;

pub(super) struct Registration {
    pub(super) client_ip: IpAddr,
    pub(super) boot_profile: String,
    pub(super) trace_id: Option<String>,
    pub(super) client_mac: Option<String>,
    pub(super) serial: Option<String>,
    pub(super) ttl_seconds: Option<u64>,
    pub(super) new_epoch: bool,
    pub(super) require_managed: bool,
}

pub(crate) struct Command {
    request: Registration,
    reply: oneshot::Sender<Response>,
}

pub(super) async fn register(state: Arc<ServerState>, request: Registration) -> Response {
    if state.persistence.is_none() {
        let _guard = state.control_plane_lock.lock().await;
        if let Err(error) = state.ensure_persistence_admission().await {
            tracing::error!(%error, "boot session persistence admission failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session persistence unavailable",
            )
                .into_response();
        }
        let ip = request.client_ip;
        return match prepare(&state, request, &HashMap::new()) {
            Ok((entry, response)) => {
                state.insert_boot_session(ip, entry);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(response) => response.into_response(),
        };
    }
    let sender = state.session_registration_queue.get_or_init(|| {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        // The idle worker must not keep the server and its own sender alive.
        tokio::spawn(run(Arc::downgrade(&state), receiver));
        sender
    });
    let (reply, response) = oneshot::channel();
    if sender.try_send(Command { request, reply }).is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Session registration at capacity",
        )
            .into_response();
    }
    response.await.unwrap_or_else(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Session registration unavailable",
        )
            .into_response()
    })
}

async fn run(state: Weak<ServerState>, mut receiver: mpsc::Receiver<Command>) {
    while let Some(first) = receiver.recv().await {
        let Some(state) = state.upgrade() else { return };
        // Collect after taking the lock: requests queued during another control
        // mutation can share this transaction, without imposing a batching timer.
        let _guard = state.control_plane_lock.lock().await;
        let mut batch = Vec::with_capacity(MAX_BATCH);
        batch.push(first);
        while batch.len() < MAX_BATCH {
            let Ok(command) = receiver.try_recv() else {
                break;
            };
            batch.push(command);
        }
        commit_batch(&state, batch).await;
    }
}

async fn commit_batch(state: &ServerState, batch: Vec<Command>) {
    let mut pending = HashMap::with_capacity(batch.len());
    let mut expected = HashMap::with_capacity(batch.len());
    let mut candidates = HashMap::<IpAddr, Vec<_>>::with_capacity(batch.len());
    for command in batch {
        if command.reply.is_closed() {
            continue;
        }
        let ip = command.request.client_ip;
        expected
            .entry(ip)
            .or_insert_with(|| active_boot_session(state, ip));
        match prepare(state, command.request, &pending) {
            Ok((entry, response)) => {
                // Duplicate clients retain sequential epoch/token semantics, but
                // only their final row is included in the atomic SQL upsert.
                pending.insert(ip, entry.clone());
                candidates
                    .entry(ip)
                    .or_default()
                    .push((entry, command.reply, response));
            }
            Err(response) => {
                let _ = command.reply.send(response.into_response());
            }
        }
    }
    if pending.is_empty() {
        return;
    }
    let mut responses = HashMap::with_capacity(candidates.len());
    let mut superseded = Vec::new();
    let mut entries = Vec::with_capacity(candidates.len());
    for (ip, mut candidates) in candidates {
        while candidates
            .last()
            .is_some_and(|(_, reply, _)| reply.is_closed())
        {
            candidates.pop();
        }
        let Some((entry, reply, response)) = candidates.pop() else {
            continue;
        };
        superseded.extend(
            candidates
                .into_iter()
                .filter_map(|(_, reply, _)| (!reply.is_closed()).then_some(reply)),
        );
        entries.push((ip, entry));
        responses.insert(ip, (reply, response));
    }
    if entries.is_empty() {
        return;
    }
    if let Some(persistence) = &state.persistence {
        let expected: Vec<_> = entries
            .iter()
            .map(|(ip, _)| {
                (
                    *ip,
                    expected
                        .remove(ip)
                        .expect("prepared client has a precondition"),
                )
            })
            .collect();
        // Admission can wait on SQL too. Once candidates are selected, keep
        // admission, commit and publication owned by this detached worker.
        if let Err(error) = async {
            state.ensure_persistence_admission().await?;
            persistence
                .persist_boot_sessions_if_unchanged(&entries, &expected)
                .await
        }
        .await
        {
            if matches!(error, crate::error::TempestError::Conflict(_)) {
                for reply in superseded
                    .into_iter()
                    .chain(responses.into_values().map(|(reply, _)| reply))
                {
                    let _ = reply.send(
                        (
                            StatusCode::CONFLICT,
                            "Durable boot session or release changed; synchronize before retrying",
                        )
                            .into_response(),
                    );
                }
                return;
            }
            let correlation_id = uuid::Uuid::new_v4();
            tracing::error!(%correlation_id, %error, "boot session persistence failed");
            for reply in superseded
                .into_iter()
                .chain(responses.into_values().map(|(reply, _)| reply))
            {
                let _ = reply.send(
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Session registration failed; reference {correlation_id}"),
                    )
                        .into_response(),
                );
            }
            return;
        }
    }
    // Once SQL starts, finish publication even if every HTTP caller disconnects.
    for (ip, entry) in entries {
        state.insert_boot_session(ip, entry);
    }
    for reply in superseded {
        let _ = reply.send(
            (
                StatusCode::CONFLICT,
                "Boot session registration was superseded by a concurrent request",
            )
                .into_response(),
        );
    }
    for (reply, response) in responses.into_values() {
        let _ = reply.send((StatusCode::CREATED, Json(response)).into_response());
    }
}

fn prepare(
    state: &ServerState,
    request: Registration,
    pending: &HashMap<IpAddr, BootSessionEntry>,
) -> Result<(BootSessionEntry, RegisterSessionResponse), (StatusCode, &'static str)> {
    if state
        .version_store
        .cutover_in_progress(&request.boot_profile)
    {
        return Err((
            StatusCode::CONFLICT,
            "Boot profile release cutover is in progress",
        ));
    }
    let existing = match pending.get(&request.client_ip) {
        Some(entry) => (entry.expires_at > Instant::now()).then(|| entry.clone()),
        None => active_boot_session(state, request.client_ip),
    };
    let additional = pending
        .keys()
        .filter(|ip| !state.boot_sessions.contains_key(ip))
        .count();
    let expired_pending = pending.contains_key(&request.client_ip) && existing.is_none();
    let occupied = state
        .boot_sessions
        .len()
        .saturating_add(additional)
        .saturating_sub(usize::from(expired_pending));
    if existing.is_none() && occupied >= state.config.server.max_boot_sessions {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Boot session capacity reached",
        ));
    }
    if existing.as_ref().is_some_and(|entry| {
        entry.pinned_boot_chain.is_some()
            && !request.new_epoch
            && entry.boot_profile != request.boot_profile
    }) {
        return Err((
            StatusCode::CONFLICT,
            "Active boot session is pinned; use new_epoch=true for a new PXE boot attempt",
        ));
    }
    let boot_epoch = existing.as_ref().map_or(1, |entry| {
        if request.new_epoch {
            entry.boot_epoch.saturating_add(1)
        } else {
            entry.boot_epoch
        }
    });
    let pinned_boot_chain = match &existing {
        Some(entry)
            if !request.new_epoch
                && entry.boot_profile == request.boot_profile
                && entry.pinned_boot_chain.is_some() =>
        {
            entry.pinned_boot_chain.clone()
        }
        _ => state
            .version_store
            .active_boot_chain_for_profile(&request.boot_profile)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid boot_profile"))?,
    };
    if request.require_managed && pinned_boot_chain.is_none() {
        return Err((StatusCode::CONFLICT, "Active managed release required"));
    }
    let response_profile = request.boot_profile.clone();
    let manifest_digest = pinned_boot_chain
        .as_ref()
        .map(|pin| pin.manifest_digest.clone());
    let ttl = Duration::from_secs(request.ttl_seconds.unwrap_or(600).min(3600));
    let artifact_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let artifact_token_hash = Some(Sha256::digest(artifact_token.as_bytes()).into());
    let expires_at = jiff::Timestamp::now() + ttl;
    Ok((
        BootSessionEntry {
            trace_id: request.trace_id,
            boot_profile: request.boot_profile,
            client_mac: request.client_mac,
            serial: request.serial,
            boot_epoch,
            artifact_token_hash,
            pinned_boot_chain,
            expires_at: Instant::now() + ttl,
        },
        RegisterSessionResponse {
            artifact_token,
            boot_profile: response_profile,
            manifest_digest,
            expires_at,
            boot_epoch,
        },
    ))
}

#[cfg(test)]
mod tests;
