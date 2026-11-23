// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Shared process lifecycle for core and downstream Tempest compositions.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::error::TempestError;
use crate::server::TftpServer;

type ServiceFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;

const FILE_DESCRIPTOR_RESERVE: u64 = 1_024;
const CORE_FILE_DESCRIPTORS_PER_TRANSFER: u64 = 2;
const READ_PROTOCOL_FILE_DESCRIPTORS_PER_TRANSFER: u64 = 1;

fn required_file_descriptor_limit(
    max_concurrent_transfers: usize,
    has_read_protocol: bool,
) -> Result<u64, TempestError> {
    let transfers = u64::try_from(max_concurrent_transfers).map_err(|_| {
        TempestError::Config("max_concurrent_transfers does not fit the platform limit".into())
    })?;
    let descriptors_per_transfer = CORE_FILE_DESCRIPTORS_PER_TRANSFER
        + u64::from(has_read_protocol) * READ_PROTOCOL_FILE_DESCRIPTORS_PER_TRANSFER;
    transfers
        .checked_mul(descriptors_per_transfer)
        .and_then(|descriptors| descriptors.checked_add(FILE_DESCRIPTOR_RESERVE))
        .ok_or_else(|| TempestError::Config("required file-descriptor limit overflows u64".into()))
}

#[cfg(unix)]
fn ensure_file_descriptor_capacity(
    max_concurrent_transfers: usize,
    has_read_protocol: bool,
    http_connections: usize,
) -> Result<(), TempestError> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let required = required_file_descriptor_limit(max_concurrent_transfers, has_read_protocol)?
        .checked_add(http_connections as u64)
        .ok_or_else(|| {
            TempestError::Config("HTTP file-descriptor capacity overflows u64".into())
        })?;
    let current = getrlimit(Resource::Nofile);
    if current.current.is_none_or(|soft| soft >= required) {
        return Ok(());
    }
    if current.maximum.is_some_and(|hard| hard < required) {
        return Err(TempestError::Config(format!(
            "RLIMIT_NOFILE hard limit {} cannot support max_concurrent_transfers={}; \
             at least {required} descriptors are required",
            current.maximum.unwrap_or_default(),
            max_concurrent_transfers
        )));
    }

    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(required),
            maximum: current.maximum,
        },
    )
    .map_err(|error| {
        TempestError::Config(format!(
            "failed to raise RLIMIT_NOFILE from {} to {required}: {error}",
            current.current.unwrap_or_default()
        ))
    })?;
    info!(
        previous_soft_limit = current.current.unwrap_or_default(),
        effective_soft_limit = required,
        hard_limit = ?current.maximum,
        max_concurrent_transfers,
        "Raised file-descriptor limit for configured transfer capacity"
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_file_descriptor_capacity(
    max_concurrent_transfers: usize,
    has_read_protocol: bool,
    http_connections: usize,
) -> Result<(), TempestError> {
    let _ = http_connections;
    required_file_descriptor_limit(max_concurrent_transfers, has_read_protocol).map(|_| ())
}

/// A required background service supervised with the TFTP and HTTP servers.
pub struct CriticalService {
    name: String,
    future: ServiceFuture,
}

impl CriticalService {
    /// Wrap a required service future and retain a stable diagnostic name.
    pub fn new<F, E>(name: impl Into<String>, future: F) -> Self
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        Self {
            name: name.into(),
            future: Box::pin(async move { future.await.map_err(|error| error.to_string()) }),
        }
    }
}

/// Errors that terminate a supervised Tempest process.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The core TFTP service failed.
    #[error("TFTP server failed: {0}")]
    Server(#[from] TempestError),
    /// The core TFTP task panicked or was cancelled unexpectedly.
    #[error("TFTP server task failed: {0}")]
    ServerTask(String),
    /// A required background service returned an error.
    #[error("critical service {name} failed: {message}")]
    CriticalService {
        /// Stable service label.
        name: String,
        /// Sanitized service error.
        message: String,
    },
    /// A required service returned success instead of running until shutdown.
    #[error("critical service {0} exited unexpectedly")]
    CriticalServiceExited(String),
    /// A required service panicked or was cancelled unexpectedly.
    #[error("critical service task failed: {0}")]
    CriticalTask(String),
    /// The runtime had no remaining required services to supervise.
    #[error("no critical services remain")]
    NoCriticalServices,
}

/// Run TFTP, HTTP, persistence synchronization, and composition services under
/// one readiness and graceful-shutdown lifecycle.
///
/// Hydrates durable state first, supervises every required task, marks
/// readiness unhealthy on critical exit, and drains transfers during shutdown.
pub async fn run_server(
    server: TftpServer,
    additional_services: Vec<CriticalService>,
) -> Result<(), RuntimeError> {
    let state = server.state();
    ensure_file_descriptor_capacity(
        state.config.server.max_concurrent_transfers,
        state.read_protocol.is_some(),
        state.config.api.max_connections,
    )?;
    if state.persistence.is_some() || state.config.persistence.enabled {
        state.sync_persistent_state().await?;
        info!("Hydrated Tempest control-plane state from persistent database");
    }

    let mut critical_tasks = JoinSet::new();
    let http_state = state.clone();
    let http_bind = std::net::SocketAddr::new(state.config.api.bind, state.config.api.port);
    // Bind before polling composition services. Required services such as the
    // integrity controller may call the loopback API on their first poll.
    let http_listener = tokio::net::TcpListener::bind(http_bind)
        .await
        .map_err(TempestError::Io)?;
    critical_tasks.spawn(async move {
        (
            "HTTP server".to_owned(),
            crate::api::run_http_server_on(http_state, http_listener)
                .await
                .map_err(|error| error.to_string()),
        )
    });

    if state.persistence.is_some() || state.config.persistence.enabled {
        let sync_state = state.clone();
        let sync_interval = Duration::from_secs(state.config.persistence.sync_interval_secs.max(1));
        critical_tasks.spawn(async move {
            let mut interval = tokio::time::interval(sync_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = persistence_refresh_result(
                    sync_state.config.persistence.coordinated_deletion,
                    sync_state.sync_persistent_state().await,
                ) {
                    break ("persistence synchronization".to_owned(), Err(error));
                }
            }
        });
    }

    for service in additional_services {
        critical_tasks.spawn(async move { (service.name, service.future.await) });
    }

    // Enter the listener from a runtime worker. Transfer tasks spawned by the
    // listener can then enter that worker's queue without waking it from the
    // runtime-driver future on every small request.
    let tftp_server = server.clone();
    let mut tftp_task = tokio::spawn(async move { tftp_server.run().await });

    let result = tokio::select! {
        result = &mut tftp_task => match result {
            Ok(result) => result.map_err(RuntimeError::from),
            Err(error) => Err(RuntimeError::ServerTask(error.to_string())),
        },
        result = wait_for_critical_task(&mut critical_tasks, &state.critical_services_healthy) => {
            server.drain();
            server.wait_for_drain().await;
            result
        }
        signal = shutdown_signal() => {
            match signal {
                Ok(signal) => info!(signal, "Received shutdown signal — entering drain mode"),
                Err(error) => warn!(%error, "Shutdown signal handler failed — entering drain mode"),
            }
            server.drain();
            tokio::select! {
                _ = server.wait_for_drain() => Ok(()),
                signal = shutdown_signal() => {
                    match signal {
                        Ok(signal) => warn!(signal, "Received second shutdown signal — forcing shutdown"),
                        Err(error) => warn!(%error, "Second shutdown signal handler failed — forcing shutdown"),
                    }
                    Ok(())
                }
            }
        }
    };

    if !tftp_task.is_finished() {
        tftp_task.abort();
        let _ = tftp_task.await;
    }
    critical_tasks.abort_all();
    while critical_tasks.join_next().await.is_some() {}
    info!("Tempest shutdown complete");
    result
}

fn persistence_refresh_result(
    coordinated_deletion: bool,
    result: Result<(), TempestError>,
) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if coordinated_deletion => Err(error.to_string()),
        Err(error) => {
            warn!(%error, "Persistence refresh failed; retrying while serving only within the configured snapshot age");
            Ok(())
        }
    }
}

async fn wait_for_critical_task(
    tasks: &mut JoinSet<(String, Result<(), String>)>,
    healthy: &AtomicBool,
) -> Result<(), RuntimeError> {
    let exit = tasks.join_next().await;
    healthy.store(false, Ordering::Release);
    match exit {
        Some(Ok((name, Err(message)))) => Err(RuntimeError::CriticalService { name, message }),
        Some(Ok((name, Ok(())))) => Err(RuntimeError::CriticalServiceExited(name)),
        Some(Err(error)) => Err(RuntimeError::CriticalTask(error.to_string())),
        None => Err(RuntimeError::NoCriticalServices),
    }
}

async fn shutdown_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                Ok("SIGINT")
            }
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("SIGINT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_refresh_failure_retains_the_last_snapshot_but_deletion_is_critical() {
        for coordinated in [false, true] {
            let failure = TempestError::Persistence("database disconnected".into());
            assert_eq!(
                persistence_refresh_result(coordinated, Err(failure)).is_err(),
                coordinated
            );
            assert!(persistence_refresh_result(coordinated, Ok(())).is_ok());
        }
    }

    #[tokio::test]
    async fn critical_exit_marks_runtime_unhealthy() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async { ("test service".to_owned(), Ok(())) });
        let healthy = AtomicBool::new(true);

        let error = wait_for_critical_task(&mut tasks, &healthy)
            .await
            .unwrap_err();

        assert!(!healthy.load(Ordering::Acquire));
        assert!(matches!(error, RuntimeError::CriticalServiceExited(_)));
    }

    #[test]
    fn descriptor_capacity_covers_transfer_sockets_files_and_runtime_reserve() {
        assert_eq!(required_file_descriptor_limit(500, false).unwrap(), 2_024);
        assert_eq!(
            required_file_descriptor_limit(9_000, false).unwrap(),
            19_024
        );
        assert_eq!(required_file_descriptor_limit(500, true).unwrap(), 2_524);
        assert_eq!(required_file_descriptor_limit(9_000, true).unwrap(), 28_024);
    }
}
