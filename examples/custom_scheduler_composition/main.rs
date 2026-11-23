// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Minimal statically linked Tempest composition with a custom scheduler.
#![forbid(unsafe_code)]

use std::env;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::BytesMut;
use tempest::config::TempestConfig;
use tempest::extension::{PacketSendFuture, TransferId, TransferScheduler};
use tempest::features::boot_phase::BootPhase;
use tempest::server::TftpServer;
use tokio::net::UdpSocket;

/// Demonstrates the smallest TID-safe scheduler implementation.
struct DirectScheduler;

impl TransferScheduler for DirectScheduler {
    fn register_transfer(
        &self,
        _transfer_id: TransferId,
        _phase: BootPhase,
        _total_bytes: u64,
        _provisioning_priority: Option<f64>,
    ) {
    }

    fn unregister_transfer(&self, _transfer_id: &TransferId) {}

    fn phase_adjusted_ceiling(&self, _transfer_id: &TransferId) -> Option<f64> {
        None
    }

    fn send_packet(
        &self,
        _transfer_id: TransferId,
        socket: Arc<UdpSocket>,
        data: BytesMut,
        destination: SocketAddr,
    ) -> PacketSendFuture<'_> {
        Box::pin(async move {
            let expected = data.len();
            let sent = socket.send_to(&data, destination).await?;
            if sent != expected {
                return Err(IoError::new(
                    ErrorKind::WriteZero,
                    format!("UDP send accepted {sent} of {expected} bytes"),
                )
                .into());
            }
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/tempest.toml"));
    let config = TempestConfig::load(&config_path)?;
    if config.persistence.enabled {
        return Err("this minimal composition requires persistence.enabled = false".into());
    }

    let http_bind = SocketAddr::new(config.api.bind, config.api.port);
    let server = TftpServer::builder(config)
        .with_scheduler(Arc::new(DirectScheduler))
        .build()?;
    let state = server.state();

    tokio::try_join!(
        server.run(),
        tempest::api::run_http_server(state, http_bind)
    )?;
    Ok(())
}
