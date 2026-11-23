// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Default Tempest server composition.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use tracing::info;

use tempest::config::TempestConfig;
use tempest::persistence::PersistenceStore;
use tempest::runtime::run_server;
use tempest::server::TftpServer;

/// Release-coherent TFTP and HTTP boot artifact server.
#[derive(Parser)]
#[command(
    name = "tempest",
    version,
    about = "Release-coherent TFTP and HTTP boot artifact server"
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long, default_value = "config/tempest.toml")]
    config: PathBuf,

    /// Bind address (overrides config)
    #[arg(short, long)]
    bind: Option<std::net::IpAddr>,

    /// TFTP port (overrides config)
    #[arg(short, long)]
    port: Option<u16>,

    /// HTTP API bind address (overrides config)
    #[arg(long)]
    api_bind: Option<std::net::IpAddr>,

    /// HTTP API port (overrides config)
    #[arg(long)]
    api_port: Option<u16>,

    /// TFTP root directory (overrides config)
    #[arg(short, long)]
    root: Option<PathBuf>,

    /// Log level (overrides config)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Validate the effective configuration and exit without starting services
    #[arg(long, conflicts_with = "print_effective_config")]
    check_config: bool,

    /// Print the validated effective configuration with secrets redacted, then exit
    #[arg(long, conflicts_with = "check_config")]
    print_effective_config: bool,

    /// Recover abandoned SQL readers offline; never starts serving
    #[arg(long, conflicts_with_all = ["check_config", "print_effective_config"], requires = "confirm_all_servers_stopped")]
    recover_sql_readers: bool,

    /// Assert that every server sharing this database has been stopped and fenced
    #[arg(long, requires = "recover_sql_readers")]
    confirm_all_servers_stopped: bool,
}

fn load_effective_config(cli: &Cli) -> anyhow::Result<TempestConfig> {
    if (cli.check_config || cli.print_effective_config || cli.recover_sql_readers)
        && !cli.config.exists()
    {
        anyhow::bail!(
            "configuration file does not exist: {}",
            cli.config.display()
        );
    }

    // Load config — use defaults if config file doesn't exist
    let mut config = if cli.config.exists() {
        TempestConfig::load(&cli.config)?
    } else {
        info!("Config file not found, using defaults");
        TempestConfig::default()
    };

    // CLI overrides
    if let Some(bind) = cli.bind {
        config.server.bind = bind;
    }
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if let Some(api_bind) = cli.api_bind {
        config.api.bind = api_bind;
    }
    if let Some(api_port) = cli.api_port {
        config.api.port = api_port;
    }
    if let Some(root) = &cli.root {
        config.server.root = root.clone();
    }
    if let Some(level) = &cli.log_level {
        config.server.log_level = level.clone();
    }

    config.validate_api_exposure()?;
    Ok(config)
}

fn redact_config_value(table: &mut toml::Table, section: &str, field: &str) {
    let Some(section) = table.get_mut(section).and_then(toml::Value::as_table_mut) else {
        return;
    };
    if section.contains_key(field) {
        section.insert(field.to_owned(), toml::Value::String("<redacted>".into()));
    }
}

fn redacted_effective_config(config: &TempestConfig) -> anyhow::Result<String> {
    let mut normalized = config.clone();
    normalized.server.listener_shards = config.server.effective_listener_shards();
    let mut value = toml::Value::try_from(&normalized)?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("effective configuration did not serialize as a table"))?;
    redact_config_value(table, "api", "api_key");
    redact_config_value(table, "persistence", "database_url");
    if let Some(extensions) = table
        .get_mut("extensions")
        .and_then(toml::Value::as_table_mut)
    {
        for (_, value) in extensions.iter_mut() {
            *value = toml::Value::String("<redacted>".into());
        }
    }

    let rendered = toml::to_string_pretty(&value)?;
    Ok(format!(
        "# Validated effective Tempest configuration; automatic values are resolved.\n\
         # Secret and extension-owned values are redacted. Diagnostic output only.\n\
         # Do not reuse it as a secrets-bearing configuration file.\n{rendered}"
    ))
}

/// Loads configuration, starts critical services, and coordinates graceful shutdown.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = load_effective_config(&cli)?;

    if cli.check_config {
        println!("configuration valid");
        return Ok(());
    }
    if cli.print_effective_config {
        print!("{}", redacted_effective_config(&config)?);
        return Ok(());
    }

    if cli.recover_sql_readers {
        if !config.persistence.enabled || !config.persistence.coordinated_deletion {
            anyhow::bail!("reader recovery requires enabled persistence and coordinated deletion");
        }
        let database_url = config
            .persistence
            .database_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("persistence.database_url is required"))?;
        let recovered = PersistenceStore::recover_abandoned_readers(
            database_url,
            cli.confirm_all_servers_stopped,
        )
        .await?;
        println!("recovered_readers={recovered}");
        return Ok(());
    }

    // Initialize structured logging
    let log_filter = config.server.log_level.clone();
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_filter));
    if config.server.json_logging {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        port = config.server.port,
        api_port = config.api.port,
        root = %config.server.root.display(),
        "Starting Tempest TFTP server"
    );

    if !config.server.root.exists() {
        #[cfg(unix)]
        {
            tokio::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(&config.server.root)
                .await?;
        }
        #[cfg(not(unix))]
        {
            tokio::fs::create_dir_all(&config.server.root).await?;
        }
        info!(root = %config.server.root.display(), "Created TFTP root directory");
    }

    let persistence = if config.persistence.enabled {
        let database_url = config
            .persistence
            .database_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("persistence.database_url is required"))?;
        let store = PersistenceStore::connect(database_url).await?;
        Some(std::sync::Arc::new(store))
    } else {
        None
    };

    let mut builder = TftpServer::builder(config.clone());
    if let Some(persistence) = persistence {
        builder = builder.with_persistence(persistence);
    }
    let server = builder.build()?;
    run_server(server, Vec::new()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_flags_are_mutually_exclusive() {
        let parsed = Cli::try_parse_from(["tempest", "--check-config", "--print-effective-config"]);
        assert!(parsed.is_err());
    }

    #[test]
    fn reader_recovery_requires_exclusive_offline_confirmation() {
        assert!(Cli::try_parse_from(["tempest", "--recover-sql-readers"]).is_err());
        assert!(Cli::try_parse_from(["tempest", "--confirm-all-servers-stopped"]).is_err());
        assert!(
            Cli::try_parse_from([
                "tempest",
                "--recover-sql-readers",
                "--confirm-all-servers-stopped",
                "--check-config",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "tempest",
                "--recover-sql-readers",
                "--confirm-all-servers-stopped",
            ])
            .is_ok()
        );
    }

    #[test]
    fn effective_config_output_redacts_every_opaque_secret_surface() {
        let mut config = TempestConfig::default();
        config.api.api_key = Some("api-secret-value".into());
        config.persistence.database_url = Some("postgres://user:password@db/tempest".into());
        config.extensions.insert(
            "example".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "token".into(),
                toml::Value::String("extension-secret-value".into()),
            )])),
        );

        let output = redacted_effective_config(&config).unwrap();
        assert!(!output.contains("api-secret-value"));
        assert!(!output.contains("postgres://user:password@db/tempest"));
        assert!(!output.contains("extension-secret-value"));
        assert!(output.contains("api_key = \"<redacted>\""));
        assert!(output.contains("database_url = \"<redacted>\""));
        assert!(output.contains("example = \"<redacted>\""));
        assert!(output.contains("listener_shards = "));
        assert!(!output.contains("listener_shards = 0"));
    }
}
