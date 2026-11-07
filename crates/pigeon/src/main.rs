//! Pigeon Mail server binary.
//!
//! Two subcommands, both meant to be scriptable by the installer:
//!
//! * `pigeon serve` — open the database, load the master key and run the three
//!   long-lived services until SIGINT/SIGTERM: the HTTP API, the inbound SMTP
//!   server and the outbound queue worker.
//! * `pigeon keygen` — bootstrap: print a fresh master key (write it to the key
//!   file), create the account's first `full` API key, and print the exact
//!   environment to paste into the unit file. Nothing is written to disk except
//!   the account and key rows in the database, so an operator always sees the key
//!   material exactly once.
//!
//! # One process, three services
//!
//! ```text
//!  :8000  HTTP API  (axum)      ← clients, webmail
//!  :2525  SMTP in   (pigeon-smtp) ← the outside world
//!  ----   queue worker          → MX of the recipient domain
//! ```
//!
//! They share one database file and one master key, and they stop together: a
//! single SIGINT/SIGTERM flips one `watch` channel that all three futures wait
//! on, so in-flight HTTP requests, SMTP sessions and deliveries finish instead of
//! being cut off. The webmail UI and the MCP server are still separate services.
//!
//! # Environment this binary adds on top of [`pigeon_core::Config`]
//!
//! * `PIGEON_SMTP_HOSTNAME` — name used in the SMTP banner and `Received:`
//!   header (default `pigeon.local`).
//! * `PIGEON_SMTP_OUT_ADDR` — smarthost `host:port` every outbound message is
//!   relayed through; unset means direct-to-MX delivery.
//! * `PIGEON_SMTP_TEST_MX_PORT` — pins every MX connection to one port (loopback
//!   testing only).
//!
//! DKIM signing is **on**, per domain: the worker looks the `From:` domain's key
//! up in the `dkim_keys` store, unseals it under the master key and prepends a
//! `DKIM-Signature`. Domains this instance does not hold a key for are delivered
//! unsigned (logged at `info`). Everything else about delivery (queue, backoff,
//! bounces, TLS policy) is live.

use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use pigeon_api::db::ApiDb;
use pigeon_api::state::ApiConfig;
use pigeon_core::{ApiKeyScope, Config, EmailAddress};
use pigeon_crypto::MasterKey;
use pigeon_smtp::worker::StoreDkimKeys;
use pigeon_smtp::{
    DeliveryConfig, InboundSmtpServer, MxResolver, OutboundSmtpClient, QueueWorker, ServerConfig,
    WorkerConfig,
};
use store::{SqliteStorage, Storage};
use tower_http::trace::TraceLayer;

/// Pigeon Mail — self-hosted encrypted email server.
#[derive(Debug, Parser)]
#[command(name = "pigeon", version, about, long_about = None)]
struct Pigeon {
    #[command(subcommand)]
    command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the HTTP API.
    Serve,
    /// Run the MCP server (JSON-RPC over stdio) for AI agents.
    Mcp,
    /// Generate a master key and a bootstrap API key (installer use).
    Keygen {
        /// Account the bootstrap key belongs to.
        #[arg(long, default_value = "admin@pigeon.local")]
        account: String,
        /// Database file; defaults to `PIGEON_DB_PATH`.
        #[arg(long)]
        db_path: Option<PathBuf>,
    },
}

fn main() {
    if let Err(error) = run() {
        // `main` returning the error would print Debug noise; print the chain.
        eprintln!("pigeon: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env()?;
    let api_config = ApiConfig {
        public_ip: std::env::var("PIGEON_PUBLIC_IP")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        ..ApiConfig::default()
    };
    let pigeon = Pigeon::parse();
    match pigeon.command {
        Command::Serve => {
            init_tracing(&config.log_filter);
            serve(config, api_config)
        }
        Command::Keygen { account, db_path } => keygen(&config, &account, db_path),
        Command::Mcp => {
            init_tracing(&config.log_filter);
            mcp(config)
        }
    }
}

/// Run the MCP server over stdio until EOF.
#[tokio::main]
async fn mcp(config: Config) -> Result<(), Box<dyn Error>> {
    use std::sync::Arc;
    let master_key = Arc::new(MasterKey::from_file(&config.master_key_file)?);
    let store = Arc::new(store::SqliteStorage::open(&config.db_path)?);
    let state = pigeon_mcp::McpState { store, master_key };
    pigeon_mcp::run_stdio(state).await?;
    Ok(())
}

/// Start the HTTP API, the inbound SMTP server and the delivery worker, and run
/// until SIGINT/SIGTERM.
#[tokio::main]
async fn serve(config: Config, api_config: ApiConfig) -> Result<(), Box<dyn Error>> {
    let master_key = MasterKey::from_file(&config.master_key_file)?;
    // One database file, two handles: `AppState` owns the `Storage` seam and the
    // API's auxiliary connection, and the SMTP engine borrows both.
    let state = pigeon_api::AppState::open(&config.db_path, master_key, api_config)?;
    let mut app = pigeon_api::router(state.clone()).layer(TraceLayer::new_for_http());
    if config.webmail {
        // Serve the built webmail bundle (web/dist) at /, behind every API
        // route. The bundle path follows install.sh's layout by default.
        let dir = std::env::var("PIGEON_WEBMAIL_DIR")
            .unwrap_or_else(|_| "/usr/local/share/pigeon/web".to_string());
        match std::fs::metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                let serve_dir = tower_http::services::ServeDir::new(&dir)
                    .append_index_html_on_directories(true);
                app = app.fallback_service(serve_dir);
                tracing::info!(webmail_dir = %dir, "webmail UI enabled");
            }
            _ => {
                tracing::warn!(
                    webmail_dir = %dir,
                    "PIGEON_WEBMAIL=on but the bundle directory is missing; serving the API only"
                );
            }
        }
    }
    let address = listen_address(&config.http_addr)?;
    let http_listener = tokio::net::TcpListener::bind(address).await?;

    // --- inbound SMTP ------------------------------------------------------
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&state.store),
        Arc::clone(&state.db),
        Arc::clone(&state.master_key),
        ServerConfig::default().with_hostname_from_env()?,
    ));
    let (smtp_listener, smtp_address) = server.bind(&config.smtp_in_addr).await?;

    // --- outbound SMTP -----------------------------------------------------
    let mut resolver = MxResolver::from_system()?;
    if let Some(port) = MxResolver::test_port_from_env()? {
        tracing::warn!(
            port,
            "PIGEON_SMTP_TEST_MX_PORT is set: every MX connection goes to this port"
        );
        resolver = resolver.with_test_port(port);
    }
    let delivery = DeliveryConfig::from_env(config.smtp_out_starttls)?;
    if let Some((host, port)) = &delivery.relay {
        tracing::info!(host = %host, port, "outbound mail is relayed through a smarthost");
    }
    // Per-domain DKIM: the source reads `dkim_keys` for each message's From
    // domain and unseals the private key under the master key.
    let dkim = Arc::new(StoreDkimKeys::new(
        Arc::clone(&state.store),
        Arc::clone(&state.master_key),
    ));
    let worker = QueueWorker::new(
        Arc::clone(&state.store),
        Arc::clone(&state.db),
        Arc::clone(&state.master_key),
        Arc::new(OutboundSmtpClient::new(resolver, delivery)),
        dkim,
        WorkerConfig::default(),
    );

    tracing::info!(
        %address,
        smtp_address = %smtp_address,
        db_path = %config.db_path.display(),
        master_key_file = %config.master_key_file.display(),
        starttls = %config.smtp_out_starttls,
        "pigeon listening"
    );

    // One stop signal for three services: the task that watches the OS signals
    // flips the channel, and every service sees it at the same time.
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });

    // JD-A-003: ConnectInfo is required for the per-IP auth failure budget;
    // without it every caller shares one bucket (global DoS with 5 requests).
    let http = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_stop(stop_rx.clone()));
    let smtp = server.serve_with_shutdown(smtp_listener, wait_for_stop(stop_rx.clone()));
    let queue = worker.run(wait_for_stop(stop_rx));

    tokio::select! {
        result = http => {
            result?;
            tracing::info!("pigeon api stopped");
        }
        () = smtp => tracing::info!("pigeon smtp stopped"),
        () = queue => tracing::info!("pigeon queue worker stopped"),
    }
    Ok(())
}

/// Resolve once the shared stop channel is set (or its sender is gone, which
/// only happens when the process is already tearing down).
async fn wait_for_stop(mut stop: tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// Generate the master key and the first API key, and print what to configure.
fn keygen(config: &Config, account: &str, db_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let path = db_path.unwrap_or_else(|| config.db_path.clone());
    let email = EmailAddress::parse(account)?;

    // `generate_content_key` returns 32 fresh CSPRNG bytes; the master key is
    // parsed from exactly those bytes so the printed hex and the key in memory
    // can never disagree.
    let raw = pigeon_crypto::generate_content_key();
    let master_key = MasterKey::parse(&raw)?;
    let hex_key = hex::encode(raw);
    // Self-check the key before printing it: a usable master key must wrap and
    // unwrap, so a problem surfaces here instead of at the first boot.
    let probe = pigeon_crypto::generate_content_key();
    let wrapped = master_key.wrap_content_key(&probe, b"pigeon/keygen/self-check")?;
    if master_key.unwrap_content_key(&wrapped, b"pigeon/keygen/self-check")? != probe {
        return Err("master key self-check failed: wrapped content did not unwrap".into());
    }

    let store = SqliteStorage::open(&path)?;
    let db = ApiDb::open(&path)?;
    let account_id = match store.create_account(&email) {
        Ok(account_id) => account_id,
        // Re-running keygen is a supported operation: the account exists, so
        // issue another key for it instead of failing.
        Err(store::StoreError::Conflict) => db
            .account_id_by_email(&email.normalized())?
            .ok_or("account exists but could not be loaded")?,
        Err(error) => return Err(error.into()),
    };
    let (key_id, api_key) = pigeon_api::keys::issue(
        &store,
        &db,
        account_id,
        "bootstrap",
        &[ApiKeyScope::Full],
        false,
    )?;

    println!("pigeon keygen");
    println!("  account:                 {email} (id {account_id})");
    println!("  master key (64 hex):     {hex_key}");
    println!("  api key id:              {key_id}");
    println!("  api key (shown once):    {api_key}");
    println!();
    println!("Save the master key now — it is not stored anywhere and cannot be recovered.");
    println!("Without it every sealed message in the database stays unreadable.");
    println!();
    println!(
        "  install -m 0600 /dev/null {}",
        config.master_key_file.display()
    );
    println!(
        "  printf '%s' '{hex_key}' > {}",
        config.master_key_file.display()
    );
    println!();
    println!("Environment for `pigeon serve` and for API clients:");
    println!(
        "  PIGEON_MASTER_KEY_FILE={}",
        config.master_key_file.display()
    );
    println!("  PIGEON_DB_PATH={}", path.display());
    println!("  PIGEON_HTTP_ADDR={}", config.http_addr);
    println!("  PIGEON_SMTP_IN_ADDR={}", config.smtp_in_addr);
    println!(
        "  PIGEON_PUBLIC_IP=<this server's public IP>   # needed by GET /v1/domains/{{id}}/dns"
    );
    println!("  PIGEON_API_KEY={api_key}                     # clients only; never commit it");
    Ok(())
}

/// Parse `PIGEON_HTTP_ADDR`, accepting the documented `:8000` shorthand.
fn listen_address(raw: &str) -> Result<SocketAddr, Box<dyn Error>> {
    let candidate = raw.trim();
    let candidate = if candidate.starts_with(':') {
        format!("0.0.0.0{candidate}")
    } else {
        candidate.to_string()
    };
    Ok(candidate
        .parse::<SocketAddr>()
        .map_err(|error| format!("PIGEON_HTTP_ADDR {raw:?} is not a socket address: {error}"))?)
}

/// `tracing` with the `PIGEON_LOG` filter, JSON when `PIGEON_LOG_FORMAT=json`.
fn init_tracing(filter: &str) {
    let json = std::env::var("PIGEON_LOG_FORMAT")
        .map(|value| value.trim().eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Resolve when the process is asked to stop, so in-flight requests finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "could not listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => tracing::info!("SIGINT received, shutting down"),
        () = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_addr_shorthand_binds_all_interfaces() {
        assert_eq!(listen_address(":8000").unwrap().to_string(), "0.0.0.0:8000");
        assert_eq!(
            listen_address("127.0.0.1:9000").unwrap().to_string(),
            "127.0.0.1:9000"
        );
        assert_eq!(
            listen_address("[::1]:8080").unwrap().to_string(),
            "[::1]:8080"
        );
        assert!(listen_address("nonsense").is_err());
    }

    #[test]
    fn cli_exposes_serve_and_keygen() {
        let parsed = Pigeon::try_parse_from(["pigeon", "serve"]).expect("serve parses");
        assert!(matches!(parsed.command, Command::Serve));

        let parsed = Pigeon::try_parse_from(["pigeon", "mcp"]).expect("mcp parses");
        assert!(matches!(parsed.command, Command::Mcp));

        let parsed = Pigeon::try_parse_from(["pigeon", "keygen"]).expect("keygen parses");
        match parsed.command {
            Command::Keygen { account, db_path } => {
                assert_eq!(account, "admin@pigeon.local");
                assert!(db_path.is_none());
            }
            Command::Serve | Command::Mcp => panic!("expected keygen"),
        }

        let parsed = Pigeon::try_parse_from([
            "pigeon",
            "keygen",
            "--account",
            "ops@example.com",
            "--db-path",
            "/tmp/pigeon.db",
        ])
        .expect("keygen with flags parses");
        match parsed.command {
            Command::Keygen { account, db_path } => {
                assert_eq!(account, "ops@example.com");
                assert_eq!(
                    db_path.as_deref(),
                    Some(std::path::Path::new("/tmp/pigeon.db"))
                );
            }
            Command::Serve | Command::Mcp => panic!("expected keygen"),
        }
    }
}
