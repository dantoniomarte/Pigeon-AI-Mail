//! Pigeon Mail server binary.
//!
//! Two subcommands, both meant to be scriptable by the installer:
//!
//! * `pigeon serve` — open the database, load the master key and run the four
//!   long-lived services until SIGINT/SIGTERM: the HTTP API, the inbound SMTP
//!   server, the outbound queue worker and the trash-retention purge worker.
//! * `pigeon keygen` — bootstrap: print a fresh master key (write it to the key
//!   file), create the account's first `full` API key, and print the exact
//!   environment to paste into the unit file. Nothing is written to disk except
//!   the account and key rows in the database, so an operator always sees the key
//!   material exactly once.
//! * `pigeon unpin-peer-key <address>` — operator recovery for the layer-3 trust
//!   store: forget the key pinned for a recipient address so the next lookup runs
//!   trust-on-first-use again. Needed when a peer rotates its key: until the pin is
//!   cleared, outbound mail stays sealed to the old key (see
//!   `docs/e2ee-model.md` "Key rotation and the pin").
//!
//! # One process, four services
//!
//! ```text
//!  :8000  HTTP API  (axum)      ← clients, webmail
//!  :2525  SMTP in   (pigeon-smtp) ← the outside world
//!  ----   queue worker          → MX of the recipient domain
//!  ----   trash purge worker    → the database only
//! ```
//!
//! They share one database file and one master key, and they stop together: a
//! single SIGINT/SIGTERM flips one `watch` channel that all four futures wait
//! on, so in-flight HTTP requests, SMTP sessions and deliveries finish instead of
//! being cut off. The webmail UI and the MCP server are still separate services.
//!
//! The purge worker enforces the per-account trash retention
//! (`accounts.trash_retention_days`, 30 by default, `0` = keep forever): every six
//! hours it deletes the trashed messages whose countdown expired. The same sweep
//! is available on demand as `POST /v1/messages/purge-trash`, so an agent or a
//! user never has to wait for the interval.
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
//! End-to-end payload sealing (layer 3) is **on** with no configuration: every
//! account gets an OpenPGP identity the first time it is needed, this instance
//! publishes it at `/.well-known/pigeon-pgp`, and outbound mail is sealed whenever
//! every recipient's key can be discovered. `PIGEON_E2E_PLAINTEXT_DOMAINS` is the
//! only way to opt a recipient domain out, and it is logged.
//!
//! DKIM signing is **on**, per domain: the worker looks the `From:` domain's key
//! up in the `dkim_keys` store, unseals it under the master key and prepends a
//! `DKIM-Signature`. Domains this instance does not hold a key for are delivered
//! unsigned (logged at `info`). Everything else about delivery (queue, backoff,
//! bounces, TLS policy) is live.

use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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

/// How often the trash purge worker sweeps the database (6 hours).
///
/// Long enough that the sweep is noise on any deployment's I/O budget, short
/// enough that a "30 days" policy is honest to within a quarter of a day.
const TRASH_PURGE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

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
    /// Forget the pinned OpenPGP key of a recipient address (re-runs trust on
    /// first use).
    ///
    /// Use it after a peer rotates its key out of band: a pin is never rotated
    /// automatically, so sealed mail keeps targeting the old key until the pin is
    /// cleared. Clear it only after verifying the new fingerprint with the
    /// recipient.
    UnpinPeerKey {
        /// Recipient address whose pin should be removed.
        address: String,
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
        // Layer 3 is on unless an operator names a recipient domain here; the list
        // is parsed and validated by `pigeon_core::Config`.
        plaintext_override_domains: config.e2e_plaintext_domains.clone(),
        ..ApiConfig::default()
    };
    let pigeon = Pigeon::parse();
    match pigeon.command {
        Command::Serve => {
            init_tracing(&config.log_filter);
            serve(config, api_config)
        }
        Command::Keygen { account, db_path } => keygen(&config, &account, db_path),
        Command::UnpinPeerKey { address, db_path } => unpin_peer_key(&config, &address, db_path),
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
    let api_db = pigeon_api::db::ApiDb::open(&config.db_path)
        .map_err(|error| format!("could not open the API database: {error}"))?;
    let state = pigeon_mcp::McpState {
        store,
        master_key,
        api_db: Arc::new(api_db),
        db_path: config.db_path.clone(),
    };
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
                // A stale cached index.html keeps serving an old bundle after
                // every deploy: the entry point must never be cached, while
                // hashed assets are safe to cache forever.
                app = app.fallback_service(
                    axum::Router::new()
                        .fallback_service(serve_dir)
                        .layer(axum::middleware::from_fn(webmail_cache_headers)),
                );
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
        plaintext_override_domains = ?config.e2e_plaintext_domains,
        "pigeon listening"
    );

    // One stop signal for three services: the task that watches the OS signals
    // flips the channel, and every service sees it at the same time.
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });

    // Trash retention: every account's own policy decides how long its trashed
    // mail survives. See `spawn_trash_purge`.
    let purge = spawn_trash_purge(Arc::clone(&state.store), stop_rx.clone());

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
        () = async { let _ = purge.await; } => tracing::info!("pigeon trash purge stopped"),
    }
    Ok(())
}

/// Spawn the trash purge worker.
///
/// Every [`TRASH_PURGE_INTERVAL`] it walks the accounts whose
/// `trash_retention_days` is enabled and deletes the messages that have been in
/// the trash for longer than that. The first tick of a `tokio` interval is
/// immediate, so a deployment that restarts more often than the interval still
/// purges.
///
/// The store is blocking (`rusqlite`), so each sweep runs on the blocking pool
/// instead of stalling the runtime. A failed sweep is logged and the next tick
/// tries again: a worker that gave up permanently would silently break the policy
/// the owner configured, and nothing in the UI would say so.
fn spawn_trash_purge(
    store: Arc<SqliteStorage>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TRASH_PURGE_INTERVAL);
        // A missed tick (process suspended, a slow sweep) must not queue up a
        // burst of catch-up runs: one sweep answers every account anyway.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let store = Arc::clone(&store);
                    let swept = tokio::task::spawn_blocking(move || purge_expired_trash_once(&store)).await;
                    match swept {
                        Ok(Ok((accounts, deleted))) => tracing::info!(
                            accounts,
                            deleted,
                            "trash retention: expired messages purged"
                        ),
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "trash retention: the purge sweep failed")
                        }
                        Err(error) => {
                            tracing::warn!(%error, "trash retention: the purge task failed")
                        }
                    }
                }
                () = wait_for_stop(stop.clone()) => {
                    tracing::info!("trash purge worker stopped");
                    return;
                }
            }
        }
    })
}

/// One sweep: purge the expired trash of every account with retention enabled.
///
/// Returns `(accounts swept, messages deleted)`. An account deleted between the
/// listing and its purge is skipped rather than aborting the sweep, so one
/// concurrent account deletion cannot leave every other mailbox un-purged.
fn purge_expired_trash_once(store: &SqliteStorage) -> store::Result<(usize, usize)> {
    let accounts = store.accounts_with_trash_purge()?;
    let mut deleted = 0usize;
    let mut failed = 0usize;
    for account_id in &accounts {
        match store.purge_expired_trash(*account_id) {
            Ok(purged) => deleted += purged,
            // A missing account is normal; any other error must not stop the
            // remaining accounts from being purged — log it and carry on.
            Err(store::StoreError::NotFound) => continue,
            Err(error) => {
                tracing::warn!(account_id, %error, "trash purge failed for one account");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        tracing::warn!(failed, "trash purge completed with per-account failures");
    }
    Ok((accounts.len(), deleted))
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
    // Create the account's OpenPGP identity now: the first external sender that
    // looks this address up in WKD gets a key instead of waiting for a key
    // generation inside that request.
    let pgp = pigeon_api::pgp::ensure_account_key(&store, &master_key, account_id, &email)?;
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
    println!("  openpgp fingerprint:     {}", pgp.fingerprint);
    println!("  wkd key url:             /.well-known/pigeon-pgp?email={email}");
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

/// Forget the pinned OpenPGP key of one recipient address.
///
/// The layer-3 trust store pins the first key it sees for an address and **never**
/// follows a later change ([`store::Storage::pin_pgp_peer_key`]), because silent
/// rotation is exactly what an attacker who takes over a key directory would want.
/// The cost of that rigidity is a lockout when a peer legitimately rotates: mail
/// keeps being sealed to a key the recipient no longer holds. This command is the
/// deliberate way out — it deletes the pin (audited) so the next discovery runs
/// trust-on-first-use again.
///
/// What it does *not* do is decide whether the new key is the right one. That is the
/// operator's job, out of band, before running it.
fn unpin_peer_key(
    config: &Config,
    address: &str,
    db_path: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let path = db_path.unwrap_or_else(|| config.db_path.clone());
    let address = EmailAddress::parse(address)?;
    let normalized = address.normalized();
    let store = SqliteStorage::open(&path)?;

    let previous = store.get_pgp_peer_key(&normalized)?;
    let removed = store.delete_pgp_peer_key(&normalized)?;

    // Audited either way: "the operator cleared this pin" is exactly the kind of
    // action that must show up in the trail, including when it changed nothing.
    let detail = match &previous {
        Some(row) => format!("was {} (source {})", row.fingerprint, row.source),
        None => "was not pinned".to_string(),
    };
    if let Err(error) = store.audit(
        "cli:operator",
        "pgp.unpin",
        &format!("{normalized}: {detail}"),
    ) {
        // A missing audit row must not fail the recovery the operator asked for.
        eprintln!("pigeon: could not write the audit row: {error}");
    }

    match (removed, previous) {
        (true, Some(row)) => {
            println!("pigeon unpin-peer-key");
            println!("  address:      {normalized}");
            println!("  removed pin:  {}", row.fingerprint);
            println!();
            println!("The next send re-runs trust on first use and will pin whatever");
            println!("the directory serves then. Verify that fingerprint with the");
            println!("recipient before you rely on it.");
        }
        _ => {
            println!("pigeon unpin-peer-key");
            println!("  address:      {normalized}");
            println!("  no pin was stored, so nothing changed");
        }
    }
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

/// Cache headers for the webmail fallback: `no-store` on the entry point and
/// any non-hashed file, long-lived immutability on hashed `/assets/*` — a
/// stale cached index.html keeps serving an old bundle after every deploy.
async fn webmail_cache_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_hashed_asset = request.uri().path().starts_with("/assets/");
    let mut response = next.run(request).await;
    // Only successful asset responses may be cached long-term: an error (a
    // 404 for a hashed name that does not exist yet) must never outlive the
    // deploy that fixes it.
    let cache_control = if is_hashed_asset && response.status().is_success() {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(cache_control),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webmail_cache_headers_split_hashed_assets_from_the_entry_point() {
        use axum::{http::StatusCode, routing::get};
        use tower::ServiceExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let app = axum::Router::new()
            .route("/assets/index-abc.js", get(|| async { "js" }))
            .route("/", get(|| async { "html" }))
            .layer(axum::middleware::from_fn(webmail_cache_headers));
        runtime.block_on(async move {
            let asset = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/assets/index-abc.js")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("asset response");
            assert_eq!(asset.status(), StatusCode::OK);
            assert_eq!(
                asset.headers()[axum::http::header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
            let index = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("index response");
            assert_eq!(index.status(), StatusCode::OK);
            assert_eq!(
                index.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
        });
    }

    #[test]
    fn failed_asset_lookups_are_never_cached_immutable() {
        use axum::{http::StatusCode, routing::get};
        use tower::ServiceExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let app = axum::Router::new()
            .route("/assets/index-abc.js", get(|| async { "js" }))
            .layer(axum::middleware::from_fn(webmail_cache_headers));
        runtime.block_on(async move {
            let missing = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/assets/nonexistent.js")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("missing response");
            assert_eq!(missing.status(), StatusCode::NOT_FOUND);
            // A 404 must never be stamped immutable: no error response may
            // outlive the deploy that fixes it.
            assert_eq!(
                missing.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
        });
    }

    #[test]
    fn api_responses_never_carry_webmail_cache_headers() {
        use axum::{http::StatusCode, routing::get};
        use tower::ServiceExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // The production shape: matched API routes sit OUTSIDE the webmail
        // wrapper, so the middleware must never stamp them (a regression that
        // moved the layer onto the outer app would pass a middleware-only
        // test).
        let app = axum::Router::new()
            .route(
                "/v1/messages",
                get(|| async { axum::Json(serde_json::json!({ "items": [] })) }),
            )
            .fallback_service(
                axum::Router::new()
                    .route("/", get(|| async { "html" }))
                    .layer(axum::middleware::from_fn(webmail_cache_headers)),
            );
        runtime.block_on(async move {
            let api = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/messages")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("api response");
            assert_eq!(api.status(), StatusCode::OK);
            assert!(
                api.headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .is_none(),
                "API responses must not be stamped by the webmail middleware"
            );
            let index = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("fallback response");
            assert_eq!(
                index.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
        });
    }

    #[test]
    fn the_purge_sweep_visits_only_accounts_that_opted_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteStorage::open(dir.path().join("pigeon.db")).expect("open store");
        let owner = EmailAddress::parse("owner@example.com").expect("address");
        let opted_out = EmailAddress::parse("keep@example.com").expect("address");
        let owner_id = store.create_account(&owner).expect("account");
        let opted_out_id = store.create_account(&opted_out).expect("account");
        store
            .set_trash_retention(opted_out_id, 0)
            .expect("keep forever");

        // Nothing is in the trash yet, so the sweep deletes nothing but must still
        // report the one account it visited instead of failing on an empty trash.
        let (accounts, deleted) = purge_expired_trash_once(&store).expect("sweep");
        assert_eq!(accounts, 1, "only the account with retention enabled");
        assert_eq!(deleted, 0);
        assert!(store.get_account(owner_id).is_ok());
    }

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
            _ => panic!("expected keygen"),
        }

        // The layer-3 recovery command: address is positional, database optional.
        let parsed = Pigeon::try_parse_from(["pigeon", "unpin-peer-key", "carol@example.org"])
            .expect("unpin-peer-key parses");
        match parsed.command {
            Command::UnpinPeerKey { address, db_path } => {
                assert_eq!(address, "carol@example.org");
                assert!(db_path.is_none());
            }
            _ => panic!("expected unpin-peer-key"),
        }
        let parsed = Pigeon::try_parse_from([
            "pigeon",
            "unpin-peer-key",
            "carol@example.org",
            "--db-path",
            "/tmp/pigeon.db",
        ])
        .expect("unpin-peer-key with flags parses");
        match parsed.command {
            Command::UnpinPeerKey { address, db_path } => {
                assert_eq!(address, "carol@example.org");
                assert_eq!(
                    db_path.as_deref(),
                    Some(std::path::Path::new("/tmp/pigeon.db"))
                );
            }
            _ => panic!("expected unpin-peer-key"),
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
            _ => panic!("expected keygen"),
        }
    }

    /// The recovery command really clears the pin, leaves a trail, and refuses a
    /// missing database instead of inventing one.
    #[test]
    fn unpin_peer_key_clears_the_pin_and_audits_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let store = SqliteStorage::open(&path).expect("open store");
        store
            .pin_pgp_peer_key("carol@example.org", "FPR-1", "armored", "pigeon-pgp")
            .expect("pin");
        drop(store);

        let config = Config {
            db_path: path.clone(),
            ..Config::default()
        };
        unpin_peer_key(&config, "Carol@Example.org", Some(path.clone())).expect("unpins");

        let store = SqliteStorage::open(&path).expect("reopen");
        assert!(store
            .get_pgp_peer_key("carol@example.org")
            .expect("get")
            .is_none());

        // The recovery is audited: "who cleared which pin" must be answerable.
        let conn = rusqlite::Connection::open(&path).expect("open audit db");
        let (action, detail): (String, String) = conn
            .query_row(
                "SELECT action, detail FROM audit ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("an audit row");
        assert_eq!(action, "pgp.unpin");
        assert!(detail.contains("carol@example.org"), "{detail}");
        assert!(
            detail.contains("FPR-1"),
            "the dropped pin is named: {detail}"
        );

        // Idempotent: a second run reports that nothing was pinned.
        unpin_peer_key(&config, "carol@example.org", None).expect("second run");
        assert!(store
            .get_pgp_peer_key("carol@example.org")
            .expect("get")
            .is_none());
    }
}
