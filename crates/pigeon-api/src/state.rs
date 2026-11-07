//! Shared application state and API tuning knobs.

use std::path::Path;
use std::sync::Arc;

use pigeon_crypto::MasterKey;
use store::SqliteStorage;

use crate::auth::AuthState;
use crate::db::ApiDb;
use crate::rate_limit::{RateLimiter, BURST, SUSTAINED_RPS};

/// Default daily send quota per account (`docs/API.md`).
pub const DEFAULT_DAILY_SEND_QUOTA: i64 = 50_000;
/// How long a verified API key stays cached, so the Argon2id KDF is not paid on
/// every request (`SECURITY.md` requires the cache).
pub const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 30;

/// Tunables a deployment may want to change without a code change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// Outbound emails allowed per account per UTC day.
    pub daily_send_quota: i64,
    /// Sustained requests per second per account.
    pub rate_limit_rps: u32,
    /// Burst capacity on top of the sustained rate.
    pub rate_limit_burst: u32,
    /// Seconds a verified API key stays cached.
    pub auth_cache_ttl_secs: u64,
    /// Public address of this server, used for the A record of a managed
    /// domain. Unset in a default deployment: `/v1/domains/{id}/dns` then refuses
    /// to invent an address.
    pub public_ip: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            daily_send_quota: DEFAULT_DAILY_SEND_QUOTA,
            rate_limit_rps: SUSTAINED_RPS,
            rate_limit_burst: BURST,
            auth_cache_ttl_secs: DEFAULT_AUTH_CACHE_TTL_SECS,
            public_ip: None,
        }
    }
}

/// Everything a handler needs, cheap to clone.
///
/// `store` and `master_key` are the two pieces the send pipeline depends on;
/// `db`, `auth` and `limiter` carry the API-only concerns documented in
/// [`crate::db`] and [`crate::auth`].
#[derive(Clone)]
pub struct AppState {
    /// Business-logic storage seam (ADR 0002).
    pub store: Arc<SqliteStorage>,
    /// Server master key: seals and opens message content.
    pub master_key: Arc<MasterKey>,
    /// Auxiliary SQL for the admin/read surface.
    pub db: Arc<ApiDb>,
    /// Tuning knobs.
    pub config: Arc<ApiConfig>,
    /// Verified-key cache and failure budget.
    pub auth: Arc<AuthState>,
    /// Per-account token buckets.
    pub limiter: Arc<RateLimiter>,
}

impl AppState {
    /// Build state from already-open pieces.
    pub fn new(store: SqliteStorage, master_key: MasterKey, db: ApiDb, config: ApiConfig) -> Self {
        Self {
            store: Arc::new(store),
            master_key: Arc::new(master_key),
            db: Arc::new(db),
            auth: Arc::new(AuthState::new(std::time::Duration::from_secs(
                config.auth_cache_ttl_secs,
            ))),
            limiter: Arc::new(RateLimiter::new(
                config.rate_limit_rps,
                config.rate_limit_burst,
            )),
            config: Arc::new(config),
        }
    }

    /// Open the database (both connections), apply migrations and build state.
    ///
    /// Both connections point at the same file: `store` runs the schema
    /// migrations, so it must be opened first.
    pub fn open(
        db_path: impl AsRef<Path>,
        master_key: MasterKey,
        config: ApiConfig,
    ) -> store::Result<Self> {
        let path = db_path.as_ref();
        let store = SqliteStorage::open(path)?;
        let db = ApiDb::open(path)?;
        Ok(Self::new(store, master_key, db, config))
    }

    /// True when the master key is loaded. The key is a required constructor
    /// argument, so this reports the readiness contract's assertion rather than
    /// probing at runtime: state cannot exist without a key, and a failure to
    /// load one aborts startup instead of serving with encryption disabled.
    pub const fn master_key_loaded(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::Storage;

    fn master_key() -> MasterKey {
        MasterKey::parse(&[7u8; 32]).expect("master key")
    }

    #[test]
    fn config_defaults_match_the_documented_limits() {
        let config = ApiConfig::default();
        assert_eq!(config.daily_send_quota, 50_000);
        assert_eq!(config.rate_limit_rps, 10);
        assert_eq!(config.rate_limit_burst, 50);
        assert_eq!(config.auth_cache_ttl_secs, 30);
    }

    #[test]
    fn state_opens_both_connections_on_one_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let state = AppState::open(&path, master_key(), ApiConfig::default()).expect("open");
        state.db.ping().expect("api connection works");
        assert!(state.master_key_loaded());
        assert_eq!(state.store.reserve_message_id().expect("store works"), 1);
    }
}
