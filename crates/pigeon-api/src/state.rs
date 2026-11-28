//! Shared application state and API tuning knobs.

use std::path::Path;
use std::sync::Arc;

use pigeon_crypto::MasterKey;
use store::SqliteStorage;

use crate::auth::AuthState;
use crate::db::ApiDb;
use crate::rate_limit::{RateLimiter, BURST, SUSTAINED_RPS};
use crate::wkd::{HttpsFetcher, KeyFetcher};

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
    /// Recipient domains an operator has explicitly opted **out** of end-to-end
    /// sealing (`PIGEON_E2E_PLAINTEXT_DOMAINS`).
    ///
    /// Empty by default and never inferred: a message with a recipient on one of
    /// these domains is sent `tls_only`, its `e2e` value is
    /// `plaintext_override`, and the choice is logged. This is the only way to
    /// get an unsealed payload — see `docs/e2ee-model.md`.
    pub plaintext_override_domains: Vec<String>,
    /// Per-hostname display names for the webmail branding
    /// (`PIGEON_INSTANCE_NAMES`, parsed `hostname:display_name` pairs).
    ///
    /// The `GET /v1/instance` handler looks the request's `Host` up here first
    /// and falls back to the server-wide [`Self::instance_name`]. Empty by
    /// default: an operator sets it only when the server serves several mail
    /// domains with distinct webmail hostnames.
    pub instance_names: Vec<(String, String)>,
    /// Server-wide fallback display name (`PIGEON_INSTANCE_NAME`).
    pub instance_name: Option<String>,
}

impl ApiConfig {
    /// True when `domain` is explicitly exempted from end-to-end sealing.
    pub fn is_plaintext_override(&self, domain: &str) -> bool {
        self.plaintext_override_domains
            .iter()
            .any(|override_domain| override_domain.eq_ignore_ascii_case(domain))
    }

    /// Resolve the webmail display name for a request `Host` (issue #136).
    ///
    /// Lookup order: exact (case-insensitive) match in [`Self::instance_names`]
    /// → the server-wide [`Self::instance_name`] → `None`. A `Host` header may
    /// carry a port (`webmail.example.com:8443`); the port is stripped before
    /// matching, and the fallback does not match the bare name when the request
    /// named a different hostname.
    pub fn display_name_for_host(&self, host: Option<&str>) -> Option<&str> {
        let bare = host
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .rsplit_once(':')
                    .filter(|(_rest, port)| {
                        !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                    })
                    .map(|(hostname, _)| hostname)
                    .unwrap_or(value)
            });
        let bare = match bare {
            Some(value) => value,
            None => return self.instance_name.as_deref(),
        };
        self.instance_names
            .iter()
            .find(|(hostname, _)| hostname.eq_ignore_ascii_case(bare))
            .map(|(_, name)| name.as_str())
            .or(self.instance_name.as_deref())
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            daily_send_quota: DEFAULT_DAILY_SEND_QUOTA,
            rate_limit_rps: SUSTAINED_RPS,
            rate_limit_burst: BURST,
            auth_cache_ttl_secs: DEFAULT_AUTH_CACHE_TTL_SECS,
            public_ip: None,
            plaintext_override_domains: Vec::new(),
            instance_names: Vec::new(),
            instance_name: None,
        }
    }
}

/// Parse `PIGEON_INSTANCE_NAMES` (`hostname:display_name` pairs, comma
/// separated) — malformed entries are skipped, never a panic (issue #136).
pub fn parse_instance_names(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (hostname, name) = entry.split_once(':')?;
            let hostname = hostname.trim();
            let name = name.trim();
            if hostname.is_empty() || name.is_empty() {
                return None;
            }
            Some((hostname.to_string(), name.to_string()))
        })
        .collect()
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
    /// Per-source-address buckets for the unauthenticated WKD endpoints.
    ///
    /// Separate from [`Self::limiter`] because the key differs (an address, not an
    /// account) and the budget is tighter: with no credential to throttle, the IP
    /// is the only thing there is.
    pub wkd_limiter: Arc<RateLimiter>,
    /// How recipient keys are fetched for layer-3 sealing.
    ///
    /// Production wires [`HttpsFetcher`]; tests inject a fetcher backed by a
    /// loopback HTTP server, so one Pigeon instance can discover another's
    /// published key without a CA-signed certificate for `127.0.0.1`.
    pub key_fetcher: Arc<dyn KeyFetcher>,
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
            wkd_limiter: Arc::new(RateLimiter::for_wkd()),
            config: Arc::new(config),
            key_fetcher: Arc::new(HttpsFetcher::default()),
        }
    }

    /// Replace the key fetcher (tests, and a deployment pointing discovery at an
    /// internal mirror).
    pub fn with_key_fetcher(mut self, fetcher: Arc<dyn KeyFetcher>) -> Self {
        self.key_fetcher = fetcher;
        self
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

#[cfg(test)]
mod branding_tests {
    use super::*;

    #[test]
    fn parse_instance_names_parses_pairs() {
        let parsed = parse_instance_names("a.example.com:Alpha, b.example.org:Beta");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0],
            ("a.example.com".to_string(), "Alpha".to_string())
        );
        assert_eq!(parsed[1], ("b.example.org".to_string(), "Beta".to_string()));
    }

    #[test]
    fn parse_instance_names_skips_malformed() {
        // Missing colon, empty name, empty hostname, empty entries — all skipped.
        let parsed = parse_instance_names(
            "no-colon.example.com, :EmptyName, EmptyHost:, , ok.example.net:Fine",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            ("ok.example.net".to_string(), "Fine".to_string())
        );
    }

    #[test]
    fn parse_instance_names_empty_string_is_empty() {
        assert!(parse_instance_names("").is_empty());
        assert!(parse_instance_names("   ").is_empty());
    }

    #[test]
    fn display_name_host_exact_match_wins() {
        let config = ApiConfig {
            instance_names: vec![(
                "webmail.example.com".to_string(),
                "Example Mail".to_string(),
            )],
            instance_name: Some("Fallback".to_string()),
            ..ApiConfig::default()
        };
        assert_eq!(
            config.display_name_for_host(Some("webmail.example.com")),
            Some("Example Mail")
        );
        // Case-insensitive host match.
        assert_eq!(
            config.display_name_for_host(Some("WEBMAIL.EXAMPLE.COM")),
            Some("Example Mail")
        );
    }

    #[test]
    fn display_name_strips_the_port_before_matching() {
        let config = ApiConfig {
            instance_names: vec![(
                "webmail.example.com".to_string(),
                "Example Mail".to_string(),
            )],
            instance_name: None,
            ..ApiConfig::default()
        };
        assert_eq!(
            config.display_name_for_host(Some("webmail.example.com:8443")),
            Some("Example Mail")
        );
    }

    #[test]
    fn display_name_unknown_host_falls_back_to_server_wide() {
        let config = ApiConfig {
            instance_names: vec![(
                "webmail.example.com".to_string(),
                "Example Mail".to_string(),
            )],
            instance_name: Some("Fallback".to_string()),
            ..ApiConfig::default()
        };
        assert_eq!(
            config.display_name_for_host(Some("other.example.net")),
            Some("Fallback")
        );
    }

    #[test]
    fn display_name_no_host_uses_server_wide_fallback() {
        let config = ApiConfig {
            instance_names: vec![(
                "webmail.example.com".to_string(),
                "Example Mail".to_string(),
            )],
            instance_name: Some("Fallback".to_string()),
            ..ApiConfig::default()
        };
        assert_eq!(config.display_name_for_host(None), Some("Fallback"));
        assert_eq!(config.display_name_for_host(Some("")), Some("Fallback"));
    }

    #[test]
    fn display_name_nothing_configured_is_null() {
        let config = ApiConfig::default();
        assert_eq!(
            config.display_name_for_host(Some("webmail.example.com")),
            None
        );
        assert_eq!(config.display_name_for_host(None), None);
    }
}
