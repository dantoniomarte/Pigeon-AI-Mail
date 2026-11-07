//! 12-factor configuration read from `PIGEON_*` environment variables.
//!
//! Every value has a production-sane default so `pigeon-api` boots with an
//! empty environment; the installer writes an env file when it needs to change
//! something (ADR 0001/0002 posture: one binary, no config file format).
//!
//! The variable names and defaults here are the ones documented in
//! `docs/ARCHITECTURE.md`; that table is the contract.

use std::fmt;
use std::path::PathBuf;

use crate::error::{CoreError, Result};

/// Environment variable prefix owned by Pigeon.
///
/// Unknown `PIGEON_*` variables are **ignored on purpose**: configuration is
/// forward compatible. A newer release may document a new variable while an
/// older binary still runs against the same env file, and unrelated tooling can
/// export names we do not own. The trade-off is that a typo falls back to the
/// default instead of failing the boot, which is the cheaper failure for a
/// self-hosted server.
pub const ENV_PREFIX: &str = "PIGEON_";

/// Variable suffixes this crate understands, without [`ENV_PREFIX`]. Used by
/// tests (and by future tooling) to prove the documented names and the parsed
/// names stay in sync.
pub const KNOWN_ENV_SUFFIXES: &[&str] = &[
    "HTTP_ADDR",
    "SMTP_IN_ADDR",
    "DB_PATH",
    "MASTER_KEY_FILE",
    "SMTP_OUT_STARTTLS",
    "WEBMAIL",
    "LOG",
    // Deprecated alias for LOG, accepted for one release.
    "LOG_FILTER",
];

/// How outbound SMTP negotiates TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTlsMode {
    /// Refuse to send unless STARTTLS succeeds (default).
    Required,
    /// Use STARTTLS when advertised, send in clear otherwise.
    Opportunistic,
}

impl StartTlsMode {
    /// Canonical lowercase representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            StartTlsMode::Required => "required",
            StartTlsMode::Opportunistic => "opportunistic",
        }
    }

    /// Parse `required` | `pinned` | `opportunistic` (trimmed,
    /// ASCII-case-insensitive). The error echoes the raw input.
    ///
    /// `pinned` is rejected until pin configuration lands: accepting it today
    /// would promise an enforcement the server cannot deliver.
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "required" => Ok(StartTlsMode::Required),
            "opportunistic" => Ok(StartTlsMode::Opportunistic),
            "pinned" => Err(CoreError::Config(format!(
                "unsupported mode {input:?}: use \"required\" or \"opportunistic\" (pinned lands later)"
            ))),
            _ => Err(CoreError::Config(format!(
                "{ENV_PREFIX}SMTP_OUT_STARTTLS must be one of required|opportunistic, got {input:?}"
            ))),
        }
    }
}

impl fmt::Display for StartTlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Effective server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// HTTP API listen address (`PIGEON_HTTP_ADDR`).
    pub http_addr: String,
    /// Inbound SMTP listen address (`PIGEON_SMTP_IN_ADDR`).
    pub smtp_in_addr: String,
    /// SQLite database file (`PIGEON_DB_PATH`).
    pub db_path: PathBuf,
    /// Master key file, root-owned (`PIGEON_MASTER_KEY_FILE`).
    pub master_key_file: PathBuf,
    /// Outbound TLS policy (`PIGEON_SMTP_OUT_STARTTLS`).
    pub smtp_out_starttls: StartTlsMode,
    /// Serve the webmail UI (`PIGEON_WEBMAIL`).
    pub webmail: bool,
    /// `tracing` filter string (`PIGEON_LOG`).
    pub log_filter: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_addr: ":8000".to_string(),
            smtp_in_addr: ":25".to_string(),
            db_path: PathBuf::from("/var/lib/pigeon/pigeon.db"),
            master_key_file: PathBuf::from("/etc/pigeon/master.key"),
            smtp_out_starttls: StartTlsMode::Required,
            webmail: false,
            log_filter: "info".to_string(),
        }
    }
}

impl Config {
    /// Read the process environment.
    ///
    /// A variable that exists but is not valid Unicode is a hard error: falling
    /// back to the default would silently bind the wrong address or use the
    /// wrong database path.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(CoreError::Config(format!("{key} is not valid Unicode")))
            }
        })
    }

    /// Build a config from an arbitrary key lookup (`PIGEON_HTTP_ADDR` ->
    /// `Some(":9000")`). Tests use this instead of mutating the process
    /// environment, which is global state and races between test threads.
    pub fn from_lookup<F>(lookup: F) -> Result<Self>
    where
        F: Fn(&str) -> Result<Option<String>>,
    {
        // Empty values are treated as unset: an exported-but-empty variable
        // ("PIGEON_HTTP_ADDR=") must not produce an unusable listener.
        let get = |suffix: &str| -> Result<Option<String>> {
            let raw = lookup(&format!("{ENV_PREFIX}{suffix}"))?;
            Ok(raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
        };

        let mut cfg = Self::default();
        if let Some(v) = get("HTTP_ADDR")? {
            cfg.http_addr = v;
        }
        if let Some(v) = get("SMTP_IN_ADDR")? {
            cfg.smtp_in_addr = v;
        }
        if let Some(v) = get("DB_PATH")? {
            cfg.db_path = PathBuf::from(v);
        }
        if let Some(v) = get("MASTER_KEY_FILE")? {
            cfg.master_key_file = PathBuf::from(v);
        }
        if let Some(v) = get("SMTP_OUT_STARTTLS")? {
            cfg.smtp_out_starttls = StartTlsMode::parse(&v)?;
        }
        if let Some(v) = get("WEBMAIL")? {
            cfg.webmail = parse_bool("WEBMAIL", &v)?;
        }
        // PIGEON_LOG is the documented name. PIGEON_LOG_FILTER is the
        // pre-0.1 name kept as a deprecated alias for one release; if both are
        // set the documented one wins.
        let log = match get("LOG")? {
            Some(v) => Some(v),
            None => get("LOG_FILTER")?,
        };
        if let Some(v) = log {
            cfg.log_filter = v;
        }
        Ok(cfg)
    }
}

fn parse_bool(suffix: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" => Ok(false),
        _ => Err(CoreError::Config(format!(
            "{ENV_PREFIX}{suffix} must be one of 1|true|on|0|false|off, got {value:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ApiKeyScope;
    use std::collections::HashMap;

    fn from_pairs(pairs: &[(&str, &str)]) -> Result<Config> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|key| Ok(map.get(key).cloned()))
    }

    #[test]
    fn defaults_match_the_documented_production_values() {
        let cfg = Config::from_lookup(|_| Ok(None)).unwrap();
        assert_eq!(cfg.http_addr, ":8000");
        assert_eq!(cfg.smtp_in_addr, ":25");
        assert_eq!(cfg.db_path, PathBuf::from("/var/lib/pigeon/pigeon.db"));
        assert_eq!(cfg.master_key_file, PathBuf::from("/etc/pigeon/master.key"));
        assert_eq!(cfg.smtp_out_starttls, StartTlsMode::Required);
        assert!(!cfg.webmail);
        assert_eq!(cfg.log_filter, "info");
    }

    #[test]
    fn explicit_values_override_defaults() {
        let cfg = from_pairs(&[
            ("PIGEON_HTTP_ADDR", "127.0.0.1:9000"),
            ("PIGEON_SMTP_IN_ADDR", "127.0.0.1:2525"),
            ("PIGEON_DB_PATH", "/tmp/pigeon.db"),
            ("PIGEON_MASTER_KEY_FILE", "/tmp/master.key"),
            ("PIGEON_SMTP_OUT_STARTTLS", "opportunistic"),
            ("PIGEON_WEBMAIL", "on"),
            ("PIGEON_LOG", "debug"),
        ])
        .unwrap();
        assert_eq!(cfg.http_addr, "127.0.0.1:9000");
        assert_eq!(cfg.smtp_in_addr, "127.0.0.1:2525");
        assert_eq!(cfg.db_path, PathBuf::from("/tmp/pigeon.db"));
        assert_eq!(cfg.master_key_file, PathBuf::from("/tmp/master.key"));
        assert_eq!(cfg.smtp_out_starttls, StartTlsMode::Opportunistic);
        assert!(cfg.webmail);
        assert_eq!(cfg.log_filter, "debug");
    }

    #[test]
    fn every_documented_env_name_and_scope_name_parses() {
        // docs/ARCHITECTURE.md "Configuration (principal env vars)".
        let documented: &[(&str, &str)] = &[
            ("PIGEON_MASTER_KEY_FILE", "/tmp/master.key"),
            ("PIGEON_DB_PATH", "/tmp/pigeon.db"),
            ("PIGEON_HTTP_ADDR", ":8123"),
            ("PIGEON_SMTP_IN_ADDR", ":2525"),
            ("PIGEON_SMTP_OUT_STARTTLS", "required"),
            ("PIGEON_WEBMAIL", "on"),
            ("PIGEON_LOG", "info"),
        ];
        for (name, _) in documented {
            let suffix = name
                .strip_prefix(ENV_PREFIX)
                .unwrap_or_else(|| panic!("{name} must use the {ENV_PREFIX} prefix"));
            assert!(
                KNOWN_ENV_SUFFIXES.contains(&suffix),
                "{name} is documented but not parsed"
            );
        }
        let cfg = from_pairs(documented).expect("all documented names are accepted");
        assert_eq!(cfg.http_addr, ":8123");
        assert_eq!(cfg.log_filter, "info");

        // docs/ARCHITECTURE.md API auth line: scopes send, read, full.
        let documented_scopes = ["send", "read", "full"];
        assert_eq!(
            ApiKeyScope::all()
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
            documented_scopes
        );
        for scope in documented_scopes {
            assert!(ApiKeyScope::parse(scope).is_ok(), "{scope} must parse");
        }
    }

    #[test]
    fn log_uses_the_documented_name_and_the_deprecated_alias() {
        let alias = from_pairs(&[("PIGEON_LOG_FILTER", "trace")]).unwrap();
        assert_eq!(alias.log_filter, "trace");

        let primary =
            from_pairs(&[("PIGEON_LOG", "debug"), ("PIGEON_LOG_FILTER", "trace")]).unwrap();
        assert_eq!(primary.log_filter, "debug", "PIGEON_LOG wins");
    }

    #[test]
    fn unknown_pigeon_variables_are_ignored_for_forward_compatibility() {
        let cfg = from_pairs(&[
            ("PIGEON_FROM_A_FUTURE_RELEASE", "whatever"),
            ("PIGEON_", ""),
            ("NOT_PREFIXED", "x"),
        ])
        .unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn empty_values_fall_back_to_defaults() {
        let cfg = from_pairs(&[("PIGEON_HTTP_ADDR", "")]).unwrap();
        assert_eq!(cfg.http_addr, ":8000");
    }

    #[test]
    fn lookup_errors_are_propagated_not_swallowed() {
        let err = Config::from_lookup(|key| {
            Err(CoreError::Config(format!("{key} is not valid Unicode")))
        })
        .unwrap_err();
        assert!(matches!(err, CoreError::Config(message) if message.contains("PIGEON_HTTP_ADDR")));
    }

    #[test]
    fn starttls_parse_accepts_enforceable_modes() {
        assert_eq!(
            StartTlsMode::parse("required").unwrap(),
            StartTlsMode::Required
        );
        assert_eq!(
            StartTlsMode::parse("opportunistic").unwrap(),
            StartTlsMode::Opportunistic
        );
        assert_eq!(
            StartTlsMode::parse("  REQUIRED ").unwrap(),
            StartTlsMode::Required
        );
        for mode in [StartTlsMode::Required, StartTlsMode::Opportunistic] {
            assert_eq!(StartTlsMode::parse(mode.as_str()).unwrap(), mode);
        }
    }

    #[test]
    fn starttls_parse_rejects_pinned_until_pins_exist() {
        let err = StartTlsMode::parse("pinned").unwrap_err();
        assert!(
            matches!(&err, CoreError::Config(message) if message.contains("pinned") && message.contains("later")),
            "got {err}"
        );
        let err = from_pairs(&[("PIGEON_SMTP_OUT_STARTTLS", "pinned")]).unwrap_err();
        assert!(matches!(err, CoreError::Config(_)));
    }

    #[test]
    fn starttls_parse_rejects_unknown_modes_echoing_the_raw_input() {
        for input in ["", "never", "tls1.3", " Required!"] {
            let err = StartTlsMode::parse(input).unwrap_err();
            assert!(matches!(err, CoreError::Config(_)), "{input:?} -> {err}");
            assert!(
                err.to_string().contains(&format!("{input:?}")),
                "error must echo the raw input {input:?}: {err}"
            );
        }
        let err = from_pairs(&[("PIGEON_SMTP_OUT_STARTTLS", "sometimes")]).unwrap_err();
        assert!(matches!(err, CoreError::Config(_)));
    }

    #[test]
    fn webmail_parses_truthy_and_falsy_values() {
        for truthy in ["1", "true", "on", "TRUE", "On"] {
            let cfg = from_pairs(&[("PIGEON_WEBMAIL", truthy)]).unwrap();
            assert!(cfg.webmail, "{truthy} should enable webmail");
        }
        for falsy in ["0", "false", "off", "FALSE"] {
            let cfg = from_pairs(&[("PIGEON_WEBMAIL", falsy)]).unwrap();
            assert!(!cfg.webmail, "{falsy} should disable webmail");
        }
        let err = from_pairs(&[("PIGEON_WEBMAIL", "yes please")]).unwrap_err();
        assert!(matches!(err, CoreError::Config(_)));
    }
}
