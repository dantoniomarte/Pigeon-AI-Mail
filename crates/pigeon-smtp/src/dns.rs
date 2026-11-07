//! MX resolution for outbound delivery.
//!
//! Two seams matter here and both exist so the delivery path is testable
//! without a DNS server:
//!
//! * [`MxSource`] is the actual lookup. Production uses [`HickoryMxSource`]
//!   (system resolver via `hickory-resolver`); tests inject a fake.
//! * [`MxResolver::port`] is the **connection port**, not a DNS concern:
//!   `PIGEON_SMTP_TEST_MX_PORT` pins every MX connection to one port so a
//!   loopback fake MX can be reached from an integration test. Production leaves
//!   it unset and uses [`DEFAULT_SMTP_PORT`].
//!
//! Resolution follows RFC 5321 §5.1: MX records ordered by preference, and when
//! a domain publishes none the bare domain is used as an **implicit MX** (the
//! A/AAAA fallback an MTA is required to try).

use std::future::Future;
use std::pin::Pin;

use hickory_resolver::TokioResolver;

use crate::error::{Result, SmtpError};

/// Port SMTP delivery uses when nothing overrides it.
pub const DEFAULT_SMTP_PORT: u16 = 25;

/// Environment variable that pins every MX connection to one port (loopback
/// testing only; never set it in production).
pub const TEST_MX_PORT_ENV: &str = "PIGEON_SMTP_TEST_MX_PORT";

/// One MX record: lower `preference` is tried first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    /// Hostname of the mail exchanger. A trailing dot from DNS is stripped, and
    /// the root exchange `.` (RFC 7505 "null MX") becomes an empty string.
    pub exchange: String,
}

impl MxRecord {
    /// Build a record, normalizing the DNS trailing dot.
    pub fn new(preference: u16, exchange: impl Into<String>) -> Self {
        let exchange = exchange.into();
        let exchange = match exchange.as_str() {
            "." => String::new(),
            other => other.trim_end_matches('.').to_string(),
        };
        Self {
            preference,
            exchange,
        }
    }

    /// True for the RFC 7505 null MX, which means "this domain accepts no mail".
    pub fn is_null(&self) -> bool {
        self.exchange.is_empty()
    }
}

/// Boxed future returned by [`MxSource`] (no `async-trait` dependency for one
/// method).
pub type LookupFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// The DNS lookup behind [`MxResolver`].
///
/// Implementations must return records **unsorted** and honour the null-MX
/// convention; ordering and the implicit-MX fallback belong to [`MxResolver`],
/// so every backend behaves the same way.
pub trait MxSource: Send + Sync {
    /// MX records for `domain`, or an empty vector when none are published.
    fn mx_records<'a>(&'a self, domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>>;
}

/// Production [`MxSource`]: `hickory-resolver` over the system configuration.
///
/// `builder_tokio` reads `/etc/resolv.conf` (or the Windows registry) once at
/// construction; lookups then run on the tokio runtime.
pub struct HickoryMxSource {
    resolver: TokioResolver,
}

impl HickoryMxSource {
    /// Build from the system resolver configuration.
    pub fn from_system() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| {
                SmtpError::Dns(format!("cannot read the system resolver config: {error}"))
            })?
            .build();
        Ok(Self { resolver })
    }
}

impl MxSource for HickoryMxSource {
    fn mx_records<'a>(&'a self, domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>> {
        Box::pin(async move {
            match self.resolver.mx_lookup(domain).await {
                Ok(lookup) => Ok(lookup
                    .iter()
                    .map(|mx| MxRecord::new(mx.preference(), mx.exchange().to_string()))
                    .collect()),
                // "No MX published" and NXDOMAIN both mean "try the bare
                // domain" per RFC 5321; the connection attempt then produces the
                // real verdict (and a bounce if the host does not exist).
                Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
                Err(error) => Err(SmtpError::Dns(format!(
                    "MX lookup for {domain} failed: {error}"
                ))),
            }
        })
    }
}

/// MX resolution plus the connection port, as the delivery client needs it.
pub struct MxResolver {
    source: Box<dyn MxSource>,
    test_port: Option<u16>,
}

impl MxResolver {
    /// Wrap a lookup backend.
    pub fn new(source: impl MxSource + 'static) -> Self {
        Self {
            source: Box::new(source),
            test_port: None,
        }
    }

    /// Production resolver over the system DNS configuration.
    pub fn from_system() -> Result<Self> {
        Ok(Self::new(HickoryMxSource::from_system()?))
    }

    /// Pin every connection to `port` (loopback testing).
    pub fn with_test_port(mut self, port: u16) -> Self {
        self.test_port = Some(port);
        self
    }

    /// Read `PIGEON_SMTP_TEST_MX_PORT`; an empty or unparsable value is an
    /// operator error rather than a silent default, because the variable only
    /// exists to redirect delivery somewhere deliberate.
    pub fn test_port_from_env() -> Result<Option<u16>> {
        match std::env::var(TEST_MX_PORT_ENV) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(raw) => raw.trim().parse::<u16>().map(Some).map_err(|error| {
                SmtpError::Config(format!(
                    "{TEST_MX_PORT_ENV} is not a port: {raw:?} ({error})"
                ))
            }),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(SmtpError::Config(format!(
                "{TEST_MX_PORT_ENV} is not valid Unicode"
            ))),
        }
    }

    /// Port delivery connects to: the override when set, else
    /// [`DEFAULT_SMTP_PORT`].
    pub fn port(&self) -> u16 {
        self.test_port.unwrap_or(DEFAULT_SMTP_PORT)
    }

    /// Resolve `domain` into delivery candidates, best first.
    ///
    /// * records sorted by preference, then hostname (a stable order makes the
    ///   retry sequence reproducible),
    /// * no MX records → one implicit-MX candidate for the domain itself,
    /// * a null MX (`.`) → an error: the domain explicitly refuses mail, so
    ///   trying the A record would be wrong.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let mut records = self.source.mx_records(domain).await?;
        if records.iter().any(MxRecord::is_null) {
            return Err(SmtpError::Dns(format!(
                "{domain} publishes a null MX (RFC 7505) and accepts no mail"
            )));
        }
        if records.is_empty() {
            records.push(MxRecord::new(0, domain));
        }
        records.sort_by(|left, right| {
            left.preference
                .cmp(&right.preference)
                .then_with(|| left.exchange.cmp(&right.exchange))
        });
        Ok(records)
    }
}

impl std::fmt::Debug for MxResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MxResolver")
            .field("test_port", &self.test_port)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic [`MxSource`] for tests: a fixed answer table.
    struct FakeSource {
        answers: std::collections::HashMap<String, Vec<MxRecord>>,
        failure: Option<String>,
    }

    impl FakeSource {
        fn new(answers: &[(&str, Vec<MxRecord>)]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .map(|(domain, records)| ((*domain).to_string(), records.clone()))
                    .collect(),
                failure: None,
            }
        }

        fn failing(reason: &str) -> Self {
            Self {
                answers: std::collections::HashMap::new(),
                failure: Some(reason.to_string()),
            }
        }
    }

    impl MxSource for FakeSource {
        fn mx_records<'a>(&'a self, domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>> {
            Box::pin(async move {
                if let Some(reason) = &self.failure {
                    return Err(SmtpError::Dns(reason.clone()));
                }
                Ok(self.answers.get(domain).cloned().unwrap_or_default())
            })
        }
    }

    #[tokio::test]
    async fn records_are_ordered_by_preference_then_hostname() {
        let resolver = MxResolver::new(FakeSource::new(&[(
            "example.com",
            vec![
                MxRecord::new(30, "c.mx.example.com."),
                MxRecord::new(10, "b.mx.example.com."),
                MxRecord::new(10, "a.mx.example.com."),
            ],
        )]));
        let records = resolver.resolve("example.com").await.expect("resolves");
        assert_eq!(
            records
                .iter()
                .map(|record| record.exchange.as_str())
                .collect::<Vec<_>>(),
            vec!["a.mx.example.com", "b.mx.example.com", "c.mx.example.com"]
        );
        assert_eq!(records[0].preference, 10);
    }

    #[tokio::test]
    async fn missing_mx_records_fall_back_to_the_bare_domain() {
        let resolver = MxResolver::new(FakeSource::new(&[]));
        let records = resolver
            .resolve("implicit.example")
            .await
            .expect("resolves");
        assert_eq!(
            records,
            vec![MxRecord {
                preference: 0,
                exchange: "implicit.example".to_string()
            }]
        );
    }

    #[tokio::test]
    async fn null_mx_is_a_permanent_failure_not_a_fallback() {
        let resolver = MxResolver::new(FakeSource::new(&[(
            "gone.example",
            vec![MxRecord::new(0, ".")],
        )]));
        let error = resolver.resolve("gone.example").await.unwrap_err();
        assert!(
            matches!(&error, SmtpError::Dns(message) if message.contains("null MX")),
            "got {error}"
        );
    }

    #[tokio::test]
    async fn lookup_errors_are_reported_rather_than_hidden() {
        let resolver = MxResolver::new(FakeSource::failing("resolver timeout"));
        let error = resolver.resolve("example.com").await.unwrap_err();
        assert!(matches!(&error, SmtpError::Dns(message) if message.contains("resolver timeout")));
    }

    #[test]
    fn test_port_override_only_replaces_the_connection_port() {
        let resolver = MxResolver::new(FakeSource::new(&[]));
        assert_eq!(resolver.port(), DEFAULT_SMTP_PORT);
        assert_eq!(resolver.with_test_port(2525).port(), 2525);
    }

    #[test]
    fn trailing_dots_are_stripped_and_null_mx_is_recognized() {
        assert_eq!(
            MxRecord::new(5, "mx.example.com.").exchange,
            "mx.example.com"
        );
        assert_eq!(
            MxRecord::new(5, "mx.example.com").exchange,
            "mx.example.com"
        );
        assert_eq!(MxRecord::new(0, ".").exchange, "");
        assert!(MxRecord::new(0, ".").is_null());
        assert!(!MxRecord::new(0, "mx.example.com").is_null());
    }
}
