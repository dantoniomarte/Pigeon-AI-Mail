//! DNS resolution seam for inbound authentication (issue #111, hardened by
//! #116).
//!
//! The auth module needs TXT (SPF records, DMARC policies, DKIM keys), A,
//! AAAA (SPF `a`/`mx` mechanisms) and MX (the SPF `mx` mechanism) lookups.
//! This trait abstracts them so tests can substitute a fake resolver,
//! mirroring `dns::MxSource` for MX.
//!
//! Hardening (#116):
//! - resolver errors **propagate** (callers map them to `TempError`
//!   verdicts, RFC 7208 §5.4) instead of being swallowed as empty results
//! - the production resolver is built **once** per process (`OnceLock`),
//!   not per message, with an explicit lookup timeout
//! - TXT records are returned as **separate strings** (RFC 7208 §3.2: the
//!   SPF record finder rejects a name with more than one `v=spf1` record)

use std::sync::OnceLock;

use crate::dns::LookupFuture;

/// DNS lookups for inbound authentication.
pub trait AuthDnsSource: Send + Sync {
    /// TXT records of `name` (fully qualified, with or without trailing dot).
    /// Each record is one string (character-strings joined per RFC 7208 §3.3;
    /// distinct TXT records stay distinct).
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>>;
    /// IPv4 A records of `name`.
    fn a<'a>(
        &'a self,
        name: &'a str,
    ) -> LookupFuture<'a, crate::error::Result<Vec<std::net::Ipv4Addr>>>;
    /// IPv6 AAAA records of `name`.
    fn aaaa<'a>(
        &'a self,
        name: &'a str,
    ) -> LookupFuture<'a, crate::error::Result<Vec<std::net::Ipv6Addr>>>;
    /// MX records of `name` (exchange hostnames, preference order).
    fn mx<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>>;
}

/// Production source over `hickory-resolver` (system configuration), built
/// once per process and reused across messages (issue #116 F3).
pub struct HickoryAuthDnsSource {
    resolver: crate::dns::TokioResolver,
}

impl HickoryAuthDnsSource {
    /// Build from the system resolver configuration with an explicit
    /// per-lookup timeout (issue #116 F2): the system default can be 5-30s,
    /// and one message triggers several sequential lookups on a blocking
    /// thread.
    fn build() -> crate::error::Result<Self> {
        let mut options = hickory_resolver::config::ResolverOpts::default();
        // Issue #116 F2: explicit per-request timeout. The system default can
        // be 5-30s, and one message triggers several sequential lookups on a
        // blocking thread — under DNS degradation that starves the pool.
        options.timeout = std::time::Duration::from_secs(5);
        let resolver = crate::dns::TokioResolver::builder_tokio()
            .map_err(|error| {
                crate::error::SmtpError::Dns(format!(
                    "cannot read the system resolver config: {error}"
                ))
            })?
            .with_options(options)
            .build();
        Ok(Self { resolver })
    }

    /// The process-wide shared instance (issue #116 F3): one resolver, one
    /// socket pool, one cache, reused by every inbound message.
    ///
    /// Only a **successful** build is cached: a transient init failure (e.g.
    /// the system resolver config briefly unavailable during container
    /// startup) is not stored, so the next message retries the build instead
    /// of running with DNS auth permanently disabled for the process
    /// lifetime (review finding R4-oncelock-init-failure-cached).
    pub fn shared() -> crate::error::Result<&'static Self> {
        static SHARED: OnceLock<HickoryAuthDnsSource> = OnceLock::new();
        if let Some(source) = SHARED.get() {
            return Ok(source);
        }
        // Build (may fail transiently). Only a success is cached; a failure
        // returns to the caller and the next message retries (issue #121
        // F9: log it so operators can see the transient failure).
        match Self::build() {
            Ok(source) => Ok(SHARED.get_or_init(|| source)),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "auth DNS resolver init failed (transient; the next message retries)"
                );
                Err(error)
            }
        }
    }
}

impl AuthDnsSource for HickoryAuthDnsSource {
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>> {
        Box::pin(async move {
            match self.resolver.txt_lookup(name).await {
                Ok(lookup) => {
                    // Each TXT record is one entry: its character-strings join
                    // without separators (RFC 7208 §3.3), but distinct records
                    // stay distinct (issue #116 F6).
                    let records: Vec<String> = lookup
                        .iter()
                        .map(|record| {
                            record
                                .txt_data()
                                .iter()
                                .map(|part| String::from_utf8_lossy(part).to_string())
                                .collect::<String>()
                        })
                        .collect();
                    Ok(Ok(records))
                }
                Err(error) => Ok(Err(crate::error::SmtpError::Dns(format!(
                    "TXT lookup of {name} failed: {error}"
                )))),
            }
        })
    }

    fn a<'a>(
        &'a self,
        name: &'a str,
    ) -> LookupFuture<'a, crate::error::Result<Vec<std::net::Ipv4Addr>>> {
        Box::pin(async move {
            match self.resolver.ipv4_lookup(name).await {
                Ok(lookup) => Ok(Ok(lookup.iter().map(|ip| ip.0).collect())),
                Err(error) => Ok(Err(crate::error::SmtpError::Dns(format!(
                    "A lookup of {name} failed: {error}"
                )))),
            }
        })
    }

    fn aaaa<'a>(
        &'a self,
        name: &'a str,
    ) -> LookupFuture<'a, crate::error::Result<Vec<std::net::Ipv6Addr>>> {
        Box::pin(async move {
            match self.resolver.ipv6_lookup(name).await {
                Ok(lookup) => Ok(Ok(lookup.iter().map(|ip| ip.0).collect())),
                Err(error) => Ok(Err(crate::error::SmtpError::Dns(format!(
                    "AAAA lookup of {name} failed: {error}"
                )))),
            }
        })
    }

    fn mx<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>> {
        Box::pin(async move {
            match self.resolver.mx_lookup(name).await {
                Ok(lookup) => Ok(Ok(lookup
                    .iter()
                    .map(|mx| mx.exchange().to_string())
                    .collect())),
                // "No MX published" is not an error for the mx mechanism: an
                // empty list simply matches nothing (RFC 7208 §5.6.4).
                // Issue #121 F5: hickory 0.25's ResolveErrorKind has no
                // typed NoRecordsFound variant — the string match is the
                // available mechanism. A hickory upgrade should revisit
                // this (the proto error carries the ResponseCode).
                Err(error)
                    if error.to_string().contains("no record")
                        || error.to_string().contains("NXDOMAIN") =>
                {
                    Ok(Ok(Vec::new()))
                }
                Err(error) => Ok(Err(crate::error::SmtpError::Dns(format!(
                    "MX lookup of {name} failed: {error}"
                )))),
            }
        })
    }
}
