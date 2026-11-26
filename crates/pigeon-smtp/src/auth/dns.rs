//! DNS resolution seam for inbound authentication (issue #111).
//!
//! The auth module needs TXT (SPF records, DMARC policies, DKIM keys), A and
//! AAAA (SPF `a`/`mx` mechanisms) lookups. This trait abstracts them so tests
//! can substitute a fake resolver, mirroring `dns::MxSource` for MX.

use crate::dns::LookupFuture;

/// DNS lookups for inbound authentication.
pub trait AuthDnsSource: Send + Sync {
    /// TXT records of `name` (fully qualified, with or without trailing dot).
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<String>>;
    /// IPv4 A records of `name`.
    fn a<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<std::net::Ipv4Addr>>;
    /// IPv6 AAAA records of `name`.
    fn aaaa<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<std::net::Ipv6Addr>>;
}

/// Production source over `hickory-resolver` (system configuration).
pub struct HickoryAuthDnsSource {
    resolver: crate::dns::TokioResolver,
}

impl HickoryAuthDnsSource {
    /// Build from the system resolver configuration.
    pub fn from_system() -> crate::error::Result<Self> {
        let resolver = crate::dns::TokioResolver::builder_tokio()
            .map_err(|error| {
                crate::error::SmtpError::Dns(format!(
                    "cannot read the system resolver config: {error}"
                ))
            })?
            .build();
        Ok(Self { resolver })
    }
}

impl AuthDnsSource for HickoryAuthDnsSource {
    fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<String>> {
        Box::pin(async move {
            match self.resolver.txt_lookup(name).await {
                Ok(lookup) => Ok(lookup
                    .iter()
                    .flat_map(|record| record.txt_data())
                    // TXT character strings join without separators (RFC 7208).
                    .map(|part| String::from_utf8_lossy(part).to_string())
                    .reduce(|joined, part| format!("{joined}{part}"))
                    .into_iter()
                    .collect()),
                Err(_) => Ok(Vec::new()),
            }
        })
    }

    fn a<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<std::net::Ipv4Addr>> {
        Box::pin(async move {
            match self.resolver.ipv4_lookup(name).await {
                Ok(lookup) => Ok(lookup.iter().map(|ip| ip.0).collect()),
                Err(_) => Ok(Vec::new()),
            }
        })
    }

    fn aaaa<'a>(&'a self, name: &'a str) -> LookupFuture<'a, Vec<std::net::Ipv6Addr>> {
        Box::pin(async move {
            match self.resolver.ipv6_lookup(name).await {
                Ok(lookup) => Ok(lookup.iter().map(|ip| ip.0).collect()),
                Err(_) => Ok(Vec::new()),
            }
        })
    }
}
