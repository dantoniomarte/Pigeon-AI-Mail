//! SPF evaluation (RFC 7208) — the common subset of mechanisms.
//!
//! Supported: `ip4:`, `ip6:`, `a`, `mx`, `include:`, `redirect=`, `all` (and
//! the `+`/`-`/`~`/`?` qualifiers). Not supported (rare, v0.3): `exists:`,
//! `ptr:`, `exp:`, macro expansion. The DNS lookup limit (10 per record,
//! RFC 7208 §4.6.4) is enforced on `include:`, `redirect=` and the
//! `a`/`mx` dereferences (issue #121 F3).
//!
//! `redirect=` is a modifier, not a mechanism: RFC 7208 §6.1 evaluates it
//! only when no mechanism matched (F5, issue #111).
//!
//! Hardening (#116): DNS errors propagate as `TempError` verdicts
//! (RFC 7208 §5.4) instead of degrading to `none`; the `mx` mechanism
//! resolves the domain's MX hosts and then their A/AAAA records (F4);
//! a name publishing more than one `v=spf1` TXT record is `permerror`
//! (F6, RFC 7208 §3.2).
//!
//! Hardening (#121): DNS errors during **per-mechanism** lookups also
//! produce `TempError` (F1) — a DNS outage during the `a` or `mx` lookup
//! no longer degrades to `Fail` via `-all`. The `mx` mechanism evaluates
//! at most 10 MX hosts (F2, RFC 7208 §5.6.4). The include: mechanism
//! propagates permerror from multiple-records (F6).

use std::net::IpAddr;

use super::dns::AuthDnsSource;

/// SPF evaluation result (RFC 7208 §2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfResult {
    pub verdict: SpfVerdict,
    /// The domain the check ran against (the envelope sender's domain).
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfVerdict {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            SpfVerdict::Pass => "pass",
            SpfVerdict::Fail => "fail",
            SpfVerdict::SoftFail => "softfail",
            SpfVerdict::Neutral => "neutral",
            SpfVerdict::None => "none",
            SpfVerdict::TempError => "temperror",
            SpfVerdict::PermError => "permerror",
        }
    }
}

impl SpfResult {
    pub fn as_str(&self) -> &'static str {
        self.verdict.as_str()
    }
}

/// The RFC 7208 §4.6.4 DNS lookup limit.
const DNS_LOOKUP_LIMIT: usize = 10;

/// The RFC 7208 §5.6.4 MX host limit for the `mx` mechanism.
const MX_HOST_LIMIT: usize = 10;

/// Per-evaluation DNS lookup budget (issue #121 F3: the old depth counter
/// only counted include/redirect; now every DNS access counts).
/// Issue #124 F1: shared via `Arc<AtomicUsize>` so `include:` lookups
/// propagate to the parent budget (the old `Clone` let each include
/// run its own full budget — 10 includes × 10 lookups = 100 total).
#[derive(Debug, Clone)]
struct LookupBudget {
    used: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl LookupBudget {
    fn new() -> Self {
        Self {
            used: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Consume one lookup slot; returns false when the budget is exhausted
    /// (RFC 7208 §4.6.4: permerror).
    fn charge(&self) -> bool {
        let n = self.used.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        n <= DNS_LOOKUP_LIMIT
    }
}

/// Check whether `peer_ip` is authorized to send mail for `domain`.
pub fn check(dns: &dyn AuthDnsSource, peer_ip: IpAddr, mail_from_domain: &str) -> SpfResult {
    super::runtime::block_on_any(check_async(dns, peer_ip, mail_from_domain))
}

/// Async core of the SPF check.
pub async fn check_async(dns: &dyn AuthDnsSource, peer_ip: IpAddr, domain: &str) -> SpfResult {
    let record = match spf_record(dns, domain).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return SpfResult {
                verdict: SpfVerdict::None,
                domain: domain.to_string(),
            }
        }
        // DNS failure: temperror, not none (RFC 7208 §5.4, issue #116 F1).
        // The multiple-SPF-records marker is permerror (RFC 7208 §3.2, F6).
        Err(error) => {
            let verdict = if is_multiple_records_error(&error) {
                SpfVerdict::PermError
            } else {
                SpfVerdict::TempError
            };
            return SpfResult {
                verdict,
                domain: domain.to_string(),
            };
        }
    };

    let budget = LookupBudget::new();
    let verdict = Box::pin(evaluate_record(dns, &record, peer_ip, domain, &budget)).await;
    SpfResult {
        verdict,
        domain: domain.to_string(),
    }
}

/// Fetch the SPF TXT record of `domain`.
///
/// Returns `Ok(None)` when no `v=spf1` record is published, `Err` on DNS
/// failure, and `Ok(Some(record))` for the single valid record. More than
/// one `v=spf1` record is `permerror` (RFC 7208 §3.2, issue #116 F6).
async fn spf_record(dns: &dyn AuthDnsSource, domain: &str) -> crate::error::Result<Option<String>> {
    let records = dns.txt(domain).await??;
    let spf_records: Vec<&String> = records
        .iter()
        .filter(|txt| txt.starts_with("v=spf1 ") || txt.as_str() == "v=spf1")
        .collect();
    match spf_records.len() {
        0 => Ok(None),
        1 => Ok(Some(spf_records[0].clone())),
        // RFC 7208 §3.2: multiple SPF records are permerror.
        _ => Err(crate::error::SmtpError::Dns(format!(
            "multiple SPF records published for {domain} (RFC 7208 §3.2 permerror)"
        ))),
    }
}

/// Evaluate one SPF record's terms left-to-right (RFC 7208 §4.6.2).
fn evaluate_record<'a>(
    dns: &'a dyn AuthDnsSource,
    record: &'a str,
    ip: IpAddr,
    domain: &'a str,
    budget: &'a LookupBudget,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfVerdict> + Send + 'a>> {
    Box::pin(async move {
        let budget = budget.clone();
        let terms: Vec<&str> = record.split_whitespace().skip(1).collect();
        let mut redirect: Option<&str> = None;

        for term in terms {
            let (qualifier, mechanism) = match term.chars().next() {
                Some('+') => (SpfVerdict::Pass, &term[1..]),
                Some('-') => (SpfVerdict::Fail, &term[1..]),
                Some('~') => (SpfVerdict::SoftFail, &term[1..]),
                Some('?') => (SpfVerdict::Neutral, &term[1..]),
                _ => (SpfVerdict::Pass, term),
            };

            // redirect= is a modifier, evaluated only when no mechanism matched.
            if let Some(target) = mechanism.strip_prefix("redirect=") {
                if redirect.is_none() {
                    redirect = Some(target);
                }
                continue;
            }

            let matched = if mechanism == "all" {
                true
            } else if let Some(cidr) = mechanism.strip_prefix("ip4:") {
                match_ip4(ip, cidr)
            } else if let Some(cidr) = mechanism.strip_prefix("ip6:") {
                match_ip6(ip, cidr)
            } else if mechanism == "a" || mechanism.starts_with("a:") || mechanism.starts_with("a/")
            {
                // Issue #121 F1: a DNS failure during the mechanism lookup
                // produces TempError (not a silent no-match that combined
                // with -all would produce Fail).
                if !budget.charge() {
                    return SpfVerdict::PermError;
                }
                let target = mechanism
                    .strip_prefix("a:")
                    .unwrap_or(domain)
                    .split('/')
                    .next()
                    .unwrap_or(domain);
                match match_a(dns, ip, target).await {
                    Ok(matched) => matched,
                    Err(_) => return SpfVerdict::TempError,
                }
            } else if mechanism == "mx" || mechanism.starts_with("mx:") {
                // RFC 7208 §5.6.4: resolve the domain's MX hosts, then the
                // A/AAAA of each host (issue #116 F4). Issue #121 F2: bound
                // the number of MX hosts evaluated to MX_HOST_LIMIT.
                if !budget.charge() {
                    return SpfVerdict::PermError;
                }
                let target = mechanism
                    .strip_prefix("mx:")
                    .unwrap_or(domain)
                    .split('/')
                    .next()
                    .unwrap_or(domain);
                // Issue #124 F3: the mx mechanism counts as ONE term
                // against the DNS lookup budget (RFC 7208 §4.6.4).
                if !budget.charge() {
                    return SpfVerdict::PermError;
                }
                match match_mx(dns, ip, target).await {
                    Ok(matched) => matched,
                    Err(_) => return SpfVerdict::TempError,
                }
            } else if let Some(include_domain) = mechanism.strip_prefix("include:") {
                // Issue #121 F6: include: propagates permerror from
                // multiple-records (the old catch-all treated it as
                // no-match).
                if !budget.charge() {
                    return SpfVerdict::PermError;
                }
                match match_include(dns, ip, include_domain, &budget).await {
                    Ok(matched) => matched,
                    Err(verdict) => return verdict,
                }
            } else {
                // Unknown mechanism: RFC 7208 §6.2 says permerror.
                return SpfVerdict::PermError;
            };

            if matched {
                return qualifier;
            }
        }

        // No mechanism matched: evaluate redirect= (RFC 7208 §6.1), else neutral.
        if let Some(target) = redirect {
            if !budget.charge() {
                return SpfVerdict::PermError;
            }
            match spf_record(dns, target).await {
                Ok(Some(record)) => {
                    return Box::pin(evaluate_record(dns, &record, ip, target, &budget)).await;
                }
                Ok(None) => {
                    // redirect target without an SPF record: permerror.
                    return SpfVerdict::PermError;
                }
                // DNS failure during redirect: temperror (issue #116 F1),
                // unless the error is the multiple-records marker.
                Err(error) => {
                    return if is_multiple_records_error(&error) {
                        SpfVerdict::PermError
                    } else {
                        SpfVerdict::TempError
                    };
                }
            }
        }
        SpfVerdict::Neutral
    })
}

fn match_ip4(ip: IpAddr, cidr: &str) -> bool {
    let IpAddr::V4(peer) = ip else { return false };
    if let Some((addr_str, len_str)) = cidr.split_once('/') {
        let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let Ok(len) = len_str.parse::<u32>() else {
            return false;
        };
        if len > 32 {
            return false;
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        (u32::from(peer) & mask) == (u32::from(addr) & mask)
    } else {
        cidr.parse::<std::net::Ipv4Addr>()
            .map(|a| a == peer)
            .unwrap_or(false)
    }
}

fn match_ip6(ip: IpAddr, cidr: &str) -> bool {
    let IpAddr::V6(peer) = ip else { return false };
    if let Some((addr_str, len_str)) = cidr.split_once('/') {
        let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        let Ok(len) = len_str.parse::<u32>() else {
            return false;
        };
        if len > 128 {
            return false;
        }
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - len)
        };
        (u128::from(peer) & mask) == (u128::from(addr) & mask)
    } else {
        cidr.parse::<std::net::Ipv6Addr>()
            .map(|a| a == peer)
            .unwrap_or(false)
    }
}

/// `a` mechanism: any A/AAAA record of `target` matches the connecting IP.
/// Returns `Err` on DNS failure (issue #121 F1: the caller maps it to
/// TempError, not a silent no-match).
async fn match_a(
    dns: &dyn AuthDnsSource,
    ip: IpAddr,
    target: &str,
) -> Result<bool, crate::error::SmtpError> {
    match ip {
        IpAddr::V4(peer) => match dns.a(target).await {
            Ok(Ok(addrs)) => Ok(addrs.contains(&peer)),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(error),
        },
        IpAddr::V6(peer) => match dns.aaaa(target).await {
            Ok(Ok(addrs)) => Ok(addrs.contains(&peer)),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(error),
        },
    }
}

/// `mx` mechanism: any A/AAAA record of any MX host of `target` matches
/// (RFC 7208 §5.6.4, issue #116 F4). Issue #121 F2: at most
/// MX_HOST_LIMIT hosts are evaluated; issue #121 F1: DNS failures
/// propagate as Err (the caller maps to TempError).
async fn match_mx(
    dns: &dyn AuthDnsSource,
    ip: IpAddr,
    target: &str,
) -> Result<bool, crate::error::SmtpError> {
    let mx_hosts = match dns.mx(target).await {
        Ok(Ok(hosts)) => hosts,
        Ok(Err(error)) => return Err(error),
        Err(error) => return Err(error),
    };
    // Issue #124 F3: the mx mechanism counts as ONE term against the DNS
    // lookup budget (RFC 7208 §4.6.4), not 1+N. The per-host A/AAAA lookups
    // are bounded separately by MX_HOST_LIMIT (issue #121 F2).
    for host in mx_hosts.iter().take(MX_HOST_LIMIT) {
        match match_a(dns, ip, host).await {
            Ok(true) => return Ok(true),
            Ok(false) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// `include:` mechanism: recursive check of `include_domain`.
/// Issue #121 F6: permerror from multiple-records propagates (the old
/// catch-all treated it as no-match).
async fn match_include(
    dns: &dyn AuthDnsSource,
    ip: IpAddr,
    include_domain: &str,
    budget: &LookupBudget,
) -> Result<bool, SpfVerdict> {
    match spf_record(dns, include_domain).await {
        Ok(Some(record)) => {
            let verdict = Box::pin(evaluate_record(dns, &record, ip, include_domain, budget)).await;
            match verdict {
                SpfVerdict::Pass => Ok(true),
                // Issue #121 F6: permerror and temperror propagate up
                // instead of being swallowed as no-match.
                SpfVerdict::PermError => Err(SpfVerdict::PermError),
                SpfVerdict::TempError => Err(SpfVerdict::TempError),
                _ => Ok(false),
            }
        }
        Ok(None) => Ok(false),
        Err(error) => {
            if is_multiple_records_error(&error) {
                Err(SpfVerdict::PermError)
            } else {
                Err(SpfVerdict::TempError)
            }
        }
    }
}

/// Classify a DNS error as the multiple-SPF-records permerror marker.
/// Issue #124 F5: a single helper centralizes the classification so a
/// format change only needs one fix (the old string matching was
/// scattered across four call sites).
fn is_multiple_records_error(error: &crate::error::SmtpError) -> bool {
    error.to_string().contains("multiple SPF")
}
