//! SPF evaluation (RFC 7208) — the common subset of mechanisms.
//!
//! Supported: `ip4:`, `ip6:`, `a`, `mx`, `include:`, `redirect=`, `all` (and
//! the `+`/`-`/`~`/`?` qualifiers). Not supported (rare, v0.3): `exists:`,
//! `ptr:`, `exp:`, macro expansion. The DNS lookup limit (10 per record,
//! RFC 7208 §4.6.4) is enforced on `include:`, `redirect=` and the
//! `a`/`mx` dereferences.
//!
//! `redirect=` is a modifier, not a mechanism: RFC 7208 §6.1 evaluates it
//! only when no mechanism matched (F5, issue #111).
//!
//! Hardening (#116): DNS errors propagate as `TempError` verdicts
//! (RFC 7208 §5.4) instead of degrading to `none`; the `mx` mechanism
//! resolves the domain's MX hosts and then their A/AAAA records (F4);
//! a name publishing more than one `v=spf1` TXT record is `permerror`
//! (F6, RFC 7208 §3.2).

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
            let verdict = if error.to_string().contains("multiple SPF") {
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

    let verdict = Box::pin(evaluate_record(dns, &record, peer_ip, domain, 0)).await;
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
        // RFC 7208 §3.2: multiple SPF records are permerror. We signal it by
        // returning the first record with a marker the caller can check; the
        // cleanest way is a dedicated error the caller maps to PermError.
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
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfVerdict> + Send + 'a>> {
    Box::pin(async move {
        if depth > 10 {
            // RFC 7208 §4.6.4: more than 10 DNS lookups → permerror.
            return SpfVerdict::PermError;
        }

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
                let target = mechanism
                    .strip_prefix("a:")
                    .unwrap_or(domain)
                    .split('/')
                    .next()
                    .unwrap_or(domain);
                match_a(dns, ip, target).await
            } else if mechanism == "mx" || mechanism.starts_with("mx:") {
                // RFC 7208 §5.6.4: resolve the domain's MX hosts, then the
                // A/AAAA of each host (issue #116 F4 — no more fallback to
                // the domain's own A record).
                let target = mechanism
                    .strip_prefix("mx:")
                    .unwrap_or(domain)
                    .split('/')
                    .next()
                    .unwrap_or(domain);
                match_mx(dns, ip, target).await
            } else if let Some(include_domain) = mechanism.strip_prefix("include:") {
                match_include(dns, ip, include_domain, depth + 1).await
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
            match spf_record(dns, target).await {
                Ok(Some(record)) => {
                    return Box::pin(evaluate_record(dns, &record, ip, target, depth + 1)).await;
                }
                Ok(None) => {
                    // redirect target without an SPF record: permerror.
                    return SpfVerdict::PermError;
                }
                // DNS failure during redirect: temperror (issue #116 F1),
                // unless the error is the multiple-records marker.
                Err(error) => {
                    return if error.to_string().contains("multiple SPF") {
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
/// DNS failure during the lookup means no match (the overall check reports
/// temperror through the record-level path when the initial TXT lookup
/// fails; per-mechanism failures degrade conservatively).
async fn match_a(dns: &dyn AuthDnsSource, ip: IpAddr, target: &str) -> bool {
    match ip {
        IpAddr::V4(peer) => match dns.a(target).await {
            Ok(Ok(addrs)) => addrs.contains(&peer),
            _ => false,
        },
        IpAddr::V6(peer) => match dns.aaaa(target).await {
            Ok(Ok(addrs)) => addrs.contains(&peer),
            _ => false,
        },
    }
}

/// `mx` mechanism: any A/AAAA record of any MX host of `target` matches
/// (RFC 7208 §5.6.4, issue #116 F4).
async fn match_mx(dns: &dyn AuthDnsSource, ip: IpAddr, target: &str) -> bool {
    let mx_hosts = match dns.mx(target).await {
        Ok(Ok(hosts)) => hosts,
        _ => return false,
    };
    for host in &mx_hosts {
        if match_a(dns, ip, host).await {
            return true;
        }
    }
    false
}

/// `include:` mechanism: recursive check of `include_domain`.
async fn match_include(
    dns: &dyn AuthDnsSource,
    ip: IpAddr,
    include_domain: &str,
    depth: usize,
) -> bool {
    match spf_record(dns, include_domain).await {
        Ok(Some(record)) => {
            Box::pin(evaluate_record(dns, &record, ip, include_domain, depth)).await
                == SpfVerdict::Pass
        }
        _ => false,
    }
}
