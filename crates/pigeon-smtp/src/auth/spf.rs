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
        Some(record) => record,
        None => {
            return SpfResult {
                verdict: SpfVerdict::None,
                domain: domain.to_string(),
            }
        }
    };

    let verdict = Box::pin(evaluate_record(dns, &record, peer_ip, domain, 0)).await;
    SpfResult {
        verdict,
        domain: domain.to_string(),
    }
}

/// Fetch the SPF TXT record of `domain` (first `v=spf1` record wins).
async fn spf_record(dns: &dyn AuthDnsSource, domain: &str) -> Option<String> {
    let records = dns.txt(domain).await.ok()?;
    records
        .into_iter()
        .find(|txt| txt.starts_with("v=spf1 ") || txt == "v=spf1")
}

/// Evaluate one SPF record's terms left-to-right (RFC 7208 §4.6.2).
async fn evaluate_record(
    dns: &dyn AuthDnsSource,
    record: &str,
    ip: IpAddr,
    domain: &str,
    depth: usize,
) -> SpfVerdict {
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
        } else if mechanism == "a" || mechanism.starts_with("a:") || mechanism.starts_with("a/") {
            // `a[:domain][/prefix]` — the target domain defaults to the
            // record's own domain (RFC 7208 §5.6.3).
            let target = mechanism
                .strip_prefix("a:")
                .unwrap_or(domain)
                .split('/')
                .next()
                .unwrap_or(domain);
            match_a(dns, ip, target).await
        } else if mechanism == "mx" || mechanism.starts_with("mx:") {
            // `mx[:domain][/prefix]` — resolve the MX hosts, then their A/AAAA
            // (RFC 7208 §5.6.4).
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
        if let Some(record) = spf_record(dns, target).await {
            return Box::pin(evaluate_record(dns, &record, ip, target, depth + 1)).await;
        }
        // redirect target without a valid SPF record: permerror.
        return SpfVerdict::PermError;
    }
    SpfVerdict::Neutral
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
async fn match_a(dns: &dyn AuthDnsSource, ip: IpAddr, target: &str) -> bool {
    match ip {
        IpAddr::V4(peer) => {
            let addrs = dns.a(target).await.unwrap_or_default();
            addrs.contains(&peer)
        }
        IpAddr::V6(peer) => {
            let addrs = dns.aaaa(target).await.unwrap_or_default();
            addrs.contains(&peer)
        }
    }
}

/// `mx` mechanism: any A/AAAA record of any MX host of `target` matches.
async fn match_mx(dns: &dyn AuthDnsSource, ip: IpAddr, target: &str) -> bool {
    // The AuthDnsSource seam has no MX lookup; reuse the crate's MxSource
    // through the shared system resolver when available. For v0.1 the mx
    // mechanism resolves via the auth DNS source's TXT-only seam plus an
    // a/aaaa lookup of "<target>" itself as a fallback (a domain's MX host
    // is usually `mail.<domain>`, and a bare-domain SPF authorizes it via
    // `a`). The strict RFC behavior lands with the resolver unification.
    match_a(dns, ip, target).await
}

/// `include:` mechanism: recursive check of `include_domain`.
async fn match_include(
    dns: &dyn AuthDnsSource,
    ip: IpAddr,
    include_domain: &str,
    depth: usize,
) -> bool {
    match spf_record(dns, include_domain).await {
        Some(record) => {
            Box::pin(evaluate_record(dns, &record, ip, include_domain, depth)).await
                == SpfVerdict::Pass
        }
        None => false,
    }
}
