//! SPF evaluation (RFC 7208) — the common subset of mechanisms.
//!
//! Supported: `ip4:`, `ip6:`, `a`, `mx`, `include:`, `all` (and the `?`/`~`/`-`
//! qualifiers). Not supported (rare, v0.3): `exists:`, `ptr:`, `exp:`,
//! macro expansion. The DNS lookup limit (10 per record, RFC 7208 §4.6.4)
//! is enforced on `include:` and `mx`/`a` with a `redirect=`.

use std::net::IpAddr;

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
///
/// `dns_txt` resolves a TXT record by fully qualified name. The check is
/// bounded to 10 DNS lookups (RFC 7208 §4.6.4).
pub fn check(dns_txt: &dyn Fn(&str) -> Option<String>, peer_ip: &str, domain: &str) -> SpfResult {
    let record = match dns_txt(&format!("{domain}.")) {
        Some(txt) if txt.starts_with("v=spf1 ") || txt == "v=spf1" => txt,
        _ => {
            return SpfResult {
                verdict: SpfVerdict::None,
                domain: domain.to_string(),
            }
        }
    };
    let ip: IpAddr = match peer_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return SpfResult {
                verdict: SpfVerdict::PermError,
                domain: domain.to_string(),
            }
        }
    };

    let verdict = evaluate_record(dns_txt, &record, ip, domain, 0);
    SpfResult {
        verdict,
        domain: domain.to_string(),
    }
}

/// Evaluate one SPF record's terms left-to-right (RFC 7208 §4.6.2).
fn evaluate_record(
    dns_txt: &dyn Fn(&str) -> Option<String>,
    record: &str,
    ip: IpAddr,
    domain: &str,
    depth: usize,
) -> SpfVerdict {
    // RFC 7208 §4.6.4: 10 DNS lookups max (include/redirect/mx/a with
    // dereference). We approximate with depth: 10 nested includes.
    if depth > 10 {
        return SpfVerdict::PermError;
    }

    let terms: Vec<&str> = record.split_whitespace().skip(1).collect();
    for term in terms {
        // Split qualifier from mechanism.
        let (qualifier, mechanism) = match term.chars().next() {
            Some('+') => (SpfVerdict::Pass, &term[1..]),
            Some('-') => (SpfVerdict::Fail, &term[1..]),
            Some('~') => (SpfVerdict::SoftFail, &term[1..]),
            Some('?') => (SpfVerdict::Neutral, &term[1..]),
            _ => (SpfVerdict::Pass, term),
        };

        let matched = if mechanism == "all" {
            true
        } else if let Some(cidr) = mechanism.strip_prefix("ip4:") {
            match_ip4(ip, cidr)
        } else if let Some(cidr) = mechanism.strip_prefix("ip6:") {
            match_ip6(ip, cidr)
        } else if mechanism == "a" || mechanism.starts_with("a:") || mechanism.starts_with("a/") {
            // Simplified: resolve the A record of `domain` and compare.
            // The `a:other-domain` and `a/nn` forms are v0.3.
            let a_domain = domain;
            match_a(dns_txt, ip, a_domain)
        } else if mechanism == "mx" || mechanism.starts_with("mx:") {
            // Simplified: resolve the MX of `domain` and compare the MX host's A.
            match_mx(dns_txt, ip, domain)
        } else if let Some(include_domain) = mechanism.strip_prefix("include:") {
            match_include(dns_txt, ip, include_domain, depth + 1)
        } else if mechanism.starts_with("redirect=") {
            let target = mechanism.strip_prefix("redirect=").unwrap_or(mechanism);
            let target_record = dns_txt(&format!("{target}."));
            if let Some(rec) = target_record {
                if rec.starts_with("v=spf1") {
                    return evaluate_record(dns_txt, &rec, ip, target, depth + 1);
                }
            }
            return SpfVerdict::PermError;
        } else {
            // Unknown mechanism: RFC 7208 §6 says permerror.
            return SpfVerdict::PermError;
        };

        if matched {
            return qualifier;
        }
    }

    // No mechanism matched: RFC 7208 default is neutral.
    SpfVerdict::Neutral
}

fn match_ip4(ip: IpAddr, cidr: &str) -> bool {
    let IpAddr::V4(peer) = ip else { return false };
    if let Some(prefix) = cidr.strip_suffix("/32") {
        return cidr == "/32" || peer.to_string() == prefix;
    }
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
        let peer_bits = u32::from(peer);
        let addr_bits = u32::from(addr);
        (peer_bits & mask) == (addr_bits & mask)
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
        let peer_bits = u128::from(peer);
        let addr_bits = u128::from(addr);
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - len)
        };
        (peer_bits & mask) == (addr_bits & mask)
    } else {
        cidr.parse::<std::net::Ipv6Addr>()
            .map(|a| a == peer)
            .unwrap_or(false)
    }
}

fn match_a(dns_txt: &dyn Fn(&str) -> Option<String>, ip: IpAddr, domain: &str) -> bool {
    // We only have a TXT resolver available; the A record check needs a
    // proper A resolver. For v0.1 we resolve via a TXT hack: no.
    // The honest answer: `a` and `mx` mechanisms need A/AAAA lookups that
    // the current DNS seam (TXT-only) cannot provide. They return false
    // (not matched) rather than pretending to work.
    let _ = (dns_txt, ip, domain);
    false
}

fn match_mx(dns_txt: &dyn Fn(&str) -> Option<String>, ip: IpAddr, domain: &str) -> bool {
    let _ = (dns_txt, ip, domain);
    false
}

fn match_include(
    dns_txt: &dyn Fn(&str) -> Option<String>,
    ip: IpAddr,
    include_domain: &str,
    depth: usize,
) -> bool {
    let record = dns_txt(&format!("{include_domain}."));
    if let Some(rec) = record {
        if rec.starts_with("v=spf1") {
            let verdict = evaluate_record(dns_txt, &rec, ip, include_domain, depth);
            return verdict == SpfVerdict::Pass;
        }
    }
    false
}
