//! DMARC policy evaluation (RFC 7489).
//!
//! DMARC builds on SPF and DKIM: it checks whether either authenticated
//! domain **aligns** with the From: header domain, and applies the published
//! policy (`none`, `quarantine`, `reject`). In v0.1 the policy is recorded
//! and surfaced, not enforced — enforcement is a config flag that ships off.

use super::spf::SpfResult;
use super::DkimSummary;

/// DMARC evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    pub verdict: DmarcVerdict,
    /// The From: header domain the policy was evaluated against.
    pub from_domain: String,
    /// The policy that was published (`none`, `quarantine`, `reject`).
    pub policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcVerdict {
    Pass,
    Fail,
    None,
    TempError,
    PermError,
}

impl DmarcVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            DmarcVerdict::Pass => "pass",
            DmarcVerdict::Fail => "fail",
            DmarcVerdict::None => "none",
            DmarcVerdict::TempError => "temperror",
            DmarcVerdict::PermError => "permerror",
        }
    }
}

impl DmarcResult {
    pub fn as_str(&self) -> &'static str {
        self.verdict.as_str()
    }
}

/// Evaluate DMARC for the From: domain given the SPF and DKIM results.
pub fn evaluate(
    dns_txt: &dyn Fn(&str) -> Option<String>,
    spf: &SpfResult,
    dkim: &DkimSummary,
    from_domain: &str,
) -> DmarcResult {
    if from_domain.is_empty() {
        return DmarcResult {
            verdict: DmarcVerdict::None,
            from_domain: from_domain.to_string(),
            policy: "none".to_string(),
        };
    }

    // Resolve the DMARC record.
    // RFC 7489 §6.6.3: look up _dmarc.<from-domain> first; if not found,
    // fall back to the organizational domain (the last two labels).
    let record = dns_txt(&format!("_dmarc.{from_domain}.")).or_else(|| {
        let org_domain = organizational_domain(from_domain);
        if org_domain != from_domain {
            dns_txt(&format!("_dmarc.{org_domain}."))
        } else {
            None
        }
    });
    let Some(record) = record else {
        return DmarcResult {
            verdict: DmarcVerdict::None,
            from_domain: from_domain.to_string(),
            policy: "none".to_string(),
        };
    };
    if !record.starts_with("v=DMARC1") {
        return DmarcResult {
            verdict: DmarcVerdict::PermError,
            from_domain: from_domain.to_string(),
            policy: "none".to_string(),
        };
    }

    // Parse the policy tag.
    let policy = record
        .split(';')
        .find_map(|tag| {
            let tag = tag.trim();
            tag.strip_prefix("p=")
        })
        .unwrap_or("none")
        .to_string();

    // Alignment check (RFC 7489 §3.1): relaxed mode by default.
    // SPF aligns when the SPF-passing domain is the same or a parent of
    // the From: domain. DKIM aligns when the `d=` domain is the same or
    // a parent of the From: domain.
    let spf_aligned =
        spf.verdict == super::spf::SpfVerdict::Pass && domains_align(&spf.domain, from_domain);
    let dkim_aligned = matches!(dkim, DkimSummary::Pass(domains) if domains.iter().any(|d| domains_align(d, from_domain)));

    let verdict = if spf_aligned || dkim_aligned {
        DmarcVerdict::Pass
    } else {
        DmarcVerdict::Fail
    };

    DmarcResult {
        verdict,
        from_domain: from_domain.to_string(),
        policy,
    }
}

/// RFC 7489 relaxed alignment: `auth_domain` equals `from_domain` or is a
/// subdomain of it (or `from_domain` is a subdomain of `auth_domain`).
fn domains_align(auth_domain: &str, from_domain: &str) -> bool {
    if auth_domain.eq_ignore_ascii_case(from_domain) {
        return true;
    }
    // Subdomain check: the From: domain ends with `.auth_domain`.
    from_domain
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", auth_domain.to_ascii_lowercase()))
}

/// The organizational domain (RFC 7489 §3.2): the last two labels of a
/// domain, used as the DMARC fallback when the exact domain has no record.
fn organizational_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() <= 2 {
        domain.to_string()
    } else {
        labels[labels.len() - 2..].join(".")
    }
}
