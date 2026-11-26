//! Inbound authentication: SPF (RFC 7208), DKIM verification (via
//! `pigeon-dkim`), and DMARC policy evaluation (RFC 7489).
//!
//! The evaluation runs after recipient resolution and before storage: the
//! verdicts decorate the stored copy. Enforcement (refusing mail on DMARC
//! `p=reject`) is a config flag that ships off — v0.1 records and surfaces,
//! it does not reject.

#[cfg(test)]
#[path = "tests.rs"]
mod auth_tests;
pub mod dmarc;
pub mod dns;
pub mod runtime;
pub mod spf;

use crate::error::Result;

/// The three authentication verdicts for one inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthVerdicts {
    pub spf: spf::SpfResult,
    pub dkim: DkimSummary,
    pub dmarc: dmarc::DmarcResult,
}

/// DKIM verification outcome: which signatures passed, which failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimSummary {
    /// No `DKIM-Signature` header present, or no signature could be checked.
    None,
    /// At least one signature verified.
    Pass(Vec<String>),
    /// Signatures present but none verified (reasons attached).
    Fail(Vec<String>),
    /// DNS or structural error prevented evaluation.
    TempError(String),
}

impl DkimSummary {
    pub fn as_str(&self) -> &'static str {
        match self {
            DkimSummary::None => "none",
            DkimSummary::Pass(_) => "pass",
            DkimSummary::Fail(_) => "fail",
            DkimSummary::TempError(_) => "temperror",
        }
    }
}

impl Default for AuthVerdicts {
    fn default() -> Self {
        Self {
            spf: spf::SpfResult {
                verdict: spf::SpfVerdict::None,
                domain: String::new(),
            },
            dkim: DkimSummary::None,
            dmarc: dmarc::DmarcResult {
                verdict: dmarc::DmarcVerdict::None,
                from_domain: String::new(),
                policy: "none".to_string(),
            },
        }
    }
}

impl AuthVerdicts {
    /// The `Authentication-Results` header value (RFC 8601, simplified).
    pub fn authentication_results(&self, hostname: &str) -> String {
        let spf_part = format!(
            "spf={} smtp.mailfrom={}",
            self.spf.as_str(),
            self.spf.domain
        );
        let dkim_part = match &self.dkim {
            DkimSummary::None => "dkim=none".to_string(),
            DkimSummary::Pass(domains) => format!("dkim=pass header.d={}", domains.join(" ")),
            DkimSummary::Fail(_) => "dkim=fail".to_string(),
            DkimSummary::TempError(_) => "dkim=temperror".to_string(),
        };
        let dmarc_part = format!(
            "dmarc={} header.from={}",
            self.dmarc.as_str(),
            self.dmarc.from_domain
        );
        format!("{hostname}; {spf_part}; {dkim_part}; {dmarc_part}")
    }

    /// The compact event detail: `auth=spf:pass,dkim:pass,dmarc:pass`.
    pub fn event_detail(&self) -> String {
        format!(
            "auth=spf:{},dkim:{},dmarc:{}",
            self.spf.as_str(),
            self.dkim.as_str(),
            self.dmarc.as_str()
        )
    }
}

/// Evaluate all three checks for one inbound message.
///
/// `dns` is the authentication DNS source (TXT for SPF/DMARC/DKIM keys, A and
/// AAAA for the SPF `a`/`mx` mechanisms). `peer_ip` is the connecting IP from
/// `envelope.peer`. `mail_from_domain` is the envelope sender's domain.
/// `parsed` is the parsed message (headers for DKIM, body for hashing).
pub fn evaluate(
    dns: &dyn dns::AuthDnsSource,
    peer_ip: std::net::IpAddr,
    mail_from_domain: &str,
    parsed: &crate::server::ParsedMessage,
) -> Result<AuthVerdicts> {
    // SPF: check the envelope sender's domain against the connecting IP.
    let spf_result = spf::check(dns, peer_ip, mail_from_domain);

    // DKIM: verify every DKIM-Signature header against the message.
    let dkim_result = verify_dkim(dns, parsed);

    // DMARC: evaluate alignment and policy for the From: domain.
    let from_domain = parsed
        .addresses("From")
        .first()
        .map(|addr| addr.domain().to_string())
        .unwrap_or_default();
    let dmarc_result = dmarc::evaluate(dns, &spf_result, &dkim_result, &from_domain);

    Ok(AuthVerdicts {
        spf: spf_result,
        dkim: dkim_result,
        dmarc: dmarc_result,
    })
}

/// Verify all DKIM-Signature headers on the message.
pub(crate) fn verify_dkim(
    dns: &dyn dns::AuthDnsSource,
    parsed: &crate::server::ParsedMessage,
) -> DkimSummary {
    let signatures: Vec<&(String, String)> = parsed
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
        .collect();
    if signatures.is_empty() {
        return DkimSummary::None;
    }

    // DKIM body hashing is byte-exact (RFC 6376 §3.7): the canonicalization
    // in pigeon-dkim operates on UTF-8 text, so a body with invalid UTF-8
    // sequences cannot be verified without corrupting it via lossy
    // conversion (issue #111 F3). Skip those signatures rather than report
    // a false fail — the body hash would never match the corrupted bytes.
    let Ok(body) = std::str::from_utf8(&parsed.body) else {
        return DkimSummary::TempError(
            "body is not valid UTF-8; DKIM verification requires byte-exact \
             canonicalization and is not attempted"
                .to_string(),
        );
    };

    let mut passed_domains = Vec::new();
    let mut failures = Vec::new();
    let mut skipped = 0usize;

    for (_, value) in &signatures {
        // Resolve the DKIM key through the auth DNS source (blocking on the
        // async resolver from this synchronous caller context).
        let key = self::runtime::block_on_any(async {
            let selector = value
                .split("s=")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
                .unwrap_or_default()
                .trim()
                .to_string();
            let domain_tag = value
                .split("d=")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
                .unwrap_or_default()
                .trim()
                .to_string();
            if selector.is_empty() || domain_tag.is_empty() {
                return None;
            }
            let name = format!("{selector}._domainkey.{domain_tag}.");
            dns.txt(&name).await.ok()
        })
        .and_then(|records| records.into_iter().next());

        let Some(key_record) = key else {
            // No key published: the signature cannot be checked — skip it
            // rather than report a false fail (issue #109 R3 fix, kept).
            skipped += 1;
            continue;
        };

        match pigeon_dkim::verify::verify_message(value, &parsed.headers, body, |_| {
            Some(key_record.clone())
        }) {
            Ok(result) => {
                if result.passed {
                    passed_domains.push(result.domain.clone());
                } else {
                    failures.push(
                        result
                            .reason
                            .clone()
                            .unwrap_or_else(|| "verification failed".to_string()),
                    );
                }
            }
            Err(_) => {
                // Structural errors in the signature header itself.
                failures.push("malformed DKIM-Signature header".to_string());
            }
        }
    }

    if !passed_domains.is_empty() {
        DkimSummary::Pass(passed_domains)
    } else if failures.is_empty() {
        // All signatures were skipped (no key published for any): report
        // "none" rather than "fail" — we could not check, we did not fail.
        DkimSummary::None
    } else if skipped == signatures.len() {
        DkimSummary::None
    } else {
        DkimSummary::Fail(failures)
    }
}
