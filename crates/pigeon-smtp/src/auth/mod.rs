//! Inbound authentication: SPF (RFC 7208), DKIM verification (via
//! `pigeon-dkim`), and DMARC policy evaluation (RFC 7489).
//!
//! The evaluation runs after recipient resolution and before storage: the
//! verdicts decorate the stored copy. Enforcement (refusing mail on DMARC
//! `p=reject`) is a config flag that ships off — v0.1 records and surfaces,
//! it does not reject.

pub mod dmarc;
pub mod spf;
#[cfg(test)]
mod tests;

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
    /// No `DKIM-Signature` header present.
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

/// Evaluate all three checks for one inbound message.
///
/// `dns_txt` resolves a TXT record by fully qualified name (the SPF record,
/// the DKIM key, the DMARC policy). `peer_ip` is the connecting IP from
/// `envelope.peer`. `mail_from` is the envelope sender. `from_header` is the
/// parsed `From:` header address.
pub fn evaluate(
    dns_txt: &dyn Fn(&str) -> Option<String>,
    peer_ip: &str,
    mail_from_domain: &str,
    from_header: &crate::server::ParsedMessage,
) -> Result<AuthVerdicts> {
    // SPF: check the envelope sender's domain against the connecting IP.
    let spf_result = spf::check(dns_txt, peer_ip, mail_from_domain);

    // DKIM: verify every DKIM-Signature header against the message.
    let dkim_result = verify_dkim(dns_txt, from_header);

    // DMARC: evaluate alignment and policy for the From: domain.
    let from_domain = from_header
        .addresses("From")
        .first()
        .map(|addr| addr.domain().to_string())
        .unwrap_or_default();
    let dmarc_result = dmarc::evaluate(dns_txt, &spf_result, &dkim_result, &from_domain);

    Ok(AuthVerdicts {
        spf: spf_result,
        dkim: dkim_result,
        dmarc: dmarc_result,
    })
}

/// Verify all DKIM-Signature headers on the message.
fn verify_dkim(
    dns_txt: &dyn Fn(&str) -> Option<String>,
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

    let body = String::from_utf8_lossy(&parsed.body).to_string();
    let mut passed_domains = Vec::new();
    let mut failures = Vec::new();

    for (_, value) in &signatures {
        match pigeon_dkim::verify::verify_message(value, &parsed.headers, &body, |name| {
            dns_txt(name)
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
            Err(error) => {
                // Key-resolution failures (no key published, DNS unreachable)
                // are not signature failures: skip the signature rather than
                // reporting a false "fail" verdict. Only crypto mismatches
                // (Ok(passed=false)) are real failures (issue #109 R3).
                let msg = error.to_string();
                if !msg.contains("no key") && !msg.contains("DNS") {
                    failures.push(msg);
                }
            }
        }
    }

    if !passed_domains.is_empty() {
        DkimSummary::Pass(passed_domains)
    } else if failures.is_empty() {
        // All signatures were skipped (no key published for any): report
        // "none" rather than "fail" — we could not check, we did not fail.
        DkimSummary::None
    } else {
        DkimSummary::Fail(failures)
    }
}
