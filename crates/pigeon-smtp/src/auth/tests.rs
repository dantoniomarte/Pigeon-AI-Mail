//! Unit tests for the inbound authentication module (issue #109, extended
//! by #111: SPF a/mx mechanisms, redirect ordering, DKIM key resolution).

#[cfg(test)]
mod tests_inner {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use crate::auth::dmarc::{self, DmarcResult, DmarcVerdict};
    use crate::auth::dns::AuthDnsSource;
    use crate::auth::spf::{self, SpfResult, SpfVerdict};
    use crate::auth::{AuthVerdicts, DkimSummary};
    use crate::dns::LookupFuture;

    /// Fake DNS source: maps names to record sets.
    struct FakeDns {
        txt: HashMap<String, Vec<String>>,
        a: HashMap<String, Vec<Ipv4Addr>>,
        aaaa: HashMap<String, Vec<Ipv6Addr>>,
        mx: HashMap<String, Vec<String>>,
    }

    impl FakeDns {
        fn new() -> Self {
            Self {
                txt: HashMap::new(),
                a: HashMap::new(),
                aaaa: HashMap::new(),
                mx: HashMap::new(),
            }
        }

        fn with_txt(mut self, name: &str, records: &[&str]) -> Self {
            self.txt.insert(
                name.to_string(),
                records.iter().map(|s| s.to_string()).collect(),
            );
            self
        }

        fn with_mx(mut self, name: &str, hosts: &[&str]) -> Self {
            self.mx.insert(
                name.to_string(),
                hosts.iter().map(|s| s.to_string()).collect(),
            );
            self
        }

        fn with_a(mut self, name: &str, addrs: &[&str]) -> Self {
            self.a.insert(
                name.to_string(),
                addrs.iter().map(|s| s.parse().expect("ipv4")).collect(),
            );
            self
        }
    }

    impl AuthDnsSource for FakeDns {
        fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>> {
            let key = name.trim_end_matches('.').to_string();
            let records = self.txt.get(&key).cloned().unwrap_or_default();
            Box::pin(async move { Ok(Ok(records)) })
        }

        fn a<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<Ipv4Addr>>> {
            let key = name.trim_end_matches('.').to_string();
            let records = self.a.get(&key).cloned().unwrap_or_default();
            Box::pin(async move { Ok(Ok(records)) })
        }

        fn aaaa<'a>(
            &'a self,
            name: &'a str,
        ) -> LookupFuture<'a, crate::error::Result<Vec<Ipv6Addr>>> {
            let key = name.trim_end_matches('.').to_string();
            let records = self.aaaa.get(&key).cloned().unwrap_or_default();
            Box::pin(async move { Ok(Ok(records)) })
        }

        fn mx<'a>(&'a self, name: &'a str) -> LookupFuture<'a, crate::error::Result<Vec<String>>> {
            let key = name.trim_end_matches('.').to_string();
            let records = self.mx.get(&key).cloned().unwrap_or_default();
            Box::pin(async move { Ok(Ok(records)) })
        }
    }

    fn block<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    // --- SPF tests ---

    #[test]
    fn spf_pass_when_ip4_matches() {
        let dns = FakeDns::new().with_txt("example.com", &["v=spf1 ip4:192.0.2.1 -all"]);
        let result = block(spf::check_async(
            &dns,
            "192.0.2.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_fail_when_ip4_does_not_match() {
        let dns = FakeDns::new().with_txt("example.com", &["v=spf1 ip4:192.0.2.1 -all"]);
        let result = block(spf::check_async(
            &dns,
            "10.0.0.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Fail);
    }

    #[test]
    fn spf_none_when_no_record() {
        let dns = FakeDns::new();
        let result = block(spf::check_async(
            &dns,
            "192.0.2.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::None);
    }

    #[test]
    fn spf_cidr_prefix_match() {
        let dns = FakeDns::new().with_txt("example.com", &["v=spf1 ip4:192.0.2.0/24 -all"]);
        let result = block(spf::check_async(
            &dns,
            "192.0.2.99".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_softfail_qualifier() {
        let dns = FakeDns::new().with_txt("example.com", &["v=spf1 ip4:192.0.2.1 ~all"]);
        let result = block(spf::check_async(
            &dns,
            "10.0.0.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::SoftFail);
    }

    #[test]
    fn spf_include_pass() {
        let dns = FakeDns::new()
            .with_txt("example.com", &["v=spf1 include:spf.example.net -all"])
            .with_txt("spf.example.net", &["v=spf1 ip4:192.0.2.1 -all"]);
        let result = block(spf::check_async(
            &dns,
            "192.0.2.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    /// Issue #111 F2: the `a` mechanism resolves the domain's A records.
    #[test]
    fn spf_a_mechanism_matches_domain_ip() {
        let dns = FakeDns::new()
            .with_txt("example.com", &["v=spf1 a -all"])
            .with_a("example.com", &["192.0.2.7"]);
        let result = block(spf::check_async(
            &dns,
            "192.0.2.7".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_a_mechanism_fails_other_ip() {
        let dns = FakeDns::new()
            .with_txt("example.com", &["v=spf1 a -all"])
            .with_a("example.com", &["192.0.2.7"]);
        let result = block(spf::check_async(
            &dns,
            "10.0.0.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Fail);
    }

    /// Issue #116 F4: the `mx` mechanism resolves the domain's MX hosts and
    /// then the A/AAAA of each host — no more fallback to the domain's own
    /// A record.
    #[test]
    fn spf_mx_mechanism_matches_the_mx_host_ip() {
        let dns = FakeDns::new()
            .with_txt("example.com", &["v=spf1 mx -all"])
            .with_mx("example.com", &["mx.example.net."])
            .with_a("mx.example.net", &["198.51.100.7"])
            .with_a("example.com", &["203.0.113.99"]);
        let result = block(spf::check_async(
            &dns,
            "198.51.100.7".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_mx_mechanism_does_not_match_the_domain_a_when_mx_differs() {
        let dns = FakeDns::new()
            .with_txt("example.com", &["v=spf1 mx -all"])
            .with_mx("example.com", &["mx.example.net."])
            .with_a("mx.example.net", &["198.51.100.7"])
            .with_a("example.com", &["203.0.113.99"]);
        let result = block(spf::check_async(
            &dns,
            "203.0.113.99".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Fail);
    }

    /// Issue #111 F5: redirect= is evaluated only when no mechanism matched.
    #[test]
    fn spf_redirect_after_mechanism_mismatch_wins() {
        // redirect= before a matching ip4 term: the ip4 term must win.
        let dns = FakeDns::new()
            .with_txt(
                "example.com",
                &["v=spf1 redirect=other.example.net ip4:192.0.2.9 -all"],
            )
            .with_txt("other.example.net", &["v=spf1 ip4:10.0.0.1 -all"]);
        let result = block(spf::check_async(
            &dns,
            "192.0.2.9".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_redirect_evaluated_when_no_mechanism_matched() {
        let dns = FakeDns::new()
            .with_txt(
                "example.com",
                &["v=spf1 ip4:203.0.113.1 redirect=other.example.net"],
            )
            .with_txt("other.example.net", &["v=spf1 ip4:10.0.0.1 -all"]);
        let result = block(spf::check_async(
            &dns,
            "10.0.0.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    // --- DMARC tests ---

    #[test]
    fn dmarc_pass_when_spf_aligned() {
        let dns = FakeDns::new().with_txt("_dmarc.example.com", &["v=DMARC1; p=none"]);
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "example.com"));
        assert_eq!(result.verdict, DmarcVerdict::Pass);
    }

    #[test]
    fn dmarc_fail_when_spf_fail_and_no_dkim() {
        let dns = FakeDns::new().with_txt("_dmarc.example.com", &["v=DMARC1; p=none"]);
        let spf = SpfResult {
            verdict: SpfVerdict::Fail,
            domain: "other.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "example.com"));
        assert_eq!(result.verdict, DmarcVerdict::Fail);
    }

    #[test]
    fn dmarc_none_when_no_record() {
        let dns = FakeDns::new();
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "example.com"));
        assert_eq!(result.verdict, DmarcVerdict::None);
    }

    #[test]
    fn dmarc_pass_when_dkim_aligned() {
        let dns = FakeDns::new().with_txt("_dmarc.example.com", &["v=DMARC1; p=quarantine"]);
        let spf = SpfResult {
            verdict: SpfVerdict::Fail,
            domain: "other.com".to_string(),
        };
        let dkim = DkimSummary::Pass(vec!["example.com".to_string()]);
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "example.com"));
        assert_eq!(result.verdict, DmarcVerdict::Pass);
    }

    #[test]
    fn dmarc_relaxed_alignment_subdomain() {
        // mail.example.com aligns with example.com (relaxed mode).
        let dns = FakeDns::new().with_txt("_dmarc.example.com", &["v=DMARC1; p=none"]);
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "mail.example.com"));
        assert_eq!(result.verdict, DmarcVerdict::Pass);
    }

    /// Issue #111: organizational domain fallback — a From: domain
    /// `sub.example.org` with a DMARC record only at `_dmarc.example.org`.
    #[test]
    fn dmarc_falls_back_to_organizational_domain() {
        let dns = FakeDns::new().with_txt("_dmarc.example.org", &["v=DMARC1; p=reject"]);
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.org".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = block(dmarc::evaluate_async(&dns, &spf, &dkim, "sub.example.org"));
        assert_eq!(result.verdict, DmarcVerdict::Pass);
        assert_eq!(result.policy, "reject");
    }

    // --- DKIM key resolution ---

    /// Issue #111 F1: with a key published in the fake DNS, a signature
    /// verifies (Pass) instead of being skipped (None).
    #[test]
    fn dkim_signature_verifies_when_key_is_published() {
        use crate::auth::verify_dkim;
        use pigeon_dkim::DkimKeyPair;

        let pair = DkimKeyPair::generate("pigeon", "example.com").expect("keypair");
        let message = "From: alice@example.com\r\nSubject: test\r\n\r\nHello.\r\n";

        // sign() takes raw "Name: value" header lines (h= names without
        // the value are parsed from them), plus the body without the final
        // header/body separation.
        let signature = pair
            .sign(&["From: alice@example.com", "Subject: test"], "Hello.\r\n")
            .expect("signature");

        // The public key in DNS TXT form.
        let key_record = pair.public_key_dns_record();
        let dns = FakeDns::new().with_txt("pigeon._domainkey.example.com", &[&key_record]);

        let parsed = crate::server::ParsedMessage {
            headers: vec![
                ("From".to_string(), "alice@example.com".to_string()),
                ("Subject".to_string(), "test".to_string()),
                ("DKIM-Signature".to_string(), signature),
            ],
            body: message
                .rsplit_once("\r\n\r\n")
                .map(|(_, b)| b.as_bytes().to_vec())
                .unwrap_or_default(),
        };
        let summary = verify_dkim(&dns, &parsed);
        // Debug the key lookup path if it skipped everything.
        let sig_debug: Vec<String> = parsed
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("DKIM-Signature"))
            .map(|(_, v)| v.chars().take(120).collect())
            .collect();
        assert!(
            matches!(summary, DkimSummary::Pass(_)),
            "expected pass with published key, got {summary:?} (sig={sig_debug:?})"
        );
    }

    // --- AuthVerdicts formatting ---

    #[test]
    fn authentication_results_header_format() {
        let verdicts = AuthVerdicts {
            spf: SpfResult {
                verdict: SpfVerdict::Pass,
                domain: "example.com".to_string(),
            },
            dkim: DkimSummary::Pass(vec!["example.com".to_string()]),
            dmarc: DmarcResult {
                verdict: DmarcVerdict::Pass,
                from_domain: "example.com".to_string(),
                policy: "none".to_string(),
            },
        };
        let header = verdicts.authentication_results("mail.example.org");
        assert!(header.contains("spf=pass"), "{header}");
        assert!(header.contains("dkim=pass"), "{header}");
        assert!(header.contains("dmarc=pass"), "{header}");
        assert!(header.contains("mail.example.org"), "{header}");
    }

    #[test]
    fn event_detail_format() {
        let verdicts = AuthVerdicts {
            spf: SpfResult {
                verdict: SpfVerdict::Fail,
                domain: "example.com".to_string(),
            },
            dkim: DkimSummary::None,
            dmarc: DmarcResult {
                verdict: DmarcVerdict::Fail,
                from_domain: "example.com".to_string(),
                policy: "none".to_string(),
            },
        };
        let detail = verdicts.event_detail();
        assert_eq!(detail, "auth=spf:fail,dkim:none,dmarc:fail");
    }

    // Silence unused warnings for the Arc/Mutex imports in some builds.
    #[allow(dead_code)]
    fn _unused(_: Arc<Mutex<FakeDns>>) {}

    // --- Issue #116 hardening tests ---

    /// F5: a DKIM-Signature with `t=s` (the timestamp tag) before `s=` must
    /// still resolve the correct selector — the old substring split
    /// matched `s=` inside `t=s` and produced an empty selector.
    #[test]
    fn dkim_tag_parsing_survives_the_timestamp_tag() {
        use crate::auth::parse_dkim_tags;
        // A realistic header with t= before s= (tag order is arbitrary).
        let value = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; t=1700000000; s=pigeon; h=from:subject; bh=abc; b=def";
        let tags = parse_dkim_tags(value);
        assert_eq!(tags.get("s").map(String::as_str), Some("pigeon"));
        assert_eq!(tags.get("d").map(String::as_str), Some("example.com"));
        assert_eq!(tags.get("t").map(String::as_str), Some("1700000000"));
        // The base64 in b= must not confuse the s= lookup either.
        let tricky = "v=1; a=rsa-sha256; b=abcs=def; s=real-selector; d=example.com";
        let tags = parse_dkim_tags(tricky);
        assert_eq!(tags.get("s").map(String::as_str), Some("real-selector"));
    }

    /// F6: a name publishing two `v=spf1` TXT records is permerror
    /// (RFC 7208 §3.2), not a merged record.
    #[test]
    fn spf_multiple_records_are_permerror() {
        let dns = FakeDns::new().with_txt(
            "example.com",
            &["v=spf1 ip4:192.0.2.1 -all", "v=spf1 ip4:198.51.100.1 -all"],
        );
        let result = block(spf::check_async(
            &dns,
            "192.0.2.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::PermError);
    }

    /// F6 (positive): unrelated TXT records (verification tokens) do not
    /// break the SPF lookup — only the `v=spf1` record counts.
    #[test]
    fn spf_ignores_unrelated_txt_records() {
        let dns = FakeDns::new().with_txt(
            "example.com",
            &[
                "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9",
                "v=spf1 ip4:192.0.2.1 -all",
            ],
        );
        let result = block(spf::check_async(
            &dns,
            "192.0.2.1".parse().unwrap(),
            "example.com",
        ));
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }
}
