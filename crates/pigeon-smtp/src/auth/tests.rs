#[cfg(test)]
mod auth_tests {
    use crate::auth::dmarc::{self, DmarcResult, DmarcVerdict};
    use crate::auth::spf::{self, SpfResult, SpfVerdict};
    use crate::auth::{AuthVerdicts, DkimSummary};

    /// A fake DNS that maps fully qualified names to TXT records.
    fn dns<'a>(records: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            records
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name.trim_end_matches('.')))
                .map(|(_, value)| value.to_string())
        }
    }

    // --- SPF tests ---

    #[test]
    fn spf_pass_when_ip4_matches() {
        let records = [("example.com", "v=spf1 ip4:192.0.2.1 -all")];
        let result = spf::check(&dns(&records), "192.0.2.1", "example.com");
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_fail_when_ip4_does_not_match() {
        let records = [("example.com", "v=spf1 ip4:192.0.2.1 -all")];
        let result = spf::check(&dns(&records), "10.0.0.1", "example.com");
        assert_eq!(result.verdict, SpfVerdict::Fail);
    }

    #[test]
    fn spf_none_when_no_record() {
        let records: [(&str, &str); 0] = [];
        let result = spf::check(&dns(&records), "192.0.2.1", "example.com");
        assert_eq!(result.verdict, SpfVerdict::None);
    }

    #[test]
    fn spf_cidr_prefix_match() {
        let records = [("example.com", "v=spf1 ip4:192.0.2.0/24 -all")];
        let result = spf::check(&dns(&records), "192.0.2.99", "example.com");
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    #[test]
    fn spf_softfail_qualifier() {
        let records = [("example.com", "v=spf1 ip4:192.0.2.1 ~all")];
        let result = spf::check(&dns(&records), "10.0.0.1", "example.com");
        assert_eq!(result.verdict, SpfVerdict::SoftFail);
    }

    #[test]
    fn spf_include_pass() {
        let records = [
            ("example.com", "v=spf1 include:spf.example.net -all"),
            ("spf.example.net", "v=spf1 ip4:192.0.2.1 -all"),
        ];
        let result = spf::check(&dns(&records), "192.0.2.1", "example.com");
        assert_eq!(result.verdict, SpfVerdict::Pass);
    }

    // --- DMARC tests ---

    #[test]
    fn dmarc_pass_when_spf_aligned() {
        let records = [("_dmarc.example.com", "v=DMARC1; p=none")];
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = dmarc::evaluate(&dns(&records), &spf, &dkim, "example.com");
        assert_eq!(result.verdict, DmarcVerdict::Pass);
    }

    #[test]
    fn dmarc_fail_when_spf_fail_and_no_dkim() {
        let records = [("_dmarc.example.com", "v=DMARC1; p=none")];
        let spf = SpfResult {
            verdict: SpfVerdict::Fail,
            domain: "other.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = dmarc::evaluate(&dns(&records), &spf, &dkim, "example.com");
        assert_eq!(result.verdict, DmarcVerdict::Fail);
    }

    #[test]
    fn dmarc_none_when_no_record() {
        let records: [(&str, &str); 0] = [];
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = dmarc::evaluate(&dns(&records), &spf, &dkim, "example.com");
        assert_eq!(result.verdict, DmarcVerdict::None);
    }

    #[test]
    fn dmarc_pass_when_dkim_aligned() {
        let records = [("_dmarc.example.com", "v=DMARC1; p=quarantine")];
        let spf = SpfResult {
            verdict: SpfVerdict::Fail,
            domain: "other.com".to_string(),
        };
        let dkim = DkimSummary::Pass(vec!["example.com".to_string()]);
        let result = dmarc::evaluate(&dns(&records), &spf, &dkim, "example.com");
        assert_eq!(result.verdict, DmarcVerdict::Pass);
    }

    #[test]
    fn dmarc_relaxed_alignment_subdomain() {
        // mail.example.com aligns with example.com (relaxed mode).
        let records = [("_dmarc.example.com", "v=DMARC1; p=none")];
        let spf = SpfResult {
            verdict: SpfVerdict::Pass,
            domain: "example.com".to_string(),
        };
        let dkim = DkimSummary::None;
        let result = dmarc::evaluate(&dns(&records), &spf, &dkim, "mail.example.com");
        // The From: domain is mail.example.com; the SPF domain is example.com.
        // Relaxed alignment: example.com is a parent of mail.example.com → pass.
        assert_eq!(result.verdict, DmarcVerdict::Pass);
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
}
