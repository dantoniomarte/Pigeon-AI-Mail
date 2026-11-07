//! Managed sending domains and the DNS records to publish.
//!
//! A domain is added with its own DKIM keypair: an **RSA 2048** key
//! (`pigeon_dkim::DkimKeyPair`, RFC 6376 `rsa-sha256`, the profile every
//! verifier accepts) whose public half goes into DNS and whose private half is
//! sealed under the master key before it is stored. Key generation happens here,
//! at add time, so the records a caller copies are real — a placeholder public
//! key would be published to DNS and then silently fail to sign.
//!
//! # One identity per domain
//!
//! The signing identity lives in `store`'s `dkim_keys` table, keyed by **domain
//! name** — not by this account, and not by the dashboard row. DKIM resolves a
//! key from `<selector>._domainkey.<domain>` alone, so two accounts sending as
//! the same domain must present the same public key; scoping it per row would
//! make the domain's key appear to rotate on every message. The selector is
//! still recorded on the domain row for display, but the key material and the
//! published TXT record come from `dkim_keys`.
//!
//! # RSA keygen is slow, and that is accepted in v0.1
//!
//! Generating a 2048-bit RSA key takes tens to hundreds of milliseconds (and
//! noticeably longer in a debug build), and it happens **inside the request** on
//! the first `POST /v1/domains` for a domain. That is deliberate for v0.1: the
//! alternative is a background job plus a "key not ready yet" state on a response
//! whose whole purpose is to hand back the records to publish. The cost is paid
//! once per domain — every later call reads the stored key.
//!
//! # v0.1 boundaries
//!
//! * The A record needs the server's public address; the deployment supplies it
//!   (`ApiConfig::public_ip`, from `PIGEON_PUBLIC_IP`). Without it the endpoint
//!   refuses to answer, because inventing an IP would send operators to publish a
//!   record pointing at somebody else's server.
//! * Verification is always `verified: false`: DNS checking (and the 15-minute
//!   re-check) lands in v0.2. `?verify=now` records the attempt and says so.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_dkim::DkimKeyPair;
use store::Storage;

use crate::auth::ApiKeyContext;
use crate::db::DomainRow;
use crate::handlers::{blocking, enum_param, Params, ProblemJson};
use crate::models::{DnsRecord, Domain, DomainCreate};
use crate::problem::{internal, not_found, validation, FieldError, Problem, ProblemType};
use crate::state::AppState;
use crate::{dkim, ids};

/// DKIM selector used for every domain (one key per domain for now).
pub const DKIM_SELECTOR: &str = "pigeon";
/// Highest accepted domain-name length (DNS: 253 characters in presentation form).
const MAX_DOMAIN_LEN: usize = 253;

/// `GET /v1/domains` — managed domains, seeding the account's own domain.
///
/// v0.1 has no domain configuration UI, so the account's email domain is the
/// sending domain. It is created on first read (with its DKIM key) instead of
/// requiring an extra call, which keeps `GET` idempotent: the second read returns
/// the same row rather than a second domain.
pub async fn list_domains(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let existing = state
            .db
            .list_domains(context.account_id)
            .map_err(Problem::from)?;
        let domains = if existing.is_empty() {
            let (_, account) = state
                .store
                .get_account(context.account_id)
                .map_err(Problem::from)?;
            let seeded = ensure_domain(&state, context.account_id, account.domain())?;
            vec![seeded]
        } else {
            existing
        };
        Ok(domains.iter().map(to_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(domains) => Json(domains).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/domains` — add a domain and return it.
pub async fn add_domain(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<DomainCreate>,
) -> Response {
    let result = blocking(move || {
        let name = validate_hostname(&request.name)?;
        let row = ensure_domain(&state, context.account_id, &name)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "domain.add",
            &row.public_id,
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(domain) => (StatusCode::CREATED, Json(domain)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/domains/{id}` — verification status (`?verify=now` records a check).
pub async fn get_domain(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::DOM) {
            return Err(not_found(format!("{id:?} is not a dom_ id")));
        }
        let mut row = state
            .db
            .domain_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("domain {id} not found")))?;
        if enum_param(&params, "verify", &["now"])?.is_some() {
            state
                .db
                .touch_domain_checked(context.account_id, &id)
                .map_err(Problem::from)?;
            row = state
                .db
                .domain_by_public_id(context.account_id, &id)
                .map_err(Problem::from)?
                .unwrap_or(row);
        }
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(domain) => Json(domain).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/domains/{id}/dns` — the exact records to publish.
pub async fn domain_dns(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::DOM) {
            return Err(not_found(format!("{id:?} is not a dom_ id")));
        }
        let row = state
            .db
            .domain_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("domain {id} not found")))?;
        let Some(public_ip) = state.config.public_ip.as_deref() else {
            return Err(Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemType::Unavailable,
                "the server's public IP is not configured, so the A record cannot be derived; \
                 set PIGEON_PUBLIC_IP and retry",
            ));
        };
        // A domain row created before the DKIM store existed has no key yet;
        // ensure it here so the guidance always carries the record the worker
        // will actually sign with.
        let identity = ensure_dkim_key(&state, &row.name)?;
        Ok(records_for(&row, public_ip, &identity))
    })
    .await;
    match result {
        Ok(records) => Json(records).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// The DKIM identity a domain signs with: the selector and the exact TXT record
/// to publish at `<selector>._domainkey.<domain>`.
struct DkimIdentity {
    selector: String,
    dns_record: String,
}

/// The five records an operator must publish (`priority` separate from `value`).
fn records_for(domain: &DomainRow, public_ip: &str, dkim: &DkimIdentity) -> Vec<DnsRecord> {
    let mail_host = format!("mail.{}", domain.name);
    vec![
        DnsRecord {
            record_type: "A".to_string(),
            host: mail_host.clone(),
            value: public_ip.to_string(),
            priority: None,
        },
        DnsRecord {
            record_type: "MX".to_string(),
            host: domain.name.clone(),
            value: format!("{mail_host}."),
            priority: Some(10),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            host: domain.name.clone(),
            value: "v=spf1 a mx -all".to_string(),
            priority: None,
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            host: format!("{}._domainkey.{}", dkim.selector, domain.name),
            // Served verbatim from the store: this is the record the outbound
            // worker's signatures verify against, so it is never re-derived here.
            value: dkim.dns_record.clone(),
            priority: None,
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            host: format!("_dmarc.{}", domain.name),
            value: format!(
                "v=DMARC1; p=quarantine; rua=mailto:postmaster@{}",
                domain.name
            ),
            priority: None,
        },
    ]
}

/// Return the domain, creating it (and its DKIM identity) when missing.
///
/// Idempotent for an existing domain: the row is returned as stored and the
/// DKIM key is only generated when the store has none, so a repeated `POST` (or
/// a `GET` that seeds the account's own domain) never rotates a live key.
fn ensure_domain(state: &AppState, account_id: i64, name: &str) -> Result<DomainRow, Problem> {
    let existing = state
        .db
        .list_domains(account_id)
        .map_err(Problem::from)?
        .into_iter()
        .find(|row| row.name == name);
    let row = match existing {
        Some(row) => row,
        None => {
            let public_id = ids::gen(ids::DOM);
            state
                .db
                .upsert_domain(&public_id, account_id, name, DKIM_SELECTOR)
                .map_err(Problem::from)?
        }
    };
    // Backfills the key for domains created before the store existed.
    ensure_dkim_key(state, name)?;
    Ok(row)
}

/// Load the domain's DKIM identity, generating and storing one on first use.
///
/// The RSA 2048 key generation in the miss path is the slow part of this module
/// (see the module docs); the hit path is a single indexed lookup.
fn ensure_dkim_key(state: &AppState, domain: &str) -> Result<DkimIdentity, Problem> {
    if let Some((selector, _wrapped, dns_record)) =
        state.store.get_dkim_key(domain).map_err(Problem::from)?
    {
        return Ok(DkimIdentity {
            selector,
            dns_record,
        });
    }

    let key = DkimKeyPair::generate(DKIM_SELECTOR, domain).map_err(internal)?;
    let pkcs8_der = key.to_pkcs8_der().map_err(internal)?;
    let wrapped =
        dkim::seal_private_key(&state.master_key, domain, &pkcs8_der).map_err(internal)?;
    let dns_record = key.public_key_dns_record();
    state
        .store
        .put_dkim_key(domain, key.selector(), &wrapped, &dns_record)
        .map_err(Problem::from)?;
    tracing::info!(
        domain,
        selector = key.selector(),
        "generated a DKIM RSA key for the domain"
    );

    Ok(DkimIdentity {
        selector: key.selector().to_string(),
        dns_record,
    })
}

fn to_view(row: &DomainRow) -> Domain {
    Domain {
        id: row.public_id.clone(),
        name: row.name.clone(),
        verified: row.verified,
        checked_at: row.checked_at.clone(),
    }
}

/// Validate and normalize a hostname: lowercase, LDH labels, at least two.
fn validate_hostname(raw: &str) -> Result<String, Problem> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut errors = Vec::new();
    if name.is_empty() {
        errors.push(FieldError::with_code(
            "name",
            "required",
            "name is required",
        ));
    } else if name.len() > MAX_DOMAIN_LEN {
        errors.push(FieldError::with_code(
            "name",
            "too-long",
            format!(
                "name is {} characters, above the {MAX_DOMAIN_LEN} limit",
                name.len()
            ),
        ));
    } else if !name.contains('.') {
        errors.push(FieldError::with_code(
            "name",
            "invalid",
            "name must be a fully qualified domain such as example.com",
        ));
    } else {
        for label in name.split('.') {
            let invalid = label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
            if invalid {
                errors.push(FieldError::with_code(
                    "name",
                    "invalid",
                    format!("label {label:?} is not a valid DNS label"),
                ));
                break;
            }
        }
    }
    if !errors.is_empty() {
        return Err(validation(errors));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> DomainRow {
        DomainRow {
            public_id: "dom_0000000000000001".to_string(),
            name: "example.com".to_string(),
            verified: false,
            checked_at: None,
            dkim_selector: DKIM_SELECTOR.to_string(),
        }
    }

    fn identity() -> DkimIdentity {
        DkimIdentity {
            selector: DKIM_SELECTOR.to_string(),
            dns_record: "v=DKIM1; k=rsa; p=cHVia2V5".to_string(),
        }
    }

    #[test]
    fn hostnames_are_normalized_and_validated() {
        assert_eq!(validate_hostname("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            validate_hostname(" mail.example.com ").unwrap(),
            "mail.example.com"
        );
        for bad in [
            "",
            "localhost",
            "exa mple.com",
            "exa..mple.com",
            "-bad.com",
            "bad-.com",
            "ex_ample.com",
            "example.com%",
        ] {
            assert!(validate_hostname(bad).is_err(), "{bad:?} must be rejected");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(validate_hostname(&long_label).is_err());
    }

    #[test]
    fn dns_records_cover_a_mx_spf_dkim_and_dmarc() {
        let records = records_for(&row(), "203.0.113.10", &identity());
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].record_type, "A");
        assert_eq!(records[0].host, "mail.example.com");
        assert_eq!(records[0].value, "203.0.113.10");
        assert_eq!(records[1].record_type, "MX");
        assert_eq!(records[1].value, "mail.example.com.");
        assert_eq!(records[1].priority, Some(10));
        assert_eq!(records[2].value, "v=spf1 a mx -all");
        assert_eq!(records[3].host, "pigeon._domainkey.example.com");
        // The DKIM record is the stored one, verbatim: an RSA record, not Ed25519.
        assert_eq!(records[3].value, "v=DKIM1; k=rsa; p=cHVia2V5");
        assert_eq!(records[4].host, "_dmarc.example.com");
        assert!(records[4].value.starts_with("v=DMARC1;"));
        // MX priority is a separate field, never embedded in the value.
        assert!(!records[1].value.contains("10 "));
    }

    #[test]
    fn views_do_not_leak_key_material() {
        let view = to_view(&row());
        let json = serde_json::to_string(&view).expect("serialize");
        assert!(!json.contains("cHVia2V5"), "{json}");
        assert!(!view.verified, "v0.1 never verifies");
        assert!(view.checked_at.is_none());
    }
}
