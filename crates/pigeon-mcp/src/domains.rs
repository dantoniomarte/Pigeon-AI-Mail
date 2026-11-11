//! Managed sending domains and the DNS records to publish, over MCP.
//!
//! Adding a domain generates its **DKIM RSA 2048** keypair at add time, so the
//! records the agent hands to a human are real: the public half goes into DNS at
//! `<selector>._domainkey.<domain>`, the private half is sealed under the master
//! key before it is stored (the store never sees plaintext key material).
//!
//! The signing identity lives in `store`'s `dkim_keys`, keyed by **domain name**,
//! so every account serving the domain presents the same public key — a re-add
//! reuses the stored identity instead of rotating a live key.
//!
//! # What this tool cannot derive
//!
//! The `A` record needs the server's public address (`PIGEON_PUBLIC_IP`). Unset,
//! the answer carries the four records that do not need it plus a `warning`
//! naming the missing variable: inventing an address would publish a record
//! pointing at somebody else's server.

use pigeon_api::db::DomainRow;
use pigeon_api::handlers::domains::DKIM_SELECTOR;
use pigeon_api::ids;
use pigeon_dkim::DkimKeyPair;
use store::Storage;

use crate::aux;
use crate::McpState;

/// Highest accepted domain-name length (DNS: 253 characters in presentation form).
const MAX_DOMAIN_LEN: usize = 253;
/// Environment variable holding this server's public address.
const PUBLIC_IP_ENV: &str = "PIGEON_PUBLIC_IP";

/// `domain_add` — manage a domain and return the records to publish.
pub fn domain_add(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let name = validate_hostname(aux::required_str(args, "name")?)?;
    let db = aux::api_db(state)?;
    // Idempotent: an existing row is reused, so a repeated add never rotates a
    // live signing key.
    let existing = db
        .list_domains(actor.account_id)
        .map_err(|error| aux::store_error("could not list the managed domains", error))?
        .into_iter()
        .find(|row| row.name == name);
    let row = match existing {
        Some(row) => row,
        None => db
            .upsert_domain(&ids::gen(ids::DOM), actor.account_id, &name, DKIM_SELECTOR)
            .map_err(|error| aux::store_error("could not add the domain", error))?,
    };
    let identity = ensure_dkim_key(state, &row.name)?;
    aux::audit(state, "domain.add", &row.public_id);
    Ok(domain_json(&row, &identity).to_string())
}

/// `domain_dns` — the records to publish for an already-managed domain.
pub fn domain_dns(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let name = validate_hostname(aux::required_str(args, "domain")?)?;
    let db = aux::api_db(state)?;
    let row = db
        .list_domains(actor.account_id)
        .map_err(|error| aux::store_error("could not list the managed domains", error))?
        .into_iter()
        .find(|row| row.name == name)
        .ok_or_else(|| format!("{name} is not a managed domain yet: call `domain_add` first"))?;
    let identity = ensure_dkim_key(state, &row.name)?;
    Ok(domain_json(&row, &identity).to_string())
}

// ---------------------------------------------------------------- helpers

/// The DKIM identity a domain signs with.
struct DkimIdentity {
    selector: String,
    dns_record: String,
}

/// Load the domain's DKIM identity, generating and storing one on first use.
fn ensure_dkim_key(state: &McpState, domain: &str) -> Result<DkimIdentity, String> {
    if let Some((selector, _wrapped, dns_record)) = state
        .store
        .get_dkim_key(domain)
        .map_err(|error| aux::store_error("could not read the domain's DKIM key", error))?
    {
        return Ok(DkimIdentity {
            selector,
            dns_record,
        });
    }
    let key = DkimKeyPair::generate(DKIM_SELECTOR, domain)
        .map_err(|error| format!("could not generate a DKIM key for {domain}: {error}"))?;
    let der = key
        .to_pkcs8_der()
        .map_err(|error| format!("could not encode the DKIM key for {domain}: {error}"))?;
    let wrapped = pigeon_api::dkim::seal_private_key(&state.master_key, domain, &der)
        .map_err(|error| format!("could not seal the DKIM key for {domain}: {error}"))?;
    let dns_record = key.public_key_dns_record();
    state
        .store
        .put_dkim_key(domain, key.selector(), &wrapped, &dns_record)
        .map_err(|error| aux::store_error("could not store the domain's DKIM key", error))?;
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

/// One managed domain plus the records an operator must publish.
fn domain_json(row: &DomainRow, identity: &DkimIdentity) -> serde_json::Value {
    let public_ip = std::env::var(PUBLIC_IP_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let records = records_for(&row.name, identity, public_ip.as_deref());
    let mut document = serde_json::json!({
        "domain_id": row.public_id,
        "name": row.name,
        "verified": row.verified,
        "checked_at": row.checked_at,
        "dkim_selector": identity.selector,
        "records": records,
    });
    if public_ip.is_none() {
        document["warning"] = serde_json::json!(format!(
            "the A record is missing because {PUBLIC_IP_ENV} is not set on the server: publish \
             the other records now and add the A record once the address is configured at \
             mail.{}",
            row.name
        ));
    }
    document
}

/// The records an operator must publish: `A`, `MX`, `SPF`, DKIM and DMARC.
fn records_for(
    name: &str,
    identity: &DkimIdentity,
    public_ip: Option<&str>,
) -> Vec<serde_json::Value> {
    let mail_host = format!("mail.{name}");
    let mut records = Vec::with_capacity(5);
    if let Some(public_ip) = public_ip {
        records.push(serde_json::json!({
            "record_type": "A",
            "host": mail_host.clone(),
            "value": public_ip,
        }));
    }
    records.push(serde_json::json!({
        "record_type": "MX",
        "host": name,
        "value": format!("{mail_host}."),
        "priority": 10,
    }));
    records.push(serde_json::json!({
        "record_type": "TXT",
        "host": name,
        "value": "v=spf1 a mx -all",
    }));
    records.push(serde_json::json!({
        "record_type": "TXT",
        "host": format!("{}._domainkey.{}", identity.selector, name),
        // Served verbatim from the store: it is the record the outbound
        // worker's signatures verify against, so it is never re-derived here.
        "value": identity.dns_record,
    }));
    records.push(serde_json::json!({
        "record_type": "TXT",
        "host": format!("_dmarc.{name}"),
        "value": format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{name}"),
    }));
    records
}

/// Validate and normalize a hostname: lowercase, LDH labels, at least two.
fn validate_hostname(raw: &str) -> Result<String, String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return Err("`name` is required".to_string());
    }
    if name.len() > MAX_DOMAIN_LEN {
        return Err(format!(
            "`name` is {} characters, above the {MAX_DOMAIN_LEN} limit",
            name.len()
        ));
    }
    if !name.contains('.') {
        return Err(format!(
            "`name` must be a fully qualified domain such as example.com, got {name:?}"
        ));
    }
    for label in name.split('.') {
        let invalid = label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if invalid {
            return Err(format!("`name`: {label:?} is not a valid DNS label"));
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_normalized_and_validated() {
        assert_eq!(
            validate_hostname("Example.COM.").expect("valid"),
            "example.com"
        );
        for bad in ["", "localhost", "exa mple.com", "-bad.com", "ex_ample.com"] {
            assert!(validate_hostname(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn records_cover_a_mx_spf_dkim_and_dmarc() {
        let identity = DkimIdentity {
            selector: DKIM_SELECTOR.to_string(),
            dns_record: "v=DKIM1; k=rsa; p=cHVia2V5".to_string(),
        };
        let with_ip = records_for("example.com", &identity, Some("203.0.113.10"));
        assert_eq!(with_ip.len(), 5);
        assert_eq!(with_ip[0]["record_type"], "A");
        assert_eq!(with_ip[2]["value"], "v=spf1 a mx -all");
        assert_eq!(with_ip[3]["host"], "pigeon._domainkey.example.com");
        assert_eq!(with_ip[4]["host"], "_dmarc.example.com");

        let without_ip = records_for("example.com", &identity, None);
        assert_eq!(
            without_ip.len(),
            4,
            "the A record is omitted, never invented"
        );
        assert_eq!(without_ip[0]["record_type"], "MX");
    }
}
