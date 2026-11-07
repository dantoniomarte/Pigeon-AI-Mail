//! Suppressions and API keys over MCP.
//!
//! # Suppressions
//!
//! The addresses this account must never mail again: a *list plus why*, paged,
//! deduplicated case-insensitively, and written to by hard bounces as well as by
//! hand. Reasons are the contract's closed set (`manual`, `bounce`, `complaint`).
//!
//! # API keys
//!
//! `api_key_create` is the only call that ever returns `pk_…`: only the Argon2id
//! hash is stored, so a lost key is re-issued, never recovered. Listing returns
//! metadata only, and revoking marks the row so the next request re-reads it
//! instead of matching a cached verification.

use pigeon_api::models::ApiKeyPatch;
use pigeon_core::ApiKeyScope;
use pigeon_core::EmailAddress;

use crate::aux;
use crate::McpState;

/// Addresses accepted per `suppression_add` call.
const MAX_ADDRESSES: usize = 100;
/// Reasons the contract defines.
const REASONS: [&str; 3] = ["manual", "bounce", "complaint"];
/// Longest accepted key label.
const MAX_KEY_NAME_LEN: usize = 100;
/// Largest page `suppression_list` returns in one call.
const MAX_SUPPRESSION_PAGE: i64 = 500;

// ------------------------------------------------------------ suppressions

/// `suppression_list` — one page of suppressed recipients, oldest first.
pub fn suppression_list(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let limit = aux::optional_i64(args, "limit")?
        .unwrap_or(100)
        .clamp(1, MAX_SUPPRESSION_PAGE);
    let offset = aux::optional_i64(args, "offset")?.unwrap_or(0).max(0);
    let (rows, total) = aux::api_db()?
        .suppression_page(actor.account_id, limit, offset)
        .map_err(|error| aux::store_error("could not list the suppressions", error))?;
    Ok(serde_json::json!({
        "items": rows.iter().map(|row| serde_json::json!({
            "address": row.address,
            "reason": row.reason,
            "source": row.source,
            "created_at": row.created_at,
        })).collect::<Vec<_>>(),
        "count": rows.len(),
        "total": total,
    })
    .to_string())
}

/// `suppression_add` — suppress up to 100 addresses, deduplicated per account.
pub fn suppression_add(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let raw = aux::required_strings(args, "addresses")?;
    if raw.is_empty() {
        return Err("`addresses` needs at least one address".to_string());
    }
    if raw.len() > MAX_ADDRESSES {
        return Err(format!(
            "{} addresses supplied, above the {MAX_ADDRESSES} limit",
            raw.len()
        ));
    }
    let addresses = aux::parse_addresses(&raw, "addresses")?;
    let reason = aux::optional_str(args, "reason").unwrap_or("manual");
    if !REASONS.contains(&reason) {
        return Err(format!(
            "`reason` must be one of {}, got {reason:?}",
            REASONS.join("|")
        ));
    }
    let added = aux::api_db()?
        .insert_suppressions(actor.account_id, &addresses, reason, Some(aux::ACTOR))
        .map_err(|error| aux::store_error("could not add the suppressions", error))?;
    aux::audit(
        state,
        "suppression.add",
        &format!("{added} addresses ({reason})"),
    );
    Ok(serde_json::json!({
        "added": added,
        "reason": reason,
        "suppressed": addresses.iter().map(EmailAddress::normalized).collect::<Vec<_>>(),
    })
    .to_string())
}

/// `suppression_remove` — let this account mail an address again.
pub fn suppression_remove(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let address = aux::parse_email(aux::required_str(args, "address")?, "address")?;
    let normalized = address.normalized();
    let removed = aux::api_db()?
        .delete_suppression(actor.account_id, &normalized)
        .map_err(|error| aux::store_error("could not remove the suppression", error))?;
    if !removed {
        return Err(format!("{normalized} is not suppressed"));
    }
    aux::audit(state, "suppression.remove", &normalized);
    Ok(serde_json::json!({ "removed": normalized }).to_string())
}

// ------------------------------------------------------------------- keys

/// `api_key_create` — mint a key; `pk_…` is returned exactly once.
pub fn api_key_create(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let name = aux::required_str(args, "name")?;
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err(format!(
            "`name` is {} characters, above the {MAX_KEY_NAME_LEN} limit",
            name.chars().count()
        ));
    }
    let scopes = parse_scopes(&aux::required_strings(args, "scopes")?)?;
    let sandbox = aux::optional_bool(args, "sandbox").unwrap_or(false);
    let (public_id, api_key) = pigeon_api::keys::issue(
        state.store.as_ref(),
        aux::api_db()?,
        actor.account_id,
        name,
        &scopes,
        sandbox,
    )
    .map_err(|error| aux::store_error("could not issue the API key", error))?;
    aux::audit(state, "key.create", &public_id);
    Ok(serde_json::json!({
        "id": public_id,
        "key": api_key,
        "name": name,
        "scopes": scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
        "sandbox": sandbox,
        "note": "this is the only time the pk_ key is returned: only its hash is stored",
    })
    .to_string())
}

/// `api_key_list` — key metadata, never key material.
pub fn api_key_list(_args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let rows = aux::api_db()?
        .list_keys(actor.account_id)
        .map_err(|error| aux::store_error("could not list the API keys", error))?;
    Ok(serde_json::json!({
        "items": rows.iter().map(|row| serde_json::json!({
            "id": row.public_id,
            "name": row.name,
            "scopes": row.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "sandbox": row.sandbox,
            "revoked": row.revoked,
            "last_used_at": row.last_used_at,
            "created_at": row.created_at,
        })).collect::<Vec<_>>(),
        "count": rows.len(),
    })
    .to_string())
}

/// `api_key_revoke` — revoke a key by its `key_…` id.
pub fn api_key_revoke(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let key_id = aux::required_str(args, "key_id")?;
    if !pigeon_api::ids::is_well_formed(key_id, pigeon_api::ids::KEY) {
        return Err(format!("{key_id:?} is not a key_ id"));
    }
    let patch = ApiKeyPatch {
        revoked: Some(true),
        ..ApiKeyPatch::default()
    };
    let revoked = aux::api_db()?
        .patch_key(actor.account_id, key_id, &patch)
        .map_err(|error| aux::store_error("could not revoke the API key", error))?
        .ok_or_else(|| format!("API key {key_id} not found"))?;
    aux::audit(state, "key.patch", key_id);
    Ok(serde_json::json!({
        "id": revoked.public_id,
        "name": revoked.name,
        "revoked": revoked.revoked,
    })
    .to_string())
}

/// Parse the scope list, deduplicating and refusing anything unknown.
fn parse_scopes(raw: &[String]) -> Result<Vec<ApiKeyScope>, String> {
    if raw.is_empty() {
        return Err("`scopes` needs at least one of send|read|full".to_string());
    }
    let mut scopes: Vec<ApiKeyScope> = Vec::with_capacity(raw.len());
    for (index, value) in raw.iter().enumerate() {
        let scope = ApiKeyScope::parse(value)
            .map_err(|error| format!("`scopes[{index}]` is not a scope: {error}"))?;
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_parsed_and_deduplicated() {
        let scopes = parse_scopes(&["send".into(), "send".into(), "read".into()]).expect("scopes");
        assert_eq!(scopes, vec![ApiKeyScope::Send, ApiKeyScope::Read]);
        assert!(parse_scopes(&[]).is_err());
        assert!(parse_scopes(&["admin".into()]).is_err());
    }

    #[test]
    fn reasons_match_the_contract_enum() {
        assert_eq!(REASONS, ["manual", "bounce", "complaint"]);
    }
}
