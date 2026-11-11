//! Shared plumbing for the tools that administer an account.
//!
//! The five messaging tools reach [`McpState`]'s `store` and `master_key` only.
//! The administration tools (organizations, catch-all, drafts, domains,
//! suppressions, API keys) need those two pieces **plus** the API's auxiliary
//! SQL connection, which is the layer that owns the `api_*` tables and the
//! domain/suppression/key listings (`pigeon_api::db::ApiDb`).
//!
//! That connection is opened eagerly by the binary against `PIGEON_DB_PATH`
//! and carried in [`McpState`] (tests open it against a tempdir database), so
//! no tool depends on process-global environment state.
//!
//! # One actor
//!
//! Every tool acts as **one** account: [`DEFAULT_ACCOUNT_ID`], the bootstrap
//! account the deployment's `pigeon keygen` created. Tools that mutate
//! account-scoped state load that account first and answer with what to do when
//! it is missing, instead of writing rows the HTTP API would refuse.
//!
//! # Same rules as the API
//!
//! The guards here mirror the HTTP handlers' guards (an organization operation
//! needs `admin`/`owner` *in that organization*; a catch-all route target must
//! be a mailbox of the routed domain; a draft id must belong to the actor).
//! MCP is a second transport, not a second policy.

use std::sync::Arc;

use pigeon_api::db::ApiDb;
use pigeon_core::types::OrgRole;
use pigeon_core::EmailAddress;
use store::{Storage, StoreError};

use crate::McpState;

/// Account every tool acts as: the deployment's bootstrap account.
pub const DEFAULT_ACCOUNT_ID: i64 = 1;

/// Audit actor recorded for changes made through MCP.
///
/// The HTTP API records `key:<public id>`; an MCP caller has no API key, so its
/// rows say plainly that an agent made the change.
pub const ACTOR: &str = "mcp:agent";

/// The pipeline state for tools that delegate to the API's own path
/// (`send_email`, `draft_send`): new connections to the same database file,
/// default tuning knobs, same master key. Built per call — see the function.
pub fn app_state(state: &McpState) -> Result<pigeon_api::AppState, String> {
    // The pipeline state: new connections to the SAME database file the state
    // already opened (SqliteStorage/ApiDb are not Clone), default tuning
    // knobs, same master key. Built per call — two SQLite opens is
    // microseconds against a send — and deliberately NOT process-global: a
    // cached state would pin the first database path it saw and route a
    // second `McpState`'s mail into the wrong database.
    let path = state.db_path.clone();
    let store = store::SqliteStorage::open(&path)
        .map_err(|error| format!("could not open the store at {}: {error}", path.display()))?;
    let db = pigeon_api::db::ApiDb::open(&path)
        .map_err(|error| format!("could not open the database at {}: {error}", path.display()))?;
    Ok(pigeon_api::AppState::new(
        store,
        (*state.master_key).clone(),
        db,
        pigeon_api::state::ApiConfig::default(),
    ))
}

/// The synthesized acting context for pipeline delegation: the bootstrap
/// account with the `full` scope (the operator's voice).
pub fn pipeline_context(account_id: i64) -> pigeon_api::auth::ApiKeyContext {
    pigeon_api::auth::ApiKeyContext {
        account_id,
        key_id: 0,
        public_id: "mcp-agent".to_string(),
        scopes: vec![pigeon_core::ApiKeyScope::Full],
        sandbox: false,
    }
}

/// The API's auxiliary SQL connection: the handle the binary opened against
/// `PIGEON_DB_PATH` and carried in [`McpState`]. No tool depends on
/// process-global environment state.
pub fn api_db(state: &McpState) -> Result<Arc<ApiDb>, String> {
    Ok(Arc::clone(&state.api_db))
}

/// The account the tools act as.
pub struct Actor {
    /// Account id (currently always [`DEFAULT_ACCOUNT_ID`]).
    pub account_id: i64,
    /// The account's own address, used as the default sender of a draft.
    pub email: EmailAddress,
}

/// Load the acting account, or explain which one is missing.
pub fn actor(state: &McpState) -> Result<Actor, String> {
    match state.store.get_account(DEFAULT_ACCOUNT_ID) {
        Ok((account_id, email)) => Ok(Actor { account_id, email }),
        Err(StoreError::NotFound) => Err(format!(
            "account {DEFAULT_ACCOUNT_ID} does not exist in this database: the MCP server acts as \
             the deployment's bootstrap account, which `pigeon keygen` creates"
        )),
        Err(error) => Err(format!(
            "could not load account {DEFAULT_ACCOUNT_ID}: {error}"
        )),
    }
}

/// True when the actor may administer `org_id`; the mirror of the HTTP guard.
pub fn require_org_admin(state: &McpState, actor: &Actor, org_id: i64) -> Result<OrgRole, String> {
    let (member_of, role) = membership(state, actor)?;
    if member_of != Some(org_id) {
        return Err(format!(
            "{} is not a member of organization {org_id}: this tool needs role `admin` or `owner` \
             there",
            actor.email
        ));
    }
    if !role.is_admin() {
        return Err(format!(
            "this tool needs role `admin` or `owner` in organization {org_id}, but {} is `{}`",
            actor.email,
            role.as_str()
        ));
    }
    Ok(role)
}

/// True when the actor may change account-wide policy (catch-all routing).
///
/// A personal workspace (`org_id = NULL`) is owned by its only account, so it
/// passes too — a single-account deployment can configure its own domain.
pub fn require_org_admin_of_own(state: &McpState, actor: &Actor) -> Result<OrgRole, String> {
    let (_, role) = membership(state, actor)?;
    if !role.is_admin() {
        return Err(format!(
            "this tool changes how mail for a whole domain is handled: it needs role `admin` or \
             `owner`, but {} is `{}`",
            actor.email,
            role.as_str()
        ));
    }
    Ok(role)
}

fn membership(state: &McpState, actor: &Actor) -> Result<(Option<i64>, OrgRole), String> {
    state
        .store
        .get_account_membership(actor.account_id)
        .map_err(|error| store_error("could not read the account's organization", error))
}

/// Refuse a sender the acting account may not use.
///
/// The mirror of the HTTP `from-not-allowed` rule: the account's own address, or
/// any sender alias assigned to it. MCP acts as the bootstrap account, so the
/// aliases it may use are that account's aliases and no other.
pub fn ensure_from_allowed(
    state: &McpState,
    actor: &Actor,
    from: &EmailAddress,
) -> Result<(), String> {
    let normalized = from.normalized();
    if actor.email.normalized() == normalized {
        return Ok(());
    }
    let aliases = state
        .store
        .aliases_for_account(actor.account_id)
        .map_err(|error| store_error("could not read the account's aliases", error))?;
    if aliases.iter().any(|alias| alias.address == normalized) {
        return Ok(());
    }
    Err(format!(
        "{normalized} is neither {} nor an alias assigned to it: ask an administrator to assign \
         the alias first",
        actor.email.normalized()
    ))
}

/// Record an audit row; a failure is logged, never a reason to fail the call.
pub fn audit(state: &McpState, action: &str, detail: &str) {
    if let Err(error) = state.store.audit(ACTOR, action, detail) {
        tracing::warn!(%error, %action, "could not write the audit row");
    }
}

/// Render a store failure as an actionable message.
pub fn store_error(what: &str, error: StoreError) -> String {
    match error {
        StoreError::NotFound => format!("{what}: record not found"),
        StoreError::Conflict => format!("{what}: it collides with an existing row"),
        other => format!("{what}: {other}"),
    }
}

// ------------------------------------------------------------------ arguments

/// A required, non-empty string argument.
pub fn required_str<'a>(args: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    match args.get(field).and_then(|value| value.as_str()) {
        Some(value) if !value.trim().is_empty() => Ok(value.trim()),
        Some(_) => Err(format!("`{field}` must not be empty")),
        None => Err(format!("missing `{field}`")),
    }
}

/// An optional string argument; blank strings count as absent.
pub fn optional_str<'a>(args: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    args.get(field)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// An optional string argument kept verbatim (bodies: whitespace is content).
pub fn optional_text(args: &serde_json::Value, field: &str) -> Option<String> {
    args.get(field)
        .and_then(|value| value.as_str())
        .map(String::from)
}

/// A required boolean argument.
pub fn required_bool(args: &serde_json::Value, field: &str) -> Result<bool, String> {
    args.get(field)
        .and_then(|value| value.as_bool())
        .ok_or_else(|| format!("missing `{field}` (true or false)"))
}

/// An optional boolean argument.
pub fn optional_bool(args: &serde_json::Value, field: &str) -> Option<bool> {
    args.get(field).and_then(|value| value.as_bool())
}

/// An optional integer argument (accepts a number or a numeric string).
pub fn optional_i64(args: &serde_json::Value, field: &str) -> Result<Option<i64>, String> {
    match args.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("`{field}` must be an integer")),
        Some(serde_json::Value::String(raw)) => raw
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| format!("`{field}` must be an integer, got {raw:?}")),
        Some(_) => Err(format!("`{field}` must be an integer")),
    }
}

/// A required integer argument.
pub fn required_i64(args: &serde_json::Value, field: &str) -> Result<i64, String> {
    optional_i64(args, field)?.ok_or_else(|| format!("missing `{field}`"))
}

/// A required array of strings.
pub fn required_strings(args: &serde_json::Value, field: &str) -> Result<Vec<String>, String> {
    let array = args
        .get(field)
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("missing `{field}` array"))?;
    let mut values = Vec::with_capacity(array.len());
    for (index, value) in array.iter().enumerate() {
        match value.as_str() {
            Some(raw) => values.push(raw.trim().to_string()),
            None => return Err(format!("`{field}[{index}]` must be a string")),
        }
    }
    Ok(values)
}

/// An optional array of strings.
pub fn optional_strings(
    args: &serde_json::Value,
    field: &str,
) -> Result<Option<Vec<String>>, String> {
    if args.get(field).is_none_or(|value| value.is_null()) {
        return Ok(None);
    }
    required_strings(args, field).map(Some)
}

/// Parse one address argument, naming the field on failure.
pub fn parse_email(raw: &str, field: &str) -> Result<EmailAddress, String> {
    EmailAddress::parse(raw.trim())
        .map_err(|error| format!("`{field}` is not a valid email address: {error}"))
}

/// Parse a list of address arguments, naming the offending index on failure.
pub fn parse_addresses(raw: &[String], field: &str) -> Result<Vec<EmailAddress>, String> {
    let mut addresses = Vec::with_capacity(raw.len());
    for (index, value) in raw.iter().enumerate() {
        addresses.push(EmailAddress::parse(value.trim()).map_err(|error| {
            format!("`{field}[{index}]` is not a valid email address: {error}")
        })?);
    }
    Ok(addresses)
}

// ------------------------------------------------------------------------- ids

/// The `msg_…` form the API derives from a row id (16 lowercase hex digits).
pub fn message_public_id(row_id: i64) -> String {
    pigeon_api::ids::derived(pigeon_api::ids::MSG, row_id)
}

/// Resolve a `msg_…` id (or a bare row id) to the row the store uses.
///
/// The canonical form is hexadecimal, matching `pigeon_api::ids::derived`, so an
/// id printed by the API, the webmail or [`message_public_id`] resolves to the
/// same row here.
pub fn message_row_id(raw: &str) -> Result<i64, String> {
    let trimmed = raw.trim();
    // Both id shapes resolve: the mailbox `msg_` form and the send surface's
    // `eml_` form — the Sent UI and the export tools accept either.
    let suffix = trimmed
        .strip_prefix(pigeon_api::ids::MSG)
        .or_else(|| trimmed.strip_prefix(pigeon_api::ids::EML))
        .unwrap_or(trimmed);
    if suffix.is_empty() {
        return Err(format!("{raw:?} is not a message id"));
    }
    match i64::from_str_radix(suffix, 16) {
        Ok(id) if id > 0 => Ok(id),
        _ => Err(format!(
            "{raw:?} is not a message id (expected {}{{:08x}})",
            pigeon_api::ids::MSG
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eml_ids_resolve_to_the_same_row() {
        // The Sent surface hands out eml_ ids; the export tools accept them
        // and resolve to the same row id as their msg_ alias.
        let row = 0x0000_0042i64;
        assert_eq!(message_row_id(&message_public_id(row)).expect("msg_"), row);
        assert_eq!(
            message_row_id(&format!("eml_{row:08x}")).expect("eml_"),
            row
        );
    }

    #[test]
    fn message_ids_round_trip_through_the_api_form() {
        for row_id in [1_i64, 10, 4096, 0x00ff_ffff] {
            let public = message_public_id(row_id);
            assert_eq!(message_row_id(&public).expect("resolve"), row_id);
        }
        // A bare suffix is hexadecimal too, like the derived `msg_` form.
        assert_eq!(message_row_id("2a").expect("bare row id"), 42);
    }

    #[test]
    fn malformed_message_ids_are_rejected() {
        for bad in ["", "msg_", "mail_1", "msg_zz"] {
            assert!(message_row_id(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn integer_arguments_accept_numbers_and_numeric_strings() {
        let args = serde_json::json!({ "a": 7, "b": "8", "c": null });
        assert_eq!(optional_i64(&args, "a").unwrap(), Some(7));
        assert_eq!(optional_i64(&args, "b").unwrap(), Some(8));
        assert_eq!(optional_i64(&args, "c").unwrap(), None);
        assert_eq!(optional_i64(&args, "missing").unwrap(), None);
        assert!(optional_i64(&serde_json::json!({ "d": true }), "d").is_err());
    }
}
