//! Sender aliases over MCP.
//!
//! The same rules as `/v1/aliases`: an alias is a free address on a domain this
//! deployment serves, it may be held by several accounts, and every account that
//! holds it may send as it and receives a copy of its mail.
//!
//! Administration needs `admin` or `owner` (a personal workspace is its own
//! owner). The acting account is the deployment's bootstrap account
//! ([`aux::DEFAULT_ACCOUNT_ID`](crate::aux::DEFAULT_ACCOUNT_ID)), exactly like every
//! other administration tool.

use store::{SenderAliasRow, Storage, StoreError};

use crate::aux;
use crate::McpState;

/// `alias_list` — every alias with its holders (admin+).
pub fn alias_list(_args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let aliases = state
        .store
        .list_aliases()
        .map_err(|error| aux::store_error("could not list the sender aliases", error))?;
    Ok(serde_json::json!({
        "items": aliases.iter().map(|alias| alias_json(alias, state)).collect::<Vec<_>>(),
        "count": aliases.len(),
    })
    .to_string())
}

/// `alias_create` — claim a free address on a served domain (admin+).
pub fn alias_create(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let address = aux::parse_email(aux::required_str(args, "address")?, "address")?;
    let alias_id = state
        .store
        .create_alias(&address, actor.account_id)
        .map_err(|error| match error {
            StoreError::Conflict => format!("{} is already an alias", address.normalized()),
            StoreError::InvalidArgument(message) => format!("`address`: {message}"),
            other => aux::store_error("could not create the alias", other),
        })?;
    aux::audit(
        state,
        "alias.create",
        &format!("alias={alias_id} address={}", address.normalized()),
    );
    let alias = state
        .store
        .get_alias(alias_id)
        .map_err(|error| aux::store_error("could not read the alias", error))?
        .ok_or_else(|| "the alias that was just written is gone".to_string())?;
    Ok(alias_json(&alias, state).to_string())
}

/// `alias_assign` — let one account send as the alias and receive its mail (admin+).
pub fn alias_assign(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let alias = lookup(state, aux::required_str(args, "address")?)?;
    let account = aux::parse_email(aux::required_str(args, "account_email")?, "account_email")?;
    let account_id = state
        .store
        .get_account_by_email(&account.normalized())
        .map_err(|error| aux::store_error("could not look up the mailbox", error))?
        .ok_or_else(|| format!("no account has the address {}", account.normalized()))?;
    state
        .store
        .assign_alias(alias.id, account_id, actor.account_id)
        .map_err(|error| match error {
            StoreError::Conflict => format!(
                "{} already holds the alias {}",
                account.normalized(),
                alias.address
            ),
            other => aux::store_error("could not assign the alias", other),
        })?;
    aux::audit(
        state,
        "alias.assign",
        &format!("alias={} account={account_id}", alias.id),
    );
    let refreshed = state
        .store
        .get_alias(alias.id)
        .map_err(|error| aux::store_error("could not read the alias", error))?
        .ok_or_else(|| format!("alias {} vanished", alias.address))?;
    Ok(alias_json(&refreshed, state).to_string())
}

/// `alias_delete` — remove the alias and every assignment to it (admin+).
pub fn alias_delete(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let alias = lookup(state, aux::required_str(args, "address")?)?;
    state
        .store
        .delete_alias(alias.id)
        .map_err(|error| match error {
            StoreError::NotFound => format!("alias {} not found", alias.address),
            other => aux::store_error("could not delete the alias", other),
        })?;
    aux::audit(
        state,
        "alias.delete",
        &format!("alias={} address={}", alias.id, alias.address),
    );
    Ok(serde_json::json!({ "deleted": alias.address }).to_string())
}

// ---------------------------------------------------------------- helpers

/// The alias with this address, or the message that says it does not exist.
fn lookup(state: &McpState, raw: &str) -> Result<SenderAliasRow, String> {
    let address = aux::parse_email(raw, "address")?;
    state
        .store
        .get_alias_by_address(&address.normalized())
        .map_err(|error| aux::store_error("could not read the alias", error))?
        .ok_or_else(|| format!("no alias has the address {}", address.normalized()))
}

fn alias_json(alias: &SenderAliasRow, state: &McpState) -> serde_json::Value {
    let assignments = state
        .store
        .alias_assignments(alias.id)
        .unwrap_or_default()
        .into_iter()
        .map(|row| {
            let email = state
                .store
                .get_account(row.account_id)
                .ok()
                .map(|(_, email)| email.to_string());
            serde_json::json!({
                "account_id": row.account_id,
                "email": email,
                "created_at": row.created_at,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "id": alias.id,
        "address": alias.address,
        "domain": alias.domain,
        "assignments": assignments,
        "created_at": alias.created_at,
    })
}
