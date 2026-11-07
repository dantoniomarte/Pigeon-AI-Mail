//! Organizations, members, invitations and catch-all routing over MCP.
//!
//! These are the same operations as `/v1/orgs/*` and `/v1/catchall/*`, with the
//! same guards: administration needs `admin` or `owner` **in that
//! organization**, an invitation can never grant `owner`, and a catch-all route
//! target must be a mailbox of the domain it routes.
//!
//! Nothing here mints a password: a new member is created with the one-time
//! bootstrap token the HTTP endpoint returns, which is the credential they log in
//! with (`POST /v1/auth/login`) and which burns on first use.

use pigeon_api::handlers::org::{MAX_DISPLAY_NAME_LEN, MAX_ORG_NAME_LEN};
use pigeon_core::types::{CatchallAction, OrgRole};
use store::{OrgAccountRow, Storage};

use crate::aux;
use crate::McpState;

// ------------------------------------------------------------------ orgs

/// `org_create` — create an organization and make the acting account its owner.
pub fn org_create(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let name = validate_name("name", aux::required_str(args, "name")?, MAX_ORG_NAME_LEN)?;
    let (current, _) = state
        .store
        .get_account_membership(actor.account_id)
        .map_err(|error| aux::store_error("could not read the account's organization", error))?;
    if let Some(current) = current {
        return Err(format!(
            "{} already belongs to organization {current}: one account belongs to one \
             organization, so a second organization is refused instead of moving the mailbox",
            actor.email
        ));
    }
    let org_id = state
        .store
        .create_org(&name)
        .map_err(|error| aux::store_error("could not create the organization", error))?;
    state
        .store
        .set_account_org(actor.account_id, Some(org_id), OrgRole::Owner)
        .map_err(|error| {
            aux::store_error("could not make the account the organization owner", error)
        })?;
    aux::audit(state, "org.create", &format!("org={org_id}"));
    Ok(serde_json::json!({
        "org_id": org_id,
        "name": name,
        "role": OrgRole::Owner.as_str(),
    })
    .to_string())
}

/// `org_members` — every account of an organization (`org_id` defaults to the
/// acting account's own organization).
pub fn org_members(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let org_id = match aux::optional_i64(args, "org_id")? {
        Some(org_id) => org_id,
        None => {
            let (own, _) = state
                .store
                .get_account_membership(actor.account_id)
                .map_err(|error| {
                    aux::store_error("could not read the account's organization", error)
                })?;
            own.ok_or_else(|| {
                format!(
                    "{} belongs to no organization: pass `org_id` to list another organization's \
                     members",
                    actor.email
                )
            })?
        }
    };
    aux::require_org_admin(state, &actor, org_id)?;
    let members = state
        .store
        .list_org_accounts(org_id)
        .map_err(|error| aux::store_error("could not list the organization's members", error))?;
    Ok(serde_json::json!({
        "org_id": org_id,
        "items": members.iter().map(member_json).collect::<Vec<_>>(),
        "count": members.len(),
    })
    .to_string())
}

/// `org_invite` — mint a one-time invitation token for an address (admin+).
pub fn org_invite(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let org_id = aux::required_i64(args, "org_id")?;
    aux::require_org_admin(state, &actor, org_id)?;
    let email = aux::parse_email(aux::required_str(args, "email")?, "email")?;
    let role = grantable_role(args)?;
    let token = state
        .store
        .create_invitation(org_id, &email, role, actor.account_id)
        .map_err(|error| aux::store_error("could not create the invitation", error))?;
    // The token is returned once and only its hash is stored; the row is where
    // the expiry lives, so read it back for the caller's calendar.
    let invitation = state
        .store
        .list_invitations(org_id)
        .map_err(|error| aux::store_error("could not read the invitation", error))?
        .into_iter()
        .find(|candidate| candidate.email == email.normalized());
    aux::audit(
        state,
        "org.invitation.create",
        &format!(
            "org={org_id} invitation={}",
            invitation
                .as_ref()
                .map_or("unknown".to_string(), |row| row.id.to_string())
        ),
    );
    Ok(serde_json::json!({
        "org_id": org_id,
        "email": email.normalized(),
        "role": role.as_str(),
        "token": token,
        "invitation_id": invitation.as_ref().map(|row| row.id),
        "expires_at": invitation.as_ref().map(|row| row.expires_at.clone()),
        "note": "the token is shown once; only its hash is stored. Deliver it out of band — it \
                 redeems at POST /v1/invitations/accept and burns on first use",
    })
    .to_string())
}

/// `org_create_member` — create a member mailbox plus its bootstrap token (admin+).
pub fn org_create_member(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let org_id = aux::required_i64(args, "org_id")?;
    aux::require_org_admin(state, &actor, org_id)?;
    let email = aux::parse_email(aux::required_str(args, "email")?, "email")?;
    let role = grantable_role(args)?;
    let display_name = match aux::optional_str(args, "display_name") {
        Some(raw) => validate_name("display_name", raw, MAX_DISPLAY_NAME_LEN)?,
        None => String::new(),
    };
    let account_id = state
        .store
        .create_member_account(&email, &display_name, org_id, role)
        .map_err(|error| match error {
            store::StoreError::Conflict => format!(
                "{} already has an account: one address is one mailbox",
                email.normalized()
            ),
            // A shared address must never be taken by a mailbox, or the alias
            // would stop delivering to every holder.
            store::StoreError::AliasShadow(address) => format!(
                "{address} is a sender alias: an account cannot own that address. Delete the \
                 alias first, or invite another address"
            ),
            other => aux::store_error("could not create the member account", other),
        })?;
    // The bootstrap token is an invitation row for the account just created:
    // login and `POST /v1/invitations/accept` are the same redemption path, and
    // both burn it.
    let bootstrap_token = state
        .store
        .create_invitation(org_id, &email, role, actor.account_id)
        .map_err(|error| aux::store_error("could not create the bootstrap token", error))?;
    aux::audit(
        state,
        "org.member.create",
        &format!("org={org_id} account={account_id} role={}", role.as_str()),
    );
    Ok(serde_json::json!({
        "org_id": org_id,
        "account_id": account_id,
        "email": email.normalized(),
        "display_name": display_name,
        "role": role.as_str(),
        "bootstrap_token": bootstrap_token,
        "note": "the bootstrap token is shown once: the member logs in with this address and the \
                 token as `code`, which burns it",
    })
    .to_string())
}

// -------------------------------------------------------------- catch-all

/// `catchall_set` — route or discard mail for unknown local parts of a domain.
///
/// The rule is the domain-level decision; `target_email` is an optional
/// **assignment**, not part of the rule. Passing it assigns that mailbox (several
/// mailboxes may hold the same catch-all, one call each); omitting it leaves the
/// existing assignees untouched, so flipping `route`↔`discard` never forgets who
/// was receiving the mail.
pub fn catchall_set(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let domain = aux::required_str(args, "domain")?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let raw_action = aux::required_str(args, "action")?;
    let action = CatchallAction::parse(raw_action)
        .ok_or_else(|| format!("`action` must be `route` or `discard`, got {raw_action:?}"))?;
    let target_account_id = match aux::optional_str(args, "target_email") {
        Some(raw) => {
            let email = aux::parse_email(raw, "target_email")?;
            if email.domain() != domain {
                return Err(format!(
                    "a catch-all assignee must be a mailbox of {domain}, but {} is not",
                    email.normalized()
                ));
            }
            let account_id = state
                .store
                .get_account_by_email(&email.normalized())
                .map_err(|error| aux::store_error("could not look up the target mailbox", error))?
                .ok_or_else(|| format!("no account has the address {}", email.normalized()))?;
            Some(account_id)
        }
        None => None,
    };
    if action == CatchallAction::Discard && target_account_id.is_some() {
        return Err(
            "action=discard must not name `target_email`: a discarded message is not stored"
                .to_string(),
        );
    }
    state
        .store
        .set_catchall(&domain, action)
        .map_err(|error| match error {
            store::StoreError::InvalidArgument(message) => format!("`domain`: {message}"),
            other => aux::store_error("could not write the catch-all rule", other),
        })?;
    aux::audit(
        state,
        "catchall.put",
        &format!("domain={domain} action={}", action.as_str()),
    );
    if let Some(account_id) = target_account_id {
        // Idempotent on purpose: an agent that repeats a `catchall_set` keeps the
        // mailbox assigned instead of failing on its own earlier call.
        match state
            .store
            .assign_catchall(&domain, account_id, actor.account_id)
        {
            Ok(()) => aux::audit(
                state,
                "catchall.assign",
                &format!("domain={domain} account={account_id}"),
            ),
            Err(store::StoreError::Conflict) => {}
            Err(other) => {
                return Err(aux::store_error(
                    "could not assign the catch-all mailbox",
                    other,
                ))
            }
        }
    }
    let rule = state
        .store
        .get_catchall(&domain)
        .map_err(|error| aux::store_error("could not read the catch-all rule", error))?
        .ok_or_else(|| "the catch-all rule that was just written is gone".to_string())?;
    Ok(catchall_json(&rule, state).to_string())
}

/// `catchall_pause` — suspend the acting account's own copy of a catch-all.
pub fn catchall_pause(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    set_own_catchall_pause(args, state, true)
}

/// `catchall_resume` — resume the acting account's own copy of a catch-all.
pub fn catchall_resume(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    set_own_catchall_pause(args, state, false)
}

/// Shared body of the two self-service pause tools.
///
/// Only the actor's own row: pausing somebody else's copy is the HTTP admin
/// surface (`PATCH /v1/catchall/{domain}/assignments/{account_id}`), and MCP is a
/// second transport, not a second policy.
fn set_own_catchall_pause(
    args: &serde_json::Value,
    state: &McpState,
    paused: bool,
) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let requested =
        aux::optional_str(args, "domain").map(|raw| raw.trim_end_matches('.').to_ascii_lowercase());
    let assignments = state
        .store
        .catchall_assignments_for_account(actor.account_id)
        .map_err(|error| aux::store_error("could not read the account's catch-alls", error))?;
    let matching: Vec<&store::CatchallAssignmentRow> = match &requested {
        Some(domain) => assignments
            .iter()
            .filter(|row| &row.domain == domain)
            .collect(),
        None => assignments.iter().collect(),
    };
    if matching.is_empty() {
        return Err(match &requested {
            Some(domain) => format!(
                "{} does not hold the catch-all of {domain}, so there is nothing to change",
                actor.email
            ),
            None => format!("{} does not hold any catch-all", actor.email),
        });
    }
    if requested.is_none() && matching.len() > 1 {
        return Err(format!(
            "{} holds {} catch-alls ({}); name the one to change with `domain`",
            actor.email,
            matching.len(),
            matching
                .iter()
                .map(|row| row.domain.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let row = matching[0];
    state
        .store
        .set_catchall_paused(&row.domain, actor.account_id, paused)
        .map_err(|error| aux::store_error("could not change the catch-all pause", error))?;
    aux::audit(
        state,
        if paused {
            "catchall.pause"
        } else {
            "catchall.resume"
        },
        &format!("domain={} account={}", row.domain, actor.account_id),
    );
    let assignment = state
        .store
        .get_catchall_assignment(&row.domain, actor.account_id)
        .map_err(|error| aux::store_error("could not read the assignment", error))?
        .ok_or_else(|| "the assignment that was just written is gone".to_string())?;
    Ok(serde_json::json!({
        "domain": assignment.domain,
        "account_id": assignment.account_id,
        "paused": assignment.paused,
    })
    .to_string())
}

/// `catchall_list` — every catch-all rule (admin+).
pub fn catchall_list(_args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let rules = state
        .store
        .list_catchalls()
        .map_err(|error| aux::store_error("could not list the catch-all rules", error))?;
    Ok(serde_json::json!({
        "items": rules.iter().map(|rule| catchall_json(rule, state)).collect::<Vec<_>>(),
        "count": rules.len(),
    })
    .to_string())
}

/// `catchall_delete` — drop a rule, restoring the refusal of unknown local parts.
pub fn catchall_delete(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    aux::require_org_admin_of_own(state, &actor)?;
    let domain = aux::required_str(args, "domain")?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    state
        .store
        .delete_catchall(&domain)
        .map_err(|error| match error {
            store::StoreError::NotFound => format!("no catch-all rule for {domain:?}"),
            other => aux::store_error("could not delete the catch-all rule", other),
        })?;
    aux::audit(state, "catchall.delete", &format!("domain={domain}"));
    Ok(serde_json::json!({ "deleted": domain }).to_string())
}

// ---------------------------------------------------------------- helpers

fn member_json(member: &OrgAccountRow) -> serde_json::Value {
    serde_json::json!({
        "account_id": member.account_id,
        "org_id": member.org_id,
        "email": member.email,
        "display_name": member.display_name,
        "role": member.role.as_str(),
        "created_at": member.created_at,
    })
}

fn catchall_json(rule: &store::CatchallRuleRow, state: &McpState) -> serde_json::Value {
    // The rule is the domain decision; the recipients are assignments, and each
    // carries its own pause switch.
    let assignments = state
        .store
        .catchall_assignees(&rule.domain)
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
                "paused": row.paused,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "domain": rule.domain,
        "action": rule.action.as_str(),
        "assignments": assignments,
    })
}

/// The role an invitation or a new member may carry: `admin` or `member`.
///
/// `owner` is refused, exactly like the HTTP endpoints: ownership moves by
/// changing an existing member's role, so a leaked invitation can never hand over
/// the organization.
fn grantable_role(args: &serde_json::Value) -> Result<OrgRole, String> {
    let raw = aux::optional_str(args, "role").unwrap_or("member");
    match OrgRole::parse(raw) {
        Some(OrgRole::Admin) => Ok(OrgRole::Admin),
        Some(OrgRole::Member) => Ok(OrgRole::Member),
        Some(OrgRole::Owner) => Err(
            "an invitation or a new member cannot grant `owner`: change an existing member's role \
             instead"
                .to_string(),
        ),
        None => Err(format!("`role` must be `admin` or `member`, got {raw:?}")),
    }
}

fn validate_name(field: &str, raw: &str, max: usize) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(format!("`{field}` must not be empty"));
    }
    if name.chars().count() > max {
        return Err(format!(
            "`{field}` is {} characters, above the {max} limit",
            name.chars().count()
        ));
    }
    Ok(name.to_string())
}
