//! Organizations, members, invitations and catch-all routing.
//!
//! # What an organization is
//!
//! A company (or team) that owns a set of accounts. **One account is one
//! mailbox**: the organization groups mailboxes, it never merges them, so every
//! member keeps their own address, their own sealed mail and their own AI-agent
//! connection (`POST /v1/account/keys`). The global unique key on `accounts.email`
//! is unchanged — one address, one account.
//!
//! # Who may administer
//!
//! Every `/v1/orgs/{id}/…` operation below first proves that the **caller** is a
//! member of *that* organization with role `owner` or `admin`, and answers `403`
//! otherwise. That check runs before the organization is even loaded, so a member
//! of one organization cannot use the endpoints to probe which organization ids
//! exist: a non-member and a nonexistent id produce the same answer.
//!
//! # Two ways to add a person, and why
//!
//! * `POST /v1/orgs/{id}/members` creates the account immediately (no password —
//!   v0.1 has no password realm) and returns a **one-time bootstrap token**. The
//!   new member logs in with their address and that token in `code`
//!   (`POST /v1/auth/login`), which burns it.
//! * `POST /v1/orgs/{id}/invitations` sends nothing (v0.1 has no outbound invite
//!   mail): it returns the token, the admin delivers it out of band, and
//!   `POST /v1/invitations/accept` redeems it against an account that already
//!   exists.
//!
//! Both paths store only an Argon2id hash of the token, both burn it on first use,
//! and neither can grant `owner`: ownership moves by patching an existing member's
//! role, so a leaked invitation can never hand over the organization.
//!
//! # Honest limits of this PR
//!
//! * Accepting an invitation **links the caller's existing account**; it does not
//!   create a second account for the invited address. The caller is always
//!   authenticated, so "create the account from the invitation email" would mean
//!   minting a mailbox for an address the caller does not control. Account
//!   creation belongs to `POST /v1/orgs/{id}/members` (which returns the bootstrap
//!   token) and to the installer.
//! * There is no email delivery, no password, and no per-organization billing.
//! * The master admin panel (cross-organization operator view) is the next PR;
//!   these endpoints are tenant-scoped on purpose.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::types::{CatchallAction, OrgRole};
use pigeon_core::EmailAddress;
use store::{InvitationRow, OrgAccountRow, OrgRow, Storage, StoreError};

use crate::auth::ApiKeyContext;
use crate::handlers::{blocking, ProblemJson};
use crate::models::{
    CatchallRuleView, CatchallUpsert, InvitationAccept, InvitationCreate, InvitationCreated,
    InvitationView, OrgCreate, OrgMemberCreate, OrgMemberCreated, OrgMemberPatch, OrgMemberView,
    OrgView,
};
use crate::problem::{forbidden, not_found, validation, FieldError, Problem, ProblemType};
use crate::state::AppState;

/// Longest accepted organization name.
pub const MAX_ORG_NAME_LEN: usize = 100;
/// Longest accepted display name.
pub const MAX_DISPLAY_NAME_LEN: usize = 100;

/// `POST /v1/orgs` — create an organization; the caller becomes its owner.
pub async fn create_org(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<OrgCreate>,
) -> Response {
    let result = blocking(move || {
        let name = validate_name("name", &request.name, MAX_ORG_NAME_LEN)?;
        // One account belongs to one organization. Creating a second one would
        // silently move the account (and its mailbox) out of the team it currently
        // serves, so it is refused instead of guessed at.
        let (current_org, _) = state
            .store
            .get_account_membership(context.account_id)
            .map_err(Problem::from)?;
        if let Some(current_org) = current_org {
            return Err(Problem::new(
                StatusCode::CONFLICT,
                ProblemType::Conflict,
                format!(
                    "this account already belongs to organization {current_org}: one account \
                     belongs to one organization"
                ),
            ));
        }
        let org_id = state.store.create_org(&name).map_err(Problem::from)?;
        // The creator owns it. `set_account_org` runs after the insert, so a
        // failure here leaves an organization with no member — an operator can
        // still delete it, and nothing half-owned is ever visible.
        state
            .store
            .set_account_org(context.account_id, Some(org_id), OrgRole::Owner)
            .map_err(Problem::from)?;
        audit(&state, &context, "org.create", &org_id.to_string());
        let org = state.store.get_org(org_id).map_err(Problem::from)?;
        Ok(OrgView {
            id: org.id,
            name: org.name,
            created_at: org.created_at,
            role: Some(OrgRole::Owner.as_str().to_string()),
        })
    })
    .await;
    match result {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/orgs` — the organizations the caller belongs to.
pub async fn list_orgs(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let (org_id, role) = state
            .store
            .get_account_membership(context.account_id)
            .map_err(Problem::from)?;
        let Some(org_id) = org_id else {
            // A personal workspace belongs to no organization: an empty list is
            // the honest answer, not an invented "personal org".
            return Ok(Vec::new());
        };
        let org = state.store.get_org(org_id).map_err(Problem::from)?;
        debug_assert_eq!(org.id, org_id);
        Ok(vec![to_org_view(&org, Some(role))])
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/orgs/{id}/members` — every account of the organization (admin+).
pub async fn list_members(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        require_org_admin(&state, context.account_id, org_id)?;
        let members = state
            .store
            .list_org_accounts(org_id)
            .map_err(Problem::from)?;
        Ok(members.iter().map(to_member_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/orgs/{id}/members` — create a member account (admin+).
///
/// The account is created without a password (v0.1 has none) and the response
/// carries the one-time bootstrap token the member logs in with. Only its hash is
/// stored, and the first use burns it.
pub async fn create_member(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(request): ProblemJson<OrgMemberCreate>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        require_org_admin(&state, context.account_id, org_id)?;
        let email = parse_email(&request.email)?;
        let role = parse_grantable_role(request.role.as_deref().unwrap_or("member"))?;
        let display_name = match request.display_name.as_deref() {
            Some(name) => validate_name("display_name", name, MAX_DISPLAY_NAME_LEN)?,
            None => String::new(),
        };
        // `owner` is not grantable from this endpoint either (see
        // `parse_grantable_role`): promoting somebody is a deliberate `PATCH`,
        // visible in the member list.
        let account_id = state
            .store
            .create_member_account(&email, &display_name, org_id, role)
            .map_err(Problem::from)?;
        // The bootstrap token is an invitation row for the account that was just
        // created: login (`POST /v1/auth/login` with it in `code`) and
        // `POST /v1/invitations/accept` are the same redemption path, and both
        // burn the row.
        let bootstrap_token = state
            .store
            .create_invitation(org_id, &email, role, context.account_id)
            .map_err(Problem::from)?;
        audit(
            &state,
            &context,
            "org.member.create",
            &format!("org={org_id} account={account_id} role={}", role.as_str()),
        );
        let member = state
            .store
            .list_org_accounts(org_id)
            .map_err(Problem::from)?
            .into_iter()
            .find(|member| member.account_id == account_id)
            .ok_or_else(|| not_found("the member that was just created is gone"))?;
        Ok(OrgMemberCreated {
            member: to_member_view(&member),
            bootstrap_token,
        })
    })
    .await;
    match result {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/orgs/{id}/members/{account_id}` — change role and/or display name.
///
/// Two rules the store and this handler share:
///
/// * the **last owner** cannot be demoted (`409 last-owner`), because an
///   organization with no owner can no longer be administered; and
/// * only an **owner** may move the `owner` role — either by promoting somebody
///   else or by demoting an owner — so an admin can never take a team over.
pub async fn patch_member(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path((id, account_id)): Path<(String, String)>,
    ProblemJson(patch): ProblemJson<OrgMemberPatch>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        let caller_role = require_org_admin(&state, context.account_id, org_id)?;
        let target = path_id(&account_id)?;
        if patch.role.is_none() && patch.display_name.is_none() {
            return Err(validation(vec![FieldError::with_code(
                "",
                "required",
                "send at least one of role or display_name",
            )]));
        }
        let members = state
            .store
            .list_org_accounts(org_id)
            .map_err(Problem::from)?;
        let member = members
            .iter()
            .find(|member| member.account_id == target)
            .ok_or_else(|| {
                not_found(format!(
                    "account {target} is not a member of this organization"
                ))
            })?;

        if let Some(raw) = patch.role.as_deref() {
            let role = parse_role(raw)?;
            if (role == OrgRole::Owner || member.role == OrgRole::Owner)
                && caller_role != OrgRole::Owner
            {
                return Err(forbidden(
                    "only an owner may grant or take away the `owner` role",
                ));
            }
            state
                .store
                .set_account_role(target, role)
                .map_err(map_role_error)?;
        }
        if let Some(name) = patch.display_name.as_deref() {
            let name = validate_name("display_name", name, MAX_DISPLAY_NAME_LEN)?;
            state
                .store
                .set_account_display_name(target, &name)
                .map_err(Problem::from)?;
        }
        audit(
            &state,
            &context,
            "org.member.patch",
            &format!("org={org_id} account={target}"),
        );
        let updated = state
            .store
            .list_org_accounts(org_id)
            .map_err(Problem::from)?
            .into_iter()
            .find(|candidate| candidate.account_id == target)
            .ok_or_else(|| {
                not_found(format!(
                    "account {target} is not a member of this organization"
                ))
            })?;
        Ok(to_member_view(&updated))
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/orgs/{id}/invitations` — mint a one-time invitation token (admin+).
pub async fn create_invitation(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(request): ProblemJson<InvitationCreate>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        require_org_admin(&state, context.account_id, org_id)?;
        let email = parse_email(&request.email)?;
        let role = parse_grantable_role(request.role.as_deref().unwrap_or("member"))?;
        let token = state
            .store
            .create_invitation(org_id, &email, role, context.account_id)
            .map_err(Problem::from)?;
        let invitation = state
            .store
            .list_invitations(org_id)
            .map_err(Problem::from)?
            .into_iter()
            .find(|invitation| invitation.email == email.normalized())
            .ok_or_else(|| not_found("the invitation that was just created is gone"))?;
        audit(
            &state,
            &context,
            "org.invitation.create",
            &format!("org={org_id} invitation={}", invitation.id),
        );
        Ok(InvitationCreated {
            invitation: to_invitation_view(&invitation),
            token,
        })
    })
    .await;
    match result {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/orgs/{id}/invitations` — pending and historical invitations (admin+).
pub async fn list_invitations(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        require_org_admin(&state, context.account_id, org_id)?;
        let invitations = state
            .store
            .list_invitations(org_id)
            .map_err(Problem::from)?;
        Ok(invitations
            .iter()
            .map(to_invitation_view)
            .collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/orgs/{id}/invitations/{invitation_id}` — revoke a pending token.
pub async fn delete_invitation(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path((id, invitation_id)): Path<(String, String)>,
) -> Response {
    let result = blocking(move || {
        let org_id = path_id(&id)?;
        require_org_admin(&state, context.account_id, org_id)?;
        let invitation_id = path_id(&invitation_id)?;
        let removed = state
            .store
            .delete_invitation(org_id, invitation_id)
            .map_err(Problem::from)?;
        if !removed {
            return Err(not_found(format!(
                "invitation {invitation_id} not found in this organization"
            )));
        }
        audit(
            &state,
            &context,
            "org.invitation.delete",
            &format!("org={org_id} invitation={invitation_id}"),
        );
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/invitations/accept` — redeem a token against the caller's account.
///
/// The account is linked to the organization with the invited role and the token
/// is burned, so a replay is a `409`. The invitation must be addressed to the
/// caller's own address: redeeming somebody else's invitation would move a
/// mailbox the caller does not own.
pub async fn accept_invitation(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<InvitationAccept>,
) -> Response {
    let result = blocking(move || {
        let token = request.token.trim();
        if token.is_empty() {
            return Err(validation(vec![FieldError::with_code(
                "token",
                "required",
                "token is required",
            )]));
        }
        let Some(invitation) = state
            .store
            .get_invitation_by_token(token)
            .map_err(Problem::from)?
        else {
            return Err(not_found(
                "no pending invitation matches that token (unknown, expired or already used)",
            ));
        };
        let (_, caller_email) = state
            .store
            .get_account(context.account_id)
            .map_err(Problem::from)?;
        if caller_email.normalized() != invitation.email {
            return Err(forbidden(format!(
                "the invitation is addressed to {} — log in as that account (or with its \
                 bootstrap token) to accept it",
                invitation.email
            )));
        }
        state
            .store
            .accept_invitation(invitation.id, context.account_id)
            .map_err(problem_for_accept)?;
        audit(
            &state,
            &context,
            "org.invitation.accept",
            &format!("org={} invitation={}", invitation.org_id, invitation.id),
        );
        let org = state
            .store
            .get_org(invitation.org_id)
            .map_err(Problem::from)?;
        let (_, role) = state
            .store
            .get_account_membership(context.account_id)
            .map_err(Problem::from)?;
        Ok(to_org_view(&org, Some(role)))
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PUT /v1/catchall/{domain}` — set the rule for one domain.
///
/// Full scope, and the caller must be an owner/admin of its own organization: a
/// catch-all decides where **every** unknown address of a domain lands, which is a
/// company-wide decision, not a personal preference. A personal workspace account
/// is its own owner, so a single-account deployment can still configure it.
pub async fn put_catchall(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(domain): Path<String>,
    ProblemJson(request): ProblemJson<CatchallUpsert>,
) -> Response {
    let result =
        blocking(move || {
            require_org_admin_of_own(&state, context.account_id)?;
            let action = parse_action(&request.action)?;
            match (action, request.target_account_id) {
                (CatchallAction::Route, Some(target_account_id)) => {
                    let (_, target_email) = state.store.get_account(target_account_id).map_err(
                        |error| match error {
                            StoreError::NotFound => {
                                not_found(format!("account {target_account_id} does not exist"))
                            }
                            other => Problem::from(other),
                        },
                    )?;
                    let rule_domain = domain.trim().to_ascii_lowercase();
                    if target_email.domain() != rule_domain {
                        return Err(validation(vec![FieldError::with_code(
                            "target_account_id",
                            "invalid",
                            format!(
                            "the catch-all target must be a mailbox of {rule_domain}, but account \
                             {target_account_id} is {}",
                            target_email
                        ),
                        )]));
                    }
                }
                (CatchallAction::Route, None) => {
                    return Err(validation(vec![FieldError::with_code(
                        "target_account_id",
                        "required",
                        "action=route needs the account that receives the mail",
                    )]))
                }
                (CatchallAction::Discard, Some(_)) => {
                    return Err(validation(vec![FieldError::with_code(
                        "target_account_id",
                        "invalid",
                        "action=discard must not name a target: nothing is stored",
                    )]))
                }
                (CatchallAction::Discard, None) => {}
            }
            state
                .store
                .set_catchall(&domain, action, request.target_account_id)
                .map_err(|error| match error {
                    StoreError::InvalidArgument(message) => {
                        validation(vec![FieldError::with_code("domain", "invalid", message)])
                    }
                    other => Problem::from(other),
                })?;
            audit(
                &state,
                &context,
                "catchall.put",
                &format!(
                    "domain={} action={}",
                    domain.trim().to_ascii_lowercase(),
                    action.as_str()
                ),
            );
            let rule = state
                .store
                .get_catchall(&domain)
                .map_err(Problem::from)?
                .ok_or_else(|| not_found("the rule that was just written is gone"))?;
            Ok(to_catchall_view(&rule))
        })
        .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/catchall` — every catch-all rule.
pub async fn list_catchalls(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        require_org_admin_of_own(&state, context.account_id)?;
        let rules = state.store.list_catchalls().map_err(Problem::from)?;
        Ok(rules.iter().map(to_catchall_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/catchall/{domain}` — remove a rule, restoring the `550`.
pub async fn delete_catchall(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(domain): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_org_admin_of_own(&state, context.account_id)?;
        state
            .store
            .delete_catchall(&domain)
            .map_err(|error| match error {
                StoreError::NotFound => not_found(format!(
                    "no catch-all rule for {:?}",
                    domain.trim().to_ascii_lowercase()
                )),
                other => Problem::from(other),
            })?;
        audit(
            &state,
            &context,
            "catchall.delete",
            &format!("domain={}", domain.trim().to_ascii_lowercase()),
        );
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

// --------------------------------------------------------------- helpers

/// The caller's role in `org_id`, or the problem that denies the request.
///
/// The membership check runs **before** the organization is loaded, so a
/// non-member cannot tell an existing organization id from a nonexistent one.
fn require_org_admin(state: &AppState, account_id: i64, org_id: i64) -> Result<OrgRole, Problem> {
    let (member_of, role) = state
        .store
        .get_account_membership(account_id)
        .map_err(Problem::from)?;
    if member_of != Some(org_id) {
        return Err(forbidden(
            "this operation needs a member of that organization with role `admin` or `owner`",
        ));
    }
    if !role.is_admin() {
        return Err(forbidden(
            "this operation needs role `admin` or `owner` in that organization",
        ));
    }
    // The caller is a member, so the organization must exist; asking for it here
    // turns a corrupt state into a `404` instead of a successful write.
    state.store.get_org(org_id).map_err(Problem::from)?;
    Ok(role)
}

/// The caller's role for the account-wide surfaces (catch-all).
///
/// A personal workspace (`org_id = NULL`) is owned by its only account, so this
/// passes there too.
fn require_org_admin_of_own(state: &AppState, account_id: i64) -> Result<OrgRole, Problem> {
    let (_, role) = state
        .store
        .get_account_membership(account_id)
        .map_err(Problem::from)?;
    if !role.is_admin() {
        return Err(forbidden(
            "this operation needs role `admin` or `owner`: it changes how mail for a whole domain \
             is handled",
        ));
    }
    Ok(role)
}

/// A `{id}` path segment as a store id.
///
/// The store's ids are integers, so a non-numeric segment is a `404` with the
/// contract's problem document rather than axum's plain-text `400`.
fn path_id(raw: &str) -> Result<i64, Problem> {
    raw.trim()
        .parse::<i64>()
        .map_err(|_| not_found(format!("{raw:?} is not a resource id")))
}

fn parse_email(raw: &str) -> Result<EmailAddress, Problem> {
    EmailAddress::parse(raw.trim()).map_err(|error| {
        validation(vec![FieldError::with_code(
            "email",
            "invalid",
            format!("email is not an address: {error}"),
        )])
    })
}

fn parse_role(raw: &str) -> Result<OrgRole, Problem> {
    OrgRole::parse(raw).ok_or_else(|| {
        validation(vec![FieldError::with_code(
            "role",
            "invalid",
            "role must be one of owner|admin|member",
        )])
    })
}

/// A role an invitation or a fresh member may carry: `admin` or `member`.
///
/// `owner` is deliberately refused here so a single invitation cannot hand over an
/// organization; promoting somebody is a separate, auditable `PATCH`.
fn parse_grantable_role(raw: &str) -> Result<OrgRole, Problem> {
    let role = parse_role(raw)?;
    if role == OrgRole::Owner {
        return Err(validation(vec![FieldError::with_code(
            "role",
            "invalid",
            "role must be admin or member; ownership is transferred by patching an existing member",
        )]));
    }
    Ok(role)
}

fn parse_action(raw: &str) -> Result<CatchallAction, Problem> {
    CatchallAction::parse(raw).ok_or_else(|| {
        validation(vec![FieldError::with_code(
            "action",
            "invalid",
            "action must be route or discard",
        )])
    })
}

/// Trim a human name, require it non-empty and bounded.
fn validate_name(field: &str, raw: &str, max_len: usize) -> Result<String, Problem> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(validation(vec![FieldError::with_code(
            field,
            "required",
            format!("{field} is required"),
        )]));
    }
    if name.chars().count() > max_len {
        return Err(validation(vec![FieldError::with_code(
            field,
            "too-long",
            format!("{field} is longer than {max_len} characters"),
        )]));
    }
    Ok(name.to_string())
}

/// Map the store's role-update conflict onto the contract's `last-owner` type.
///
/// `set_account_role` reports exactly one kind of conflict — the demotion that
/// would leave the organization without an owner — so the mapping is total.
fn map_role_error(error: StoreError) -> Problem {
    match error {
        StoreError::Conflict => Problem::new(
            StatusCode::CONFLICT,
            ProblemType::LastOwner,
            "this is the last owner of the organization: promote somebody else to owner first",
        ),
        other => Problem::from(other),
    }
}

/// Map an invitation-acceptance failure onto the contract.
fn problem_for_accept(error: StoreError) -> Problem {
    match error {
        StoreError::Conflict => Problem::new(
            StatusCode::CONFLICT,
            ProblemType::Conflict,
            "that invitation is no longer redeemable (expired or already used), or the account \
             already belongs to another organization",
        ),
        other => Problem::from(other),
    }
}

fn to_org_view(org: &OrgRow, role: Option<OrgRole>) -> OrgView {
    OrgView {
        id: org.id,
        name: org.name.clone(),
        created_at: org.created_at.clone(),
        role: role.map(|role| role.as_str().to_string()),
    }
}

fn to_member_view(member: &OrgAccountRow) -> OrgMemberView {
    OrgMemberView {
        account_id: member.account_id,
        email: member.email.clone(),
        display_name: member.display_name.clone(),
        role: member.role.as_str().to_string(),
        created_at: member.created_at.clone(),
    }
}

fn to_invitation_view(invitation: &InvitationRow) -> InvitationView {
    InvitationView {
        id: invitation.id,
        email: invitation.email.clone(),
        role: invitation.role.as_str().to_string(),
        invited_by: invitation.invited_by,
        created_at: invitation.created_at.clone(),
        expires_at: invitation.expires_at.clone(),
        accepted_at: invitation.accepted_at.clone(),
    }
}

fn to_catchall_view(rule: &store::CatchallRuleRow) -> CatchallRuleView {
    CatchallRuleView {
        domain: rule.domain.clone(),
        action: rule.action.as_str().to_string(),
        target_account_id: rule.target_account_id,
        created_at: rule.created_at.clone(),
    }
}

/// Best-effort audit row: an audit failure is logged, never returned.
fn audit(state: &AppState, context: &ApiKeyContext, action: &str, detail: &str) {
    if let Err(error) = state
        .store
        .audit(&format!("key:{}", context.public_id), action, detail)
    {
        tracing::warn!(%error, %action, "could not write audit row");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_ids_reject_non_numeric_segments_with_a_problem() {
        assert_eq!(path_id("7").expect("numeric id"), 7);
        assert_eq!(path_id(" 12 ").expect("trimmed id"), 12);
        for junk in ["", "org_1", "-1x", "9999999999999999999999"] {
            let problem = path_id(junk).expect_err(junk);
            assert_eq!(problem.status, 404);
            assert_eq!(problem.type_, "not-found");
        }
    }

    #[test]
    fn roles_parse_and_ownership_is_never_grantable() {
        assert_eq!(parse_role("OWNER").expect("role"), OrgRole::Owner);
        assert_eq!(parse_grantable_role("admin").expect("role"), OrgRole::Admin);
        assert_eq!(
            parse_grantable_role("member").expect("role"),
            OrgRole::Member
        );
        for junk in ["", "root", "owner"] {
            let problem = parse_grantable_role(junk).expect_err(junk);
            assert_eq!(problem.status, 422);
            assert_eq!(problem.errors.expect("field errors")[0].field, "role");
        }
        let problem = parse_role("root").expect_err("root");
        assert_eq!(problem.status, 422);
    }

    #[test]
    fn names_are_trimmed_required_and_bounded() {
        assert_eq!(validate_name("name", "  Acme  ", 10).expect("name"), "Acme");
        assert_eq!(
            validate_name("name", "Acme Corp", 10).expect("name"),
            "Acme Corp"
        );
        assert_eq!(
            validate_name("name", "Acme Corporation", 10)
                .unwrap_err()
                .status,
            422
        );
        let empty = validate_name("name", "   ", 10).expect_err("empty");
        assert_eq!(
            empty.errors.expect("errors")[0].code.as_deref(),
            Some("required")
        );
    }

    #[test]
    fn the_last_owner_conflict_becomes_the_contract_type() {
        let problem = map_role_error(StoreError::Conflict);
        assert_eq!(problem.status, 409);
        assert_eq!(problem.type_, "last-owner");
        let other = map_role_error(StoreError::NotFound);
        assert_eq!(other.status, 404);
    }

    #[test]
    fn catchall_actions_parse_and_unknown_values_are_422() {
        assert_eq!(
            parse_action("ROUTE").expect("action"),
            CatchallAction::Route
        );
        assert_eq!(
            parse_action("discard").expect("action"),
            CatchallAction::Discard
        );
        let problem = parse_action("bounce").expect_err("bounce");
        assert_eq!(problem.status, 422);
        assert_eq!(problem.errors.expect("errors")[0].field, "action");
    }

    #[test]
    fn emails_are_validated_with_a_field_error() {
        assert_eq!(
            parse_email("dana@example.com").expect("email").to_string(),
            "dana@example.com"
        );
        let problem = parse_email("not-an-address").expect_err("bad address");
        assert_eq!(problem.status, 422);
        assert_eq!(problem.errors.expect("errors")[0].field, "email");
    }
}
