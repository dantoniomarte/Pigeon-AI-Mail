//! Sender aliases: a secondary address on a served domain, shared by several
//! accounts.
//!
//! # What an alias is, and what it is not
//!
//! An alias owns **no mailbox**. It is a free address on a domain this
//! deployment already serves (`sales@example.com`), and it is handed to one
//! or more accounts:
//!
//! * mail addressed to the alias is copied into **every** assignee's inbox,
//!   marked with `delivered_for = <alias>` so the webmail can group it;
//! * every assignee may send **as** the alias (`POST /v1/emails` with
//!   `from: sales@…`), which is what makes it useful to a team;
//! * an address that already belongs to an account can never become an alias —
//!   that would silently turn one delivery into copies for strangers.
//!
//! # Who may do what
//!
//! * `GET /v1/aliases` is a **self view**: a member sees the aliases assigned to
//!   them (what the compose box offers), an owner/admin sees every alias of the
//!   deployment with its assignees. It sits in the `send` scope because choosing a
//!   sender is part of sending.
//! * Every mutation needs an owner/admin of its own organization, and is audited
//!   (`alias.create`, `alias.delete`, `alias.assign`, `alias.unassign`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::EmailAddress;
use store::{AliasAssignmentRow, SenderAliasRow, Storage, StoreError};

use crate::auth::ApiKeyContext;
use crate::handlers::{blocking, ProblemJson};
use crate::models::{AliasAssign, AliasAssignmentView, AliasCreate, AliasView};
use crate::problem::{forbidden, not_found, validation, FieldError, Problem, ProblemType};
use crate::state::AppState;

/// `GET /v1/aliases` — the aliases the caller may use or administer.
///
/// `?mine=1` always answers with only the caller's own aliases, which is the
/// compose-box query; without it the answer depends on the role (see the module
/// docs). An owner/admin asking for `mine=1` gets their own list too — the flag is
/// "what may I send as", not "everything I administer".
pub async fn list_aliases(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    axum::extract::Query(params): axum::extract::Query<crate::handlers::Params>,
) -> Response {
    let result = blocking(move || {
        let mine = crate::handlers::bool_param(&params, "mine", false)?;
        let (_, role) = state
            .store
            .get_account_membership(context.account_id)
            .map_err(Problem::from)?;
        let aliases = if mine || !role.is_admin() {
            state
                .store
                .aliases_for_account(context.account_id)
                .map_err(Problem::from)?
        } else {
            state.store.list_aliases().map_err(Problem::from)?
        };
        let mut views = Vec::with_capacity(aliases.len());
        for alias in &aliases {
            views.push(to_alias_view(&state, alias)?);
        }
        Ok(views)
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/aliases` — claim a free address on a served domain.
///
/// `409` when the address is taken (by an account or another alias), `422` when
/// it does not parse or its domain is not one this deployment serves: an alias on
/// a foreign domain could neither receive nor send mail.
pub async fn create_alias(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<AliasCreate>,
) -> Response {
    let result = blocking(move || {
        require_admin_of_own(&state, context.account_id)?;
        let address = EmailAddress::parse(request.address.trim()).map_err(|error| {
            validation(vec![FieldError::with_code(
                "address",
                "invalid",
                format!("address is not an email address: {error}"),
            )])
        })?;
        let alias_id = state
            .store
            .create_alias(&address, context.account_id)
            .map_err(|error| match error {
                StoreError::Conflict => Problem::new(
                    StatusCode::CONFLICT,
                    ProblemType::Conflict,
                    format!("{} is already an alias", address.normalized()),
                ),
                StoreError::InvalidArgument(message) => {
                    validation(vec![FieldError::with_code("address", "invalid", message)])
                }
                StoreError::NotFound => not_found("the account creating the alias does not exist"),
                other => Problem::from(other),
            })?;
        audit(
            &state,
            &context,
            "alias.create",
            &format!("alias={alias_id} address={}", address.normalized()),
        );
        let alias = state
            .store
            .get_alias(alias_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found("the alias that was just written is gone"))?;
        to_alias_view(&state, &alias)
    })
    .await;
    match result {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/aliases/{id}` — remove the alias and every assignment to it.
///
/// Mail already delivered keeps its `delivered_for` marker: revoking a grant is
/// not a reason to rewrite somebody's mailbox history.
pub async fn delete_alias(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_admin_of_own(&state, context.account_id)?;
        let alias_id = parse_id(&id)?;
        let alias = state
            .store
            .get_alias(alias_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("alias {alias_id} not found")))?;
        state
            .store
            .delete_alias(alias_id)
            .map_err(|error| match error {
                StoreError::NotFound => not_found(format!("alias {alias_id} not found")),
                other => Problem::from(other),
            })?;
        audit(
            &state,
            &context,
            "alias.delete",
            &format!("alias={alias_id} address={}", alias.address),
        );
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/aliases/{id}/assign` — let one account send as the alias and
/// receive a copy of its mail.
pub async fn assign_alias(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(request): ProblemJson<AliasAssign>,
) -> Response {
    let result = blocking(move || {
        require_admin_of_own(&state, context.account_id)?;
        let alias_id = parse_id(&id)?;
        state
            .store
            .assign_alias(alias_id, request.account_id, context.account_id)
            .map_err(|error| match error {
                StoreError::Conflict => Problem::new(
                    StatusCode::CONFLICT,
                    ProblemType::Conflict,
                    format!("account {} already holds this alias", request.account_id),
                ),
                StoreError::NotFound => not_found(format!(
                    "alias {alias_id} or account {} does not exist",
                    request.account_id
                )),
                other => Problem::from(other),
            })?;
        audit(
            &state,
            &context,
            "alias.assign",
            &format!("alias={alias_id} account={}", request.account_id),
        );
        let alias = state
            .store
            .get_alias(alias_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("alias {alias_id} not found")))?;
        to_alias_view(&state, &alias)
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/aliases/{id}/unassign` — stop that account's sending and delivery.
pub async fn unassign_alias(
    State(state): State<AppState>,
    axum::extract::Extension(context): axum::extract::Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(request): ProblemJson<AliasAssign>,
) -> Response {
    let result = blocking(move || {
        require_admin_of_own(&state, context.account_id)?;
        let alias_id = parse_id(&id)?;
        state
            .store
            .unassign_alias(alias_id, request.account_id)
            .map_err(|error| match error {
                StoreError::NotFound => not_found(format!(
                    "account {} does not hold alias {alias_id}",
                    request.account_id
                )),
                other => Problem::from(other),
            })?;
        audit(
            &state,
            &context,
            "alias.unassign",
            &format!("alias={alias_id} account={}", request.account_id),
        );
        let alias = state
            .store
            .get_alias(alias_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("alias {alias_id} not found")))?;
        to_alias_view(&state, &alias)
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

// --------------------------------------------------------------- helpers

/// The caller's role for the account-wide alias surfaces.
///
/// A personal workspace (`org_id = NULL`) is owned by its only account, so a
/// single-account deployment administers its own aliases.
fn require_admin_of_own(state: &AppState, account_id: i64) -> Result<(), Problem> {
    let (_, role) = state
        .store
        .get_account_membership(account_id)
        .map_err(Problem::from)?;
    if !role.is_admin() {
        return Err(forbidden(
            "this operation needs role `admin` or `owner`: it shares an address across the \
             whole deployment",
        ));
    }
    Ok(())
}

/// A `{id}` path segment as a store id; a non-numeric segment is a `404`.
fn parse_id(raw: &str) -> Result<i64, Problem> {
    raw.trim()
        .parse::<i64>()
        .map_err(|_| not_found(format!("{raw:?} is not a resource id")))
}

fn to_alias_view(state: &AppState, alias: &SenderAliasRow) -> Result<AliasView, Problem> {
    let assignments = state
        .store
        .alias_assignments(alias.id)
        .map_err(Problem::from)?;
    Ok(AliasView {
        id: alias.id,
        address: alias.address.clone(),
        domain: alias.domain.clone(),
        assignments: assignments
            .iter()
            .map(|row| to_assignment_view(state, row))
            .collect(),
        created_at: alias.created_at.clone(),
    })
}

fn to_assignment_view(state: &AppState, assignment: &AliasAssignmentRow) -> AliasAssignmentView {
    // The address is best-effort: an account deleted between the two queries must
    // not make the listing fail.
    let email = state
        .store
        .get_account(assignment.account_id)
        .ok()
        .map(|(_, email)| email.to_string());
    AliasAssignmentView {
        account_id: assignment.account_id,
        email,
        created_at: assignment.created_at.clone(),
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
    fn alias_ids_must_be_numeric() {
        assert_eq!(parse_id("7").expect("numeric"), 7);
        assert_eq!(parse_id(" 12 ").expect("trimmed"), 12);
        for junk in ["", "alias_1", "-1x"] {
            let problem = parse_id(junk).expect_err(junk);
            assert_eq!(problem.status, 404);
            assert_eq!(problem.type_, "not-found");
        }
    }
}
