//! Account administration: API keys and the account-wide settings.
//!
//! Key creation returns the `pk_…` value exactly once (only the Argon2id hash is
//! stored), listing returns metadata only, and revoking or deleting a key clears
//! the verification cache so the change takes effect on the next request instead
//! of after the cache TTL.
//!
//! Settings are the mailbox policy that belongs to the account rather than to a
//! key: today that is the trash retention window, which the purge worker reads
//! back from the store on every run.
//!
//! The session realm (cookie login, TOTP enrollment) lives in
//! [`crate::handlers::sessions`] and [`crate::handlers::twofa`]: it authenticates
//! browsers, not machines, and is layered behind `auth::require_session`.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::ApiKeyScope;
use store::Storage;

use crate::auth::ApiKeyContext;
use crate::db::KeyRow;
use crate::handlers::{blocking, ProblemJson};
use crate::ids;
use crate::models::{
    AccountSettings, AccountSettingsPatch, ApiKeyCreate, ApiKeyCreated, ApiKeyPatch, ApiKeyView,
};
use crate::problem::{not_found, validation, FieldError, Problem};
use crate::state::AppState;

/// Longest accepted key label.
const MAX_KEY_NAME_LEN: usize = 100;

/// Ceiling on the trash retention the API accepts, in days (`0` = keep forever).
///
/// The store owns the constant: the same bound guards the column, so an API bug
/// cannot persist a value the store would refuse to write back.
const MAX_TRASH_RETENTION_DAYS: i64 = store::MAX_TRASH_RETENTION_DAYS;

/// `POST /v1/account/keys` — create a key, returning `pk_…` once.
pub async fn create_key(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<ApiKeyCreate>,
) -> Response {
    let result = blocking(move || {
        let name = validate_name(&request.name)?;
        let scopes = parse_scopes(&request.scopes)?;
        let (public_id, api_key) = crate::keys::issue(
            &state.store,
            &state.db,
            context.account_id,
            &name,
            &scopes,
            request.sandbox,
        )
        .map_err(Problem::from)?;
        // A brand-new key cannot be cached yet, but the caller's own key may be:
        // clearing keeps the cache from hiding a later revoke/delete sequence.
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "key.create",
            &public_id,
        ) {
            tracing::warn!(%error, %public_id, "could not write audit row");
        }
        Ok(ApiKeyCreated {
            id: public_id,
            key: api_key,
        })
    })
    .await;
    match result {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/account/keys` — metadata only, never key material.
pub async fn list_keys(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let rows = state
            .db
            .list_keys(context.account_id)
            .map_err(Problem::from)?;
        Ok(rows.iter().map(to_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/account/keys/{id}` — rename, revoke or toggle sandbox.
pub async fn patch_key(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(patch): ProblemJson<ApiKeyPatch>,
) -> Response {
    let result = blocking(move || {
        if !crate::ids::is_well_formed(&id, crate::ids::KEY) {
            return Err(not_found(format!("{id:?} is not a key_ id")));
        }
        if let Some(name) = patch.name.as_deref() {
            validate_name(name)?;
        }
        let Some(row) = state
            .db
            .patch_key(context.account_id, &id, &patch)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("API key {id} not found")));
        };
        if patch.revoked == Some(true) || patch.sandbox.is_some() || patch.name.is_some() {
            // The cached verification carries the old scopes/sandbox/revocation
            // state; drop it so the next request re-reads the row.
            state.auth.invalidate_all();
        }
        if let Err(error) =
            state
                .store
                .audit(&format!("key:{}", context.public_id), "key.patch", &id)
        {
            tracing::warn!(%error, %id, "could not write audit row");
        }
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/account/keys/{id}` — immediate deletion.
pub async fn delete_key(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        if !crate::ids::is_well_formed(&id, crate::ids::KEY) {
            return Err(not_found(format!("{id:?} is not a key_ id")));
        }
        let Some(_key_id) = state
            .db
            .delete_key(context.account_id, &id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("API key {id} not found")));
        };
        state.auth.invalidate_all();
        if let Err(error) =
            state
                .store
                .audit(&format!("key:{}", context.public_id), "key.delete", &id)
        {
            tracing::warn!(%error, %id, "could not write audit row");
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/account/settings` — the account-wide mailbox policy.
///
/// Reachable with an API key holding `read` and with a webmail session cookie
/// (a session carries `full` authority, which is a superset): the settings page
/// is a browser surface, but an agent reading the policy needs no different
/// route.
pub async fn get_settings(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let days = state
            .store
            .get_trash_retention(context.account_id)
            .map_err(Problem::from)?;
        Ok(AccountSettings {
            trash_retention_days: days,
        })
    })
    .await;
    match result {
        Ok(settings) => Json(settings).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/account/settings` — change the trash retention window.
///
/// `0` means "keep forever" and is a valid value; anything outside `0..=365` is
/// a `422` with a field-level error rather than a silent clamp, because a
/// clamped retention would delete mail the caller did not ask to delete.
pub async fn patch_settings(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<AccountSettingsPatch>,
) -> Response {
    let result = blocking(move || {
        let days = request.trash_retention_days;
        if !(0..=MAX_TRASH_RETENTION_DAYS).contains(&days) {
            return Err(validation(vec![FieldError::with_code(
                "trash_retention_days",
                "out-of-range",
                format!(
                    "trash_retention_days must be between 0 (keep forever) and \
                     {MAX_TRASH_RETENTION_DAYS}, got {days}"
                ),
            )]));
        }
        state
            .store
            .set_trash_retention(context.account_id, days)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "account.settings",
            &format!("trash_retention_days={days}"),
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(AccountSettings {
            trash_retention_days: days,
        })
    })
    .await;
    match result {
        Ok(settings) => Json(settings).into_response(),
        Err(problem) => problem.into_response(),
    }
}

fn validate_name(name: &str) -> Result<String, Problem> {
    let name = name.trim();
    if name.is_empty() {
        return Err(validation(vec![FieldError::with_code(
            "name",
            "required",
            "name is required",
        )]));
    }
    if name.len() > MAX_KEY_NAME_LEN {
        return Err(validation(vec![FieldError::with_code(
            "name",
            "too-long",
            format!(
                "name is {} characters, above the {MAX_KEY_NAME_LEN} limit",
                name.len()
            ),
        )]));
    }
    Ok(name.to_string())
}

fn parse_scopes(raw: &[String]) -> Result<Vec<ApiKeyScope>, Problem> {
    if raw.is_empty() {
        return Err(validation(vec![FieldError::with_code(
            "scopes",
            "required",
            "at least one scope is required",
        )]));
    }
    let mut scopes: Vec<ApiKeyScope> = Vec::with_capacity(raw.len());
    let mut errors: Vec<FieldError> = Vec::new();
    for (index, value) in raw.iter().enumerate() {
        match ApiKeyScope::parse(value) {
            Ok(scope) => {
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
            Err(error) => errors.push(FieldError::with_code(
                format!("scopes[{index}]"),
                "invalid",
                error.to_string(),
            )),
        }
    }
    if errors.is_empty() {
        Ok(scopes)
    } else {
        Err(validation(errors))
    }
}

fn to_view(row: &KeyRow) -> ApiKeyView {
    ApiKeyView::new(
        if row.public_id.is_empty() {
            ids::derived(ids::KEY, row.key_id)
        } else {
            row.public_id.clone()
        },
        row.name.clone(),
        row.scopes.clone(),
        row.sandbox,
        row.revoked,
        row.last_used_at.clone(),
        row.created_at.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  ci  ").unwrap(), "ci");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_KEY_NAME_LEN + 1)).is_err());
        assert!(validate_name(&"x".repeat(MAX_KEY_NAME_LEN)).is_ok());
    }

    #[test]
    fn scopes_parse_and_deduplicate() {
        let scopes = parse_scopes(&["send".into(), "send".into(), "read".into()]).unwrap();
        assert_eq!(scopes, vec![ApiKeyScope::Send, ApiKeyScope::Read]);
        assert!(parse_scopes(&[]).is_err());
        let error = parse_scopes(&["admin".into()]).unwrap_err();
        assert_eq!(error.errors.as_ref().unwrap()[0].field, "scopes[0]");
    }

    #[test]
    fn view_never_carries_key_material() {
        let row = KeyRow {
            key_id: 7,
            public_id: "key_0000000000000007".to_string(),
            name: "ci".to_string(),
            scopes: vec![ApiKeyScope::Full],
            revoked: false,
            sandbox: true,
            last_used_at: None,
            created_at: "2026-11-06T00:00:00Z".to_string(),
        };
        let view = to_view(&row);
        assert_eq!(view.id, row.public_id);
        assert_eq!(view.scopes, vec!["full".to_string()]);
        let json = serde_json::to_string(&view).expect("serialize");
        assert!(!json.contains("pk_"), "{json}");
        assert!(!json.contains("hash"), "{json}");
    }

    #[test]
    fn keys_written_outside_the_api_get_a_derived_public_id() {
        let row = KeyRow {
            key_id: 9,
            public_id: String::new(),
            name: "bootstrap".to_string(),
            scopes: vec![ApiKeyScope::Full],
            revoked: false,
            sandbox: false,
            last_used_at: None,
            created_at: "2026-11-06T00:00:00Z".to_string(),
        };
        assert_eq!(to_view(&row).id, "key_00000009");
    }
}
