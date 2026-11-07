//! Webhooks: creation (secret shown once), listing and deletion.
//!
//! The signing secret follows the same rule as API keys: it is returned exactly
//! once, at creation, and never again — not on list, not on get. A caller either
//! stores it or asks for a new webhook. When the caller supplies its own secret
//! the format is enforced (`≥32` characters of `[A-Za-z0-9_-]`) so a trivially
//! guessable value cannot be configured.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use store::Storage;

use crate::auth::ApiKeyContext;
use crate::db::WebhookRow;
use crate::handlers::{blocking, ProblemJson};
use crate::ids;
use crate::models::{WebhookCreate, WebhookCreated, WebhookView, WEBHOOK_EVENTS};
use crate::problem::{not_found, validation, FieldError, Problem};
use crate::state::AppState;

/// Minimum length of a caller-supplied signing secret.
const MIN_SECRET_LEN: usize = 32;
/// Longest accepted delivery URL.
const MAX_URL_LEN: usize = 2048;

/// `POST /v1/webhooks` — create, returning the secret once.
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<WebhookCreate>,
) -> Response {
    let result = blocking(move || {
        let url = validate_url(&request.url)?;
        let events = validate_events(&request.events)?;
        let secret = match request.secret.as_deref() {
            Some(secret) => validate_secret(secret)?,
            None => pigeon_crypto::generate_webhook_secret(),
        };
        let row = state
            .db
            .create_webhook(context.account_id, &url, &events, &secret)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "webhook.create",
            &row.public_id,
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(WebhookCreated {
            id: row.public_id,
            url: row.url,
            events: row.events,
            created_at: row.created_at,
            secret: row.secret,
        })
    })
    .await;
    match result {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/webhooks` — never includes secrets.
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let rows = state
            .db
            .list_webhooks(context.account_id)
            .map_err(Problem::from)?;
        Ok(rows.iter().map(to_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(views) => Json(views).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/webhooks/{id}` — never includes the secret.
pub async fn get_webhook(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::WHK) {
            return Err(not_found(format!("{id:?} is not a whk_ id")));
        }
        let row = state
            .db
            .webhook_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("webhook {id} not found")))?;
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/webhooks/{id}`.
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::WHK) {
            return Err(not_found(format!("{id:?} is not a whk_ id")));
        }
        if !state
            .db
            .delete_webhook(context.account_id, &id)
            .map_err(Problem::from)?
        {
            return Err(not_found(format!("webhook {id} not found")));
        }
        if let Err(error) =
            state
                .store
                .audit(&format!("key:{}", context.public_id), "webhook.delete", &id)
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

fn to_view(row: &WebhookRow) -> WebhookView {
    WebhookView {
        id: row.public_id.clone(),
        url: row.url.clone(),
        events: row.events.clone(),
        created_at: row.created_at.clone(),
    }
}

fn validate_url(raw: &str) -> Result<String, Problem> {
    let url = raw.trim();
    let mut errors = Vec::new();
    if url.is_empty() {
        errors.push(FieldError::with_code("url", "required", "url is required"));
    } else if url.len() > MAX_URL_LEN {
        errors.push(FieldError::with_code(
            "url",
            "too-long",
            format!(
                "url is {} characters, above the {MAX_URL_LEN} limit",
                url.len()
            ),
        ));
    } else if !(url.starts_with("https://") || url.starts_with("http://")) {
        errors.push(FieldError::with_code(
            "url",
            "invalid",
            "url must be an absolute http:// or https:// URL",
        ));
    } else if url.chars().any(char::is_whitespace) {
        errors.push(FieldError::with_code(
            "url",
            "invalid",
            "url must not contain whitespace",
        ));
    }
    if errors.is_empty() {
        Ok(url.to_string())
    } else {
        Err(validation(errors))
    }
}

fn validate_events(events: &[String]) -> Result<Vec<String>, Problem> {
    let mut errors = Vec::new();
    if events.is_empty() {
        errors.push(FieldError::with_code(
            "events",
            "required",
            "at least one event is required",
        ));
    }
    let mut validated: Vec<String> = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        if !WEBHOOK_EVENTS.contains(&event.as_str()) {
            errors.push(FieldError::with_code(
                format!("events[{index}]"),
                "invalid",
                format!("{event:?} is not one of {}", WEBHOOK_EVENTS.join(", ")),
            ));
        } else if !validated.contains(event) {
            validated.push(event.clone());
        }
    }
    if errors.is_empty() {
        Ok(validated)
    } else {
        Err(validation(errors))
    }
}

fn validate_secret(raw: &str) -> Result<String, Problem> {
    let secret = raw.trim();
    let valid = secret.len() >= MIN_SECRET_LEN
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if valid {
        Ok(secret.to_string())
    } else {
        Err(validation(vec![FieldError::with_code(
            "secret",
            "invalid",
            format!("secret must be at least {MIN_SECRET_LEN} characters of [A-Za-z0-9_-]"),
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_must_be_absolute_http_or_https() {
        assert_eq!(
            validate_url(" https://example.com/hook ").unwrap(),
            "https://example.com/hook"
        );
        assert!(validate_url("http://localhost:8080/hook").is_ok());
        for bad in [
            "",
            "example.com/hook",
            "ftp://example.com",
            "https://exa mple.com",
        ] {
            assert!(validate_url(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(validate_url(&format!("https://example.com/{}", "a".repeat(MAX_URL_LEN))).is_err());
    }

    #[test]
    fn events_must_come_from_the_contract_list_and_are_deduplicated() {
        let events = validate_events(&[
            "email.sent".to_string(),
            "email.sent".to_string(),
            "email.bounced".to_string(),
        ])
        .unwrap();
        assert_eq!(events, vec!["email.sent", "email.bounced"]);
        assert!(validate_events(&[]).is_err());
        let error = validate_events(&["email.exploded".to_string()]).unwrap_err();
        assert_eq!(error.errors.as_ref().unwrap()[0].field, "events[0]");
    }

    #[test]
    fn supplied_secrets_are_format_checked() {
        assert!(validate_secret(&"a".repeat(32)).is_ok());
        assert!(validate_secret(&"a".repeat(31)).is_err());
        assert!(validate_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!").is_err());
        // The generated secret satisfies the same rule.
        let generated = pigeon_crypto::generate_webhook_secret();
        assert!(generated.starts_with("whsec_"));
        assert!(validate_secret(&generated).is_ok());
    }

    #[test]
    fn views_never_carry_the_secret() {
        let row = WebhookRow {
            public_id: "whk_0000000000000001".to_string(),
            url: "https://example.com/hook".to_string(),
            events: vec!["email.sent".to_string()],
            secret: "whsec_supersecret".to_string(),
            created_at: "2026-11-06T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&to_view(&row)).expect("serialize");
        assert!(!json.contains("whsec_"), "{json}");
        assert!(json.contains("email.sent"));
    }
}
