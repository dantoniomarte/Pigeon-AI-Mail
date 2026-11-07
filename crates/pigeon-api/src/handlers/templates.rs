//! Templates: CRUD plus the rendered test-send.
//!
//! Names are unique per account (`409` on a duplicate, distinguishing a rename
//! collision from a missing template). `id` and `updated_at` are server-owned:
//! the update is a partial patch, so a client can change one field without
//! echoing the rest back.
//!
//! Templates are **unlimited**: a name is unique per account and that is the
//! only constraint. A `description` (plain text, optional) travels with every
//! template so a list can explain itself without opening each one.
//!
//! A test-send goes through the same accept path as `POST /v1/emails`, so it is
//! quota-checked, sealed and queued exactly like a real send — a test that
//! bypassed the pipeline would not test anything.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use store::Storage;

use crate::auth::ApiKeyContext;
use crate::db::TemplateRow;
use crate::handlers::{blocking, send, ProblemJson};
use crate::models::{
    SendRequest, Template, TemplateCreate, TemplatePatch, TestSendRequest, MAX_SUBJECT_LEN,
    MAX_TEST_RECIPIENTS,
};
use crate::problem::{not_found, validation, FieldError, Problem};
use crate::state::AppState;
use crate::{ids, templates};
use pigeon_core::EmailAddress;

/// Longest accepted template name.
const MAX_NAME_LEN: usize = 100;

/// Longest accepted template description.
const MAX_DESCRIPTION_LEN: usize = 500;

/// `POST /v1/templates` — create (`409` on a duplicate name).
pub async fn create_template(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<TemplateCreate>,
) -> Response {
    let result = blocking(move || {
        let name = validate_name(&request.name)?;
        validate_description(request.description.as_deref())?;
        validate_subject(request.subject.as_deref())?;
        let Some(template_id) = create_row(&state, context.account_id, &name, &request)? else {
            return Err(Problem::new(
                StatusCode::CONFLICT,
                crate::problem::ProblemType::Conflict,
                format!("a template named {name:?} already exists for this account"),
            ));
        };
        let row = state
            .db
            .template_by_public_id(context.account_id, &ids::derived(ids::TPL, template_id))
            .map_err(Problem::from)?
            .ok_or_else(|| not_found("template vanished after insert"))?;
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(template) => (StatusCode::CREATED, Json(template)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/templates` — every template of the account.
pub async fn list_templates(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let rows = state
            .db
            .list_templates(context.account_id)
            .map_err(Problem::from)?;
        Ok(rows.iter().map(to_view).collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(list) => Json(list).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/templates/{id}`.
pub async fn get_template(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        let row = state
            .db
            .template_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("template {id} not found")))?;
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(template) => Json(template).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/templates/{id}` — partial update.
pub async fn update_template(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(patch): ProblemJson<TemplatePatch>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        if let Some(name) = patch.name.as_deref() {
            validate_name(name)?;
        }
        validate_description(patch.description.as_deref())?;
        validate_subject(patch.subject.as_deref())?;
        let Some(template_id) = parse_id(&id) else {
            return Err(not_found(format!("template {id} not found")));
        };
        let Some(row) = state
            .db
            .update_template(context.account_id, template_id, &patch)
            .map_err(|error| match error {
                store::StoreError::Conflict => Problem::new(
                    StatusCode::CONFLICT,
                    crate::problem::ProblemType::Conflict,
                    "another template of this account already uses that name",
                ),
                other => Problem::from(other),
            })?
        else {
            return Err(not_found(format!("template {id} not found")));
        };
        Ok(to_view(&row))
    })
    .await;
    match result {
        Ok(template) => Json(template).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/templates/{id}`.
pub async fn delete_template(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        let Some(template_id) = parse_id(&id) else {
            return Err(not_found(format!("template {id} not found")));
        };
        if !state
            .db
            .delete_template(context.account_id, template_id)
            .map_err(Problem::from)?
        {
            return Err(not_found(format!("template {id} not found")));
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/templates/{id}/test-send` — render and queue a real send.
pub async fn test_send(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(request): ProblemJson<TestSendRequest>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        if request.to.is_empty() {
            return Err(validation(vec![FieldError::with_code(
                "to",
                "required",
                "at least one recipient is required",
            )]));
        }
        if request.to.len() > MAX_TEST_RECIPIENTS {
            return Err(validation(vec![FieldError::with_code(
                "to",
                "too-many",
                format!(
                    "{} recipients supplied, above the {MAX_TEST_RECIPIENTS} limit",
                    request.to.len()
                ),
            )]));
        }
        let mut recipients = Vec::with_capacity(request.to.len());
        for (index, raw) in request.to.iter().enumerate() {
            match EmailAddress::parse(raw.trim()) {
                Ok(address) => recipients.push(address.to_string()),
                Err(error) => {
                    return Err(validation(vec![FieldError::with_code(
                        format!("to[{index}]"),
                        "invalid",
                        error.to_string(),
                    )]))
                }
            }
        }

        let row = state
            .db
            .template_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("template {id} not found")))?;
        let (_, account) = state
            .store
            .get_account(context.account_id)
            .map_err(Problem::from)?;

        let variables = &request.variables;
        let subject = templates::render(&row.subject, variables);
        let html = templates::render(&row.html, variables);
        let text = templates::render(&row.text, variables);
        let payload = serde_json::json!({
            "from": account.to_string(),
            "to": recipients,
            "subject": if subject.trim().is_empty() { row.name.clone() } else { subject },
            "html": (!html.is_empty()).then_some(html),
            "text": (!text.is_empty()).then_some(text),
        });
        let send_request: SendRequest =
            serde_json::from_value(payload).map_err(crate::problem::internal)?;
        send::accept(&state, &context, &send_request, None)
    })
    .await;
    match result {
        Ok(accepted) => (StatusCode::ACCEPTED, Json(accepted)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Insert the row, mapping the duplicate-name conflict onto `None` so the caller
/// can answer `409` with a helpful message.
fn create_row(
    state: &AppState,
    account_id: i64,
    name: &str,
    request: &TemplateCreate,
) -> Result<Option<i64>, Problem> {
    match state.db.create_template(
        account_id,
        name,
        request.description.as_deref().unwrap_or_default(),
        request.subject.as_deref().unwrap_or_default(),
        request.html.as_deref().unwrap_or_default(),
        request.text.as_deref().unwrap_or_default(),
    ) {
        Ok(template_id) => Ok(Some(template_id)),
        Err(store::StoreError::Conflict) => Ok(None),
        Err(error) => Err(Problem::from(error)),
    }
}

fn require_well_formed(id: &str) -> Result<(), Problem> {
    if ids::is_well_formed(id, ids::TPL) {
        Ok(())
    } else {
        Err(not_found(format!("{id:?} is not a tpl_ id")))
    }
}

fn parse_id(id: &str) -> Option<i64> {
    i64::from_str_radix(id.strip_prefix(ids::TPL)?, 16).ok()
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
    if name.len() > MAX_NAME_LEN {
        return Err(validation(vec![FieldError::with_code(
            "name",
            "too-long",
            format!(
                "name is {} characters, above the {MAX_NAME_LEN} limit",
                name.len()
            ),
        )]));
    }
    Ok(name.to_string())
}

fn validate_description(description: Option<&str>) -> Result<(), Problem> {
    let Some(description) = description else {
        return Ok(());
    };
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(validation(vec![FieldError::with_code(
            "description",
            "too-long",
            format!(
                "description is {} characters, above the {MAX_DESCRIPTION_LEN} limit",
                description.chars().count()
            ),
        )]));
    }
    Ok(())
}

fn validate_subject(subject: Option<&str>) -> Result<(), Problem> {
    let Some(subject) = subject else {
        return Ok(());
    };
    let mut errors = Vec::new();
    if subject.len() > MAX_SUBJECT_LEN {
        errors.push(FieldError::with_code(
            "subject",
            "too-long",
            format!(
                "subject is {} bytes, above the {MAX_SUBJECT_LEN} limit",
                subject.len()
            ),
        ));
    }
    if crate::models::has_header_break(subject) {
        errors.push(FieldError::with_code(
            "subject",
            "invalid-characters",
            "subject must not contain CR or LF",
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(validation(errors))
    }
}

fn to_view(row: &TemplateRow) -> Template {
    Template {
        id: row.public_id.clone(),
        name: row.name.clone(),
        updated_at: row.updated_at.clone(),
        description: (!row.description.is_empty()).then(|| row.description.clone()),
        subject: (!row.subject.is_empty()).then(|| row.subject.clone()),
        html: (!row.html.is_empty()).then(|| row.html.clone()),
        text: (!row.text.is_empty()).then(|| row.text.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> TemplateRow {
        TemplateRow {
            template_id: 3,
            public_id: ids::derived(ids::TPL, 3),
            name: "welcome".to_string(),
            description: "First contact".to_string(),
            subject: "Hi {{name}}".to_string(),
            html: String::new(),
            text: "Hello".to_string(),
            updated_at: "2026-11-06T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn views_omit_empty_parts() {
        let view = to_view(&row());
        assert_eq!(view.id, "tpl_00000003");
        assert_eq!(view.subject.as_deref(), Some("Hi {{name}}"));
        assert_eq!(view.description.as_deref(), Some("First contact"));
        assert!(view.html.is_none(), "an empty html template is omitted");
        assert_eq!(view.text.as_deref(), Some("Hello"));
    }

    #[test]
    fn ids_round_trip_through_the_path() {
        let id = ids::derived(ids::TPL, 42);
        assert!(require_well_formed(&id).is_ok());
        assert_eq!(parse_id(&id), Some(42));
        assert!(require_well_formed("tpl_zz").is_err());
        assert_eq!(parse_id("tpl_zz"), None);
        assert_eq!(parse_id("eml_00000001"), None);
    }

    #[test]
    fn names_and_subjects_are_validated() {
        assert!(validate_name("  welcome  ").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_subject(None).is_ok());
        assert!(validate_subject(Some("hi")).is_ok());
        assert!(validate_subject(Some("hi\r\nBcc: evil@example.org")).is_err());
        assert!(validate_subject(Some(&"x".repeat(MAX_SUBJECT_LEN + 1))).is_err());
        assert!(validate_description(None).is_ok());
        assert!(validate_description(Some("")).is_ok());
        assert!(validate_description(Some(&"x".repeat(MAX_DESCRIPTION_LEN))).is_ok());
        assert!(validate_description(Some(&"x".repeat(MAX_DESCRIPTION_LEN + 1))).is_err());
    }
}
