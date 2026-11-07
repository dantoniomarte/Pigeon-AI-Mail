//! Drafts: save an email now, send it later.
//!
//! A draft is *editable* state, which is why it lives in its own table
//! (migration `0007`) instead of being a `messages` row with a flag: `messages`
//! holds the sealed, append-only delivery record, while a draft holds the
//! plaintext the compose box is still working on. The two never mix until the
//! draft is sent.
//!
//! `/v1/drafts/{id}/send` is deliberately **not** a second send implementation:
//! it builds the same `SendRequest` a client would post to `/v1/emails` and hands
//! it to [`super::send::accept`]. Quota, validation, sealing, attachment
//! encryption and queueing therefore behave identically, and the draft is only
//! deleted once the email was accepted — a failed send keeps the draft.
//!
//! Scopes follow the existing pattern: writes need `send`, listing needs `read`.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::EmailAddress;
use store::{NewDraft, Storage};

use crate::auth::ApiKeyContext;
use crate::handlers::{blocking, int_param, send, Params, ProblemJson};
use crate::models::{
    is_valid_tag, AttachmentInput, Draft, DraftCreate, DraftPage, DraftPatch, PageMeta,
    SendRequest, MAX_ATTACHMENTS, MAX_TAGS,
};
use crate::problem::{not_found, validation, FieldError, Problem};
use crate::state::AppState;
use crate::{ids, time};

/// `POST /v1/drafts` — save a new draft, `201`.
pub async fn create_draft(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<DraftCreate>,
) -> Response {
    let result = blocking(move || {
        let draft = draft_from_create(&request)?;
        let public_id = ids::gen(ids::DRF);
        state
            .store
            .create_draft(context.account_id, &public_id, &draft)
            .map_err(Problem::from)?;
        load(&state, context.account_id, &public_id)
    })
    .await;
    match result {
        Ok(draft) => (StatusCode::CREATED, Json(draft)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/drafts` — one page of drafts, newest save first.
pub async fn list_drafts(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        let limit = int_param(&params, "limit", 50, 1, 100)?;
        let offset = int_param(&params, "offset", 0, 0, i64::MAX)?;
        let rows = state
            .store
            .list_drafts(context.account_id, limit, offset)
            .map_err(Problem::from)?;
        let total = state
            .store
            .count_drafts(context.account_id)
            .map_err(Problem::from)?;
        let page = PageMeta::new(total, offset, rows.len() as i64);
        Ok(DraftPage {
            items: rows.iter().map(to_view).collect(),
            page,
        })
    })
    .await;
    match result {
        Ok(page) => Json(page).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/drafts/{id}` — the full draft, bodies included.
pub async fn get_draft(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || load(&state, context.account_id, &id)).await;
    match result {
        Ok(draft) => Json(draft).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/drafts/{id}` — partial update; `updated_at` is bumped.
pub async fn update_draft(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(patch): ProblemJson<DraftPatch>,
) -> Response {
    let result = blocking(move || {
        let existing = state
            .store
            .get_draft(&id, context.account_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("draft {id} not found")))?;
        let draft = draft_from_patch(&existing, &patch)?;
        let updated = state
            .store
            .update_draft(&id, context.account_id, &draft)
            .map_err(Problem::from)?;
        if !updated {
            // The row vanished between the read and the write (a concurrent
            // delete): same answer as never having had it.
            return Err(not_found(format!("draft {id} not found")));
        }
        load(&state, context.account_id, &id)
    })
    .await;
    match result {
        Ok(draft) => Json(draft).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/drafts/{id}` — discard a draft, `204`.
pub async fn delete_draft(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        let removed = state
            .store
            .delete_draft(&id, context.account_id)
            .map_err(Problem::from)?;
        if !removed {
            return Err(not_found(format!("draft {id} not found")));
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/drafts/{id}/send` — turn a draft into a real send, `202`.
///
/// The draft's fields become the send request verbatim: attachments already
/// arrive as base64 JSON, so they pass straight through to the seal-and-queue
/// path. The draft is deleted only after the email was accepted.
pub async fn send_draft(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        require_well_formed(&id)?;
        let row = state
            .store
            .get_draft(&id, context.account_id)
            .map_err(Problem::from)?
            .ok_or_else(|| not_found(format!("draft {id} not found")))?;

        // Build the same body a client would `POST /v1/emails`: one validation
        // path for both, and `accept` reports field errors the same way.
        let payload = serde_json::json!({
            "from": row.from_addr,
            "to": row.to_addrs,
            "cc": row.cc_addrs,
            "bcc": row.bcc_addrs,
            "subject": row.subject,
            "html": row.body_html,
            "text": row.body_text,
            "attachments": row.attachments,
            "tags": row.tags,
        });
        let request: SendRequest =
            serde_json::from_value(payload).map_err(crate::problem::internal)?;
        let accepted = send::accept(&state, &context, &request, None)?;

        if let Err(error) = state.store.delete_draft(&id, context.account_id) {
            // The email is already queued; a lingering draft is a nuisance, not
            // a delivery problem, so this never turns a success into a failure.
            tracing::warn!(%error, %id, "could not delete the sent draft");
        }
        Ok(accepted)
    })
    .await;
    match result {
        Ok(accepted) => (StatusCode::ACCEPTED, Json(accepted)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Load one draft or answer `404` (also for a malformed id).
fn load(state: &AppState, account_id: i64, id: &str) -> Result<Draft, Problem> {
    require_well_formed(id)?;
    let row = state
        .store
        .get_draft(id, account_id)
        .map_err(Problem::from)?
        .ok_or_else(|| not_found(format!("draft {id} not found")))?;
    Ok(to_view(&row))
}

fn require_well_formed(id: &str) -> Result<(), Problem> {
    if ids::is_well_formed(id, ids::DRF) {
        Ok(())
    } else {
        Err(not_found(format!("{id:?} is not a drf_ id")))
    }
}

/// Build a new draft's contents from a create body.
fn draft_from_create(request: &DraftCreate) -> Result<NewDraft, Problem> {
    let mut errors = Vec::new();
    let from = normalize_from(request.from.as_deref(), &mut errors);
    let to = normalize_addresses("to", request.to.as_deref(), &mut errors);
    let cc = normalize_addresses("cc", request.cc.as_deref(), &mut errors);
    let bcc = normalize_addresses("bcc", request.bcc.as_deref(), &mut errors);
    let tags = normalize_tags(request.tags.as_deref(), &mut errors);
    let attachments = normalize_attachments(request.attachments.as_deref(), &mut errors);
    collect(errors)?;
    Ok(NewDraft {
        from_addr: from,
        to_addrs: to,
        cc_addrs: cc,
        bcc_addrs: bcc,
        subject: request.subject.clone(),
        body_html: request.html.clone(),
        body_text: request.text.clone(),
        attachments,
        tags,
    })
}

/// Merge a patch onto the stored draft: a present member replaces, an absent one
/// is kept, which is what "save the compose box" needs.
fn draft_from_patch(existing: &store::DraftRow, patch: &DraftPatch) -> Result<NewDraft, Problem> {
    let mut errors = Vec::new();
    let from = match patch.from.as_deref() {
        Some(raw) => normalize_from(Some(raw), &mut errors),
        None => existing.from_addr.clone(),
    };
    let to = match patch.to.as_deref() {
        Some(raw) => normalize_addresses("to", Some(raw), &mut errors),
        None => existing.to_addrs.clone(),
    };
    let cc = match patch.cc.as_deref() {
        Some(raw) => normalize_addresses("cc", Some(raw), &mut errors),
        None => existing.cc_addrs.clone(),
    };
    let bcc = match patch.bcc.as_deref() {
        Some(raw) => normalize_addresses("bcc", Some(raw), &mut errors),
        None => existing.bcc_addrs.clone(),
    };
    let tags = match patch.tags.as_deref() {
        Some(raw) => normalize_tags(Some(raw), &mut errors),
        None => existing.tags.clone(),
    };
    let attachments = match patch.attachments.as_deref() {
        Some(raw) => normalize_attachments(Some(raw), &mut errors),
        None => existing.attachments.clone(),
    };
    collect(errors)?;
    Ok(NewDraft {
        from_addr: from,
        to_addrs: to,
        cc_addrs: cc,
        bcc_addrs: bcc,
        subject: patch.subject.clone().or_else(|| existing.subject.clone()),
        body_html: patch.html.clone().or_else(|| existing.body_html.clone()),
        body_text: patch.text.clone().or_else(|| existing.body_text.clone()),
        attachments,
        tags,
    })
}

/// Validate the sender and return it as stored.
///
/// An absent or empty sender is allowed: a draft is written before it is
/// finished. A *present* sender must parse, exactly like a send would demand, so
/// the compose box cannot save something it could never send.
fn normalize_from(raw: Option<&str>, errors: &mut Vec<FieldError>) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match crate::models::parse_mailbox(trimmed) {
        Ok(_) => trimmed.to_string(),
        Err(message) => {
            errors.push(FieldError::with_code("from", "invalid", message));
            String::new()
        }
    }
}

/// Parse a recipient list, reporting each bad entry by index.
fn normalize_addresses(
    field: &str,
    raw: Option<&[String]>,
    errors: &mut Vec<FieldError>,
) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.iter()
        .enumerate()
        .filter_map(|(index, value)| match EmailAddress::parse(value.trim()) {
            Ok(address) => Some(address.to_string()),
            Err(error) => {
                errors.push(FieldError::with_code(
                    format!("{field}[{index}]"),
                    "invalid",
                    error.to_string(),
                ));
                None
            }
        })
        .collect()
}

/// Keep only valid tags; a draft may hold at most the send cap, so a saved draft
/// is never unsendable.
fn normalize_tags(raw: Option<&[String]>, errors: &mut Vec<FieldError>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    if raw.len() > MAX_TAGS {
        errors.push(FieldError::with_code(
            "tags",
            "too-many",
            format!("{} tags supplied, above the {MAX_TAGS} limit", raw.len()),
        ));
        return Vec::new();
    }
    let mut tags = Vec::with_capacity(raw.len());
    for tag in raw {
        if !is_valid_tag(tag) {
            errors.push(FieldError::with_code(
                format!("tags[{}]", tags.len()),
                "invalid",
                format!("{tag:?} does not match [a-z0-9-]{{1,40}}"),
            ));
        } else {
            tags.push(tag.clone());
        }
    }
    tags
}

/// Validate attachment shapes and hand them back untouched.
///
/// The API does not decode a draft's attachments: it only proves each one is an
/// object with a filename and base64 content, and stores the JSON verbatim so
/// the send path receives exactly what the compose box saved.
fn normalize_attachments(
    raw: Option<&[serde_json::Value]>,
    errors: &mut Vec<FieldError>,
) -> Vec<serde_json::Value> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    if raw.len() > MAX_ATTACHMENTS {
        errors.push(FieldError::with_code(
            "attachments",
            "too-many",
            format!(
                "{} attachments supplied, above the {MAX_ATTACHMENTS} limit",
                raw.len()
            ),
        ));
        return Vec::new();
    }
    for (index, value) in raw.iter().enumerate() {
        if let Err(error) = serde_json::from_value::<AttachmentInput>(value.clone()) {
            errors.push(FieldError::with_code(
                format!("attachments[{index}]"),
                "invalid",
                error.to_string(),
            ));
        }
    }
    raw.to_vec()
}

/// Turn collected field problems into the contract's `422`, if any.
fn collect(errors: Vec<FieldError>) -> Result<(), Problem> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(validation(errors))
    }
}

/// Project a stored draft onto the contract's `Draft`.
fn to_view(row: &store::DraftRow) -> Draft {
    Draft {
        id: row.public_id.clone(),
        from: row.from_addr.clone(),
        to: row.to_addrs.clone(),
        cc: row.cc_addrs.clone(),
        bcc: row.bcc_addrs.clone(),
        subject: row.subject.clone().filter(|value| !value.is_empty()),
        html: row.body_html.clone().filter(|value| !value.is_empty()),
        text: row.body_text.clone().filter(|value| !value.is_empty()),
        attachments: row.attachments.clone(),
        tags: row.tags.clone(),
        updated_at: time::iso_from_sqlite(&row.updated_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> store::DraftRow {
        store::DraftRow {
            id: 1,
            account_id: 7,
            public_id: ids::derived(ids::DRF, 1),
            from_addr: "dana@example.com".to_string(),
            to_addrs: vec!["carol@example.org".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            subject: Some("Half written".to_string()),
            body_html: None,
            body_text: Some("still writing".to_string()),
            attachments: vec![serde_json::json!({"filename": "a.txt", "content": "aGk="})],
            tags: vec!["billing".to_string()],
            updated_at: "2026-11-06 00:00:00".to_string(),
        }
    }

    #[test]
    fn views_keep_bodies_and_omit_empty_parts() {
        let view = to_view(&row());
        assert_eq!(view.id, "drf_00000001");
        assert_eq!(view.subject.as_deref(), Some("Half written"));
        assert!(view.html.is_none(), "an empty body is omitted");
        assert_eq!(view.text.as_deref(), Some("still writing"));
        assert_eq!(view.updated_at, "2026-11-06T00:00:00Z");
        assert_eq!(view.attachments.len(), 1);
    }

    #[test]
    fn draft_ids_are_checked_before_a_lookup() {
        let id = ids::gen(ids::DRF);
        assert!(require_well_formed(&id).is_ok());
        assert!(require_well_formed("tpl_12345678").is_err());
        assert!(require_well_formed("drf_zz").is_err());
    }

    #[test]
    fn create_rejects_bad_addresses_tags_and_attachments() {
        let bad = DraftCreate {
            to: Some(vec!["nope".to_string()]),
            tags: Some(vec!["Not A Tag".to_string()]),
            attachments: Some(vec![serde_json::json!({"filename": "a.txt"})]),
            ..DraftCreate::default()
        };
        let problem = draft_from_create(&bad).unwrap_err();
        let fields: Vec<&str> = problem
            .errors
            .as_ref()
            .expect("field errors")
            .iter()
            .map(|error| error.field.as_str())
            .collect();
        assert!(fields.contains(&"to[0]"), "{fields:?}");
        assert!(fields.contains(&"tags[0]"), "{fields:?}");
        assert!(fields.contains(&"attachments[0]"), "{fields:?}");
    }

    #[test]
    fn create_accepts_an_empty_draft_and_normalizes_addresses() {
        let empty = draft_from_create(&DraftCreate::default()).expect("empty draft is valid");
        assert_eq!(empty.from_addr, "");
        assert!(empty.to_addrs.is_empty());

        let created = draft_from_create(&DraftCreate {
            from: Some(" Dana <dana@example.com> ".to_string()),
            to: Some(vec![" Carol@Example.org ".to_string()]),
            ..DraftCreate::default()
        })
        .expect("valid draft");
        assert_eq!(created.from_addr, "Dana <dana@example.com>");
        assert_eq!(created.to_addrs, vec!["Carol@example.org".to_string()]);
    }

    #[test]
    fn patch_keeps_absent_members_and_replaces_present_ones() {
        let existing = row();
        let patch: DraftPatch = serde_json::from_value(serde_json::json!({
            "subject": "Renamed",
            "to": ["erin@example.org"],
        }))
        .expect("patch");
        let merged = draft_from_patch(&existing, &patch).expect("merged");
        assert_eq!(merged.subject.as_deref(), Some("Renamed"));
        assert_eq!(merged.to_addrs, vec!["erin@example.org".to_string()]);
        assert_eq!(merged.body_text.as_deref(), Some("still writing"));
        assert_eq!(merged.tags, existing.tags);
        assert_eq!(merged.attachments, existing.attachments);
        assert_eq!(merged.from_addr, existing.from_addr);
    }
}
