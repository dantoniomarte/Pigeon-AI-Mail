//! Send, list, inspect and cancel outbound email.
//!
//! `POST /v1/emails` is the endpoint the whole contract is built around, and its
//! order of operations is the interesting part:
//!
//! 1. **Quota** — checked before any work, so an over-quota account cannot make
//!    the server seal and store a message it will refuse.
//! 2. **Template render** — `template_id` + `variables` produce the body before
//!    validation, because validation is what decides whether a body exists.
//! 3. **Validation** — every field problem collected at once (`422` + `errors[]`).
//! 4. **Idempotency** — a repeated key returns `409 idempotent-replay` carrying
//!    the *original* id, never a second email.
//! 5. **Reserve → seal → insert** — the id is reserved first so the body can be
//!    sealed with `account:{account}:message:{id}` as AAD, then written with that
//!    same id (the `store` crate guarantees the two cannot diverge).
//! 6. **Queue** — `run_after` is now, or `scheduled_at` when it is in the future.
//!
//! The sealed body *is* the generated MIME: the worker transmits exactly those
//! bytes, and `?raw=true` hands the same bytes back to a sandbox caller.

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::{Direction, EmailAddress};
use store::{NewMessage, Storage};

use crate::auth::ApiKeyContext;
use crate::db::{EmailRow, NewEmail};
use crate::handlers::{
    blocking, bool_param, enum_param, int_param, opt_param, Params, ProblemJson,
};
use crate::models::{
    is_valid_tag, AttachmentPart, BatchRequest, BatchResult, BatchResults, DeferredView, EmailPage,
    EmailResponse, EmailStatus, EmailView, PageMeta, SendAccepted, SendRequest, TemplateRender,
    E2E_PLACEHOLDER, MAX_BATCH_ITEMS,
};
use crate::problem::{internal, not_found, validation, FieldError, Problem, ProblemType, Quota};
use crate::state::AppState;
use crate::{aad, ids, mime, templates, time};

/// Every lifecycle status, for `?status=` validation.
const STATUSES: [&str; 8] = [
    "queued",
    "scheduled",
    "sending",
    "sent",
    "deferred",
    "bounced",
    "failed",
    "cancelled",
];

/// `POST /v1/emails` — queue one email, `202 Accepted`.
pub async fn send_email(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    headers: HeaderMap,
    ProblemJson(request): ProblemJson<SendRequest>,
) -> Response {
    let header_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let result = blocking(move || accept(&state, &context, &request, header_key.as_deref())).await;
    match result {
        Ok(accepted) => (StatusCode::ACCEPTED, Json(accepted)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/emails/batch` — up to 100 emails, one result per item.
pub async fn send_batch(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<BatchRequest>,
) -> Response {
    let result = blocking(move || {
        if request.items.is_empty() {
            return Err(validation(vec![FieldError::with_code(
                "items",
                "required",
                "items must hold at least one send request",
            )]));
        }
        if request.items.len() > MAX_BATCH_ITEMS {
            return Err(validation(vec![FieldError::with_code(
                "items",
                "too-many",
                format!(
                    "{} items supplied, above the {MAX_BATCH_ITEMS} limit",
                    request.items.len()
                ),
            )]));
        }
        let mut results = Vec::with_capacity(request.items.len());
        for (index, item) in request.items.iter().enumerate() {
            // Decode each item on its own: a malformed item is that item's
            // problem, never the batch's.
            let outcome = serde_json::from_value::<SendRequest>(item.clone())
                .map_err(|error| crate::handlers::deserialization_problem(&error))
                .and_then(|request| accept(&state, &context, &request, None));
            match outcome {
                Ok(accepted) => results.push(BatchResult {
                    index,
                    id: Some(accepted.id),
                    status: Some(accepted.status),
                    error: None,
                }),
                Err(problem) => results.push(BatchResult {
                    index,
                    id: None,
                    status: None,
                    // The problem is embedded per item, so one rejected email
                    // never hides the ids of the accepted ones.
                    error: serde_json::to_value(&problem).ok(),
                }),
            }
        }
        Ok(BatchResults { results })
    })
    .await;
    match result {
        Ok(results) => (StatusCode::ACCEPTED, Json(results)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/emails` — page of lifecycle views, newest first.
pub async fn list_emails(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        let limit = int_param(&params, "limit", 50, 1, 100)?;
        let offset = int_param(&params, "offset", 0, 0, i64::MAX)?;
        let status = enum_param(&params, "status", &STATUSES)?;
        let tag = opt_param(&params, "tag").map(str::to_string);
        if let Some(tag) = &tag {
            if !is_valid_tag(tag) {
                return Err(validation(vec![FieldError::with_code(
                    "tag",
                    "invalid",
                    "tag must match [a-z0-9-]{1,40}",
                )]));
            }
        }
        let (rows, total) = state
            .db
            .email_page(
                context.account_id,
                limit,
                offset,
                status.as_deref(),
                tag.as_deref(),
            )
            .map_err(Problem::from)?;
        let page = PageMeta::new(total, offset, rows.len() as i64);
        Ok(EmailPage {
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

/// `GET /v1/emails/{id}` — lifecycle view, or the raw MIME for sandbox sends.
pub async fn get_email(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::EML) {
            return Err(not_found(format!("{id:?} is not an eml_ id")));
        }
        let raw = bool_param(&params, "raw", false)?;
        let Some(row) = state
            .db
            .email_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("email {id} not found")));
        };
        if !raw {
            return Ok(EmailResponse::View(Box::new(to_view(&row))));
        }
        // Raw MIME exposes the exact bytes that would be delivered, which is a
        // sandbox-only introspection tool; a real message would leak its body
        // past the seal.
        if !row.sandbox {
            return Err(crate::problem::forbidden(
                "raw=true is only available for messages created by a sandbox key",
            ));
        }
        let mime = open_body(&state, context.account_id, &id)?;
        Ok(EmailResponse::Raw(Box::new(
            crate::models::SandboxMessage {
                id: row.public_id,
                mime,
            },
        )))
    })
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/emails/{id}` — cancel while still queued or scheduled.
pub async fn cancel_email(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::EML) {
            return Err(not_found(format!("{id:?} is not an eml_ id")));
        }
        let Some(row) = state
            .db
            .email_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("email {id} not found")));
        };
        let status = EmailStatus::parse(&row.status).unwrap_or_default();
        if !status.is_cancellable() {
            return Err(Problem::new(
                StatusCode::CONFLICT,
                ProblemType::NotCancellable,
                format!(
                    "email {id} is `{}`; only queued or scheduled emails can be cancelled",
                    status.as_str()
                ),
            ));
        }
        state
            .db
            .cancel_email(context.account_id, &id)
            .map_err(Problem::from)?;
        if let Err(error) =
            state
                .store
                .record_event(row.message_id, "cancelled", "cancelled through the API")
        {
            tracing::warn!(%error, message_id = row.message_id, "could not record cancel event");
        }
        if let Err(error) =
            state
                .store
                .audit(&format!("key:{}", context.public_id), "email.cancel", &id)
        {
            tracing::warn!(%error, %id, "could not write audit row");
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Validate, seal, store and queue one email. Shared by the single send, the
/// batch endpoint and template test-sends.
pub(crate) fn accept(
    state: &AppState,
    context: &ApiKeyContext,
    request: &SendRequest,
    header_key: Option<&str>,
) -> Result<SendAccepted, Problem> {
    let now = time::now_unix();
    let mut request = request.clone();
    if request.idempotency_key.is_none() {
        // `Idempotency-Key` is the header form of the same deduplication key.
        request.idempotency_key = header_key.map(str::to_string);
    }

    check_quota(state, context.account_id)?;

    let template = render_template(state, context.account_id, &request)?;
    let send = request.validate(template.as_ref()).map_err(validation)?;

    if let Some(key) = send.idempotency_key.as_deref() {
        if let Some(existing) = state
            .db
            .email_id_by_idempotency(context.account_id, key)
            .map_err(Problem::from)?
        {
            return Err(Problem::new(
                StatusCode::CONFLICT,
                ProblemType::IdempotentReplay,
                format!(
                    "idempotency_key {key:?} was already used; the original email is still tracked"
                ),
            )
            .with_id(existing));
        }
    }

    let message_id = state.store.reserve_message_id().map_err(Problem::from)?;
    let public_id = ids::gen(ids::EML);
    let message_aad = aad::message(context.account_id, message_id);
    let content_key = pigeon_crypto::generate_content_key();
    let wrapped_key = state
        .master_key
        .wrap_content_key(&content_key, message_aad.as_bytes())
        .map_err(internal)?;
    let body = mime::build(&send, &public_id, now);
    let sealed_body = pigeon_crypto::seal_content(&content_key, &body, message_aad.as_bytes())
        .map_err(internal)?;

    // The envelope carries bcc; the MIME never does.
    let mut to_addrs: Vec<EmailAddress> = send.to.clone();
    to_addrs.extend(send.cc.iter().cloned());
    to_addrs.extend(send.bcc.iter().cloned());

    let stored_id = state
        .store
        .insert_message(
            NewMessage {
                account_id: context.account_id,
                direction: Direction::Out,
                from_addr: send.from.address.clone(),
                to_addrs,
                subject: send.subject.clone(),
                sealed_body,
                idempotency_key: send.idempotency_key.clone(),
            },
            message_id,
        )
        .map_err(Problem::from)?;
    if stored_id != message_id {
        // Another request won the idempotency race between the pre-check and
        // this insert: report the same replay a sequential retry would get.
        let existing = state
            .db
            .public_id_for_message(stored_id)
            .map_err(Problem::from)?
            .unwrap_or_else(|| ids::derived(ids::EML, stored_id));
        return Err(Problem::new(
            StatusCode::CONFLICT,
            ProblemType::IdempotentReplay,
            "this idempotency_key was claimed by a concurrent request",
        )
        .with_id(existing));
    }

    let status = send.initial_status(now);
    state
        .db
        .insert_email(&NewEmail {
            account_id: context.account_id,
            message_id,
            public_id: public_id.clone(),
            status: status.as_str().to_string(),
            to_addrs: send.to.iter().map(ToString::to_string).collect(),
            cc_addrs: send.cc.iter().map(ToString::to_string).collect(),
            tags: send.tags.clone(),
            sandbox: context.sandbox,
            e2e: E2E_PLACEHOLDER.to_string(),
            wrapped_key,
        })
        .map_err(Problem::from)?;

    for (ordinal, attachment) in send.attachments.iter().enumerate() {
        let sealed = seal_attachment(
            &content_key,
            context.account_id,
            message_id,
            ordinal,
            attachment,
        )?;
        state
            .db
            .insert_attachment(
                message_id,
                &attachment.filename,
                attachment.bytes.len() as i64,
                &sealed,
            )
            .map_err(Problem::from)?;
    }

    state
        .store
        .queue_enqueue(message_id, send.run_after(now))
        .map_err(Problem::from)?;

    if let Err(error) = state.store.record_event(
        message_id,
        status.as_str(),
        if status == EmailStatus::Scheduled {
            "scheduled through the API"
        } else {
            "queued through the API"
        },
    ) {
        tracing::warn!(%error, message_id, "could not record queue event");
    }
    if let Err(error) = state.store.audit(
        &format!("key:{}", context.public_id),
        "email.send",
        &public_id,
    ) {
        tracing::warn!(%error, %public_id, "could not write audit row");
    }

    Ok(SendAccepted {
        id: public_id,
        status,
        e2e: E2E_PLACEHOLDER.to_string(),
    })
}

/// Seal one attachment under the message content key.
pub(crate) fn seal_attachment(
    content_key: &[u8; 32],
    account_id: i64,
    message_id: i64,
    ordinal: usize,
    attachment: &AttachmentPart,
) -> Result<Vec<u8>, Problem> {
    let attachment_aad = aad::attachment(account_id, message_id, ordinal, &attachment.filename);
    pigeon_crypto::seal_content(content_key, &attachment.bytes, attachment_aad.as_bytes())
        .map_err(internal)
}

/// Reject a send that would exceed the account's daily quota.
fn check_quota(state: &AppState, account_id: i64) -> Result<(), Problem> {
    let used = state
        .db
        .daily_outbound_count(account_id)
        .map_err(Problem::from)?;
    let limit = state.config.daily_send_quota;
    if used >= limit {
        return Err(Problem::new(
            StatusCode::PAYMENT_REQUIRED,
            ProblemType::QuotaExceeded,
            format!("daily send quota of {limit} emails reached; it resets at 00:00 UTC"),
        )
        .with_quota(Quota::daily(limit, used)));
    }
    Ok(())
}

/// Load and render the template named by `template_id`.
fn render_template(
    state: &AppState,
    account_id: i64,
    request: &SendRequest,
) -> Result<Option<TemplateRender>, Problem> {
    let Some(template_id) = request.template_id.as_deref() else {
        return Ok(None);
    };
    let Some(row) = state
        .db
        .template_by_public_id(account_id, template_id)
        .map_err(Problem::from)?
    else {
        return Err(validation(vec![FieldError::with_code(
            "template_id",
            "not-found",
            format!("unknown template {template_id:?}"),
        )]));
    };
    let variables = &request.variables;
    Ok(Some(TemplateRender {
        subject: templates::render(&row.subject, variables),
        html: (!row.html.is_empty()).then(|| templates::render(&row.html, variables)),
        text: (!row.text.is_empty()).then(|| templates::render(&row.text, variables)),
    }))
}

/// Open the sealed body of one email and return it as text.
fn open_body(state: &AppState, account_id: i64, public_id: &str) -> Result<String, Problem> {
    let Some(stored) = state
        .db
        .message_by_public_id(account_id, public_id)
        .map_err(Problem::from)?
    else {
        return Err(not_found(format!("email {public_id} not found")));
    };
    let Some(wrapped) = stored.wrapped_key else {
        return Err(internal("message has no wrapped content key"));
    };
    let message_aad = aad::message(account_id, stored.message_id);
    let content_key = state
        .master_key
        .unwrap_content_key(&wrapped, message_aad.as_bytes())
        .map_err(internal)?;
    let plaintext =
        pigeon_crypto::open_content(&content_key, &stored.sealed_body, message_aad.as_bytes())
            .map_err(internal)?;
    String::from_utf8(plaintext).map_err(|_| internal("stored body is not UTF-8 MIME text"))
}

/// Project a stored row onto the contract's `EmailView`.
fn to_view(row: &EmailRow) -> EmailView {
    let status = EmailStatus::parse(&row.status).unwrap_or_default();
    EmailView {
        id: row.public_id.clone(),
        status,
        created_at: row.created_at.clone(),
        last_event: row.last_event.clone(),
        from: Some(row.from_addr.clone()),
        to: Some(row.to_addrs.clone()),
        cc: (!row.cc_addrs.is_empty()).then(|| row.cc_addrs.clone()),
        subject: Some(row.subject.clone()),
        tags: (!row.tags.is_empty()).then(|| row.tags.clone()),
        sandbox: Some(row.sandbox),
        e2e: Some(row.e2e.clone()),
        mx: None,
        deferred: (status == EmailStatus::Deferred).then(|| DeferredView {
            next_attempt_at: time::iso_from_unix(row.queue_run_after.unwrap_or_default()),
            attempts: row.queue_attempts,
        }),
        bounced: None,
        failed: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_request(json: serde_json::Value) -> SendRequest {
        serde_json::from_value(json).expect("request")
    }

    #[test]
    fn view_omits_empty_optionals_and_maps_status() {
        let row = EmailRow {
            message_id: 1,
            public_id: "eml_0000000000000001".to_string(),
            status: "sent".to_string(),
            from_addr: "dana@pigeonmail.dev".to_string(),
            to_addrs: vec!["carol@example.org".to_string()],
            cc_addrs: Vec::new(),
            subject: "hi".to_string(),
            tags: Vec::new(),
            sandbox: false,
            e2e: "tls_only".to_string(),
            wrapped_key: None,
            created_at: "2026-11-06T00:00:00Z".to_string(),
            queue_status: Some("done".to_string()),
            queue_attempts: 1,
            queue_run_after: Some(1_793_923_200),
            last_event: Some("2026-11-06T00:00:01Z".to_string()),
        };
        let view = to_view(&row);
        assert_eq!(view.status, EmailStatus::Sent);
        assert_eq!(view.id, row.public_id);
        assert!(view.cc.is_none(), "empty cc is omitted, not null");
        assert!(view.tags.is_none());
        assert!(view.deferred.is_none());
        assert_eq!(view.last_event.as_deref(), Some("2026-11-06T00:00:01Z"));
    }

    #[test]
    fn deferred_view_is_only_emitted_for_deferred_emails() {
        let mut row = EmailRow {
            message_id: 1,
            public_id: "eml_0000000000000001".to_string(),
            status: "deferred".to_string(),
            from_addr: "dana@pigeonmail.dev".to_string(),
            to_addrs: Vec::new(),
            cc_addrs: Vec::new(),
            subject: String::new(),
            tags: Vec::new(),
            sandbox: false,
            e2e: "tls_only".to_string(),
            wrapped_key: None,
            created_at: "2026-11-06T00:00:00Z".to_string(),
            queue_status: Some("ready".to_string()),
            queue_attempts: 3,
            queue_run_after: Some(1_793_923_200),
            last_event: None,
        };
        let view = to_view(&row);
        let deferred = view.deferred.expect("deferred details");
        assert_eq!(deferred.attempts, 3);
        assert_eq!(deferred.next_attempt_at, "2026-11-06T00:00:00Z");

        row.status = "sent".to_string();
        assert!(to_view(&row).deferred.is_none());
    }

    #[test]
    fn status_list_covers_every_lifecycle_value() {
        for status in [
            EmailStatus::Queued,
            EmailStatus::Scheduled,
            EmailStatus::Sending,
            EmailStatus::Sent,
            EmailStatus::Deferred,
            EmailStatus::Bounced,
            EmailStatus::Failed,
            EmailStatus::Cancelled,
        ] {
            assert!(STATUSES.contains(&status.as_str()), "{status:?} missing");
        }
    }

    #[test]
    fn validation_errors_are_reported_for_an_empty_request() {
        let request = send_request(serde_json::json!({"from": "", "to": []}));
        let errors = request.validate(None).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "from"));
        assert!(errors.iter().any(|error| error.field == "to"));
    }

    #[test]
    fn batch_limit_matches_the_contract() {
        assert_eq!(MAX_BATCH_ITEMS, 100);
    }
}
