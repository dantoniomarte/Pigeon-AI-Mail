//! Inbound messages: the folder listing, the sealed/decrypted views, and
//! attachments.
//!
//! The mailbox surface (folder listing, read state, trash purge) works on the
//! row ids the `store` crate owns: an incoming public id is resolved through
//! `api_messages` (with a derived fallback) to a row id, and every mutation goes
//! through the `Storage` seam, so folder and read state have one owner.
//!
//! The default read is the **sealed** view: metadata, auth verdicts, the
//! ciphertext itself and the attachment *list*. A `read` key can therefore tell
//! that a message carries `receipt.pdf` and how large it is while the content
//! stays sealed. Plaintext is a separate scope (`full`) on the same endpoint,
//! asked for explicitly with `?sealed=false`, so a client can never get
//! plaintext by forgetting a parameter.

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use pigeon_core::{ApiKeyScope, MessageFolder};
use store::{MessageRow, Storage};

use crate::auth::ApiKeyContext;
use crate::db::StoredMessage;
use crate::handlers::{
    blocking, bool_param, enum_param, int_param, opt_param, Params, ProblemJson,
};
use crate::models::{
    AuthVerdict, DecryptedMessageView, DeliveredForCount, EmailStatus, EmptyTrashResult,
    FolderCounts, MessageAttachmentView, MessagePage, MessagePatch, MessageSummary,
    PurgeTrashResult, SealedMessageView,
};
use crate::problem::{
    forbidden, internal, not_found, validation, FieldError, Problem, ProblemType,
};
use crate::state::AppState;
use crate::{aad, ids};

/// Folders a listing or a move may name, in the order the contract documents
/// them. Kept as strings so [`enum_param`] and the problem message share one
/// source of truth; the typed value comes from [`MessageFolder::parse`].
const FOLDER_VALUES: [&str; 4] = ["inbox", "sent", "spam", "trash"];

/// `GET /v1/messages` — metadata page of one folder, plus per-folder counts.
///
/// Listing is folder-scoped: the send pipeline files accepted mail in `sent`
/// and received/alias/catch-all mail in `inbox`, so each folder lists exactly
/// the messages a client can move or delete from it.
pub async fn list_messages(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        let folder = match enum_param(&params, "folder", &FOLDER_VALUES)? {
            Some(raw) => parse_folder(&raw)?,
            // Documented default: an unqualified listing is the inbox.
            None => MessageFolder::Inbox,
        };
        let limit = int_param(&params, "limit", 100, 1, 500)?;
        let offset = int_param(&params, "offset", 0, 0, i64::MAX)?;
        // The pseudo-folder filter: `?delivered_for=sales@example.com` answers the
        // inbox items that arrived for that shared address. The message stays in
        // `inbox`; only the listing narrows.
        let delivered_for = opt_param(&params, "delivered_for").map(str::to_string);
        if let Some(raw) = &delivered_for {
            pigeon_core::EmailAddress::parse(raw).map_err(|error| {
                validation(vec![FieldError::with_code(
                    "delivered_for",
                    "invalid",
                    format!("delivered_for must be an address: {error}"),
                )])
            })?;
        }
        let (rows, total) = match &delivered_for {
            Some(marker) => (
                state
                    .store
                    .list_delivered_for(context.account_id, marker, limit, offset)
                    .map_err(Problem::from)?,
                state
                    .store
                    .count_delivered_for(context.account_id, marker)
                    .map_err(Problem::from)?,
            ),
            None => (
                state
                    .store
                    .list_folder(context.account_id, folder, limit, offset)
                    .map_err(Problem::from)?,
                state
                    .store
                    .count_folder(context.account_id, folder)
                    .map_err(Problem::from)?,
            ),
        };
        let counts = folder_counts(&state, context.account_id)?;
        let delivered_counts = state
            .store
            .delivered_for_counts(context.account_id)
            .map_err(Problem::from)?;
        let page = crate::models::PageMeta::new(total, offset, rows.len() as i64);
        let items = rows.iter().map(summary).collect();
        Ok(MessagePage {
            items,
            page,
            counts,
            delivered_for_counts: delivered_counts
                .into_iter()
                .map(|(address, count)| DeliveredForCount { address, count })
                .collect(),
        })
    })
    .await;
    match result {
        Ok(page) => Json(page).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `PATCH /v1/messages/{id}` — move a message between folders and/or flip its
/// read state. Returns the updated metadata view.
pub async fn patch_message(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    ProblemJson(patch): ProblemJson<MessagePatch>,
) -> Response {
    let result = blocking(move || {
        let message_id = resolve(&state, context.account_id, &id)?;
        // Both members are optional, but a patch that changes nothing is a
        // client mistake: answering 200 would claim a write that never happened.
        if patch.folder.is_none() && patch.read.is_none() {
            return Err(validation(vec![FieldError::with_code(
                "",
                "required",
                "provide at least one of `folder` or `read`",
            )]));
        }
        let folder = match patch.folder.as_deref() {
            Some(raw) => Some(parse_folder(raw)?),
            None => None,
        };
        if let Some(folder) = folder {
            state
                .store
                .set_message_folder(message_id, folder)
                .map_err(Problem::from)?;
        }
        if let Some(read) = patch.read {
            state
                .store
                .set_message_read(message_id, read)
                .map_err(Problem::from)?;
        }
        let row = state.store.get_message(message_id).map_err(Problem::from)?;
        let mut detail = Vec::new();
        if let Some(folder) = folder {
            detail.push(format!("folder={folder}"));
        }
        if let Some(read) = patch.read {
            detail.push(format!("read={read}"));
        }
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "message.update",
            &format!("{id} {}", detail.join(" ")),
        ) {
            tracing::warn!(%error, %id, "could not write audit row");
        }
        Ok(summary(&row))
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/messages/{id}` — permanent delete of the row and its lifecycle
/// metadata. Ordinary "remove from the inbox" is a folder move to `trash`.
/// The id may be the mailbox `msg_` id or the `eml_` id of an owned sent email
/// ([`resolve_deletable`]); queued mail is refused and must be cancelled.
pub async fn delete_message(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
) -> Response {
    let result = blocking(move || {
        let message_id = resolve_deletable(&state, context.account_id, &id)?;
        // The message row goes first: `DELETE` on a row that is not there is the
        // only failure mode worth reporting, and doing it first means a 404
        // leaves every other table untouched.
        state
            .store
            .delete_message(message_id)
            .map_err(Problem::from)?;
        // Usually already gone through ON DELETE CASCADE; deleting explicitly
        // keeps the operation independent of the pragma.
        if let Err(error) = state.db.delete_api_message(message_id) {
            tracing::warn!(%error, message_id, "could not delete api_messages row");
        }
        if let Err(error) =
            state
                .store
                .audit(&format!("key:{}", context.public_id), "message.delete", &id)
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

/// `POST /v1/messages/empty-trash` — purge the caller's trash folder.
pub async fn empty_trash(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let deleted = state
            .store
            .empty_folder(context.account_id, MessageFolder::Trash)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "messages.empty_trash",
            &format!("deleted={deleted}"),
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(EmptyTrashResult {
            deleted: i64::try_from(deleted).unwrap_or(i64::MAX),
        })
    })
    .await;
    match result {
        Ok(emptied) => Json(emptied).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/messages/purge-trash` — run the retention purge for the caller now.
///
/// The same purge the background worker runs every six hours, on demand: an
/// agent (or a user who just changed the setting) does not have to wait for the
/// interval to see the trash shrink. "Expired" is defined by the account's own
/// retention window, so this endpoint never deletes a message the worker would
/// have kept.
pub async fn purge_trash(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
) -> Response {
    let result = blocking(move || {
        let deleted = state
            .store
            .purge_expired_trash(context.account_id)
            .map_err(Problem::from)?;
        let remaining = state
            .store
            .count_trash(context.account_id)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "messages.purge_trash",
            &format!("deleted={deleted}"),
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(PurgeTrashResult {
            deleted: i64::try_from(deleted).unwrap_or(i64::MAX),
            trash_remaining: remaining,
        })
    })
    .await;
    match result {
        Ok(purged) => Json(purged).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Decode a folder already validated by [`enum_param`] or handed over by a
/// request body.
fn parse_folder(raw: &str) -> Result<MessageFolder, Problem> {
    MessageFolder::parse(raw).ok_or_else(|| {
        validation(vec![FieldError::with_code(
            "folder",
            "invalid",
            format!("folder must be one of {}", FOLDER_VALUES.join("|")),
        )])
    })
}

/// Resolve a public id to its row id for this account, or the `404` that every
/// message endpoint answers for an id the caller does not own.
fn resolve(state: &AppState, account_id: i64, id: &str) -> Result<i64, Problem> {
    if !ids::is_well_formed(id, ids::MSG) {
        return Err(not_found(format!("{id:?} is not a msg_ id")));
    }
    state
        .db
        .message_id_by_public_id(account_id, id)
        .map_err(Problem::from)?
        .ok_or_else(|| not_found(format!("message {id} not found")))
}

/// Resolve the id of `DELETE /v1/messages/{id}`.
///
/// Both id shapes a caller can hold for an owned row are accepted: the mailbox
/// `msg_` id and — for an outbound copy listed on `/v1/emails` — the `eml_` id,
/// which is the only id the webmail holds for the Sent folder. An `eml_` id
/// resolves through the lifecycle row with the same account scoping as the send
/// surface, so a foreign id is the same `404` as an unknown one. A still-queued
/// email must be cancelled instead of deleted, so the delete is refused with
/// `409 not-cancellable` pointing at the cancel route; anything past that
/// deletes permanently, lifecycle row included.
fn resolve_deletable(state: &AppState, account_id: i64, id: &str) -> Result<i64, Problem> {
    if ids::is_well_formed(id, ids::MSG) {
        let message_id = resolve(state, account_id, id)?;
        // The queued guard holds on every id shape a caller can hold — but
        // only while the email still lives in `sent`: the derived `msg_` id is
        // what GET /v1/messages?folder=sent hands out, and an email already
        // moved out of sent (trash purge flows) keeps its pinned hard-delete
        // semantics.
        if let Some((status, folder)) = state
            .db
            .email_status_and_folder_for_message(message_id)
            .map_err(Problem::from)?
        {
            let status = EmailStatus::parse(&status).unwrap_or_default();
            if folder == "sent" && status.is_cancellable() {
                // The cancel route speaks `eml_`: name the id the caller (or
                // the lifecycle row) actually holds for this message.
                let cancel_id = state
                    .db
                    .public_id_for_message(message_id)
                    .map_err(Problem::from)?
                    // The guard only fires when the lifecycle row exists, so
                    // the stored id is always there; the derived eml_ fallback
                    // keeps the named cancel id in the route's id shape.
                    .unwrap_or_else(|| crate::ids::derived(crate::ids::EML, message_id));
                return Err(Problem::new(
                    StatusCode::CONFLICT,
                    ProblemType::NotCancellable,
                    format!(
                        "email {cancel_id} is `{}` and may still be delivered; cancel it with DELETE /v1/emails/{cancel_id} instead",
                        status.as_str()
                    ),
                ));
            }
        }
        return Ok(message_id);
    }
    if !ids::is_well_formed(id, ids::EML) {
        return Err(not_found(format!("{id:?} is not a msg_ or eml_ id")));
    }
    let Some(row) = state
        .db
        .email_by_public_id(account_id, id)
        .map_err(Problem::from)?
    else {
        return Err(not_found(format!("message {id} not found")));
    };
    let status = EmailStatus::parse(&row.status).unwrap_or_default();
    if status.is_cancellable() {
        return Err(Problem::new(
            StatusCode::CONFLICT,
            ProblemType::NotCancellable,
            format!(
                "email {id} is `{}` and may still be delivered; cancel it with DELETE /v1/emails/{id} instead",
                status.as_str()
            ),
        ));
    }
    Ok(row.message_id)
}

/// Metadata view of one stored row.
///
/// The id is the `msg_` form derived from the row id, which is what the
/// `MessagePage.items[].id` pattern in the contract allows and what both
/// `GET /v1/messages/{id}` and [`message_id_by_public_id`] resolve back. A
/// message accepted through `POST /v1/emails` keeps its `eml_` id on the send
/// surface; the mailbox surface speaks `msg_` for every row, whichever pipeline
/// wrote it.
///
/// [`message_id_by_public_id`]: crate::db::ApiDb::message_id_by_public_id
fn summary(row: &MessageRow) -> MessageSummary {
    MessageSummary {
        id: Some(ids::derived(ids::MSG, row.id)),
        from_addr: Some(row.from_addr.to_string()),
        subject: Some(row.subject.clone()),
        created_at: Some(row.created_at.clone()),
        folder: row.folder.as_str().to_string(),
        read: row.read_at.is_some(),
        delivered_for: row.delivered_for.clone(),
    }
}

/// Sidebar counts for every folder of one account.
///
/// Each folder is one counting query that returns both its size and its unread
/// half. `sent` only contributes a size: outbound copies are never unread for
/// the webmail, which never marks them read, so reporting an unread number there
/// would be a badge that can never be cleared.
fn folder_counts(state: &AppState, account_id: i64) -> Result<FolderCounts, Problem> {
    let mut counts = FolderCounts {
        inbox: 0,
        sent: 0,
        spam: 0,
        trash: 0,
        unread_inbox: 0,
        unread_spam: 0,
        unread_trash: 0,
    };
    for folder in MessageFolder::all() {
        match folder {
            MessageFolder::Sent => {
                counts.sent = state
                    .store
                    .count_folder(account_id, *folder)
                    .map_err(Problem::from)?;
            }
            MessageFolder::Inbox | MessageFolder::Spam | MessageFolder::Trash => {
                let (total, unread) = state
                    .store
                    .count_folder_with_unread(account_id, *folder)
                    .map_err(Problem::from)?;
                match folder {
                    MessageFolder::Inbox => {
                        counts.inbox = total;
                        counts.unread_inbox = unread;
                    }
                    MessageFolder::Spam => {
                        counts.spam = total;
                        counts.unread_spam = unread;
                    }
                    MessageFolder::Trash => {
                        counts.trash = total;
                        counts.unread_trash = unread;
                    }
                    MessageFolder::Sent => unreachable!("sent is counted above"),
                }
            }
        }
    }
    Ok(counts)
}

/// `GET /v1/messages/{id}` — sealed view by default, decrypted with scope `full`.
pub async fn get_message(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::MSG) {
            return Err(not_found(format!("{id:?} is not a msg_ id")));
        }
        let sealed = bool_param(&params, "sealed", true)?;
        // Checked before touching the database: plaintext is refused on the
        // credential, not on whether a body happens to exist.
        if !sealed && !context.has_scope(ApiKeyScope::Full) {
            return Err(forbidden(
                "decrypted bodies require an API key with the `full` scope; use the default sealed view",
            ));
        }
        let Some(stored) = state
            .db
            .message_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("message {id} not found")));
        };
        if stored.direction != "in" {
            return Err(not_found(format!("{id} is an outbound email, not a message")));
        }
        let attachments = attachment_views(&state, stored.message_id)?;
        if sealed {
            return Ok(MessageResponse::Sealed(SealedMessageView {
                id,
                from_addr: stored.from_addr,
                to: Some(stored.to_addrs),
                subject: Some(stored.subject),
                created_at: stored.created_at,
                delivered_for: stored.delivered_for,
                sealed_body: base64::engine::general_purpose::STANDARD
                    .encode(&stored.sealed_body),
                auth: AuthVerdict::default(),
                attachments: Some(attachments),
            }));
        }
        let plaintext = open_body(&state, context.account_id, &stored)?;
        let (body_text, body_html) = split_parts(&plaintext);
        Ok(MessageResponse::Decrypted(DecryptedMessageView {
            id,
            from_addr: stored.from_addr,
            to: Some(stored.to_addrs),
            subject: Some(stored.subject),
            created_at: stored.created_at,
            delivered_for: stored.delivered_for,
            body_text,
            body_html,
            attachments: Some(attachments),
            auth: AuthVerdict::default(),
        }))
    })
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /v1/messages/{id}/attachments/{aid}` — bytes, sealed or decrypted.
pub async fn get_attachment(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path((id, aid)): Path<(String, String)>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        if !ids::is_well_formed(&id, ids::MSG) && !ids::is_well_formed(&id, ids::EML) {
            return Err(not_found(format!("{id:?} is not a message id")));
        }
        let sealed = bool_param(&params, "sealed", true)?;
        if !sealed && !context.has_scope(ApiKeyScope::Full) {
            return Err(forbidden(
                "decrypted attachments require an API key with the `full` scope",
            ));
        }
        if !ids::is_well_formed(&aid, ids::ATC) {
            return Err(not_found(format!("{aid:?} is not an atc_ id")));
        }
        let Some(stored) = state
            .db
            .message_by_public_id(context.account_id, &id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("message {id} not found")));
        };
        let attachment_id = i64::from_str_radix(&aid[ids::ATC.len()..], 16)
            .map_err(|_| not_found(format!("{aid:?} is not an atc_ id")))?;
        let Some(attachment) = state
            .db
            .attachment(stored.message_id, attachment_id)
            .map_err(Problem::from)?
        else {
            return Err(not_found(format!("attachment {aid} not found")));
        };
        if sealed {
            return Ok(attachment.sealed_content);
        }
        let content_key = content_key(&state, context.account_id, &stored)?;
        let attachment_aad = aad::attachment(
            context.account_id,
            stored.message_id,
            attachment.ordinal.max(0) as usize,
            &attachment.filename,
        );
        pigeon_crypto::open_content(
            &content_key,
            &attachment.sealed_content,
            attachment_aad.as_bytes(),
        )
        .map_err(|error| internal(format!("could not open attachment: {error}")))
    })
    .await;
    match result {
        Ok(bytes) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            bytes,
        )
            .into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Either view of `GET /v1/messages/{id}` (`oneOf` in the contract).
#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum MessageResponse {
    /// Metadata plus ciphertext (default).
    Sealed(SealedMessageView),
    /// Plaintext (scope `full`).
    Decrypted(DecryptedMessageView),
}

fn attachment_views(
    state: &AppState,
    message_id: i64,
) -> Result<Vec<MessageAttachmentView>, Problem> {
    Ok(state
        .db
        .attachments_for(message_id)
        .map_err(Problem::from)?
        .into_iter()
        .map(|row| MessageAttachmentView {
            id: row.public_id,
            filename: row.filename,
            size: row.size,
        })
        .collect())
}

/// Unwrap the message content key with the master key.
fn content_key(
    state: &AppState,
    account_id: i64,
    stored: &StoredMessage,
) -> Result<[u8; 32], Problem> {
    let Some(wrapped) = stored.wrapped_key.as_ref() else {
        // Inbound messages are sealed by the SMTP pipeline, which does not exist
        // yet: there is no content key to unwrap, so say so instead of
        // pretending the blob is corrupt.
        return Err(Problem::new(
            StatusCode::CONFLICT,
            crate::problem::ProblemType::Unavailable,
            "this message has no wrapped content key yet; inbound decryption lands with the SMTP service",
        ));
    };
    let message_aad = aad::message(account_id, stored.message_id);
    state
        .master_key
        .unwrap_content_key(wrapped, message_aad.as_bytes())
        .map_err(|error| internal(format!("could not unwrap content key: {error}")))
}

/// Open the sealed body of a message.
fn open_body(
    state: &AppState,
    account_id: i64,
    stored: &StoredMessage,
) -> Result<Vec<u8>, Problem> {
    let key = content_key(state, account_id, stored)?;
    let message_aad = aad::message(account_id, stored.message_id);
    pigeon_crypto::open_content(&key, &stored.sealed_body, message_aad.as_bytes())
        .map_err(|error| internal(format!("could not open message body: {error}")))
}

/// Split plaintext into the `body_text` / `body_html` pair.
///
/// Every stored body is a complete RFC822 document — the inbound SMTP path
/// seals the received bytes with our trace header on top, and the send path
/// seals [`crate::mime::build`] output. Clients read a message, not the wire:
/// [`crate::mime_read`] walks the document and extracts the text/html parts.
/// The JSON part pair (`{"text": …, "html": …}`) is kept as the first
/// branch for historical payloads, and a document with no readable text part
/// (PGP armor, binary bodies) is exposed verbatim rather than truncated.
fn split_parts(plaintext: &[u8]) -> (Option<String>, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Parts {
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        html: Option<String>,
    }
    match serde_json::from_slice::<Parts>(plaintext) {
        Ok(parts) => (parts.text, parts.html),
        Err(_) => {
            let (text, html) = crate::mime_read::extract_parts(plaintext);
            if text.is_none() && html.is_none() {
                // Nothing readable in the document (PGP armor, opaque binary
                // parts): expose it as-is instead of silently truncating.
                (Some(String::from_utf8_lossy(plaintext).into_owned()), None)
            } else {
                (text, html)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folder_list_matches_the_domain_enum() {
        assert_eq!(
            FOLDER_VALUES.as_slice(),
            MessageFolder::all()
                .iter()
                .map(|folder| folder.as_str())
                .collect::<Vec<_>>()
                .as_slice(),
            "the query/body allow-list must not drift from MessageFolder"
        );
        for raw in FOLDER_VALUES {
            assert!(parse_folder(raw).is_ok(), "{raw} must parse");
        }
        let error = parse_folder("archive").unwrap_err();
        assert_eq!(error.status, 422);
        assert_eq!(error.errors.as_ref().unwrap()[0].field, "folder");
    }

    #[test]
    fn json_payloads_split_into_text_and_html() {
        let (text, html) = split_parts(br#"{"text":"hi","html":"<p>hi</p>"}"#);
        assert_eq!(text.as_deref(), Some("hi"));
        assert_eq!(html.as_deref(), Some("<p>hi</p>"));
    }

    #[test]
    fn html_only_payloads_leave_text_absent() {
        let (text, html) = split_parts(br#"{"html":"<p>hi</p>"}"#);
        assert!(text.is_none());
        assert_eq!(html.as_deref(), Some("<p>hi</p>"));
    }

    #[test]
    fn simple_documents_read_as_their_body_not_their_headers() {
        // The stored document carries trace/transport headers a reader never
        // asked for; only the body is the message.
        let (text, html) = split_parts(b"Subject: hi\r\n\r\nbody");
        assert_eq!(text.as_deref(), Some("body"));
        assert!(html.is_none());
    }

    #[test]
    fn opaque_payloads_without_readable_parts_are_exposed_verbatim() {
        // A document whose parts are all non-text (PGP/MIME armor) routes to
        // the verbatim fallback: deleting that arm must fail this test.
        let (text, html) = split_parts(
            b"Content-Type: multipart/encrypted; boundary=\"pgp\"\r\n\
              \r\n\
              --pgp\r\n\
              Content-Type: application/pgp-encrypted\r\n\
              \r\n\
              Version: 1\r\n\
              --pgp\r\n\
              Content-Type: application/octet-stream\r\n\
              \r\n\
              -----BEGIN PGP MESSAGE-----\r\n\
              hQEMA\r\n\
              --pgp--\r\n",
        );
        assert!(
            text.as_deref()
                .unwrap_or_default()
                .contains("BEGIN PGP MESSAGE"),
            "the armor must surface verbatim, got {text:?}"
        );
        assert!(html.is_none());
    }

    #[test]
    fn deeply_nested_documents_fall_back_to_verbatim() {
        // Beyond the walk cap the document is exposed verbatim (never lost)
        // instead of crashing the read.
        let mut document =
            String::from("Content-Type: multipart/mixed; boundary=\"d0\"\r\n\r\n--d0\r\n");
        for level in 1..64 {
            document.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"d{level}\"\r\n\r\n--d{level}\r\n"
            ));
        }
        document.push_str("Content-Type: text/plain\r\n\r\ncore\r\n");
        for level in (0..64).rev() {
            document.push_str(&format!("--d{level}--\r\n"));
        }
        let (text, html) = split_parts(document.as_bytes());
        assert!(html.is_none());
        let text = text.expect("verbatim text");
        assert!(
            text.contains("multipart/mixed"),
            "verbatim exposes the wire"
        );
        assert!(text.contains("core"), "nothing is lost");
    }

    #[test]
    fn a_message_without_a_wrapped_key_is_reported_as_such() {
        let stored = StoredMessage {
            message_id: 1,
            public_id: "msg_00000001".to_string(),
            direction: "in".to_string(),
            from_addr: "sender@example.org".to_string(),
            to_addrs: vec!["owner@example.com".to_string()],
            subject: "hi".to_string(),
            sealed_body: vec![0x01; 41],
            created_at: crate::time::iso_now(),
            wrapped_key: None,
            delivered_for: None,
        };
        assert!(stored.wrapped_key.is_none());
        assert_eq!(stored.direction, "in");
    }
}
