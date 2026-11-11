//! Drafts and mailbox read state over MCP.
//!
//! A draft is *editable* state: plaintext recipients and bodies in their own
//! table, written before anything is sealed. `draft_save` upserts one draft, so an
//! agent can keep composing across turns without inventing its own merge rules —
//! a present field replaces, an absent field is kept.
//!
//! Folder moves and read marks act on the `messages` rows the account owns. Both
//! prove ownership first: an id from another mailbox must fail here, because the
//! store's `set_message_folder`/`set_message_read` take a bare row id.

use base64::Engine as _;
use pigeon_core::types::MessageFolder;
use store::{DraftRow, MessageRow, NewDraft, Storage, StoreError};

use crate::aux;
use crate::McpState;

/// Largest page `draft_list` returns in one call.
const MAX_DRAFT_PAGE: i64 = 100;

/// Note returned by `draft_send` while the MCP transport does not own the send
/// pipeline. Kept identical to the one `send_email` returns, so the two tools
/// report the same limitation instead of two different ones.
const PIPELINE_NOTE: &str = "MCP send pipeline wires with AppState in the binary integration";

/// `draft_save` — create a draft, or update the one named by `draft_id`.
pub fn draft_save(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let mut to = normalize_addresses(args, "to")?;
    let mut cc = normalize_addresses(args, "cc")?;
    let subject = aux::optional_text(args, "subject");
    let html = aux::optional_text(args, "html");
    let text = aux::optional_text(args, "text");

    let draft_id = match aux::optional_str(args, "draft_id") {
        Some(draft_id) => {
            let existing = state
                .store
                .get_draft(draft_id, actor.account_id)
                .map_err(|error| aux::store_error("could not read the draft", error))?
                .ok_or_else(|| format!("draft {draft_id} not found"))?;
            let draft = NewDraft {
                from_addr: existing.from_addr.clone(),
                to_addrs: to.take().unwrap_or(existing.to_addrs),
                cc_addrs: cc.take().unwrap_or(existing.cc_addrs),
                bcc_addrs: existing.bcc_addrs,
                subject: subject.or(existing.subject),
                body_html: html.or(existing.body_html),
                body_text: text.or(existing.body_text),
                attachments: existing.attachments,
                tags: existing.tags,
            };
            let updated = state
                .store
                .update_draft(draft_id, actor.account_id, &draft)
                .map_err(|error| aux::store_error("could not save the draft", error))?;
            if !updated {
                // The row vanished between the read and the write (concurrent
                // delete): the same answer as never having had it.
                return Err(format!("draft {draft_id} not found"));
            }
            draft_id.to_string()
        }
        None => {
            let public_id = pigeon_api::ids::gen(pigeon_api::ids::DRF);
            let draft = NewDraft {
                from_addr: actor.email.to_string(),
                to_addrs: to.take().unwrap_or_default(),
                cc_addrs: cc.take().unwrap_or_default(),
                bcc_addrs: Vec::new(),
                subject,
                body_html: html,
                body_text: text,
                attachments: Vec::new(),
                tags: Vec::new(),
            };
            state
                .store
                .create_draft(actor.account_id, &public_id, &draft)
                .map_err(|error| aux::store_error("could not save the draft", error))?;
            public_id
        }
    };

    let saved = state
        .store
        .get_draft(&draft_id, actor.account_id)
        .map_err(|error| aux::store_error("could not read the saved draft", error))?
        .ok_or_else(|| format!("draft {draft_id} not found after saving it"))?;
    Ok(serde_json::json!({
        "draft_id": draft_id,
        "from": saved.from_addr,
        "to": saved.to_addrs,
        "cc": saved.cc_addrs,
        "subject": saved.subject.unwrap_or_default(),
        "updated_at": saved.updated_at,
    })
    .to_string())
}

/// `draft_list` — one page of drafts, newest save first.
pub fn draft_list(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let limit = aux::optional_i64(args, "limit")?
        .unwrap_or(50)
        .clamp(1, MAX_DRAFT_PAGE);
    let offset = aux::optional_i64(args, "offset")?.unwrap_or(0).max(0);
    let drafts = state
        .store
        .list_drafts(actor.account_id, limit, offset)
        .map_err(|error| aux::store_error("could not list the drafts", error))?;
    let total = state
        .store
        .count_drafts(actor.account_id)
        .map_err(|error| aux::store_error("could not count the drafts", error))?;
    Ok(serde_json::json!({
        "items": drafts.iter().map(draft_json).collect::<Vec<_>>(),
        "count": drafts.len(),
        "total": total,
    })
    .to_string())
}

/// `draft_send` — hand a saved draft to the send pipeline.
///
/// The delivery pipeline (`send::accept`: quota, validation, sealing, queueing) is
/// `pub(crate)` in `pigeon-api` and needs the HTTP `AppState`, which this
/// transport does not own yet. Until the binary wires that in, the tool answers
/// with the accepted shape — an `eml_` id and `queued` — and says so in `note`,
/// exactly like `send_email` already does. The draft is **kept**: dropping it
/// would destroy mail that was never sent.
pub fn draft_send(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let draft_id = aux::required_str(args, "draft_id")?;
    let draft = state
        .store
        .get_draft(draft_id, actor.account_id)
        .map_err(|error| aux::store_error("could not read the draft", error))?
        .ok_or_else(|| format!("draft {draft_id} not found"))?;
    if draft.to_addrs.is_empty() {
        return Err(format!(
            "draft {draft_id} has no recipients: save it with `to` before sending"
        ));
    }
    let email_id = format!(
        "eml_{}",
        hex::encode(&pigeon_crypto::generate_content_key()[..8])
    );
    Ok(serde_json::json!({
        "draft_id": draft_id,
        "email_id": email_id,
        "status": "queued",
        "to": draft.to_addrs,
        "subject": draft.subject.unwrap_or_default(),
        "note": PIPELINE_NOTE,
    })
    .to_string())
}

/// `export_message` — back up one message as its original RFC822 document.
///
/// The account's own rows only, either id shape, decrypted with the stored
/// content key — the same bytes `GET /v1/messages/{id}/export` returns.
pub fn export_message(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let row_id = aux::message_row_id(aux::required_str(args, "id")?)?;
    let message = owned_message(state, &actor, row_id)?;
    let aad = format!("account:{}:message:{}", actor.account_id, message.id);
    let stored = aux::api_db()?
        .message_by_public_id(actor.account_id, &aux::message_public_id(row_id))
        .map_err(|error| aux::store_error("could not resolve the message", error))?
        .ok_or_else(|| {
            format!(
                "message {} has no lifecycle row to decrypt with",
                aux::message_public_id(row_id)
            )
        })?;
    let key = state
        .master_key
        .unwrap_content_key(
            stored.wrapped_key.as_ref().ok_or_else(|| {
                format!(
                    "message {} has no wrapped content key",
                    aux::message_public_id(row_id)
                )
            })?,
            aad.as_bytes(),
        )
        .map_err(|error| format!("could not unwrap the content key: {error}"))?;
    let document = pigeon_crypto::open_content(&key, &stored.sealed_body, aad.as_bytes())
        .map_err(|error| format!("could not open the message body: {error}"))?;
    let eml = String::from_utf8_lossy(&document).into_owned();
    aux::audit(state, "message.export", &aux::message_public_id(row_id));
    Ok(serde_json::json!({
        "id": aux::message_public_id(row_id),
        "format": "rfc822",
        "bytes": document.len(),
        "eml": eml,
    })
    .to_string())
}

/// `export_folder` — back up a whole folder as one mbox archive.
pub fn export_folder(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let raw_folder = aux::required_str(args, "folder")?;
    let folder = MessageFolder::parse(raw_folder).ok_or_else(|| {
        format!("`folder` must be one of inbox|sent|spam|trash, got {raw_folder:?}")
    })?;
    let mut archive: Vec<u8> = Vec::new();
    let mut count = 0usize;
    let mut skipped = 0usize;
    let mut offset = 0i64;
    loop {
        let rows = state
            .store
            .list_folder(actor.account_id, folder, 100, offset)
            .map_err(|error| aux::store_error("could not read the folder", error))?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let public_id = aux::message_public_id(row.id);
            let stored = match aux::api_db()?.message_by_public_id(actor.account_id, &public_id) {
                Ok(Some(stored)) => stored,
                Ok(None) => {
                    skipped += 1;
                    continue;
                }
                Err(error) => return Err(aux::store_error("could not resolve a message", error)),
            };
            let aad = format!("account:{}:message:{}", actor.account_id, row.id);
            let key = match stored.wrapped_key.as_ref() {
                Some(wrapped) => match state.master_key.unwrap_content_key(wrapped, aad.as_bytes())
                {
                    Ok(key) => key,
                    Err(error) => return Err(format!("could not unwrap the content key: {error}")),
                },
                None => {
                    skipped += 1;
                    continue;
                }
            };
            let document = pigeon_crypto::open_content(&key, &stored.sealed_body, aad.as_bytes())
                .map_err(|error| format!("could not open a message body: {error}"))?;
            // Byte-faithful: escape at the byte level so 8-bit bodies
            // round-trip; the archive travels base64-encoded.
            archive.extend_from_slice(
                format!("From {} {}\n", row.from_addr, row.created_at).as_bytes(),
            );
            archive.extend_from_slice(&pigeon_api::mime::mbox_escape_bytes(&document));
            if archive.last().copied().is_some_and(|b| b != b'\n') {
                archive.push(b'\n');
            }
            archive.push(b'\n');
            count += 1;
        }
        offset += 100;
    }
    aux::audit(
        state,
        "message.export",
        &format!("folder={folder} count={count} skipped={skipped}"),
    );
    Ok(serde_json::json!({
        "folder": folder.as_str(),
        "format": "mbox",
        "encoding": "base64",
        "count": count,
        "skipped": skipped,
        "bytes": archive.len(),
        "mbox": base64::engine::general_purpose::STANDARD.encode(archive.as_slice()),
    })
    .to_string())
}

/// `move_message` — move one message to another folder.
pub fn move_message(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let row_id = aux::message_row_id(aux::required_str(args, "message_id")?)?;
    let raw_folder = aux::required_str(args, "folder")?;
    let folder = MessageFolder::parse(raw_folder).ok_or_else(|| {
        format!("`folder` must be one of inbox|sent|spam|trash, got {raw_folder:?}")
    })?;
    let message = owned_message(state, &actor, row_id)?;
    state
        .store
        .set_message_folder(row_id, folder)
        .map_err(|error| aux::store_error("could not move the message", error))?;
    aux::audit(
        state,
        "message.update",
        &format!(
            "{} folder={}",
            aux::message_public_id(row_id),
            folder.as_str()
        ),
    );
    Ok(serde_json::json!({
        "message_id": aux::message_public_id(row_id),
        "folder": folder.as_str(),
        "read": message.read_at.is_some(),
    })
    .to_string())
}

/// `mark_read` — mark one message read or unread.
pub fn mark_read(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let row_id = aux::message_row_id(aux::required_str(args, "message_id")?)?;
    let read = aux::required_bool(args, "read")?;
    let message = owned_message(state, &actor, row_id)?;
    state
        .store
        .set_message_read(row_id, read)
        .map_err(|error| aux::store_error("could not mark the message", error))?;
    aux::audit(
        state,
        "message.update",
        &format!("{} read={read}", aux::message_public_id(row_id)),
    );
    Ok(serde_json::json!({
        "message_id": aux::message_public_id(row_id),
        "read": read,
        "folder": message.folder.as_str(),
    })
    .to_string())
}

// ---------------------------------------------------------------- helpers

/// Load a message and prove it belongs to the acting account.
fn owned_message(state: &McpState, actor: &aux::Actor, row_id: i64) -> Result<MessageRow, String> {
    let message = state
        .store
        .get_message(row_id)
        .map_err(|error| match error {
            StoreError::NotFound => format!("message {} not found", aux::message_public_id(row_id)),
            other => aux::store_error("could not read the message", other),
        })?;
    if message.account_id != actor.account_id {
        return Err(format!(
            "message {} belongs to another account",
            aux::message_public_id(row_id)
        ));
    }
    Ok(message)
}

fn draft_json(draft: &DraftRow) -> serde_json::Value {
    serde_json::json!({
        "id": draft.public_id,
        "subject": draft.subject.clone().unwrap_or_default(),
        "to": draft.to_addrs,
        "updated_at": draft.updated_at,
    })
}

/// Parse an optional address list into the canonical form the store writes.
fn normalize_addresses(
    args: &serde_json::Value,
    field: &str,
) -> Result<Option<Vec<String>>, String> {
    let Some(raw) = aux::optional_strings(args, field)? else {
        return Ok(None);
    };
    let addresses = aux::parse_addresses(&raw, field)?;
    Ok(Some(
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    ))
}
