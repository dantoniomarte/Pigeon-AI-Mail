//! Local-recipient resolution and storage, shared by the inbound SMTP server
//! and the delivery worker (issue #100).
//!
//! Before this module the two paths disagreed: the inbound server resolved
//! recipients against the store (mailbox → sender alias → catch-all rule) and
//! sealed a copy per account, while the outbound worker always opened an SMTP
//! transaction to the recipient's MX — even when that MX was its own server.
//! Self-delivery then depended on hairpin NAT, container DNS and the outbound
//! STARTTLS policy, and failed terminally whenever any of those five layers
//! shifted. Both callers now share this module: one resolver, one storage
//! path, one behavior.

use std::collections::BTreeMap;

use pigeon_api::db::ApiDb;
use pigeon_api::handlers::wkd::INBOUND_E2E;
use pigeon_core::types::CatchallAction;
use pigeon_core::{Direction, EmailAddress};
use pigeon_crypto::MasterKey;
use store::{CatchallAssignmentRow, CatchallRuleRow, NewMessage, SqliteStorage, Storage};

use crate::error::{Result, SmtpError};
use crate::server::{decode_rfc2047, parse_message, CatchallSource};

/// How one recipient resolved against this deployment.
#[derive(Debug, Clone)]
pub(crate) enum LocalResolution {
    /// The address belongs to the account itself.
    Direct(i64),
    /// The address is a sender alias: every holder gets a sealed copy marked
    /// with the address it arrived for.
    Alias(Vec<i64>),
    /// The domain's catch-all route assigns the message to these (unpaused)
    /// accounts, each marked with the address it arrived for.
    Catchall(Vec<i64>),
    /// A catch-all rule accepts and drops (`discard`, or a route whose every
    /// assignee is paused): terminal for the sender, nothing stored.
    Discard,
    /// Not hosted here: the recipient belongs in the remote MX flow.
    NotLocal,
}

/// Resolve `recipient` in the documented order: exact mailbox, then sender
/// alias, then the domain's catch-all rule.
pub(crate) fn resolve_local(
    store: &SqliteStorage,
    db: &ApiDb,
    catchall: &dyn CatchallSource,
    recipient: &EmailAddress,
) -> Result<LocalResolution> {
    if let Some(account_id) = db
        .account_id_by_email(&recipient.normalized())
        .map_err(SmtpError::from)?
    {
        return Ok(LocalResolution::Direct(account_id));
    }
    let normalized = recipient.normalized();
    let holders = store
        .accounts_for_alias(&normalized)
        .map_err(SmtpError::from)?;
    if !holders.is_empty() {
        return Ok(LocalResolution::Alias(holders));
    }
    let domain = recipient.domain().to_string();
    let rule: Option<CatchallRuleRow> = catchall.rule_for(&domain)?;
    match rule {
        Some(rule) if rule.action == CatchallAction::Route => {
            let rows: Vec<CatchallAssignmentRow> = catchall.assignees_for(&domain)?;
            let live: Vec<i64> = rows
                .iter()
                .filter(|row| !row.paused)
                .map(|row| row.account_id)
                .collect();
            if live.is_empty() {
                // A route rule with every assignee paused accepts and drops,
                // exactly like `discard`: the domain is configured to take
                // catch-all mail, so refusing it would turn a member's holiday
                // switch into a delivery failure for the sender.
                Ok(LocalResolution::Discard)
            } else {
                Ok(LocalResolution::Catchall(live))
            }
        }
        // Anti-enumeration: accepted, then dropped.
        Some(_) => Ok(LocalResolution::Discard),
        None => Ok(LocalResolution::NotLocal),
    }
}

/// One sealed copy to write: who receives it, and under which shared-address
/// marker. `via` is the event fragment the mailbox owner reads to tell "own
/// address" (empty) from "shared alias" (` via=alias`) and from "catch-all
/// route" (` via=catchall`).
#[derive(Debug, Clone)]
pub(crate) struct LocalCopy {
    pub account_id: i64,
    pub delivered_for: Option<String>,
    pub via: &'static str,
    pub recipient: EmailAddress,
}

/// Seal and store one inbound copy per `(account, delivered_for)` group —
/// the exact storage path the inbound server uses: the `messages` row, the
/// `api_messages` row the API read path opens bodies from, and the
/// `email.received` event. Two recipients that resolve to the same account
/// and marker share one sealed body; the body is the document verbatim (for
/// the worker: the prepared, DKIM-signed MIME, the same bytes a remote MX
/// would have received). Returns the stored message ids in group order.
pub(crate) fn store_local_copies(
    store: &SqliteStorage,
    db: &ApiDb,
    master_key: &MasterKey,
    from: EmailAddress,
    origin: &str,
    document: &[u8],
    copies: &[LocalCopy],
) -> Result<Vec<i64>> {
    let parsed = parse_message(document);
    let subject = decode_rfc2047(parsed.header("Subject").unwrap_or_default());

    let mut per_account: BTreeMap<(i64, Option<String>), Vec<&LocalCopy>> = BTreeMap::new();
    for copy in copies {
        per_account
            .entry((copy.account_id, copy.delivered_for.clone()))
            .or_default()
            .push(copy);
    }

    let mut stored_ids = Vec::new();
    for ((account_id, delivered_for), group) in per_account {
        let via = group[0].via;
        let recipients: Vec<EmailAddress> =
            group.iter().map(|copy| copy.recipient.clone()).collect();
        let message_id = store.reserve_message_id()?;
        let message_aad = format!("account:{account_id}:message:{message_id}");
        let content_key = pigeon_crypto::generate_content_key();
        let wrapped_key = master_key
            .wrap_content_key(&content_key, message_aad.as_bytes())
            .map_err(store::StoreError::from)?;
        let sealed_body =
            pigeon_crypto::seal_content(&content_key, document, message_aad.as_bytes())
                .map_err(store::StoreError::from)?;
        store
            .insert_message(
                NewMessage {
                    account_id,
                    direction: Direction::In,
                    from_addr: from.clone(),
                    to_addrs: recipients.clone(),
                    subject: subject.clone(),
                    sealed_body,
                    idempotency_key: None,
                    delivered_for,
                },
                message_id,
            )
            .map_err(SmtpError::from)?;

        // The wrapped content key lives in `api_messages` (the API's read path
        // opens bodies from there). Without this row the body would be
        // unrecoverable, so a failure here is a failure of the whole copy.
        db.insert_email(&pigeon_api::db::NewEmail {
            account_id,
            message_id,
            public_id: pigeon_api::ids::derived(pigeon_api::ids::MSG, message_id),
            status: "received".to_string(),
            to_addrs: recipients.iter().map(ToString::to_string).collect(),
            cc_addrs: Vec::new(),
            tags: Vec::new(),
            sandbox: false,
            // The copy is sealed at rest by the receiving server — identical
            // semantics to an inbound accept, transport differences aside
            // (local delivery never crosses a network at all).
            e2e: INBOUND_E2E.as_str().to_string(),
            wrapped_key,
        })?;

        // Recorded on the row so a mailbox owner can tell "this arrived because I
        // own the address" from "this arrived for a shared alias" and from "the
        // domain routes unknown addresses here".
        let delivered = match &group[0].delivered_for {
            Some(address) => format!(" delivered_for={address}"),
            None => String::new(),
        };
        store.record_event(
            message_id,
            "email.received",
            &format!("from={from} {origin}{via}{delivered}"),
        )?;
        stored_ids.push(message_id);
    }
    Ok(stored_ids)
}
