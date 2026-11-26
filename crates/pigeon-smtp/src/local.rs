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
    /// A catch-all `discard` rule accepts and drops: terminal for the sender,
    /// nothing stored.
    DiscardRule,
    /// A catch-all `route` rule whose every assignee is paused: accepted and
    /// dropped, same outcome as `DiscardRule` but a distinct cause an operator
    /// needs to see in logs.
    DiscardRouteAllPaused,
    /// Not hosted here: the recipient belongs in the remote MX flow.
    NotLocal,
}

/// Resolve `recipient` in the documented order: exact mailbox, then sender
/// alias, then the domain's catch-all rule.
/// Resolve every recipient in one pass, memoizing per-domain rule/assignee
/// lookups and per-alias holder lookups so a message with N recipients on one
/// catch-all domain costs one rule lookup + one assignee lookup, not N of each
/// (issue #105 R1: the base ingest loop had these caches; the shared extraction
/// dropped them).
pub(crate) fn resolve_all_local(
    store: &SqliteStorage,
    db: &ApiDb,
    catchall: &dyn CatchallSource,
    recipients: &[EmailAddress],
) -> Result<Vec<(EmailAddress, LocalResolution)>> {
    let mut rules: BTreeMap<String, Option<CatchallRuleRow>> = BTreeMap::new();
    let mut assignees: BTreeMap<String, Vec<CatchallAssignmentRow>> = BTreeMap::new();
    let mut alias_holders: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut results = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let resolution = resolve_local_with_caches(
            store,
            db,
            catchall,
            recipient,
            &mut rules,
            &mut assignees,
            &mut alias_holders,
        )?;
        results.push((recipient.clone(), resolution));
    }
    Ok(results)
}

fn resolve_local_with_caches(
    store: &SqliteStorage,
    db: &ApiDb,
    catchall: &dyn CatchallSource,
    recipient: &EmailAddress,
    rules: &mut BTreeMap<String, Option<CatchallRuleRow>>,
    assignees: &mut BTreeMap<String, Vec<CatchallAssignmentRow>>,
    alias_holders: &mut BTreeMap<String, Vec<i64>>,
) -> Result<LocalResolution> {
    if let Some(account_id) = db
        .account_id_by_email(&recipient.normalized())
        .map_err(SmtpError::from)?
    {
        return Ok(LocalResolution::Direct(account_id));
    }
    let normalized = recipient.normalized();
    if !alias_holders.contains_key(&normalized) {
        let holders = store
            .accounts_for_alias(&normalized)
            .map_err(SmtpError::from)?;
        alias_holders.insert(normalized.clone(), holders);
    }
    let holders = alias_holders
        .get(&normalized)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if !holders.is_empty() {
        return Ok(LocalResolution::Alias(holders.to_vec()));
    }
    let domain = recipient.domain().to_string();
    if !rules.contains_key(&domain) {
        let rule = catchall.rule_for(&domain)?;
        rules.insert(domain.clone(), rule);
    }
    match rules.get(&domain).and_then(Option::as_ref) {
        Some(rule) if rule.action == CatchallAction::Route => {
            if !assignees.contains_key(&domain) {
                let rows = catchall.assignees_for(&domain)?;
                assignees.insert(domain.clone(), rows);
            }
            let live: Vec<i64> = assignees
                .get(&domain)
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter(|row| !row.paused)
                .map(|row| row.account_id)
                .collect();
            if live.is_empty() {
                // A route rule with every assignee paused accepts and drops,
                // exactly like `discard`: the domain is configured to take
                // catch-all mail, so refusing it would turn a member's holiday
                // switch into a delivery failure for the sender.
                Ok(LocalResolution::DiscardRouteAllPaused)
            } else {
                Ok(LocalResolution::Catchall(live))
            }
        }
        // Anti-enumeration: accepted, then dropped.
        Some(_) => Ok(LocalResolution::DiscardRule),
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

#[cfg(test)]
mod tests {
    use pigeon_api::db::ApiDb;
    use pigeon_core::types::CatchallAction;
    use pigeon_core::EmailAddress;
    use store::{SqliteStorage, Storage};

    /// Minimal in-memory store for the resolver tests.
    struct TestSetup {
        _dir: tempfile::TempDir,
        store: SqliteStorage,
        db: ApiDb,
        catchall: crate::server::StoreCatchall,
    }

    impl TestSetup {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("test.db");
            let store = SqliteStorage::open(&path).expect("store");
            let db = ApiDb::open(&path).expect("db");
            let catchall = crate::server::StoreCatchall::new(std::sync::Arc::new(
                SqliteStorage::open(&path).expect("store2"),
            ));
            Self {
                _dir: dir,
                store,
                db,
                catchall,
            }
        }

        fn addr(email: &str) -> EmailAddress {
            EmailAddress::parse(email).expect("address")
        }
    }

    fn resolve(setup: &TestSetup, email: &str) -> crate::local::LocalResolution {
        let recipient = TestSetup::addr(email);
        crate::local::resolve_all_local(&setup.store, &setup.db, &setup.catchall, &[recipient])
            .expect("resolve")
            .remove(0)
            .1
    }

    #[test]
    fn direct_resolution_for_an_existing_account() {
        let setup = TestSetup::new();
        let account = setup
            .store
            .create_account(&TestSetup::addr("alice@example.com"))
            .expect("account");
        assert!(matches!(
            resolve(&setup, "alice@example.com"),
            crate::local::LocalResolution::Direct(id) if id == account
        ));
    }

    #[test]
    fn alias_resolution_when_no_mailbox() {
        let setup = TestSetup::new();
        // An alias may only live on a served domain (one with an account on
        // it), so the holder is on the same domain as the alias it holds.
        let holder = setup
            .store
            .create_account(&TestSetup::addr("bob@example.com"))
            .expect("holder");
        let alias = setup
            .store
            .create_alias(&TestSetup::addr("sales@example.com"), holder)
            .expect("alias");
        setup
            .store
            .assign_alias(alias, holder, holder)
            .expect("assign");
        assert!(matches!(
            resolve(&setup, "sales@example.com"),
            crate::local::LocalResolution::Alias(holders) if holders == vec![holder]
        ));
    }

    #[test]
    fn not_local_when_no_mailbox_no_alias_no_catchall() {
        let setup = TestSetup::new();
        assert!(matches!(
            resolve(&setup, "nobody@example.com"),
            crate::local::LocalResolution::NotLocal
        ));
    }

    /// The two accept-and-drop causes are distinct variants: an operator must
    /// be able to tell a `discard` rule from a route whose assignees are all
    /// paused (issue #105 R2: the collapsed log arm lost that distinction).
    #[test]
    fn discard_rule_and_all_paused_route_are_distinct_causes() {
        let setup = TestSetup::new();
        let assignee = setup
            .store
            .create_account(&TestSetup::addr("carol@paused.com"))
            .expect("assignee");
        setup
            .store
            .set_catchall("paused.com", CatchallAction::Route)
            .expect("route rule");
        setup
            .store
            .assign_catchall("paused.com", assignee, assignee)
            .expect("assignee");
        setup
            .store
            .set_catchall_paused("paused.com", assignee, true)
            .expect("pause");
        setup
            .store
            .set_catchall("drop.com", CatchallAction::Discard)
            .expect("discard rule");

        assert!(matches!(
            resolve(&setup, "unknown@paused.com"),
            crate::local::LocalResolution::DiscardRouteAllPaused
        ));
        assert!(matches!(
            resolve(&setup, "unknown@drop.com"),
            crate::local::LocalResolution::DiscardRule
        ));
    }

    #[test]
    fn catchall_route_resolves_to_unpaused_assignees() {
        let setup = TestSetup::new();
        let a = setup
            .store
            .create_account(&TestSetup::addr("a@route.com"))
            .expect("a");
        let b = setup
            .store
            .create_account(&TestSetup::addr("b@route.com"))
            .expect("b");
        setup
            .store
            .set_catchall("route.com", CatchallAction::Route)
            .expect("rule");
        setup
            .store
            .assign_catchall("route.com", a, a)
            .expect("assign a");
        setup
            .store
            .assign_catchall("route.com", b, b)
            .expect("assign b");
        setup
            .store
            .set_catchall_paused("route.com", b, true)
            .expect("pause b");
        assert!(matches!(
            resolve(&setup, "unknown@route.com"),
            crate::local::LocalResolution::Catchall(live) if live == vec![a]
        ));
    }

    #[test]
    fn resolve_all_local_produces_the_same_results_as_individual_calls() {
        let setup = TestSetup::new();
        let a = setup
            .store
            .create_account(&TestSetup::addr("a@example.com"))
            .expect("a");
        let _b = setup
            .store
            .create_account(&TestSetup::addr("b@example.com"))
            .expect("b");
        setup
            .store
            .set_catchall("drop.com", CatchallAction::Discard)
            .expect("rule");
        let recipients: Vec<EmailAddress> =
            ["a@example.com", "b@example.com", "x@drop.com", "x@else.org"]
                .iter()
                .map(|s| TestSetup::addr(s))
                .collect();
        let batch =
            crate::local::resolve_all_local(&setup.store, &setup.db, &setup.catchall, &recipients)
                .expect("batch");
        assert_eq!(batch.len(), 4);
        assert!(matches!(batch[0].1, crate::local::LocalResolution::Direct(id) if id == a));
        assert!(matches!(
            batch[1].1,
            crate::local::LocalResolution::Direct(_)
        ));
        assert!(matches!(
            batch[2].1,
            crate::local::LocalResolution::DiscardRule
        ));
        assert!(matches!(
            batch[3].1,
            crate::local::LocalResolution::NotLocal
        ));
    }
}
