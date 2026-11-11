//! End-to-end: an agent backs mail up over MCP — one message as its original
//! RFC822 document, a folder as an mbox archive.
//!
//! The tools are driven through [`pigeon_mcp::tools::dispatch`], the same
//! entry point `tools/call` uses, against a real `SqliteStorage` on a real
//! tempdir database with a real sealed, wrapped document — nothing stubbed.
//! Backups that only backed up metadata would be worthless: the assertion is
//! on the decrypted bytes.

use std::sync::Arc;

use base64::Engine as _;
use pigeon_core::Direction;
use pigeon_core::EmailAddress;
use pigeon_crypto::MasterKey;
use pigeon_mcp::{tools, McpState};
use serde_json::{json, Value};
use store::{NewMessage, SqliteStorage, Storage};

/// The bootstrap account every MCP tool acts as (`aux::DEFAULT_ACCOUNT_ID`).
const ACTOR_EMAIL: &str = "admin@pigeon.local";

fn state() -> (
    tempfile::TempDir,
    McpState,
    Arc<SqliteStorage>,
    pigeon_api::db::ApiDb,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pigeon.db");

    let store = Arc::new(SqliteStorage::open(&path).expect("open store"));
    let account = EmailAddress::parse(ACTOR_EMAIL).expect("account address");
    let account_id = store.create_account(&account).expect("create account");
    assert_eq!(account_id, 1, "the bootstrap account is account 1");
    let api_db = Arc::new(pigeon_api::db::ApiDb::open(&path).expect("test api db"));
    let state = McpState {
        store: Arc::clone(&store),
        master_key: Arc::new(MasterKey::parse(&[0xb7u8; 32]).expect("master key")),
        api_db: Arc::clone(&api_db),
        db_path: path.clone(),
    };
    let db = pigeon_api::db::ApiDb::open(&path).expect("test api db");
    (dir, state, store, db)
}

async fn call(state: &McpState, name: &str, args: Value) -> Value {
    let text = tools::dispatch(name, &args, state)
        .await
        .unwrap_or_else(|error| panic!("{name} failed: {error}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{name} did not return JSON: {error} in {text}"))
}

/// Seed one stored message with a sealed RFC822 document and its wrapped
/// content key in the lifecycle table, exactly the inbound pipeline's shape.
fn seed_message(
    state: &McpState,
    api_db: &pigeon_api::db::ApiDb,
    subject: &str,
    document: &str,
) -> i64 {
    let store = &state.store;
    let reserved = store.reserve_message_id().expect("reserve id");
    let aad = format!("account:1:message:{reserved}");
    let content_key = pigeon_crypto::generate_content_key();
    let sealed = pigeon_crypto::seal_content(&content_key, document.as_bytes(), aad.as_bytes())
        .expect("seal body");
    let wrapped = state
        .master_key
        .wrap_content_key(&content_key, aad.as_bytes())
        .expect("wrap key");
    store
        .insert_message(
            NewMessage {
                account_id: 1,
                direction: Direction::In,
                from_addr: EmailAddress::parse("friend@example.org").expect("sender"),
                to_addrs: vec![EmailAddress::parse("admin@pigeon.local").expect("recipient")],
                subject: subject.to_string(),
                sealed_body: sealed,
                idempotency_key: None,
                delivered_for: None,
            },
            reserved,
        )
        .expect("insert message");
    // The lifecycle row with the wrapped content key, exactly what the
    // inbound pipeline records (the test's own ApiDb connection).
    api_db
        .insert_email(&pigeon_api::db::NewEmail {
            account_id: 1,
            message_id: reserved,
            public_id: pigeon_mcp::aux::message_public_id(reserved),
            status: "received".to_string(),
            to_addrs: vec!["admin@pigeon.local".to_string()],
            cc_addrs: Vec::new(),
            tags: Vec::new(),
            sandbox: false,
            e2e: "tls_only".to_string(),
            wrapped_key: wrapped,
        })
        .expect("lifecycle row");
    reserved
}

#[tokio::test]
async fn an_agent_exports_one_message_as_eml_and_a_folder_as_mbox() {
    let (_dir, state, _store, api_db) = state();

    let document = "Received: from mx.test by mail.example.com\r\n\
                    Subject: keep me\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    From the top, this is stored mail.\r\n\
                    >From the quoted reply.\r\n\
                    From the bottom too.\r\n";
    seed_message(&state, &api_db, "keep me", document);

    // One message: the original wire document, decrypted.
    let listing = call(&state, "list_messages", json!({})).await;
    let id = listing["items"][0]["id"].as_str().expect("id").to_string();
    let exported = call(&state, "export_message", json!({ "id": id })).await;
    let eml = exported["eml"].as_str().expect("eml text");
    assert!(eml.contains("Subject: keep me"), "{eml}");
    assert!(eml.contains("From the top, this is stored mail."), "{eml}");

    // The whole folder: an mbox archive with mboxrd escaping (bare and quoted
    // From_ lines both gain one '>'). The archive is byte-faithful, so it
    // travels base64-encoded with its byte size (8-bit mail round-trips).
    let folder = call(&state, "export_folder", json!({ "folder": "inbox" })).await;
    assert_eq!(folder["encoding"], "base64", "{folder}");
    assert!(folder["bytes"].as_u64().expect("byte size") > 0);
    let mbox = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(folder["mbox"].as_str().expect("mbox b64"))
            .expect("base64"),
    )
    .expect("archive");
    assert!(mbox.starts_with("From "), "mbox separator: {mbox}");
    assert!(mbox.contains("Subject: keep me"));
    assert!(
        mbox.contains(">From the top, this is stored mail."),
        "{mbox}"
    );
    assert!(mbox.contains(">>From the quoted reply."), "{mbox}");
    assert!(folder["count"].as_u64().expect("count") >= 1);
    // The latin-1 test below proves the bytes themselves survive; here the
    // decoded archive must be byte-identical to what the API endpoint ships.

    // The export tool accepts both id shapes (the sent UI holds eml_ ids).
    let sent_row = seed_message(
        &state,
        &api_db,
        "sent copy",
        "Subject: sent copy\r\nContent-Type: text/plain\r\n\r\nsent body\r\n",
    );
    let eml_id = format!("eml_{sent_row:08x}");
    let by_eml = call(&state, "export_message", json!({ "id": eml_id })).await;
    assert!(
        by_eml["eml"].as_str().expect("eml").contains("sent body"),
        "{by_eml}"
    );

    // Byte fidelity: a latin-1 stored document round-trips byte-identically
    // through the base64 archive (no lossy decode anywhere).
    // Latin-1 bytes via a byte string (\xF1 is invalid in a str escape).
    let latin1_doc: &[u8] = b"Subject: latin-1 mcp\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nespa\xF1ol\r\n";
    {
        let store = &state.store;
        let reserved = store.reserve_message_id().expect("reserve id");
        let aad = format!("account:1:message:{reserved}");
        let content_key = pigeon_crypto::generate_content_key();
        let sealed = pigeon_crypto::seal_content(&content_key, latin1_doc, aad.as_bytes())
            .expect("seal body");
        let wrapped = state
            .master_key
            .wrap_content_key(&content_key, aad.as_bytes())
            .expect("wrap key");
        store
            .insert_message(
                NewMessage {
                    account_id: 1,
                    direction: Direction::In,
                    from_addr: EmailAddress::parse("friend@example.org").expect("sender"),
                    to_addrs: vec![EmailAddress::parse("admin@pigeon.local").expect("recipient")],
                    subject: "latin-1 mcp".to_string(),
                    sealed_body: sealed,
                    idempotency_key: None,
                    delivered_for: None,
                },
                reserved,
            )
            .expect("insert message");
        api_db
            .insert_email(&pigeon_api::db::NewEmail {
                account_id: 1,
                message_id: reserved,
                public_id: pigeon_mcp::aux::message_public_id(reserved),
                status: "received".to_string(),
                to_addrs: vec!["admin@pigeon.local".to_string()],
                cc_addrs: Vec::new(),
                tags: Vec::new(),
                sandbox: false,
                e2e: "tls_only".to_string(),
                wrapped_key: wrapped,
            })
            .expect("lifecycle row");
    }
    let folder = call(&state, "export_folder", json!({ "folder": "inbox" })).await;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(folder["mbox"].as_str().expect("mbox b64"))
        .expect("base64");
    let needle: &[u8] = b"espa\xF1ol";
    assert!(
        raw.windows(needle.len()).any(|w| w == needle),
        "8-bit bytes must survive the MCP archive"
    );

    // A foreign or unknown id is a clean error, never a leak.
    let error = tools::dispatch("export_message", &json!({ "id": "msg_00ffffff" }), &state)
        .await
        .expect_err("unknown id must fail");
    assert!(error.contains("not found"), "{error}");
}

#[tokio::test]
async fn an_agent_sends_real_mail_and_manages_real_webhooks() {
    let (_dir, state, _store, api_db) = state();

    // A real send: the queue must gain a job the SMTP worker would claim, and
    // the lifecycle row must exist for the returned eml_ id.
    let sent = call(
        &state,
        "send_email",
        json!({
            "to": ["peer@example.org"],
            "subject": "agent hello",
            "text": "sent through the real pipeline"
        }),
    )
    .await;
    eprintln!("SEND-RESPONSE: {sent}");
    assert_eq!(sent["status"], "queued", "{sent}");
    let email_id = sent["id"].as_str().expect("eml id").to_string();
    assert!(email_id.starts_with("eml_"), "{sent}");
    // The queue the pipeline wrote (through its own connection) must hold the
    // job; claim through the test's store handle (same file, WAL-shared).
    let fresh = pigeon_api::db::ApiDb::open(&state.db_path).expect("fresh conn");
    let via_fresh = fresh
        .queue_rows_debug()
        .unwrap_or_else(|e| vec![format!("debug error: {e}")])
        .join("; ");
    eprintln!("QUEUE-VIA-FRESH: {via_fresh}");
    let row = state
        .store
        .queue_claim("test-worker", 60)
        .expect("claim")
        .unwrap_or_else(|| panic!("queue must hold the job; fresh conn: {via_fresh}"));
    let stored = api_db
        .email_by_public_id(1, &email_id)
        .expect("lookup")
        .expect("lifecycle row must exist for the returned id");
    assert_eq!(stored.message_id, row.message_id, "{sent}");
    assert_eq!(stored.status, "queued", "{sent}");

    // Webhooks: create, list, delete — real rows, real responses.
    let created = call(
        &state,
        "manage_webhooks",
        json!({ "action": "create", "url": "https://hooks.example.org/agent", "events": ["delivered"] }),
    )
    .await;
    assert_eq!(created["status"], "created", "{created}");
    let hook_id = created["id"].as_str().expect("webhook id").to_string();
    let listed = call(&state, "manage_webhooks", json!({ "action": "list" })).await;
    let hooks = listed["webhooks"].as_array().expect("webhooks");
    assert_eq!(hooks.len(), 1, "{listed}");
    assert_eq!(hooks[0]["url"], "https://hooks.example.org/agent");
    let deleted = call(
        &state,
        "manage_webhooks",
        json!({ "action": "delete", "id": hook_id }),
    )
    .await;
    assert_eq!(deleted["status"], "deleted", "{deleted}");
    let after = call(&state, "manage_webhooks", json!({ "action": "list" })).await;
    assert_eq!(after["webhooks"].as_array().expect("webhooks").len(), 0);
}

#[tokio::test]
async fn an_agent_sends_a_saved_draft_through_the_real_pipeline() {
    let (_dir, state, _store, api_db) = state();

    // Save a draft with cc recipients.
    let saved = call(
        &state,
        "draft_save",
        json!({
            "id": "welcome-draft",
            "to": ["peer@example.org"],
            "cc": ["observer@example.org"],
            "subject": "draft pipeline",
            "text": "sent from a saved draft"
        }),
    )
    .await;
    let draft_id = saved["draft_id"].as_str().expect("draft id").to_string();

    // Send it: the real pipeline runs, the queue gains a job, the lifecycle
    // row is `queued`, the cc recipients ride the request, and the draft is
    // KEPT (destroying it would lose mail that was never sent).
    let sent = call(&state, "draft_send", json!({ "draft_id": draft_id })).await;
    eprintln!("DRAFT-SEND-RESPONSE: {sent}");
    assert_eq!(sent["status"], "queued", "{sent}");
    let email_id = sent["email_id"].as_str().expect("eml id").to_string();
    assert!(email_id.starts_with("eml_"), "{sent}");

    let row = state
        .store
        .queue_claim("draft-test-worker", 60)
        .expect("claim")
        .expect("queue must hold the drafted send");
    let stored = api_db
        .email_by_public_id(1, &email_id)
        .expect("lookup")
        .expect("lifecycle row");
    assert_eq!(stored.message_id, row.message_id);
    assert_eq!(stored.status, "queued");
    // The cc recipients ride the request: a mutation that drops them must
    // fail here (same silent-unmail class the send_email cc defect was).
    assert_eq!(stored.cc_addrs, vec!["observer@example.org".to_string()]);

    // The draft survives the send.
    let drafts = call(&state, "draft_list", json!({})).await;
    let listed = drafts["items"].as_array().expect("items");
    assert!(
        listed
            .iter()
            .any(|d| d["id"].as_str() == Some(draft_id.as_str())),
        "the draft must be kept after sending: {drafts}"
    );
}
