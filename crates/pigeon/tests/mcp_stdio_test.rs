//! End-to-end test: spawn the real binary in MCP mode, speak JSON-RPC over
//! stdio, verify the protocol and the whole tool surface.
//!
//! The database is seeded before the server starts, the way a real deployment is:
//! `pigeon keygen` creates the bootstrap account (id 1, the account every tool
//! acts as) and inbound SMTP stores a message. Everything after that happens
//! through the MCP tools, exactly as an agent would drive them.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use pigeon_core::{Direction, EmailAddress};
use pigeon_crypto::MasterKey;
use store::{NewMessage, SqliteStorage, Storage};

/// The tool surface: 5 messaging + 28 administration tools.
///
/// `catchall_pause`/`catchall_resume` and the four `alias_*` tools joined the
/// surface with sender aliases + the multi-assignee catch-all: the two backup export tools bring the catalog to 35.
const TOOL_COUNT: usize = 35;

/// The bootstrap account the tools act as.
const ACTOR_EMAIL: &str = "admin@pigeon.local";

/// Seed the database the binary will open: the bootstrap account and one inbound
/// message, so the folder tools have something to move.
fn seed_database(db: &Path) {
    // The master key file holds 64 hex characters = 32 bytes of 0xaa.
    let master_key = MasterKey::parse(&[0xaau8; 32]).expect("master key");
    let store = SqliteStorage::open(db).expect("open store");
    let account = EmailAddress::parse(ACTOR_EMAIL).expect("account address");
    let account_id = store.create_account(&account).expect("create account");
    assert_eq!(account_id, 1, "the bootstrap account is account 1");

    let message_id = store.reserve_message_id().expect("reserve message id");
    let aad = format!("account:{account_id}:message:{message_id}");
    let content_key = pigeon_crypto::generate_content_key();
    let sealed = master_key
        .wrap_content_key(&content_key, aad.as_bytes())
        .expect("seal body");
    store
        .insert_message(
            NewMessage {
                account_id,
                direction: Direction::In,
                from_addr: EmailAddress::parse("sender@example.net").expect("sender"),
                to_addrs: vec![account.clone()],
                subject: "Hello agent".to_string(),
                sealed_body: sealed,
                idempotency_key: None,
                delivered_for: None,
            },
            message_id,
        )
        .expect("insert message");
}

/// A running `pigeon mcp` process with a persistent stdout reader.
///
/// One reader for the whole test: a fresh `BufReader` per call could buffer the
/// next response and lose it.
struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Harness {
    fn spawn(master_key: &Path, db: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pigeon"))
            .arg("mcp")
            .env("PIGEON_MASTER_KEY_FILE", master_key)
            .env("PIGEON_DB_PATH", db)
            .env("PIGEON_LOG", "error")
            .env_remove("PIGEON_PUBLIC_IP")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pigeon mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    /// Send one JSON-RPC message and read one response line.
    fn send_raw(&mut self, message: &str) -> serde_json::Value {
        writeln!(self.stdin, "{message}").expect("write");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read line");
        serde_json::from_str(&line).expect("valid json response")
    }

    /// Send a request with an auto-incremented id.
    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send_raw(
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            })
            .to_string(),
        )
    }

    /// Call a tool and return its parsed JSON payload, asserting it succeeded.
    fn call(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let response = self.request(
            "tools/call",
            serde_json::json!({ "name": name, "arguments": arguments }),
        );
        let result = &response["result"];
        assert_ne!(
            result["isError"], true,
            "{name} failed: {}",
            result["content"][0]["text"]
        );
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} returned no text content"));
        serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("{name} did not return JSON: {error} in {text}"))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_initialize_and_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("master.key");
    std::fs::write(&key_file, "a".repeat(64)).unwrap();
    let db = dir.path().join("pigeon.db");
    seed_database(&db);

    let mut harness = Harness::spawn(&key_file, &db);

    // initialize
    let resp = harness.request(
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }),
    );
    assert_eq!(resp["result"]["serverInfo"]["name"], "pigeon-mail");

    // tools/list
    let resp = harness.request("tools/list", serde_json::json!({}));
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert_eq!(
        tools.len(),
        TOOL_COUNT,
        "5 messaging + 30 administration tools"
    );
    for name in [
        // messaging
        "send_email",
        "list_messages",
        "get_message",
        "create_template",
        "manage_webhooks",
        // organizations
        "org_create",
        "org_members",
        "org_invite",
        "org_create_member",
        // catch-all
        "catchall_set",
        "catchall_list",
        "catchall_delete",
        "catchall_pause",
        "catchall_resume",
        // sender aliases
        "alias_list",
        "alias_create",
        "alias_assign",
        "alias_delete",
        // drafts
        "draft_save",
        "draft_list",
        "draft_send",
        // folders
        "move_message",
        "mark_read",
        // domains
        "domain_add",
        "domain_dns",
        // suppressions
        "suppression_list",
        "suppression_add",
        "suppression_remove",
        // keys
        "api_key_create",
        "api_key_list",
        "api_key_revoke",
        // account settings
        "account_settings",
        "set_trash_retention",
    ] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "{name} must be advertised"
        );
        let entry = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("entry");
        assert_eq!(
            entry["inputSchema"]["type"], "object",
            "{name} must carry an object schema"
        );
        assert!(
            !entry["description"].as_str().unwrap_or("").is_empty(),
            "{name} needs a description for agents"
        );
    }

    // tools/call send_email
    let parsed = harness.call(
        "send_email",
        serde_json::json!({"to": ["a@b.co"], "subject": "Hi", "text": "Hello"}),
    );
    assert_eq!(parsed["status"], "queued");
    assert!(parsed["id"].as_str().unwrap().starts_with("eml_"));

    // unknown method
    let resp = harness.request("no/such", serde_json::json!({}));
    assert_eq!(resp["error"]["code"], -32601);

    // malformed json — must not crash, respond with parse error
    let resp = harness.send_raw("not json at all");
    assert_eq!(resp["error"]["code"], -32700);
}

#[test]
fn mcp_agent_manages_the_whole_deployment() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("master.key");
    std::fs::write(&key_file, "a".repeat(64)).unwrap();
    let db = dir.path().join("pigeon.db");
    seed_database(&db);

    let mut harness = Harness::spawn(&key_file, &db);

    // 1. Create the team. The acting account becomes its owner.
    let org = harness.call("org_create", serde_json::json!({"name": "Acme Mail"}));
    let org_id = org["org_id"].as_i64().expect("org_id");
    assert_eq!(org["role"], "owner");
    assert_eq!(org["name"], "Acme Mail");

    // 2. Add a member mailbox and hand back its bootstrap token.
    let member = harness.call(
        "org_create_member",
        serde_json::json!({
            "org_id": org_id,
            "email": "founder@example.com",
            "display_name": "Founder",
            "role": "admin"
        }),
    );
    assert!(member["account_id"].as_i64().unwrap() > 1);
    assert!(!member["bootstrap_token"].as_str().unwrap().is_empty());
    assert_eq!(member["role"], "admin");
    assert_eq!(member["email"], "founder@example.com");

    // ... and the member list shows both mailboxes.
    let members = harness.call("org_members", serde_json::json!({ "org_id": org_id }));
    assert_eq!(members["count"], 2);
    assert!(members["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["role"] == "owner"));

    // 3. Route every unknown address of the team's domain into that mailbox.
    let rule = harness.call(
        "catchall_set",
        serde_json::json!({
            "domain": "example.com",
            "action": "route",
            "target_email": "founder@example.com"
        }),
    );
    assert_eq!(rule["action"], "route");
    assert_eq!(rule["assignments"][0]["email"], "founder@example.com");
    assert_eq!(rule["assignments"][0]["paused"], false);
    let rules = harness.call("catchall_list", serde_json::json!({}));
    assert_eq!(rules["count"], 1);

    // 3b. A sender alias: a free address the team shares, held by one account.
    let alias = harness.call(
        "alias_create",
        serde_json::json!({"address": "sales@example.com"}),
    );
    assert_eq!(alias["address"], "sales@example.com");
    assert_eq!(alias["domain"], "example.com");
    let alias_id = alias["id"].as_i64().expect("alias id");
    let assigned = harness.call(
        "alias_assign",
        serde_json::json!({ "address": "sales@example.com", "account_email": "founder@example.com" }),
    );
    assert_eq!(assigned["assignments"][0]["email"], "founder@example.com");
    let alias_listing = harness.call("alias_list", serde_json::json!({}));
    assert_eq!(alias_listing["count"], 1);
    assert!(alias_id > 0);

    // 3c. The catch-all assignee can pause and resume *its own* copy. The agent's
    // account holds the catch-all of its own domain, which is the row the
    // self-service tools may touch.
    let own_rule = harness.call(
        "catchall_set",
        serde_json::json!({
            "domain": "pigeon.local",
            "action": "route",
            "target_email": "admin@pigeon.local"
        }),
    );
    assert_eq!(own_rule["assignments"][0]["email"], "admin@pigeon.local");
    let paused = harness.call(
        "catchall_pause",
        serde_json::json!({ "domain": "pigeon.local" }),
    );
    assert_eq!(paused["paused"], true);
    let resumed = harness.call(
        "catchall_resume",
        serde_json::json!({ "domain": "pigeon.local" }),
    );
    assert_eq!(resumed["paused"], false);

    // 4. Save a draft, then send it.
    let draft = harness.call(
        "draft_save",
        serde_json::json!({
            "to": ["customer@example.net"],
            "subject": "Welcome to Acme",
            "text": "Thanks for signing up."
        }),
    );
    let draft_id = draft["draft_id"].as_str().expect("draft_id");
    assert!(draft_id.starts_with("drf_"), "{draft_id}");

    let drafts = harness.call("draft_list", serde_json::json!({}));
    assert_eq!(drafts["count"], 1);
    assert_eq!(drafts["items"][0]["id"], draft_id);

    let sent = harness.call("draft_send", serde_json::json!({ "draft_id": draft_id }));
    assert!(sent["email_id"].as_str().unwrap().starts_with("eml_"));
    assert_eq!(sent["status"], "queued");

    // 5. Move and read the inbound message the SMTP side stored.
    let inbox = harness.call("list_messages", serde_json::json!({}));
    let message_id = inbox["items"][0]["id"]
        .as_str()
        .expect("message id")
        .to_string();
    let moved = harness.call(
        "move_message",
        serde_json::json!({ "message_id": message_id, "folder": "trash" }),
    );
    assert_eq!(moved["folder"], "trash");
    let marked = harness.call(
        "mark_read",
        serde_json::json!({ "message_id": message_id, "read": true }),
    );
    assert_eq!(marked["read"], true);

    // 6. Manage the sending domain: real DKIM key, real records to publish.
    let domain = harness.call("domain_add", serde_json::json!({"name": "example.com"}));
    assert!(domain["domain_id"].as_str().unwrap().starts_with("dom_"));
    let records = domain["records"].as_array().expect("records");
    for record_type in ["MX", "TXT"] {
        assert!(
            records
                .iter()
                .any(|record| record["record_type"] == record_type),
            "the records must cover {record_type}: {records:?}"
        );
    }
    assert!(records
        .iter()
        .any(|record| record["host"] == "pigeon._domainkey.example.com"));
    let dns = harness.call("domain_dns", serde_json::json!({"domain": "example.com"}));
    assert_eq!(dns["records"], domain["records"]);

    // 7. Suppress a hard-bounced address and read the list back.
    let added = harness.call(
        "suppression_add",
        serde_json::json!({ "addresses": ["bounced@example.org"], "reason": "bounce" }),
    );
    assert_eq!(added["added"], 1);
    assert_eq!(added["suppressed"][0], "bounced@example.org");
    let suppressed = harness.call("suppression_list", serde_json::json!({}));
    assert_eq!(suppressed["total"], 1);
    assert_eq!(suppressed["items"][0]["address"], "bounced@example.org");
    assert_eq!(suppressed["items"][0]["reason"], "bounce");

    // 8. Issue an API key for the agent and check the listing never leaks it.
    let created = harness.call(
        "api_key_create",
        serde_json::json!({ "name": "agent-ci", "scopes": ["send", "read"] }),
    );
    let key_id = created["id"].as_str().expect("key id").to_string();
    assert!(key_id.starts_with("key_"), "{key_id}");
    assert!(created["key"].as_str().unwrap().starts_with("pk_"));
    let listed = harness.call("api_key_list", serde_json::json!({}));
    let listing = listed.to_string();
    assert!(!listing.contains("pk_"), "the listing leaked key material");
    assert_eq!(listed["items"][0]["name"], "agent-ci");
    assert_eq!(listed["items"][0]["revoked"], false);
    let revoked = harness.call("api_key_revoke", serde_json::json!({ "key_id": key_id }));
    assert_eq!(revoked["revoked"], true);
}
