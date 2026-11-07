//! End-to-end: an agent reads and changes the trash retention over MCP.
//!
//! The tools are driven through [`pigeon_mcp::tools::dispatch`], the same entry
//! point `tools/call` uses, against a real `SqliteStorage` on a real tempdir
//! database — nothing is stubbed. That matters here because the point of these
//! two tools is that an agent writes **the** policy the purge worker and the
//! settings page read, not a copy of it.

use std::sync::Arc;

use pigeon_core::EmailAddress;
use pigeon_crypto::MasterKey;
use pigeon_mcp::{tools, McpState};
use serde_json::{json, Value};
use store::{SqliteStorage, Storage};

/// The bootstrap account every MCP tool acts as (`aux::DEFAULT_ACCOUNT_ID`).
const ACTOR_EMAIL: &str = "admin@pigeon.local";

/// A state whose database has the bootstrap account, exactly what `pigeon
/// keygen` leaves behind before the MCP server starts.
fn state() -> (tempfile::TempDir, McpState, Arc<SqliteStorage>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pigeon.db");
    let store = Arc::new(SqliteStorage::open(&path).expect("open store"));
    let account = EmailAddress::parse(ACTOR_EMAIL).expect("account address");
    let account_id = store.create_account(&account).expect("create account");
    assert_eq!(account_id, 1, "the bootstrap account is account 1");
    let state = McpState {
        store: Arc::clone(&store),
        master_key: Arc::new(MasterKey::parse(&[0xb7u8; 32]).expect("master key")),
    };
    (dir, state, store)
}

/// Call one tool and parse its JSON payload, failing with the tool's own message.
async fn call(state: &McpState, name: &str, args: Value) -> Value {
    let text = tools::dispatch(name, &args, state)
        .await
        .unwrap_or_else(|error| panic!("{name} failed: {error}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{name} did not return JSON: {error} in {text}"))
}

#[tokio::test]
async fn an_agent_reads_and_sets_the_trash_retention() {
    let (_dir, state, store) = state();

    // The documented default: an agent that never touched the setting sees 30.
    let settings = call(&state, "account_settings", json!({})).await;
    assert_eq!(settings["trash_retention_days"], 30, "{settings}");

    // Set it, and prove the value landed in the column every other reader uses.
    let saved = call(&state, "set_trash_retention", json!({ "days": 7 })).await;
    assert_eq!(saved["trash_retention_days"], 7, "{saved}");
    assert_eq!(store.get_trash_retention(1).expect("store read"), 7);

    let reread = call(&state, "account_settings", json!({})).await;
    assert_eq!(reread["trash_retention_days"], 7, "{reread}");

    // `0` is a real setting (keep forever), not a missing one.
    let keep_forever = call(&state, "set_trash_retention", json!({ "days": 0 })).await;
    assert_eq!(keep_forever["trash_retention_days"], 0, "{keep_forever}");
    assert_eq!(store.get_trash_retention(1).expect("store read"), 0);

    // The ceiling is accepted, and anything outside 0..=365 is refused with an
    // explanation instead of a silent clamp.
    let ceiling = call(&state, "set_trash_retention", json!({ "days": 365 })).await;
    assert_eq!(ceiling["trash_retention_days"], 365, "{ceiling}");
    for bad in [json!(366), json!(-1), json!("soon")] {
        let error = tools::dispatch("set_trash_retention", &json!({ "days": bad }), &state)
            .await
            .expect_err("out-of-range retention must be refused");
        assert!(
            !error.is_empty(),
            "the refusal must explain itself, got {error:?}"
        );
        assert_eq!(
            store.get_trash_retention(1).expect("store read"),
            365,
            "a refused call leaves the policy untouched"
        );
    }

    // The catalog advertises both tools with an object schema, so an agent that
    // lists before calling sees them.
    let catalog = tools::all_tools();
    for name in ["account_settings", "set_trash_retention"] {
        let entry = catalog
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("{name} must be advertised"));
        assert_eq!(entry["inputSchema"]["type"], "object", "{name}");
        assert!(
            entry["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{name} needs a description for agents"
        );
    }
    assert_eq!(catalog.len(), 27, "the documented tool count");
}
