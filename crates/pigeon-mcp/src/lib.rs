//! MCP (Model Context Protocol) server for Pigeon Mail.
//!
//! Exposes the same operations as the HTTP API as JSON-RPC tools over
//! stdio, so any AI agent (Pi, Claude, custom harnesses) can operate
//! mail natively. Same store, same master key, same audit trail — no
//! elevated path.
//!
//! Protocol: JSON-RPC 2.0, one request/response per line (LSP-style).
//! Method: `initialize` → `tools/list` → `tools/call`.
//!
//! # Surface
//!
//! 33 tools, grouped: messaging (send, read, list, templates, webhooks),
//! organizations, catch-all routing (multi-assignee, with a per-member pause),
//! sender aliases, drafts, folders, domains, suppressions, API keys and the
//! account settings (trash retention). The administration tools
//! reuse the API's own auxiliary SQL layer ([`aux`]) against the same database
//! file, so an agent manages exactly the state the HTTP API manages — never a
//! private copy of it.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod admin;
pub mod aliases;
pub mod aux;
pub mod domains;
pub mod mail;
pub mod org;
pub mod protocol;
pub mod tools;

use pigeon_crypto::MasterKey;
use std::sync::Arc;
use store::SqliteStorage;

pub use protocol::Content;

/// Shared state for MCP tool handlers (same as the HTTP AppState).
///
/// The two fields are the send pipeline's dependencies, and the tools that need
/// more (the `api_*` tables, the key metadata) open the API's auxiliary
/// connection lazily through [`aux::api_db`] against the same database file.
pub struct McpState {
    pub store: Arc<SqliteStorage>,
    pub master_key: Arc<MasterKey>,
}

/// Run the MCP server loop over stdin/stdout.
///
/// Each line of stdin is a JSON-RPC request; each line of stdout is a
/// JSON-RPC response (or notification ack). The loop exits on EOF.
pub async fn run_stdio(state: McpState) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::stdin;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = handle_message(trimmed, &state).await;
        if let Some(resp) = response {
            let mut out = serde_json::to_string(&resp)?;
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

async fn handle_message(raw: &str, state: &McpState) -> Option<serde_json::Value> {
    let msg: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return Some(error_response(
                serde_json::Value::Null,
                -32700,
                &format!("parse error: {e}"),
            ))
        }
    };

    let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

    // Notifications (no id) get no response
    if id.is_null() && !method.starts_with("tools/") {
        return None;
    }

    match method {
        "initialize" => Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "pigeon-mail", "version": "0.1.0" }
            }
        })),
        "notifications/initialized" => None,
        "tools/list" => Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tools::all_tools() }
        })),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            match tools::dispatch(name, &args, state).await {
                Ok(result) => Some(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": result }] }
                })),
                Err(e) => Some(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": format!("error: {e}") }],
                        "isError": true
                    }
                })),
            }
        }
        _ => Some(error_response(
            id,
            -32601,
            &format!("method not found: {method}"),
        )),
    }
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}
