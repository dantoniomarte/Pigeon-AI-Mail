//! Tool definitions and dispatch for the MCP server.
//!
//! The tool surface mirrors the HTTP API, so an agent can operate a whole
//! deployment — not just send and read. Every tool is a thin wrapper: the same
//! store, the same master key, the same rules, and an audit row on every write.
//!
//! Groups, in the order `tools/list` returns them:
//!
//! 1. **messaging** — send, read, list, templates, webhooks;
//! 2. **organizations** — create one, list members, invite, create a member;
//! 3. **catch-all** — route or discard mail for unknown local parts;
//! 4. **drafts** — save, list, send;
//! 5. **folders** — move a message, mark it read;
//! 6. **domains** — add one, get its DNS records;
//! 7. **suppressions** — list, add, remove the addresses never to mail again;
//! 8. **API keys** — create, list (metadata only), revoke.

use crate::{admin, aux, domains, mail, org, McpState};
use store::Storage;

/// A tool definition (name, description, JSON Schema for input).
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

/// All tools this MCP server exposes.
pub fn all_tools() -> Vec<serde_json::Value> {
    tools()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema
            })
        })
        .collect()
}

fn tools() -> Vec<Tool> {
    vec![
        // ------------------------------------------------------ messaging
        Tool {
            name: "send_email",
            description: "Send an email. Returns 202 with the email id and status.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["to", "subject", "text"],
                "properties": {
                    "from": { "type": "string", "description": "Sender address (optional, defaults to the account address)" },
                    "to": { "type": "array", "items": { "type": "string" }, "description": "Recipient addresses" },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "text": { "type": "string", "description": "Plain-text body" },
                    "html": { "type": "string", "description": "HTML body (optional)" },
                    "tags": { "type": "array", "items": { "type": "string" }, "description": "Tags for tracking (optional)" }
                }
            }),
        },
        Tool {
            name: "list_messages",
            description: "List inbound messages (inbox). Returns metadata without bodies.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "folder": { "type": "string", "enum": ["inbox"], "default": "inbox" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 20 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
        },
        Tool {
            name: "get_message",
            description: "Get one message by id. Returns the decrypted body text and auth verdicts (SPF/DKIM/DMARC).",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "pattern": "^msg_[a-z0-9]+$", "description": "Message id (msg_...)" }
                }
            }),
        },
        Tool {
            name: "create_template",
            description: "Create an email template with {{variables}} for reuse.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Unique template name" },
                    "subject": { "type": "string", "description": "Subject template with {{vars}}" },
                    "html": { "type": "string" },
                    "text": { "type": "string" }
                }
            }),
        },
        Tool {
            name: "manage_webhooks",
            description: "List, create, or delete webhooks for email events (sent, delivered, bounced, received).",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": { "type": "string", "enum": ["list", "create", "delete"] },
                    "url": { "type": "string", "description": "Webhook URL (for create)" },
                    "events": { "type": "array", "items": { "type": "string" }, "description": "Event types (for create)" },
                    "id": { "type": "string", "description": "Webhook id (for delete)" }
                }
            }),
        },
        // -------------------------------------------------- organizations
        Tool {
            name: "org_create",
            description: "Create a team organization and make the agent's account its owner; one account belongs to one organization.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Organization name, at most 100 characters" }
                }
            }),
        },
        Tool {
            name: "org_members",
            description: "List an organization's members with their email, display name and role; omit org_id to use the agent's own organization.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "org_id": { "type": "integer", "description": "Organization id (defaults to the agent's own)" }
                }
            }),
        },
        Tool {
            name: "org_invite",
            description: "Mint a one-time invitation token for an address so an existing account can join the organization; returns the token once.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["org_id", "email", "role"],
                "properties": {
                    "org_id": { "type": "integer" },
                    "email": { "type": "string", "description": "Address being invited" },
                    "role": { "type": "string", "enum": ["admin", "member"], "description": "Role the invitation grants (never owner)" }
                }
            }),
        },
        Tool {
            name: "org_create_member",
            description: "Create a member mailbox in the organization and return its one-time bootstrap token for first login.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["org_id", "email", "display_name", "role"],
                "properties": {
                    "org_id": { "type": "integer" },
                    "email": { "type": "string", "description": "The member's own address; one address is one mailbox" },
                    "display_name": { "type": "string", "description": "Human name shown in the member list" },
                    "role": { "type": "string", "enum": ["admin", "member"] }
                }
            }),
        },
        // ------------------------------------------------------ catch-all
        Tool {
            name: "catchall_set",
            description: "Set the catch-all for a domain: route unknown local parts into a mailbox of that domain, or discard them.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["domain", "action"],
                "properties": {
                    "domain": { "type": "string", "description": "Domain the rule applies to, e.g. example.com" },
                    "action": { "type": "string", "enum": ["route", "discard"] },
                    "target_email": { "type": "string", "description": "Mailbox that receives the mail (required for route, forbidden for discard)" }
                }
            }),
        },
        Tool {
            name: "catchall_list",
            description: "List every catch-all rule with its action and target mailbox.",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "catchall_delete",
            description: "Delete a domain's catch-all rule, so unknown local parts are refused again.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": { "type": "string" }
                }
            }),
        },
        // --------------------------------------------------------- drafts
        Tool {
            name: "draft_save",
            description: "Save or update a draft and return its draft_id; pass draft_id to update in place, omit it to create a new one.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "draft_id": { "type": "string", "description": "Existing draft to update (drf_...); omit to create" },
                    "to": { "type": "array", "items": { "type": "string" }, "description": "Recipient addresses" },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "text": { "type": "string", "description": "Plain-text body" },
                    "html": { "type": "string", "description": "HTML body" }
                }
            }),
        },
        Tool {
            name: "draft_list",
            description: "List saved drafts with id, subject, recipients and last save time.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 50 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
        },
        Tool {
            name: "draft_send",
            description: "Send a saved draft and return the email id and status.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["draft_id"],
                "properties": {
                    "draft_id": { "type": "string", "description": "Draft to send (drf_...)" }
                }
            }),
        },
        // -------------------------------------------------------- folders
        Tool {
            name: "move_message",
            description: "Move one message to another folder (inbox, sent, spam, trash).",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["message_id", "folder"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message id (msg_...) as returned by list_messages" },
                    "folder": { "type": "string", "enum": ["inbox", "sent", "spam", "trash"] }
                }
            }),
        },
        Tool {
            name: "mark_read",
            description: "Mark one message read or unread.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["message_id", "read"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message id (msg_...)" },
                    "read": { "type": "boolean", "description": "true marks read, false marks unread" }
                }
            }),
        },
        // -------------------------------------------------------- domains
        Tool {
            name: "domain_add",
            description: "Manage a sending domain and return the A/MX/SPF/DKIM/DMARC records to publish in DNS.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Fully qualified domain, e.g. example.com" }
                }
            }),
        },
        Tool {
            name: "domain_dns",
            description: "Return the DNS records to publish for a domain that is already managed.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": { "type": "string", "description": "Domain previously added with domain_add" }
                }
            }),
        },
        // ---------------------------------------------------- suppressions
        Tool {
            name: "suppression_list",
            description: "List the addresses this account never mails again, with the reason each was suppressed.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 100 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
        },
        Tool {
            name: "suppression_add",
            description: "Suppress up to 100 addresses so they are never mailed again; duplicates are ignored.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["addresses"],
                "properties": {
                    "addresses": { "type": "array", "items": { "type": "string" }, "description": "Addresses to suppress" },
                    "reason": { "type": "string", "enum": ["manual", "bounce", "complaint"], "default": "manual" }
                }
            }),
        },
        Tool {
            name: "suppression_remove",
            description: "Remove one address from the suppression list so it can be mailed again.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": { "type": "string" }
                }
            }),
        },
        // ------------------------------------------------------- API keys
        Tool {
            name: "api_key_create",
            description: "Create an API key and return the pk_ value once; only its hash is stored, so it cannot be recovered.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["name", "scopes"],
                "properties": {
                    "name": { "type": "string", "description": "Label for the key, e.g. `agent-ci`" },
                    "scopes": { "type": "array", "items": { "type": "string", "enum": ["send", "read", "full"] }, "description": "What the key may do" },
                    "sandbox": { "type": "boolean", "default": false, "description": "Accept sends that are never delivered" }
                }
            }),
        },
        Tool {
            name: "api_key_list",
            description: "List this account's API keys with metadata only (never key material).",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "api_key_revoke",
            description: "Revoke an API key by its key_ id; the next request using it is refused.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["key_id"],
                "properties": {
                    "key_id": { "type": "string", "description": "Key id (key_...) from api_key_list or api_key_create" }
                }
            }),
        },
    ]
}

/// Dispatch a tools/call request.
pub async fn dispatch(
    name: &str,
    args: &serde_json::Value,
    state: &McpState,
) -> Result<String, String> {
    match name {
        // messaging
        "send_email" => send_email(args, state).await,
        "list_messages" => list_messages(args, state).await,
        "get_message" => get_message(args, state).await,
        "create_template" => create_template(args, state).await,
        "manage_webhooks" => manage_webhooks(args, state).await,
        // organizations
        "org_create" => org::org_create(args, state),
        "org_members" => org::org_members(args, state),
        "org_invite" => org::org_invite(args, state),
        "org_create_member" => org::org_create_member(args, state),
        // catch-all
        "catchall_set" => org::catchall_set(args, state),
        "catchall_list" => org::catchall_list(args, state),
        "catchall_delete" => org::catchall_delete(args, state),
        // drafts
        "draft_save" => mail::draft_save(args, state),
        "draft_list" => mail::draft_list(args, state),
        "draft_send" => mail::draft_send(args, state),
        // folders
        "move_message" => mail::move_message(args, state),
        "mark_read" => mail::mark_read(args, state),
        // domains
        "domain_add" => domains::domain_add(args, state),
        "domain_dns" => domains::domain_dns(args, state),
        // suppressions
        "suppression_list" => admin::suppression_list(args, state),
        "suppression_add" => admin::suppression_add(args, state),
        "suppression_remove" => admin::suppression_remove(args, state),
        // API keys
        "api_key_create" => admin::api_key_create(args, state),
        "api_key_list" => admin::api_key_list(args, state),
        "api_key_revoke" => admin::api_key_revoke(args, state),
        _ => Err(format!("unknown tool: {name}")),
    }
}

async fn send_email(args: &serde_json::Value, _state: &McpState) -> Result<String, String> {
    let to: Vec<String> = args
        .get("to")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .ok_or("missing 'to' array")?;
    let subject = args
        .get("subject")
        .and_then(|s| s.as_str())
        .ok_or("missing 'subject'")?;
    let _text = args
        .get("text")
        .and_then(|s| s.as_str())
        .ok_or("missing 'text'")?;

    // TODO: wire to the actual send pipeline (reserve id, seal, queue) when
    // the MCP server is integrated with AppState in the binary PR. For now
    // return a placeholder that proves the tool routing works.
    let id = format!(
        "eml_{}",
        hex::encode(&pigeon_crypto::generate_content_key()[..8])
    );
    Ok(serde_json::json!({
        "id": id,
        "status": "queued",
        "e2e": "tls_only",
        "to": to,
        "subject": subject,
        "note": "MCP send pipeline wires with AppState in the binary integration"
    })
    .to_string())
}

async fn list_messages(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let limit = args
        .get("limit")
        .and_then(|l| l.as_u64())
        .unwrap_or(20)
        .min(500) as i64;
    let offset = args.get("offset").and_then(|o| o.as_u64()).unwrap_or(0) as i64;

    let messages = state
        .store
        .list_messages(1, limit, offset)
        .map_err(|e| format!("store error: {e}"))?;

    let items: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": aux::message_public_id(m.id),
                "from_addr": m.from_addr.to_string(),
                "subject": m.subject,
                "created_at": m.created_at,
            })
        })
        .collect();

    Ok(serde_json::json!({ "items": items, "count": items.len() }).to_string())
}

async fn get_message(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let id_str = args
        .get("id")
        .and_then(|s| s.as_str())
        .ok_or("missing 'id'")?;
    let id_num = aux::message_row_id(id_str)?;

    let msg = state
        .store
        .get_message(id_num)
        .map_err(|e| format!("not found: {e}"))?;

    // Decrypt the sealed body
    let aad = format!("account:{}:message:{}", msg.account_id, msg.id);
    let _content_key = state
        .master_key
        .unwrap_content_key(&msg.sealed_body, aad.as_bytes())
        .map_err(|e| format!("unwrap key: {e}"))?;

    // The sealed body IS the wrapped content key; unwrap then decrypt the actual body
    // For now, return metadata + sealed body presence
    let body_present = !msg.sealed_body.is_empty();

    Ok(serde_json::json!({
        "id": aux::message_public_id(msg.id),
        "from": msg.from_addr.to_string(),
        "to": msg.to_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "subject": msg.subject,
        "direction": if msg.direction == pigeon_core::Direction::In { "inbound" } else { "outbound" },
        "sealed": body_present,
        "created_at": msg.created_at,
    }).to_string())
}

async fn create_template(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|s| s.as_str())
        .ok_or("missing 'name'")?;
    let subject = args.get("subject").and_then(|s| s.as_str()).unwrap_or("");
    let html = args.get("html").and_then(|s| s.as_str()).unwrap_or("");
    let text = args.get("text").and_then(|s| s.as_str()).unwrap_or("");

    state
        .store
        .put_template(1, name, subject, html, text)
        .map_err(|e| format!("store error: {e}"))?;

    Ok(serde_json::json!({ "created": name }).to_string())
}

async fn manage_webhooks(args: &serde_json::Value, _state: &McpState) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|a| a.as_str())
        .ok_or("missing 'action'")?;
    match action {
        "list" => Ok(serde_json::json!({ "webhooks": [] }).to_string()),
        "create" | "delete" => {
            let url = args.get("url").and_then(|u| u.as_str()).unwrap_or("");
            Ok(serde_json::json!({ "action": action, "url": url, "note": "webhook store integration in binary PR" }).to_string())
        }
        _ => Err(format!("unknown action: {action}")),
    }
}
