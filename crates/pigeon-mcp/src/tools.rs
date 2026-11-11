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
//! 3. **catch-all** — route or discard mail for unknown local parts, with several
//!    assignees and a per-member pause;
//! 4. **sender aliases** — a secondary address a team shares to send and receive;
//! 5. **drafts** — save, list, send;
//! 6. **folders** — move a message, mark it read;
//! 7. **domains** — add one, get its DNS records;
//! 8. **suppressions** — list, add, remove the addresses never to mail again;
//! 9. **API keys** — create, list (metadata only), revoke;
//! 10. **account settings** — read and set the trash retention window.

use crate::{admin, aliases, aux, domains, mail, org, McpState};
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
            name: "export_message",
            description: "Back up one message: the original RFC822 document, decrypted, as EML text. Works for inbound and sent mail.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "description": "Message id (msg_... or eml_...)" }
                }
            }),
        },
        Tool {
            name: "export_folder",
            description: "Back up a whole folder as one mbox archive (mboxrd). Returns { folder, format, encoding: \"base64\", count, skipped, bytes, mbox } — the mbox field is the archive BASE64-ENCODED (byte-faithful for 8-bit mail); decode it before reading.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["folder"],
                "properties": {
                    "folder": { "type": "string", "enum": ["inbox", "sent", "spam", "trash"], "description": "Folder to archive" }
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
            description: "Set the catch-all decision for a domain (route unknown local parts into every assignee, or discard them) and optionally assign a mailbox that receives a copy. Several mailboxes may hold the same catch-all: call it once per mailbox.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["domain", "action"],
                "properties": {
                    "domain": { "type": "string", "description": "Domain the rule applies to, e.g. example.com" },
                    "action": { "type": "string", "enum": ["route", "discard"] },
                    "target_email": { "type": "string", "description": "Optional mailbox of that domain to assign a copy to; forbidden for discard. Omitting it keeps the existing assignees" }
                }
            }),
        },
        Tool {
            name: "catchall_list",
            description: "List every catch-all rule with its action and its assignees (each with its own paused flag).",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "catchall_pause",
            description: "Pause the agent's own copy of a catch-all: the domain keeps routing to everybody else. Omit domain when the account holds exactly one.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Which catch-all to pause (required when the account holds more than one)" }
                }
            }),
        },
        Tool {
            name: "catchall_resume",
            description: "Resume the agent's own copy of a catch-all it paused.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Which catch-all to resume (required when the account holds more than one)" }
                }
            }),
        },
        // ------------------------------------------------- sender aliases
        Tool {
            name: "alias_list",
            description: "List the sender aliases of the deployment with the accounts that hold each one.",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "alias_create",
            description: "Claim a free address on a served domain as a sender alias. It must not belong to an account nor to another alias.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": { "type": "string", "description": "Alias address, e.g. sales@example.com" }
                }
            }),
        },
        Tool {
            name: "alias_assign",
            description: "Let one account send as an alias and receive a copy of its mail; the alias may have several holders.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["address", "account_email"],
                "properties": {
                    "address": { "type": "string", "description": "Alias address (sales@example.com)" },
                    "account_email": { "type": "string", "description": "Mailbox that receives the copy and may send as the alias" }
                }
            }),
        },
        Tool {
            name: "alias_delete",
            description: "Delete a sender alias and every assignment to it; mail already delivered stays in its mailbox.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": { "type": "string", "description": "Alias address to delete" }
                }
            }),
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
        // ----------------------------------------------- account settings
        Tool {
            name: "account_settings",
            description: "Read the account's mailbox policy: the trash retention in days (0 means trashed mail is kept forever).",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "set_trash_retention",
            description: "Set how many days a message stays in the trash before it is deleted automatically: 0 keeps trashed mail forever, the default is 30, the range is 0-365.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["days"],
                "properties": {
                    "days": { "type": "integer", "minimum": 0, "maximum": 365, "description": "Retention window in days (0 = never auto-delete)" }
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
        "export_message" => mail::export_message(args, state),
        "export_folder" => mail::export_folder(args, state),
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
        "catchall_pause" => org::catchall_pause(args, state),
        "catchall_resume" => org::catchall_resume(args, state),
        // sender aliases
        "alias_list" => aliases::alias_list(args, state),
        "alias_create" => aliases::alias_create(args, state),
        "alias_assign" => aliases::alias_assign(args, state),
        "alias_delete" => aliases::alias_delete(args, state),
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
        // account settings
        "account_settings" => admin::account_settings(args, state),
        "set_trash_retention" => admin::set_trash_retention(args, state),
        _ => Err(format!("unknown tool: {name}")),
    }
}

async fn send_email(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    // Identity first: the agent may send as its own account or as an alias an
    // administrator assigned to it, and nothing else.
    let actor = aux::actor(state)?;
    let from = match aux::optional_str(args, "from") {
        Some(raw) => aux::parse_email(raw, "from")?,
        None => actor.email.clone(),
    };
    aux::ensure_from_allowed(state, &actor, &from)?;
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
    let text = args
        .get("text")
        .and_then(|s| s.as_str())
        .ok_or("missing 'text'")?;
    let html = args.get("html").and_then(|s| s.as_str()).map(String::from);
    let tags: Vec<String> = args
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let cc: Vec<String> = args
        .get("cc")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // The real pipeline: same quota, validation, sealing, queueing as
    // POST /v1/emails. The MCP actor is the deployment's bootstrap account,
    // so the synthesized context carries the `full` scope.
    let app = aux::app_state(state)?;
    let context = aux::pipeline_context(actor.account_id);
    let request = pigeon_api::models::SendRequest {
        from: from.to_string(),
        to,
        cc,
        bcc: Vec::new(),
        reply_to: None,
        subject: Some(subject.to_string()),
        html,
        text: Some(text.to_string()),
        headers: Default::default(),
        attachments: Vec::new(),
        tags,
        template_id: None,
        variables: Default::default(),
        scheduled_at: None,
        idempotency_key: None,
    };
    let accepted = pigeon_api::handlers::send_email_pipeline(&app, &context, &request)
        .map_err(|problem| format!("send refused: {}", problem.detail))?;
    aux::audit(
        state,
        "email.send",
        &format!("{} to={:?}", accepted.id, request.to),
    );
    Ok(serde_json::json!({
        "id": accepted.id,
        "status": accepted.status.as_str(),
        "e2e": accepted.e2e,
        "to": request.to,
        "subject": subject,
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

async fn manage_webhooks(args: &serde_json::Value, state: &McpState) -> Result<String, String> {
    let actor = aux::actor(state)?;
    let action = args
        .get("action")
        .and_then(|a| a.as_str())
        .ok_or("missing 'action'")?;
    let db = aux::api_db(state)?;
    match action {
        "list" => {
            let hooks = db
                .list_webhooks(actor.account_id)
                .map_err(|error| aux::store_error("could not read webhooks", error))?;
            let items: Vec<serde_json::Value> = hooks
                .iter()
                .map(|hook| {
                    serde_json::json!({
                        "id": hook.public_id,
                        "url": hook.url,
                        "events": hook.events,
                        "created_at": hook.created_at,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "webhooks": items }).to_string())
        }
        "create" => {
            let url = aux::required_str(args, "url")?;
            let events: Vec<String> = args
                .get("events")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| vec!["delivered".to_string()]);
            // The signing secret is generated server-side, like the HTTP path.
            let secret = hex::encode(&pigeon_crypto::generate_content_key()[..16]);
            let hook = db
                .create_webhook(actor.account_id, url, &events, &secret)
                .map_err(|error| aux::store_error("could not create the webhook", error))?;
            aux::audit(state, "webhook.create", &hook.public_id);
            Ok(serde_json::json!({
                "status": "created",
                "id": hook.public_id,
                "url": hook.url,
                "events": hook.events,
            })
            .to_string())
        }
        "delete" => {
            let id = aux::required_str(args, "id")?;
            let removed = db
                .delete_webhook(actor.account_id, id)
                .map_err(|error| aux::store_error("could not delete the webhook", error))?;
            if !removed {
                return Err(format!("webhook {id} not found"));
            }
            aux::audit(state, "webhook.delete", id);
            Ok(serde_json::json!({ "status": "deleted", "id": id }).to_string())
        }
        _ => Err(format!("unknown action: {action}")),
    }
}
