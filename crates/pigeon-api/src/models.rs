//! Request and response DTOs, and the validation that turns a request body into
//! [`ValidatedSend`].
//!
//! Requests are `#[serde(deny_unknown_fields)]` because every request schema in
//! `openapi.yaml` is closed (`additionalProperties: false`): a typo such as
//! `"subjct"` must be a `422` with the offending field named, never a silently
//! dropped field. Responses mirror the contract member for member and omit
//! optional members instead of emitting `null`, which is what the schemas
//! declare.

use std::collections::BTreeMap;

use base64::Engine;
use pigeon_core::{ApiKeyScope, EmailAddress};
use serde::{Deserialize, Serialize};

use crate::problem::FieldError;

/// Total recipients allowed across `to` + `cc` + `bcc`.
pub const MAX_RECIPIENTS: usize = 50;
/// RFC 5322 subject cap from the contract.
pub const MAX_SUBJECT_LEN: usize = 998;
/// Tags per email.
pub const MAX_TAGS: usize = 10;
/// Longest tag, in characters.
pub const MAX_TAG_LEN: usize = 40;
/// Attachments per email.
pub const MAX_ATTACHMENTS: usize = 10;
/// Decoded bytes allowed across all attachments (25 MB).
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
/// Longest accepted idempotency key.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;
/// Items allowed in one batch call.
pub const MAX_BATCH_ITEMS: usize = 100;
/// Test-send recipients.
pub const MAX_TEST_RECIPIENTS: usize = 5;
/// Webhook events the contract defines.
pub const WEBHOOK_EVENTS: [&str; 6] = [
    "email.sent",
    "email.delivered",
    "email.delivery_delayed",
    "email.bounced",
    "email.failed",
    "email.received",
];

/// Header names the server owns; a client may not set them.
pub const HEADER_DENYLIST: [&str; 13] = [
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "return-path",
    "received",
    "message-id",
    "date",
    "content-type",
    "content-transfer-encoding",
    "dkim-signature",
    "authentication-results",
];

/// Payload protection actually in force for one message.
///
/// This is the `e2e` field of `SendAccepted`, `EmailView` and the webhook payloads,
/// and `docs/e2ee-model.md` defines what each value promises:
///
/// * [`E2e::Sealed`] — the body is OpenPGP-sealed to **every** recipient's
///   discovered key (plus the sender's own, so the sent copy stays readable). The
///   sending server, the network and the receiving server's storage cannot read
///   it.
/// * [`E2e::TlsOnly`] — transport TLS, no end-to-end payload seal: at least one
///   recipient had no discoverable key, or delivery stays inside this instance.
/// * [`E2e::PlaintextOverride`] — an operator explicitly opted a recipient domain
///   out of E2E ([`crate::state::ApiConfig::plaintext_override_domains`]). Always
///   logged, never a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2e {
    /// Sealed to every recipient.
    Sealed,
    /// Transport TLS only.
    TlsOnly,
    /// Explicit per-domain plaintext override.
    PlaintextOverride,
}

impl E2e {
    /// Canonical wire/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            E2e::Sealed => "sealed",
            E2e::TlsOnly => "tls_only",
            E2e::PlaintextOverride => "plaintext_override",
        }
    }

    /// Parse a stored value, or `None` when it is not one of the three.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "sealed" => Some(E2e::Sealed),
            "tls_only" => Some(E2e::TlsOnly),
            "plaintext_override" => Some(E2e::PlaintextOverride),
            _ => None,
        }
    }

    /// Every value the contract allows.
    pub const ALL: [E2e; 3] = [E2e::Sealed, E2e::TlsOnly, E2e::PlaintextOverride];
}

impl Default for E2e {
    /// The safe default: no seal, no claim.
    fn default() -> Self {
        E2e::TlsOnly
    }
}

impl Serialize for E2e {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl std::fmt::Display for E2e {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed `Name <addr@example.com>` mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Display name, if the caller supplied one.
    pub display: Option<String>,
    /// The bare address.
    pub address: EmailAddress,
}

impl Mailbox {
    /// The address as it belongs in a header, keeping a display name.
    pub fn to_header(&self) -> String {
        match &self.display {
            // JD-A-001: a display name containing CR/LF/NUL/" is a header
            // injection; drop it and emit the bare address instead.
            Some(display)
                if !display.is_empty()
                    && !display
                        .bytes()
                        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b == b'"') =>
            {
                format!("{display} <{}>", self.address)
            }
            _ => self.address.to_string(),
        }
    }
}

/// One decoded attachment, ready to be sealed and rendered into MIME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentPart {
    /// Client-supplied filename.
    pub filename: String,
    /// Inline `cid:` reference, when supplied.
    pub content_id: Option<String>,
    /// Decoded bytes (never larger than [`MAX_ATTACHMENT_BYTES`] in total).
    pub bytes: Vec<u8>,
}

/// A send request that passed validation.
#[derive(Debug, Clone)]
pub struct ValidatedSend {
    /// Envelope/header sender.
    pub from: Mailbox,
    /// `To:` recipients.
    pub to: Vec<EmailAddress>,
    /// `Cc:` recipients.
    pub cc: Vec<EmailAddress>,
    /// `Bcc:` recipients — envelope only, never rendered into MIME.
    pub bcc: Vec<EmailAddress>,
    /// `Reply-To:`.
    pub reply_to: Option<EmailAddress>,
    /// Subject after template rendering.
    pub subject: String,
    /// HTML part.
    pub html: Option<String>,
    /// Text part.
    pub text: Option<String>,
    /// Custom headers (denylist and CR/LF already enforced).
    pub headers: BTreeMap<String, String>,
    /// Decoded attachments.
    pub attachments: Vec<AttachmentPart>,
    /// Tags (already validated).
    pub tags: Vec<String>,
    /// Template the body was rendered from, if any.
    pub template_id: Option<String>,
    /// Template variables, kept for auditing/rendering.
    pub variables: serde_json::Map<String, serde_json::Value>,
    /// Unix seconds the send becomes due, when scheduled.
    pub scheduled_at: Option<i64>,
    /// Client deduplication key.
    pub idempotency_key: Option<String>,
}

impl ValidatedSend {
    /// Status this send starts in: `scheduled` when the due time is in the
    /// future, `queued` otherwise.
    pub fn initial_status(&self, now_unix: i64) -> EmailStatus {
        match self.scheduled_at {
            Some(at) if at > now_unix => EmailStatus::Scheduled,
            _ => EmailStatus::Queued,
        }
    }

    /// Unix time the queue row becomes due.
    pub fn run_after(&self, now_unix: i64) -> i64 {
        self.scheduled_at.map_or(now_unix, |at| at.max(now_unix))
    }
}

/// Lifecycle states of an outbound email.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailStatus {
    /// Waiting in the queue.
    #[default]
    Queued,
    /// Waiting for `scheduled_at`.
    Scheduled,
    /// Claimed by a worker.
    Sending,
    /// Handed to the remote MTA.
    Sent,
    /// Temporary failure; the queue will retry.
    Deferred,
    /// Permanent failure reported by the remote MTA.
    Bounced,
    /// Local failure that will not be retried.
    Failed,
    /// Cancelled before delivery.
    Cancelled,
}

impl EmailStatus {
    /// Wire representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            EmailStatus::Queued => "queued",
            EmailStatus::Scheduled => "scheduled",
            EmailStatus::Sending => "sending",
            EmailStatus::Sent => "sent",
            EmailStatus::Deferred => "deferred",
            EmailStatus::Bounced => "bounced",
            EmailStatus::Failed => "failed",
            EmailStatus::Cancelled => "cancelled",
        }
    }

    /// Parse a stored/wire status.
    pub fn parse(input: &str) -> Option<Self> {
        Some(match input {
            "queued" => EmailStatus::Queued,
            "scheduled" => EmailStatus::Scheduled,
            "sending" => EmailStatus::Sending,
            "sent" => EmailStatus::Sent,
            "deferred" => EmailStatus::Deferred,
            "bounced" => EmailStatus::Bounced,
            "failed" => EmailStatus::Failed,
            "cancelled" => EmailStatus::Cancelled,
            _ => return None,
        })
    }

    /// True while a cancel is still allowed.
    pub fn is_cancellable(self) -> bool {
        matches!(self, EmailStatus::Queued | EmailStatus::Scheduled)
    }
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

/// `SendRequest` from the contract.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// Sender mailbox (`Name <addr>` or a bare address).
    pub from: String,
    /// Primary recipients.
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    #[serde(default)]
    pub cc: Vec<String>,
    /// Blind carbon-copy recipients (never echoed).
    #[serde(default)]
    pub bcc: Vec<String>,
    /// Reply-To address.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Subject line.
    #[serde(default)]
    pub subject: Option<String>,
    /// HTML part.
    #[serde(default)]
    pub html: Option<String>,
    /// Text part.
    #[serde(default)]
    pub text: Option<String>,
    /// Custom headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Attachments.
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Template to render.
    #[serde(default)]
    pub template_id: Option<String>,
    /// Template variables.
    #[serde(default)]
    pub variables: serde_json::Map<String, serde_json::Value>,
    /// Future ISO 8601 send time.
    #[serde(default)]
    pub scheduled_at: Option<String>,
    /// Deduplication key.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// One attachment in a send request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentInput {
    /// Filename.
    pub filename: String,
    /// base64-encoded content.
    pub content: String,
    /// Inline `cid:` reference.
    #[serde(default)]
    pub content_id: Option<String>,
}

/// `{ "items": [...] }` wrapper for the batch endpoint.
///
/// Items are kept as raw JSON: "one invalid item never blocks the rest" means a
/// malformed item must become that item's `422` entry, not a rejection of the
/// whole batch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    /// Up to [`MAX_BATCH_ITEMS`] send requests, decoded one by one.
    pub items: Vec<serde_json::Value>,
}

/// Rendered template contents plus the send fields that reference one.
#[derive(Debug, Clone)]
pub struct TemplateRender {
    /// Rendered subject.
    pub subject: String,
    /// Rendered HTML.
    pub html: Option<String>,
    /// Rendered text.
    pub text: Option<String>,
}

/// True when `tag` matches `[a-z0-9-]{1,40}` and does not start with a hyphen.
pub fn is_valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_TAG_LEN
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !tag.starts_with('-')
}

impl SendRequest {
    /// Validate and normalize the request. `template` supplies the rendered
    /// body when the request carries a `template_id`; every problem found is
    /// reported at once so a client fixes one body, not one field per round
    /// trip.
    pub fn validate(
        &self,
        template: Option<&TemplateRender>,
    ) -> Result<ValidatedSend, Vec<FieldError>> {
        let mut errors = Vec::new();

        let from = match parse_mailbox(&self.from) {
            Ok(from) => Some(from),
            Err(message) => {
                errors.push(FieldError::with_code("from", "invalid", message));
                None
            }
        };

        let mut to = self.parse_addresses("to", &self.to, &mut errors);
        let cc = self.parse_addresses("cc", &self.cc, &mut errors);
        let bcc = self.parse_addresses("bcc", &self.bcc, &mut errors);
        let reply_to = match self.reply_to.as_deref().map(str::trim) {
            Some(raw) if !raw.is_empty() => match EmailAddress::parse(raw) {
                Ok(address) => Some(address),
                Err(error) => {
                    errors.push(FieldError::with_code(
                        "reply_to",
                        "invalid",
                        error.to_string(),
                    ));
                    None
                }
            },
            _ => None,
        };

        if to.is_empty() && self.to.is_empty() {
            errors.push(FieldError::with_code(
                "to",
                "required",
                "at least one recipient is required",
            ));
        }
        let total = to.len() + cc.len() + bcc.len();
        if total > MAX_RECIPIENTS {
            errors.push(FieldError::with_code(
                "to",
                "too-many-recipients",
                format!("to+cc+bcc holds {total} recipients, above the {MAX_RECIPIENTS} limit"),
            ));
        }

        let subject = match self.subject.as_deref() {
            Some(raw) => validate_subject(raw, &mut errors),
            None => {
                // JD-A-002: the template-rendered subject must go through the same
                // CRLF/NUL validation as a caller-supplied one — a variable value
                // like "x\r\nBcc: evil" must not reach the MIME renderer.
                template
                    .as_ref()
                    .map(|rendered| validate_subject(&rendered.subject, &mut errors))
                    .unwrap_or_default()
            }
        };
        if subject.trim().is_empty() && template.is_none() {
            errors.push(FieldError::with_code(
                "subject",
                "required",
                "subject is required unless template_id is set",
            ));
        }

        let html = self
            .html
            .clone()
            .or_else(|| template.and_then(|rendered| rendered.html.clone()));
        let text = self
            .text
            .clone()
            .or_else(|| template.and_then(|rendered| rendered.text.clone()));
        if html.is_none() && text.is_none() {
            errors.push(FieldError::with_code(
                "html",
                "required",
                "at least one of html, text or template_id is required",
            ));
        }

        let tags = self.validate_tags(&mut errors);
        self.validate_headers(&mut errors);
        let attachments = self.validate_attachments(&mut errors);

        let scheduled_at = match self.scheduled_at.as_deref().map(str::trim) {
            Some(raw) if !raw.is_empty() => match crate::time::parse_iso(raw) {
                Some(secs) => Some(secs),
                None => {
                    errors.push(FieldError::with_code(
                        "scheduled_at",
                        "invalid",
                        format!("{raw:?} is not an ISO 8601 timestamp"),
                    ));
                    None
                }
            },
            _ => None,
        };

        let idempotency_key = match self.idempotency_key.clone() {
            Some(key) => {
                let key = key.trim().to_string();
                if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
                    errors.push(FieldError::with_code(
                        "idempotency_key",
                        "too-long",
                        format!(
                            "idempotency_key is {} characters, above the {MAX_IDEMPOTENCY_KEY_LEN} limit",
                            key.len()
                        ),
                    ));
                    None
                } else if key.is_empty() {
                    None
                } else {
                    Some(key)
                }
            }
            None => None,
        };

        if let Some(template_id) = self.template_id.as_deref() {
            if !crate::ids::is_well_formed(template_id, crate::ids::TPL) {
                errors.push(FieldError::with_code(
                    "template_id",
                    "invalid",
                    format!("{template_id:?} is not a tpl_ id"),
                ));
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // `to` is rebuilt from the parsed addresses so a partially invalid list
        // can never reach the queue.
        to.shrink_to_fit();

        Ok(ValidatedSend {
            from: from.expect("validated: from parsed or an error was recorded"),
            to,
            cc,
            bcc,
            reply_to,
            subject,
            html,
            text,
            headers: self.headers.clone(),
            attachments,
            tags,
            template_id: self.template_id.clone(),
            variables: self.variables.clone(),
            scheduled_at,
            idempotency_key,
        })
    }

    fn parse_addresses(
        &self,
        field: &str,
        raw: &[String],
        errors: &mut Vec<FieldError>,
    ) -> Vec<EmailAddress> {
        raw.iter()
            .enumerate()
            .filter_map(|(index, value)| match EmailAddress::parse(value.trim()) {
                Ok(address) => Some(address),
                Err(error) => {
                    errors.push(FieldError::with_code(
                        format!("{field}[{index}]"),
                        "invalid",
                        error.to_string(),
                    ));
                    None
                }
            })
            .collect()
    }

    fn validate_tags(&self, errors: &mut Vec<FieldError>) -> Vec<String> {
        if self.tags.len() > MAX_TAGS {
            errors.push(FieldError::with_code(
                "tags",
                "too-many",
                format!(
                    "{} tags supplied, above the {MAX_TAGS} limit",
                    self.tags.len()
                ),
            ));
        }
        self.tags
            .iter()
            .enumerate()
            .filter_map(|(index, tag)| {
                if is_valid_tag(tag) {
                    Some(tag.clone())
                } else {
                    errors.push(FieldError::with_code(
                        format!("tags[{index}]"),
                        "invalid",
                        format!("{tag:?} must match [a-z0-9-]{{1,{MAX_TAG_LEN}}}"),
                    ));
                    None
                }
            })
            .collect()
    }

    fn validate_headers(&self, errors: &mut Vec<FieldError>) {
        for (name, value) in &self.headers {
            let field = format!("headers.{name}");
            if name.is_empty()
                || name
                    .bytes()
                    .any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b':')
            {
                errors.push(FieldError::with_code(
                    field,
                    "invalid-name",
                    "header names must be printable ASCII without ':' or whitespace",
                ));
                continue;
            }
            if HEADER_DENYLIST
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(name.trim()))
            {
                errors.push(FieldError::with_code(
                    field,
                    "denylisted",
                    format!("{name} is set by the server and cannot be overridden"),
                ));
                continue;
            }
            if has_header_break(name) || has_header_break(value) {
                errors.push(FieldError::with_code(
                    field,
                    "invalid-characters",
                    "header names and values must not contain CR or LF",
                ));
            }
        }
    }

    fn validate_attachments(&self, errors: &mut Vec<FieldError>) -> Vec<AttachmentPart> {
        if self.attachments.len() > MAX_ATTACHMENTS {
            errors.push(FieldError::with_code(
                "attachments",
                "too-many",
                format!(
                    "{} attachments supplied, above the {MAX_ATTACHMENTS} limit",
                    self.attachments.len()
                ),
            ));
        }
        let mut total: u64 = 0;
        let mut parts = Vec::new();
        for (index, attachment) in self.attachments.iter().enumerate() {
            let field = format!("attachments[{index}]");
            if attachment.filename.is_empty()
                || attachment.filename.len() > 255
                || has_header_break(&attachment.filename)
            {
                errors.push(FieldError::with_code(
                    format!("{field}.filename"),
                    "invalid",
                    "filename must be 1-255 characters without CR or LF",
                ));
                continue;
            }
            if let Some(content_id) = attachment.content_id.as_deref() {
                if content_id.is_empty() || has_header_break(content_id) {
                    errors.push(FieldError::with_code(
                        format!("{field}.content_id"),
                        "invalid",
                        "content_id must be non-empty without CR or LF",
                    ));
                    continue;
                }
            }
            let decoded =
                match base64::engine::general_purpose::STANDARD.decode(attachment.content.trim()) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        errors.push(FieldError::with_code(
                            format!("{field}.content"),
                            "invalid-base64",
                            format!("content is not valid base64: {error}"),
                        ));
                        continue;
                    }
                };
            total = total.saturating_add(decoded.len() as u64);
            parts.push(AttachmentPart {
                filename: attachment.filename.clone(),
                content_id: attachment.content_id.clone(),
                bytes: decoded,
            });
        }
        if total > MAX_ATTACHMENT_BYTES {
            errors.push(FieldError::with_code(
                "attachments",
                "too-large",
                format!(
                    "decoded attachments total {total} bytes, above the {MAX_ATTACHMENT_BYTES} limit"
                ),
            ));
        }
        parts
    }
}

fn validate_subject(raw: &str, errors: &mut Vec<FieldError>) -> String {
    let subject = raw.to_string();
    if subject.len() > MAX_SUBJECT_LEN {
        errors.push(FieldError::with_code(
            "subject",
            "too-long",
            format!(
                "subject is {} bytes, above the {MAX_SUBJECT_LEN} limit",
                subject.len()
            ),
        ));
    }
    if has_header_break(&subject) {
        errors.push(FieldError::with_code(
            "subject",
            "invalid-characters",
            "subject must not contain CR or LF",
        ));
    }
    subject
}

/// True when a string contains a bare CR/LF or NUL — the characters that turn a
/// header value into a new header or a smuggled body.
pub fn has_header_break(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
}

/// Parse `Name <addr@example.com>` or a bare address.
pub fn parse_mailbox(raw: &str) -> Result<Mailbox, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("from is required".to_string());
    }
    let (display, address) = match (trimmed.rfind('<'), trimmed.ends_with('>')) {
        (Some(open), true) => {
            let display = trimmed[..open].trim().trim_matches('"').trim();
            let address = &trimmed[open + 1..trimmed.len() - 1];
            (
                if display.is_empty() {
                    None
                } else {
                    Some(display.to_string())
                },
                address.trim(),
            )
        }
        _ => (None, trimmed),
    };
    let parsed = EmailAddress::parse(address).map_err(|error| error.to_string())?;
    Ok(Mailbox {
        display,
        address: parsed,
    })
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `SendAccepted` — the 202 body.
#[derive(Debug, Clone, Serialize)]
pub struct SendAccepted {
    /// Public email id (`eml_...`).
    pub id: String,
    /// `queued` or `scheduled`.
    pub status: EmailStatus,
    /// Payload protection actually in force.
    pub e2e: String,
}

/// `BatchResult` — one entry per submitted item.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    /// Position in the request array.
    pub index: usize,
    /// Public email id, when accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `queued`/`scheduled`, when accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<EmailStatus>,
    /// The per-item problem, when rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

/// `BatchResults` — the 202 batch body.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResults {
    /// Per-item results, in request order.
    pub results: Vec<BatchResult>,
}

/// `PageMeta`.
#[derive(Debug, Clone, Serialize)]
pub struct PageMeta {
    /// Rows matched by the filter, ignoring pagination.
    pub total: i64,
    /// Whether another page exists.
    pub has_more: bool,
    /// Offset of the next page, `null` on the last page.
    pub next_offset: Option<i64>,
}

impl PageMeta {
    /// Page metadata for a query returning `returned` rows out of `total`, at
    /// `offset`.
    pub fn new(total: i64, offset: i64, returned: i64) -> Self {
        let seen = offset.saturating_add(returned);
        let has_more = seen < total;
        Self {
            total,
            has_more,
            next_offset: if has_more { Some(seen) } else { None },
        }
    }
}

/// `EmailView` — lifecycle view of an outbound email (bcc never echoed).
#[derive(Debug, Clone, Serialize)]
pub struct EmailView {
    /// Public id.
    pub id: String,
    /// Current lifecycle status.
    pub status: EmailStatus,
    /// Creation timestamp.
    pub created_at: String,
    /// Latest lifecycle transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event: Option<String>,
    /// Sender as submitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// To recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Cc recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// True when a sandbox key created it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<bool>,
    /// Payload protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2e: Option<String>,
    /// Remote MX details, once a delivery attempt ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mx: Option<MxView>,
    /// Deferral details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred: Option<DeferredView>,
    /// Bounce details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounced: Option<BouncedView>,
    /// Local failure details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<FailedView>,
}

/// `EmailView.mx`.
#[derive(Debug, Clone, Serialize)]
pub struct MxView {
    /// MX hostname.
    pub host: String,
    /// Resolved IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Negotiated TLS version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
}

/// `EmailView.deferred`.
#[derive(Debug, Clone, Serialize)]
pub struct DeferredView {
    /// When the next attempt is due.
    pub next_attempt_at: String,
    /// Attempts so far.
    pub attempts: i64,
}

/// `EmailView.bounced`.
#[derive(Debug, Clone, Serialize)]
pub struct BouncedView {
    /// SMTP/enhanced status code.
    pub code: String,
    /// Human-readable reason.
    pub reason: String,
    /// True for a permanent bounce.
    pub hard: bool,
}

/// `EmailView.failed`.
#[derive(Debug, Clone, Serialize)]
pub struct FailedView {
    /// Why delivery failed locally.
    pub reason: String,
}

/// `EmailPage`.
#[derive(Debug, Clone, Serialize)]
pub struct EmailPage {
    /// Emails on this page.
    pub items: Vec<EmailView>,
    /// Pagination metadata.
    pub page: PageMeta,
}

/// `SandboxMessage` — the `?raw=true` body.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxMessage {
    /// Public email id.
    pub id: String,
    /// Exact generated MIME.
    pub mime: String,
}

/// `GET /v1/emails/{id}` may return either the lifecycle view or, with
/// `?raw=true` on a sandbox message, the generated MIME.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum EmailResponse {
    /// Lifecycle view (the default).
    View(Box<EmailView>),
    /// Raw MIME (sandbox only).
    Raw(Box<SandboxMessage>),
}

/// `AuthVerdict`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthVerdict {
    /// SPF result.
    pub spf: String,
    /// DKIM result.
    pub dkim: String,
    /// DMARC result.
    pub dmarc: String,
    /// TLS version the message arrived over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
}

impl Default for AuthVerdict {
    fn default() -> Self {
        // Nothing evaluates SPF/DKIM/DMARC until the inbound SMTP service
        // lands, so `none` is the honest verdict rather than a fake pass.
        Self {
            spf: "none".to_string(),
            dkim: "none".to_string(),
            dmarc: "none".to_string(),
            tls: None,
        }
    }
}

/// `SealedMessageView.attachments[]` / `DecryptedMessageView.attachments[]`.
#[derive(Debug, Clone, Serialize)]
pub struct MessageAttachmentView {
    /// Public attachment id (`atc_...`).
    pub id: String,
    /// Filename.
    pub filename: String,
    /// Size in bytes.
    pub size: i64,
}

/// `SealedMessageView` — metadata plus ciphertext, no plaintext.
#[derive(Debug, Clone, Serialize)]
pub struct SealedMessageView {
    /// Public message id.
    pub id: String,
    /// Sender.
    pub from_addr: String,
    /// Recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Arrival time.
    pub created_at: String,
    /// Address this copy was delivered for, when it is not the account's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_for: Option<String>,
    /// base64 sealed body.
    pub sealed_body: String,
    /// Authentication verdicts.
    pub auth: AuthVerdict,
    /// Attachments discoverable while content stays sealed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<MessageAttachmentView>>,
}

/// `DecryptedMessageView` — plaintext, scope `full` only.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptedMessageView {
    /// Public message id.
    pub id: String,
    /// Sender.
    pub from_addr: String,
    /// Recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Arrival time.
    pub created_at: String,
    /// Address this copy was delivered for, when it is not the account's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_for: Option<String>,
    /// Plain-text part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_text: Option<String>,
    /// HTML part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// Attachments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<MessageAttachmentView>>,
    /// Authentication verdicts.
    pub auth: AuthVerdict,
}

/// `MessagePage.items[]` — metadata only, never bodies.
#[derive(Debug, Clone, Serialize)]
pub struct MessageSummary {
    /// Public message id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_addr: Option<String>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Arrival time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Folder the message currently lives in.
    pub folder: String,
    /// True once the message has been read (`read_at` set on the row).
    pub read: bool,
    /// The address this copy was delivered for, when it is not the mailbox's own:
    /// a sender alias or the catch-all local part. Absent on ordinary mail; the
    /// webmail groups the inbox by it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_for: Option<String>,
}

/// `MessagePage.counts` — per-folder totals for the caller's account.
///
/// The sidebar renders one badge per folder, so the listing hands them over
/// with the page instead of making the client issue four counting requests.
#[derive(Debug, Clone, Serialize)]
pub struct FolderCounts {
    /// Messages in `inbox`.
    pub inbox: i64,
    /// Messages in `sent`.
    pub sent: i64,
    /// Messages in `spam`.
    pub spam: i64,
    /// Messages in `trash`.
    pub trash: i64,
}

/// One `delivered_for` marker with its inbox count: the webmail's pseudo-folder.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveredForCount {
    /// The alias or catch-all address the mail was delivered for.
    pub address: String,
    /// Inbox messages carrying that marker.
    pub count: i64,
}

/// `MessagePage`.
#[derive(Debug, Clone, Serialize)]
pub struct MessagePage {
    /// Messages on this page.
    pub items: Vec<MessageSummary>,
    /// Pagination metadata.
    pub page: PageMeta,
    /// Per-folder counts for the account (sidebar badges).
    pub counts: FolderCounts,
    /// Inbox counts per shared address (`delivered_for`), so a client can render
    /// one pseudo-folder per alias or catch-all without a second request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delivered_for_counts: Vec<DeliveredForCount>,
}

/// `MessagePatch` — partial update of folder and/or read state.
///
/// Both members are optional but at least one must be present: an empty patch is
/// a client bug, not a no-op write.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagePatch {
    /// Target folder: `inbox`, `sent`, `spam` or `trash`.
    #[serde(default)]
    pub folder: Option<String>,
    /// Mark the message read (`true`) or unread (`false`).
    #[serde(default)]
    pub read: Option<bool>,
}

/// `POST /v1/messages/empty-trash` result.
#[derive(Debug, Clone, Serialize)]
pub struct EmptyTrashResult {
    /// Number of messages permanently removed.
    pub deleted: i64,
}

/// `POST /v1/messages/purge-trash` result — the retention purge, run now.
///
/// `deleted` counts only the messages whose retention window had already
/// expired; everything newer than the window stays in the trash and is what
/// `trash_remaining` counts.
#[derive(Debug, Clone, Serialize)]
pub struct PurgeTrashResult {
    /// Messages removed by this run.
    pub deleted: i64,
    /// Messages still in the trash afterwards (fresh ones, and every one kept
    /// because the retention is `0`).
    pub trash_remaining: i64,
}

/// `GET /v1/account/settings` — the account-wide mailbox policy.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSettings {
    /// Days a message stays in `trash` before the purge deletes it (`0` = keep
    /// forever).
    pub trash_retention_days: i64,
}

/// `PATCH /v1/account/settings` body.
///
/// `trash_retention_days` is required: a settings patch that changes nothing is
/// a client bug, and an omitted field would be indistinguishable from "set it to
/// the default again".
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSettingsPatch {
    /// `0..=365`; `0` keeps trash forever.
    pub trash_retention_days: i64,
}

/// `Template`.
#[derive(Debug, Clone, Serialize)]
pub struct Template {
    /// Public template id.
    pub id: String,
    /// Unique-per-account name.
    pub name: String,
    /// Last update timestamp.
    pub updated_at: String,
    /// Short human description, omitted when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Subject template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// HTML template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Text template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// `TemplateCreate`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCreate {
    /// Unique-per-account name.
    pub name: String,
    /// Short human description.
    #[serde(default)]
    pub description: Option<String>,
    /// Subject template.
    #[serde(default)]
    pub subject: Option<String>,
    /// HTML template.
    #[serde(default)]
    pub html: Option<String>,
    /// Text template.
    #[serde(default)]
    pub text: Option<String>,
}

/// `TemplatePatch` — partial update; `id`/`updated_at` are server-owned.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplatePatch {
    /// New name.
    #[serde(default)]
    pub name: Option<String>,
    /// New description.
    #[serde(default)]
    pub description: Option<String>,
    /// New subject template.
    #[serde(default)]
    pub subject: Option<String>,
    /// New HTML template.
    #[serde(default)]
    pub html: Option<String>,
    /// New text template.
    #[serde(default)]
    pub text: Option<String>,
}

/// `POST /v1/templates/{id}/test-send` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSendRequest {
    /// Recipients, at most [`MAX_TEST_RECIPIENTS`].
    pub to: Vec<String>,
    /// Template variables.
    #[serde(default)]
    pub variables: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Drafts
// ---------------------------------------------------------------------------

/// `Draft` — a saved email that has not been sent.
///
/// Drafts carry their bodies in full (they are small, and the compose box needs
/// them back verbatim). Empty optional members are omitted, exactly like every
/// other response in this contract.
#[derive(Debug, Clone, Serialize)]
pub struct Draft {
    /// Public draft id (`drf_…`).
    pub id: String,
    /// Sender mailbox, empty when the compose box has none yet.
    pub from: String,
    /// Recipients.
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    pub cc: Vec<String>,
    /// Blind carbon-copy recipients. Unlike a sent message, a draft echoes these
    /// back to its own account: they have not left the account yet.
    pub bcc: Vec<String>,
    /// Subject, omitted when the draft has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// HTML body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Text body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Attachments as received: `filename`, base64 `content`, optional
    /// `content_id`. Never interpreted by the API — a draft stores what the
    /// client will send.
    pub attachments: Vec<serde_json::Value>,
    /// Tags.
    pub tags: Vec<String>,
    /// Last save timestamp (ISO 8601 UTC).
    pub updated_at: String,
}

/// `POST /v1/drafts` body — every member optional, because a draft is written
/// while it is still being written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftCreate {
    /// Sender mailbox.
    #[serde(default)]
    pub from: Option<String>,
    /// Recipients.
    #[serde(default)]
    pub to: Option<Vec<String>>,
    /// Carbon-copy recipients.
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    /// Blind carbon-copy recipients.
    #[serde(default)]
    pub bcc: Option<Vec<String>>,
    /// Subject.
    #[serde(default)]
    pub subject: Option<String>,
    /// HTML body.
    #[serde(default)]
    pub html: Option<String>,
    /// Text body.
    #[serde(default)]
    pub text: Option<String>,
    /// Attachments (`filename` + base64 `content`).
    #[serde(default)]
    pub attachments: Option<Vec<serde_json::Value>>,
    /// Tags.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// `PATCH /v1/drafts/{id}` body — every member optional; a member that is
/// present replaces the stored one, a member that is absent is left alone.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftPatch {
    /// Sender mailbox.
    #[serde(default)]
    pub from: Option<String>,
    /// Recipients.
    #[serde(default)]
    pub to: Option<Vec<String>>,
    /// Carbon-copy recipients.
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    /// Blind carbon-copy recipients.
    #[serde(default)]
    pub bcc: Option<Vec<String>>,
    /// Subject.
    #[serde(default)]
    pub subject: Option<String>,
    /// HTML body.
    #[serde(default)]
    pub html: Option<String>,
    /// Text body.
    #[serde(default)]
    pub text: Option<String>,
    /// Attachments (`filename` + base64 `content`).
    #[serde(default)]
    pub attachments: Option<Vec<serde_json::Value>>,
    /// Tags.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// `DraftPage`.
#[derive(Debug, Clone, Serialize)]
pub struct DraftPage {
    /// Drafts on this page, newest save first.
    pub items: Vec<Draft>,
    /// Pagination metadata.
    pub page: PageMeta,
}

/// `Domain`.
#[derive(Debug, Clone, Serialize)]
pub struct Domain {
    /// Public domain id.
    pub id: String,
    /// The domain name.
    pub name: String,
    /// Verification status (always false in v0.1: DNS checking lands in v0.2).
    pub verified: bool,
    /// Last verification attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
}

/// `POST /v1/domains` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainCreate {
    /// Hostname to manage.
    pub name: String,
}

/// `DnsRecord`.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    /// Record type (`A`, `MX`, `TXT`).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record host.
    pub host: String,
    /// Bare value (MX priority is never embedded here).
    pub value: String,
    /// MX priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

/// `WebhookCreate`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCreate {
    /// Delivery URL.
    pub url: String,
    /// Event types to deliver.
    pub events: Vec<String>,
    /// Optional caller-supplied signing secret.
    #[serde(default)]
    pub secret: Option<String>,
}

/// `WebhookView` — never carries the secret.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookView {
    /// Public webhook id.
    pub id: String,
    /// Delivery URL.
    pub url: String,
    /// Subscribed events.
    pub events: Vec<String>,
    /// Creation timestamp.
    pub created_at: String,
}

/// `WebhookCreated` — the only response that carries the secret.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookCreated {
    /// Public webhook id.
    pub id: String,
    /// Delivery URL.
    pub url: String,
    /// Subscribed events.
    pub events: Vec<String>,
    /// Creation timestamp.
    pub created_at: String,
    /// Signing secret, shown exactly once.
    pub secret: String,
}

/// `POST /v1/suppressions` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionCreate {
    /// Addresses to suppress, at most 100.
    pub addresses: Vec<String>,
    /// Why they are suppressed.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `SuppressionPage.items[]`.
#[derive(Debug, Clone, Serialize)]
pub struct SuppressionView {
    /// Suppressed address.
    pub address: String,
    /// `manual`, `bounce` or `complaint`.
    pub reason: String,
    /// Email id or admin action that caused it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// When it was added.
    pub created_at: String,
}

/// `SuppressionPage`.
#[derive(Debug, Clone, Serialize)]
pub struct SuppressionPage {
    /// Suppressions on this page.
    pub items: Vec<SuppressionView>,
    /// Pagination metadata.
    pub page: PageMeta,
}

/// `ApiKeyCreate`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyCreate {
    /// Human-readable label.
    pub name: String,
    /// Scopes to grant.
    pub scopes: Vec<String>,
    /// Create the key in sandbox mode.
    #[serde(default)]
    pub sandbox: bool,
}

// ------------------------------------------------------- sessions / 2fa DTOs

/// `POST /v1/auth/login` request body.
///
/// `password` is part of the contract body and is accepted (and ignored) here:
/// **v0.1 has no password realm**. A session is issued after identifying the
/// account by email, plus a TOTP or recovery code when 2FA is enrolled — see
/// [`crate::handlers::sessions::login`]. Accepting the member keeps a client
/// written against `openapi.yaml` from failing on an unknown field the day the
/// password realm lands.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Account address to identify.
    pub email: String,
    /// Accepted for contract compatibility; unused until passwords exist.
    #[serde(default)]
    pub password: Option<String>,
    /// TOTP code (6 or 8 digits) or one-time recovery code.
    #[serde(default)]
    pub code: Option<String>,
}

/// `POST /v1/auth/login` response: the session the cookie carries.
#[derive(Debug, Clone, Serialize)]
pub struct SessionIssued {
    /// Public session id (`sess_…`).
    pub session_id: String,
    /// ISO 8601 expiry of the session (and of the cookie).
    pub expires_at: String,
}

/// `POST /v1/account/2fa/enroll` response: provisioning data.
#[derive(Debug, Clone, Serialize)]
pub struct TotpEnrollmentView {
    /// Base32 (RFC 4648, no padding) secret an authenticator app stores.
    pub secret_base32: String,
    /// The `otpauth://` URI to render as a QR code.
    pub otpauth_uri: String,
}

/// `POST /v1/account/2fa/activate` response: the recovery codes, shown once.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryCodesIssued {
    /// Ten single-use codes. Only their Argon2id hashes are stored.
    pub recovery_codes: Vec<String>,
}

/// A TOTP or recovery code in a request body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCodeRequest {
    /// TOTP (6 or 8 digits) or recovery code.
    pub code: String,
}

/// `POST /v1/account/2fa/verify` response.
#[derive(Debug, Clone, Serialize)]
pub struct CodeVerified {
    /// Always `true`: a rejected code is a `401`, never `{"verified": false}`.
    pub verified: bool,
}

/// `ApiKeyPatch`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyPatch {
    /// Revoke the key.
    #[serde(default)]
    pub revoked: Option<bool>,
    /// Toggle sandbox mode.
    #[serde(default)]
    pub sandbox: Option<bool>,
    /// Rename the key.
    #[serde(default)]
    pub name: Option<String>,
}

/// `ApiKeyCreated` — the only response that carries key material.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyCreated {
    /// Public key id.
    pub id: String,
    /// The `pk_...` key, shown exactly once.
    pub key: String,
}

/// `ApiKeyView` — metadata only.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyView {
    /// Public key id.
    pub id: String,
    /// Label.
    pub name: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Whether the key is in sandbox mode.
    pub sandbox: bool,
    /// Whether the key is revoked.
    pub revoked: bool,
    /// Last authenticated use.
    pub last_used_at: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
}

impl ApiKeyView {
    /// Build the view from stored parts.
    pub fn new(
        id: String,
        name: String,
        scopes: Vec<ApiKeyScope>,
        sandbox: bool,
        revoked: bool,
        last_used_at: Option<String>,
        created_at: String,
    ) -> Self {
        Self {
            id,
            name,
            scopes: scopes
                .iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
            sandbox,
            revoked,
            last_used_at,
            created_at,
        }
    }
}

/// `Org` — one organization (company/team) the caller belongs to.
///
/// Ids are integers here, not `org_…` strings: an organization is a tenant
/// boundary created by the operator/dashboard, not a resource a client mints and
/// then passes around by opaque handle, and the master admin panel (the next PR)
/// addresses it the same way.
#[derive(Debug, Clone, Serialize)]
pub struct OrgView {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    /// The caller's role in this organization (`owner`/`admin`/`member`). Only
    /// present on the "my organizations" listing, where the role is what makes
    /// the list actionable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// `OrgMember` — one account of an organization.
#[derive(Debug, Clone, Serialize)]
pub struct OrgMemberView {
    pub account_id: i64,
    pub email: String,
    /// Human name; empty when nobody has set one.
    pub display_name: String,
    pub role: String,
    pub created_at: String,
}

/// `OrgMemberCreated` — the member plus its one-time bootstrap token.
#[derive(Debug, Clone, Serialize)]
pub struct OrgMemberCreated {
    pub member: OrgMemberView,
    /// Shown exactly once. Logging in with it in `code` (or redeeming it at
    /// `POST /v1/invitations/accept`) burns it; only its Argon2id hash is stored.
    pub bootstrap_token: String,
}

/// `Invitation` — one invitation to join an organization.
///
/// The token is **not** part of this view: it exists only in the creation
/// response ([`InvitationCreated`]).
#[derive(Debug, Clone, Serialize)]
pub struct InvitationView {
    pub id: i64,
    pub email: String,
    pub role: String,
    pub invited_by: i64,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

/// `InvitationCreated` — the invitation plus the plaintext token, shown once.
#[derive(Debug, Clone, Serialize)]
pub struct InvitationCreated {
    pub invitation: InvitationView,
    pub token: String,
}

/// `CatchallRule` — what the inbound server does with unknown local parts of a
/// managed domain, plus who currently receives a routed copy.
#[derive(Debug, Clone, Serialize)]
pub struct CatchallRuleView {
    pub domain: String,
    /// `route` or `discard`.
    pub action: String,
    /// Every account holding the catch-all, paused or live. `route` copies the
    /// message to each **non-paused** one; `discard` stores nothing and therefore
    /// ignores this list without deleting it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<CatchallAssignmentView>,
    pub created_at: String,
}

/// One account holding a catch-all, with its own pause switch.
#[derive(Debug, Clone, Serialize)]
pub struct CatchallAssignmentView {
    pub account_id: i64,
    /// The mailbox address, so a client does not have to join two listings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `true` suspended only this member's copy.
    pub paused: bool,
    pub created_at: String,
}

/// `SenderAlias` — a secondary address on a served domain.
#[derive(Debug, Clone, Serialize)]
pub struct AliasView {
    pub id: i64,
    /// Normalized address (`sales@example.com`).
    pub address: String,
    pub domain: String,
    /// Accounts that may send as the alias and receive a copy of its mail.
    pub assignments: Vec<AliasAssignmentView>,
    pub created_at: String,
}

/// One account holding a sender alias.
#[derive(Debug, Clone, Serialize)]
pub struct AliasAssignmentView {
    pub account_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub created_at: String,
}

/// `POST /v1/orgs` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgCreate {
    pub name: String,
}

/// `POST /v1/orgs/{id}/members` body: create a member account directly.
///
/// There is no password member: v0.1 has no password realm, so a new member is
/// entered with the one-time bootstrap token the response carries (see
/// `docs/API.md`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgMemberCreate {
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// `admin` or `member`; defaults to `member`. `owner` is refused: ownership
    /// moves by patching an existing member's role.
    #[serde(default)]
    pub role: Option<String>,
}

/// `PATCH /v1/orgs/{id}/members/{account_id}` body: at least one member.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgMemberPatch {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// `POST /v1/orgs/{id}/invitations` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationCreate {
    pub email: String,
    /// `admin` or `member`; defaults to `member`.
    #[serde(default)]
    pub role: Option<String>,
}

/// `POST /v1/invitations/accept` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationAccept {
    pub token: String,
}

/// `PUT /v1/catchall/{domain}` body.
///
/// Only the domain-level decision lives here: the recipients are assignments
/// (`POST /v1/catchall/{domain}/assign`), because several accounts may hold the
/// same catch-all and each may pause its own copy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatchallUpsert {
    /// `route` or `discard`.
    pub action: String,
}

/// `POST /v1/catchall/{domain}/assign` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatchallAssign {
    pub account_id: i64,
}

/// `PATCH /v1/catchall/{domain}/assignments/{account_id}` body: the admin force.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatchallAssignmentPatch {
    /// `true` pauses that member's copy, `false` resumes it.
    pub paused: bool,
}

/// `POST /v1/catchall/me/pause` and `/resume` body.
///
/// `domain` may be omitted when the caller holds exactly one catch-all; holding
/// several requires naming one, because guessing would pause the wrong address.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatchallSelfScope {
    #[serde(default)]
    pub domain: Option<String>,
}

/// `POST /v1/aliases` body: the address being claimed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasCreate {
    pub address: String,
}

/// `POST /v1/aliases/{id}/assign` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasAssign {
    pub account_id: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: serde_json::Value) -> SendRequest {
        serde_json::from_value(json).expect("test request deserializes")
    }

    fn valid() -> serde_json::Value {
        serde_json::json!({
            "from": "Dana <dana@pigeonmail.dev>",
            "to": ["carol@example.org"],
            "subject": "hi",
            "text": "hello",
        })
    }

    #[test]
    fn a_minimal_request_validates() {
        let send = request(valid()).validate(None).expect("valid");
        assert_eq!(send.from.display.as_deref(), Some("Dana"));
        assert_eq!(send.from.address.to_string(), "dana@pigeonmail.dev");
        assert_eq!(send.to.len(), 1);
        assert_eq!(send.subject, "hi");
        assert_eq!(send.text.as_deref(), Some("hello"));
        assert_eq!(send.initial_status(0), EmailStatus::Queued);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = serde_json::json!({"from": "a@b.co", "to": ["c@d.co"], "subjct": "typo"});
        assert!(serde_json::from_value::<SendRequest>(json).is_err());
    }

    #[test]
    fn missing_from_is_a_deserialization_error_naming_the_field() {
        let json = serde_json::json!({"to": ["c@d.co"], "text": "x"});
        let error = serde_json::from_value::<SendRequest>(json).unwrap_err();
        assert!(error.to_string().contains("from"), "{error}");
    }

    #[test]
    fn recipient_total_is_capped_across_to_cc_bcc() {
        let mut json = valid();
        let many: Vec<String> = (0..30).map(|i| format!("u{i}@example.org")).collect();
        json["cc"] = serde_json::json!(many.clone());
        json["bcc"] = serde_json::json!(many);
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "to" && e.code.as_deref() == Some("too-many-recipients")));
    }

    #[test]
    fn invalid_addresses_are_reported_per_index() {
        let mut json = valid();
        json["to"] = serde_json::json!(["good@example.org", "not-an-address"]);
        let errors = request(json).validate(None).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "to[1]");
    }

    #[test]
    fn body_or_template_is_required() {
        let json = serde_json::json!({"from": "a@b.co", "to": ["c@d.co"], "subject": "s"});
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "html"));
    }

    #[test]
    fn subject_is_required_without_a_template() {
        let json = serde_json::json!({"from": "a@b.co", "to": ["c@d.co"], "text": "x"});
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "subject"));
    }

    #[test]
    fn subject_length_and_crlf_are_enforced() {
        let mut json = valid();
        json["subject"] = serde_json::json!("x".repeat(MAX_SUBJECT_LEN + 1));
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "subject" && e.code.as_deref() == Some("too-long")));

        let mut json = valid();
        json["subject"] = serde_json::json!("hi\r\nBcc: evil@example.org");
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "subject" && e.code.as_deref() == Some("invalid-characters")));
    }

    #[test]
    fn tags_are_validated_against_the_pattern() {
        for tag in ["billing", "a", "invoice-2026"] {
            let mut json = valid();
            json["tags"] = serde_json::json!([tag]);
            assert!(request(json).validate(None).is_ok(), "{tag} should pass");
        }
        for tag in [
            "Billing",
            "has space",
            "",
            "-leading",
            "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong",
        ] {
            let mut json = valid();
            json["tags"] = serde_json::json!([tag]);
            let errors = request(json).validate(None).unwrap_err();
            assert!(
                errors.iter().any(|e| e.field == "tags[0]"),
                "{tag:?} should fail"
            );
        }
        let mut json = valid();
        json["tags"] = serde_json::json!(vec!["t"; 11]);
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "tags"));
    }

    #[test]
    fn denylisted_and_crlf_headers_are_rejected() {
        for name in ["From", "message-id", "Content-Type", "DKIM-Signature"] {
            let mut json = valid();
            json["headers"] = serde_json::json!({ name: "x" });
            let errors = request(json).validate(None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.code.as_deref() == Some("denylisted")),
                "{name} must be denylisted"
            );
        }
        let mut json = valid();
        json["headers"] = serde_json::json!({"X-Campaign": "nov\r\nBcc: evil@example.org"});
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.code.as_deref() == Some("invalid-characters")));

        let mut json = valid();
        json["headers"] = serde_json::json!({"X-Campaign": "nov-billing"});
        let send = request(json).validate(None).expect("custom header ok");
        assert_eq!(
            send.headers.get("X-Campaign").map(String::as_str),
            Some("nov-billing")
        );
    }

    #[test]
    fn attachments_are_decoded_and_bounded() {
        let mut json = valid();
        json["attachments"] = serde_json::json!([
            {"filename": "receipt.pdf", "content": "aGVsbG8=", "content_id": "receipt"}
        ]);
        let send = request(json).validate(None).expect("attachment ok");
        assert_eq!(send.attachments.len(), 1);
        assert_eq!(send.attachments[0].bytes, b"hello");
        assert_eq!(send.attachments[0].content_id.as_deref(), Some("receipt"));

        let mut json = valid();
        json["attachments"] = serde_json::json!([{"filename": "x.txt", "content": "!!!"}]);
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "attachments[0].content"));

        let mut json = valid();
        let too_many: Vec<serde_json::Value> = (0..11)
            .map(|i| serde_json::json!({"filename": format!("f{i}.txt"), "content": "aGk="}))
            .collect();
        json["attachments"] = serde_json::json!(too_many);
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "attachments"));
    }

    #[test]
    fn scheduling_and_idempotency_are_normalized() {
        let mut json = valid();
        json["scheduled_at"] = serde_json::json!("2030-01-01T00:00:00Z");
        json["idempotency_key"] = serde_json::json!("  invoice-1  ");
        let send = request(json).validate(None).expect("valid");
        assert_eq!(send.scheduled_at, Some(1_893_456_000));
        assert_eq!(send.idempotency_key.as_deref(), Some("invoice-1"));
        assert_eq!(send.initial_status(0), EmailStatus::Scheduled);
        assert_eq!(send.run_after(0), 1_893_456_000);
        assert_eq!(send.initial_status(1_893_456_000), EmailStatus::Queued);

        let mut json = valid();
        json["scheduled_at"] = serde_json::json!("tomorrow");
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "scheduled_at"));
    }

    #[test]
    fn idempotency_key_length_is_capped() {
        let mut json = valid();
        json["idempotency_key"] = serde_json::json!("k".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1));
        let errors = request(json).validate(None).unwrap_err();
        assert!(errors.iter().any(|e| e.field == "idempotency_key"));
    }

    #[test]
    fn template_render_supplies_subject_and_body() {
        let json = serde_json::json!({
            "from": "a@b.co", "to": ["c@d.co"], "template_id": "tpl_12345678",
        });
        let rendered = TemplateRender {
            subject: "Welcome".to_string(),
            html: Some("<p>hi</p>".to_string()),
            text: Some("hi".to_string()),
        };
        let send = request(json).validate(Some(&rendered)).expect("valid");
        assert_eq!(send.subject, "Welcome");
        assert_eq!(send.template_id.as_deref(), Some("tpl_12345678"));
    }

    #[test]
    fn mailbox_parsing_handles_display_names_and_bare_addresses() {
        assert_eq!(parse_mailbox("a@b.co").unwrap().display, None);
        assert_eq!(
            parse_mailbox("Dana <dana@pigeonmail.dev>")
                .unwrap()
                .display
                .as_deref(),
            Some("Dana")
        );
        assert_eq!(
            parse_mailbox("\"Dana Q\" <dana@pigeonmail.dev>")
                .unwrap()
                .display
                .as_deref(),
            Some("Dana Q")
        );
        assert!(parse_mailbox("").is_err());
        assert!(parse_mailbox("Dana").is_err());
    }

    #[test]
    fn status_round_trips_and_parses() {
        for status in [
            EmailStatus::Queued,
            EmailStatus::Scheduled,
            EmailStatus::Sending,
            EmailStatus::Sent,
            EmailStatus::Deferred,
            EmailStatus::Bounced,
            EmailStatus::Failed,
            EmailStatus::Cancelled,
        ] {
            assert_eq!(EmailStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(EmailStatus::parse("unknown"), None);
        assert!(EmailStatus::Queued.is_cancellable());
        assert!(EmailStatus::Scheduled.is_cancellable());
        assert!(!EmailStatus::Sent.is_cancellable());
        assert!(!EmailStatus::Cancelled.is_cancellable());
    }

    #[test]
    fn page_meta_computes_next_offset() {
        let meta = PageMeta::new(10, 0, 5);
        assert!(meta.has_more);
        assert_eq!(meta.next_offset, Some(5));
        let meta = PageMeta::new(10, 5, 5);
        assert!(!meta.has_more);
        assert_eq!(meta.next_offset, None);
        let meta = PageMeta::new(0, 0, 0);
        assert!(!meta.has_more);
        assert_eq!(meta.next_offset, None);
    }

    #[test]
    fn every_e2e_value_round_trips_and_only_the_three_exist() {
        assert_eq!(E2e::ALL.len(), 3);
        for value in E2e::ALL {
            assert_eq!(E2e::parse(value.as_str()), Some(value));
            // The contract's enum is exactly these spellings; anything else is a
            // stored value a client would reject.
            assert!(matches!(
                value.as_str(),
                "sealed" | "tls_only" | "plaintext_override"
            ));
        }
        assert_eq!(E2e::parse("pgp"), None);
        assert_eq!(E2e::parse(""), None);
        assert_eq!(
            E2e::default(),
            E2e::TlsOnly,
            "the safe default claims nothing"
        );
        assert_eq!(serde_json::to_string(&E2e::Sealed).unwrap(), "\"sealed\"");
        assert_eq!(E2e::PlaintextOverride.to_string(), "plaintext_override");
    }
}
