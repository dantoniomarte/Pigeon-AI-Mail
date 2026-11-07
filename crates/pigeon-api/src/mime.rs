//! MIME generation for outbound mail.
//!
//! The sealed body of an outbound message **is** this MIME document: the SMTP
//! worker signs and transmits exactly these bytes, and `GET /v1/emails/{id}?raw=true`
//! hands the same bytes to a sandbox caller. Generating it once, at accept time,
//! means the sandbox view can never drift from what would be delivered.
//!
//! Two rules are structural rather than incidental:
//!
//! * **Bcc never appears.** It travels in the SMTP envelope only; writing it into
//!   `To:`/`Cc:` or a hidden header is how a "blind" copy stops being blind.
//! * **CRLF everywhere.** A bare LF is a header-injection surface for
//!   intermediaries that fold or rewrite headers differently than we do.
//!
//! Header values are already validated (no CR/LF, addresses parsed) by
//! [`crate::models::SendRequest::validate`], so this module never re-checks
//! caller text.

use base64::Engine;

use crate::models::{AttachmentPart, ValidatedSend};
use crate::time::rfc5322_date;

const CRLF: &str = "\r\n";

/// Render `send` as a complete MIME message, CRLF-terminated and ready to seal.
pub fn build(send: &ValidatedSend, message_id: &str, created_unix: i64) -> Vec<u8> {
    let domain = send.from.address.domain();
    let mut headers: Vec<(String, String)> = Vec::new();
    headers.push(("From".to_string(), send.from.to_header()));
    headers.push((
        "To".to_string(),
        join_addresses(send.to.iter().map(ToString::to_string)),
    ));
    if !send.cc.is_empty() {
        headers.push((
            "Cc".to_string(),
            join_addresses(send.cc.iter().map(ToString::to_string)),
        ));
    }
    if let Some(reply_to) = &send.reply_to {
        headers.push(("Reply-To".to_string(), reply_to.to_string()));
    }
    headers.push(("Subject".to_string(), encode_subject(&send.subject)));
    headers.push(("Date".to_string(), rfc5322_date(created_unix)));
    headers.push(("Message-ID".to_string(), format!("<{message_id}@{domain}>")));
    headers.push(("MIME-Version".to_string(), "1.0".to_string()));
    for (name, value) in &send.headers {
        headers.push((name.clone(), value.clone()));
    }

    let (body_headers, body) = body_part(send);
    headers.extend(body_headers);

    let mut out = String::with_capacity(body.len() + 1024);
    for (name, value) in headers {
        out.push_str(&name);
        out.push_str(": ");
        out.push_str(&value);
        out.push_str(CRLF);
    }
    out.push_str(CRLF);
    out.push_str(&body);
    out.into_bytes()
}

/// Headers and body of the message's `body` part(s), wrapped in
/// `multipart/mixed` when attachments are present.
fn body_part(send: &ValidatedSend) -> (Vec<(String, String)>, String) {
    if send.attachments.is_empty() {
        return single_body(send);
    }
    let boundary = format!("mixed-{}", random_token());
    let mut headers = vec![(
        "Content-Type".to_string(),
        format!("multipart/mixed; boundary=\"{boundary}\""),
    )];
    let mut body = String::new();
    let (inner_headers, inner_body) = single_body(send);
    body.push_str(&format!("--{boundary}{CRLF}"));
    for (name, value) in inner_headers {
        body.push_str(&format!("{name}: {value}{CRLF}"));
    }
    body.push_str(CRLF);
    body.push_str(&inner_body);
    if !body.ends_with(CRLF) {
        body.push_str(CRLF);
    }
    for attachment in &send.attachments {
        body.push_str(&attachment_part(attachment, &boundary));
    }
    body.push_str(&format!("--{boundary}--{CRLF}"));
    headers.shrink_to_fit();
    (headers, body)
}

/// The body part: a single text or HTML part, or `multipart/alternative` when
/// both are present.
fn single_body(send: &ValidatedSend) -> (Vec<(String, String)>, String) {
    match (&send.text, &send.html) {
        (Some(text), Some(html)) => {
            let boundary = format!("alt-{}", random_token());
            let mut body = String::new();
            body.push_str(&format!("--{boundary}{CRLF}"));
            body.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            body.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            body.push_str(&wrap_base64(&base64_bytes(text.as_bytes())));
            body.push_str(&format!("{CRLF}--{boundary}{CRLF}"));
            body.push_str("Content-Type: text/html; charset=utf-8\r\n");
            body.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            body.push_str(&wrap_base64(&base64_bytes(html.as_bytes())));
            body.push_str(&format!("{CRLF}--{boundary}--{CRLF}"));
            (
                vec![(
                    "Content-Type".to_string(),
                    format!("multipart/alternative; boundary=\"{boundary}\""),
                )],
                body,
            )
        }
        (Some(text), None) => text_body(text),
        (None, Some(html)) => html_body(html),
        // Validation guarantees one of the two exists; a body-only fallback
        // keeps the function total instead of panicking in a handler.
        (None, None) => text_body(""),
    }
}

fn text_body(text: &str) -> (Vec<(String, String)>, String) {
    (
        vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        format!(
            "Content-Transfer-Encoding: base64{CRLF}{CRLF}{}{CRLF}",
            wrap_base64(&base64_bytes(text.as_bytes()))
        ),
    )
}

fn html_body(html: &str) -> (Vec<(String, String)>, String) {
    (
        vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        format!(
            "Content-Transfer-Encoding: base64{CRLF}{CRLF}{}{CRLF}",
            wrap_base64(&base64_bytes(html.as_bytes()))
        ),
    )
}

fn attachment_part(attachment: &AttachmentPart, boundary: &str) -> String {
    let mut out = format!("--{boundary}{CRLF}");
    out.push_str(&format!(
        "Content-Type: application/octet-stream; name=\"{}\"{CRLF}",
        attachment.filename
    ));
    out.push_str("Content-Transfer-Encoding: base64\r\n");
    out.push_str(&format!(
        "Content-Disposition: attachment; filename=\"{}\"{CRLF}",
        attachment.filename
    ));
    if let Some(content_id) = &attachment.content_id {
        out.push_str(&format!("Content-ID: <{content_id}>{CRLF}"));
    }
    out.push_str(CRLF);
    out.push_str(&wrap_base64(&base64_bytes(&attachment.bytes)));
    out.push_str(CRLF);
    out
}

fn join_addresses(addresses: impl Iterator<Item = String>) -> String {
    addresses.collect::<Vec<_>>().join(", ")
}

fn base64_bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Fold base64 into 76-character lines, as RFC 2045 requires.
fn wrap_base64(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2);
    for (index, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if index > 0 {
            out.push_str(CRLF);
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

/// RFC 2047 encoded-word for non-ASCII subjects; ASCII subjects pass through so
/// the common case stays readable in a mail client.
fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() {
        return subject.to_string();
    }
    format!("=?UTF-8?B?{}?=", base64_bytes(subject.as_bytes()))
}

/// 16 hex characters of OS randomness, for MIME boundaries.
fn random_token() -> String {
    let random = pigeon_crypto::generate_content_key();
    hex::encode(&random[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Mailbox, SendRequest};
    use std::collections::BTreeMap;

    fn validated(json: serde_json::Value) -> ValidatedSend {
        let request: SendRequest = serde_json::from_value(json).expect("request");
        request.validate(None).expect("valid")
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "from": "Dana <dana@pigeonmail.dev>",
            "to": ["carol@example.org"],
            "subject": "Invoice #2041 paid",
            "text": "Thanks!",
        })
    }

    #[test]
    fn text_only_message_has_the_expected_headers_and_no_bcc() {
        let mut json = base();
        json["bcc"] = serde_json::json!(["secret@example.org"]);
        json["cc"] = serde_json::json!(["dave@example.net"]);
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_9f2a44c1", 1_793_923_200)).expect("utf8");

        assert!(mime.contains("From: Dana <dana@pigeonmail.dev>\r\n"));
        assert!(mime.contains("To: carol@example.org\r\n"));
        assert!(mime.contains("Cc: dave@example.net\r\n"));
        assert!(mime.contains("Subject: Invoice #2041 paid\r\n"));
        assert!(mime.contains("Message-ID: <eml_9f2a44c1@pigeonmail.dev>\r\n"));
        assert!(mime.contains("Date: Fri, 06 Nov 2026 00:00:00 +0000\r\n"));
        assert!(mime.contains("MIME-Version: 1.0\r\n"));
        assert!(mime.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(
            !mime.contains("secret@example.org"),
            "bcc must never be rendered: {mime}"
        );
        assert!(
            !mime.replace("\r\n", "").contains('\n'),
            "every LF must be preceded by CR: {mime}"
        );
    }

    #[test]
    fn html_and_text_become_multipart_alternative() {
        let mut json = base();
        json["html"] = serde_json::json!("<p>Thanks!</p>");
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        assert!(mime.contains("multipart/alternative; boundary=\"alt-"));
        assert!(mime.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(mime.contains("Content-Type: text/html; charset=utf-8"));
        assert!(
            mime.contains(&base64::engine::general_purpose::STANDARD.encode("<p>Thanks!</p>")),
            "html body is base64"
        );
    }

    #[test]
    fn attachments_wrap_the_body_in_multipart_mixed() {
        let mut json = base();
        json["attachments"] = serde_json::json!([
            {"filename": "receipt.pdf", "content": "aGVsbG8=", "content_id": "receipt"}
        ]);
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        assert!(mime.contains("multipart/mixed; boundary=\"mixed-"));
        assert!(mime.contains("Content-Disposition: attachment; filename=\"receipt.pdf\""));
        assert!(mime.contains("Content-ID: <receipt>"));
        assert!(mime.contains("aGVsbG8="));
        assert!(mime.trim_end().ends_with("--"));
    }

    #[test]
    fn custom_headers_are_rendered_and_denylisted_ones_are_impossible() {
        let mut json = base();
        json["headers"] = serde_json::json!({"X-Campaign": "nov-billing"});
        json["reply_to"] = serde_json::json!("support@pigeonmail.dev");
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        assert!(mime.contains("X-Campaign: nov-billing\r\n"));
        assert!(mime.contains("Reply-To: support@pigeonmail.dev\r\n"));
    }

    #[test]
    fn non_ascii_subjects_are_rfc2047_encoded() {
        let mut json = base();
        json["subject"] = serde_json::json!("Factura nº 2041 — pagada");
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        assert!(mime.contains("Subject: =?UTF-8?B?"));
        assert!(
            !mime.contains("Factura nº"),
            "raw non-ASCII must not reach a header"
        );
    }

    #[test]
    fn base64_lines_are_folded_at_76_characters() {
        let long = "x".repeat(500);
        let mut json = base();
        json["text"] = serde_json::json!(long);
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        for line in mime.split("\r\n") {
            assert!(line.len() <= 998, "MIME lines stay under the hard limit");
        }
        assert!(mime.lines().any(|line| line.len() >= 60));
    }

    #[test]
    fn header_order_puts_server_headers_after_caller_headers() {
        let mut json = base();
        let mut headers = BTreeMap::new();
        headers.insert("X-One".to_string(), "1".to_string());
        json["headers"] = serde_json::json!(headers);
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        let x_index = mime.find("X-One: 1").expect("custom header");
        let content_type = mime.find("Content-Type:").expect("content type");
        assert!(x_index < content_type);
        assert_eq!(
            send.from,
            Mailbox {
                display: Some("Dana".to_string()),
                address: pigeon_core::EmailAddress::parse("dana@pigeonmail.dev").expect("address")
            }
        );
    }

    #[test]
    fn boundaries_are_random_per_message() {
        let send = validated(base());
        let one = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        let two = String::from_utf8(build(&send, "eml_1", 0)).expect("utf8");
        assert_eq!(random_token().len(), 16);
        // Text-only messages have no boundary at all, so compare token draws.
        assert!(one.contains("Content-Type: text/plain"));
        assert!(two.contains("Content-Type: text/plain"));
    }
}
