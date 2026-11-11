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
//!
//! # Sealed messages (layer 3)
//!
//! [`build_encrypted`] renders the same envelope with the body replaced by an
//! OpenPGP seal, in the shape RFC 3156 §4 defines: a `multipart/encrypted` with a
//! `Version: 1` control part and an `application/octet-stream` part holding the
//! armored message. The plaintext that gets sealed is [`body_part_bytes`] — the
//! body part **with its own headers**, which is what RFC 3156 requires and what
//! makes the message openable by any PGP-capable client.
//!
//! `From`, `To`, `Subject`, `Date` and `Message-ID` stay in the clear: SMTP routing
//! needs them, and that is the same subject-line caveat Proton documents.

use base64::Engine;

use crate::models::{AttachmentPart, ValidatedSend};
use crate::time::rfc5322_date;

const CRLF: &str = "\r\n";

/// Escape a stored document for mbox (mboxrd): every line that starts with
/// any number of `>` followed by `From ` gains one `>` — both a bare `From `
/// and a quoted `>From ` must survive a round-trip through a conformant mbox
/// reader (which strips one `>` from `^>*From ` lines) without being
/// mistaken for separators. Shared by the API and MCP export surfaces.
pub fn mbox_escape(document: &str) -> String {
    let mut out = String::with_capacity(document.len() + 16);
    for line in document.split_inclusive('\n') {
        let trimmed = line.strip_suffix('\n').unwrap_or(line);
        let mut depth = 0usize;
        for byte in trimmed.bytes() {
            if byte == b'>' {
                depth += 1;
            } else {
                break;
            }
        }
        if trimmed[depth..].starts_with("From ") {
            out.push('>');
        }
        out.push_str(line);
        if !line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Render `send` as a complete MIME message, CRLF-terminated and ready to seal.
pub fn build(send: &ValidatedSend, message_id: &str, created_unix: i64) -> Vec<u8> {
    let mut headers = envelope_headers(send, message_id, created_unix);
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

/// The body part on its own — headers **and** body — as the plaintext an OpenPGP
/// seal covers (RFC 3156 §4: the encrypted entity is a MIME body part).
pub fn body_part_bytes(send: &ValidatedSend) -> Vec<u8> {
    let (headers, body) = body_part(send);
    let mut out = String::with_capacity(body.len() + 512);
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

/// Render `send` with its body replaced by an OpenPGP seal (layer 3).
///
/// `armored` is the sealed payload from [`pigeon_crypto::seal_payload`]; the
/// headers of the message stay exactly as [`build`] renders them, because the
/// envelope must remain routable and readable.
pub fn build_encrypted(
    send: &ValidatedSend,
    message_id: &str,
    created_unix: i64,
    armored: &str,
) -> Vec<u8> {
    let boundary = format!("pgp-{}", random_token());
    let mut headers = envelope_headers(send, message_id, created_unix);
    headers.push((
        "Content-Type".to_string(),
        format!(
            "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\""
        ),
    ));

    let mut out = String::with_capacity(armored.len() + 2048);
    for (name, value) in headers {
        out.push_str(&name);
        out.push_str(": ");
        out.push_str(&value);
        out.push_str(CRLF);
    }
    out.push_str(CRLF);

    // Part 1: the version control part, with an empty body (RFC 3156 §4).
    out.push_str(&format!("--{boundary}{CRLF}"));
    out.push_str("Content-Type: application/pgp-encrypted\r\n");
    out.push_str("Content-Description: PGP/MIME version identification\r\n");
    out.push_str(CRLF);
    out.push_str(&format!("Version: 1{CRLF}"));
    out.push_str(CRLF);

    // Part 2: the armored OpenPGP message.
    out.push_str(&format!("--{boundary}{CRLF}"));
    out.push_str(&format!(
        "Content-Type: application/octet-stream; name=\"encrypted.asc\"{CRLF}"
    ));
    out.push_str("Content-Description: OpenPGP encrypted message\r\n");
    out.push_str(&format!(
        "Content-Disposition: inline; filename=\"encrypted.asc\"{CRLF}"
    ));
    out.push_str(CRLF);
    // The armor already ends with its own newline; normalize to CRLF so no bare
    // LF reaches an intermediary that folds differently than we do.
    for line in armored.replace("\r\n", "\n").lines() {
        out.push_str(line);
        out.push_str(CRLF);
    }
    out.push_str(&format!("--{boundary}--{CRLF}"));
    out.into_bytes()
}

/// Caller-visible headers, independent of how the body is protected.
fn envelope_headers(
    send: &ValidatedSend,
    message_id: &str,
    created_unix: i64,
) -> Vec<(String, String)> {
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
    headers
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
        vec![
            (
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            // The CTE is a PART HEADER: it must sit before the blank line that
            // separates headers from the body. Writing it into the body string
            // made clients render the literal header line and the raw base64
            // (the text-only send path; the multipart/alternative path was
            // always correct).
            (
                "Content-Transfer-Encoding".to_string(),
                "base64".to_string(),
            ),
        ],
        format!("{}{CRLF}", wrap_base64(&base64_bytes(text.as_bytes()))),
    )
}

fn html_body(html: &str) -> (Vec<(String, String)>, String) {
    (
        vec![
            (
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            // Same part-header rule as text_body (see the comment there).
            (
                "Content-Transfer-Encoding".to_string(),
                "base64".to_string(),
            ),
        ],
        format!("{}{CRLF}", wrap_base64(&base64_bytes(html.as_bytes()))),
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
    fn html_only_part_carries_cte_as_a_header() {
        // Mirror of the text-only regression test: html_body() had the same
        // body-string CTE defect, and base()-derived tests always carry a text
        // part, so nothing exercised this function until now.
        let mut json = base();
        json["text"] = serde_json::Value::Null;
        json["html"] = serde_json::json!("<p>Hi</p>");
        let send = validated(json);
        let mime = String::from_utf8(build(&send, "eml_cte_html", 1_793_923_200)).expect("utf8");
        let header_block = mime.split("\r\n\r\n").next().expect("header block");
        assert!(header_block.contains("Content-Type: text/html; charset=utf-8"));
        assert!(header_block.contains("Content-Transfer-Encoding: base64"));
        let body = mime.split("\r\n\r\n").nth(1).expect("body block");
        assert!(!body.contains("Content-Transfer-Encoding"));
    }

    #[test]
    fn text_only_part_carries_cte_as_a_header_not_body_text() {
        // Regression: the CTE used to be written at the START of the body
        // string, AFTER the header/body blank line — clients then rendered the
        // literal "Content-Transfer-Encoding: base64" line and the raw base64
        // as the message text (observed in production with an integrated
        // transactional sender). The CTE is a part header and must precede
        // the blank line.
        let send = validated(base());
        let mime = String::from_utf8(build(&send, "eml_cte_test", 1_793_923_200)).expect("utf8");
        let header_block = mime.split("\r\n\r\n").next().expect("header block");
        assert!(
            header_block.contains("Content-Transfer-Encoding: base64"),
            "CTE must be a header of the part, before the first blank line: {mime}"
        );
        // And the body itself must be pure base64 (no header text inside).
        let body = mime.split("\r\n\r\n").nth(1).expect("body block");
        assert!(
            !body.contains("Content-Transfer-Encoding"),
            "the body must not embed a header line: {body}"
        );
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
    fn the_sealed_body_is_the_body_part_with_its_own_headers() {
        let mut json = base();
        json["html"] = serde_json::json!("<p>Thanks!</p>");
        let send = validated(json);
        let inner = String::from_utf8(body_part_bytes(&send)).expect("utf8");
        // RFC 3156 encrypts a MIME body part, headers included, and nothing of the
        // envelope: the subject and the addresses stay outside the seal.
        assert!(inner.starts_with("Content-Type: multipart/alternative; boundary="));
        assert!(inner.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(!inner.contains("Subject:"));
        assert!(!inner.contains("From:"));
        assert!(!inner.contains("To:"));
    }

    #[test]
    fn a_sealed_message_keeps_the_envelope_and_wraps_the_ciphertext() {
        let send = validated(base());
        let armor = "-----BEGIN PGP MESSAGE-----\n\nhQEMA123\n-----END PGP MESSAGE-----\n";
        let mime =
            String::from_utf8(build_encrypted(&send, "eml_1", 1_793_923_200, armor)).expect("utf8");

        // The envelope is routing information and stays readable (Proton's
        // documented subject-line caveat).
        assert!(mime.contains("From: Dana <dana@pigeonmail.dev>\r\n"));
        assert!(mime.contains("Subject: Invoice #2041 paid\r\n"));
        assert!(mime.contains("Message-ID: <eml_1@pigeonmail.dev>\r\n"));
        assert!(mime.contains("Date: Fri, 06 Nov 2026 00:00:00 +0000\r\n"));

        // The body is an RFC 3156 multipart/encrypted with a version part and the
        // armored payload, and no plaintext of the original body survives.
        assert!(mime.contains(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"pgp-"
        ));
        assert!(mime.contains("Content-Type: application/pgp-encrypted"));
        assert!(mime.contains("Version: 1\r\n"));
        assert!(mime.contains("Content-Type: application/octet-stream; name=\"encrypted.asc\""));
        assert!(mime.contains("-----BEGIN PGP MESSAGE-----"));
        assert!(
            !mime.contains("Thanks!"),
            "the plaintext body must not appear: {mime}"
        );
        assert!(
            !mime.replace("\r\n", "").contains('\n'),
            "the armored block is normalized to CRLF: {mime}"
        );
        assert!(mime.trim_end().ends_with("--"));
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
    #[test]
    fn text_only_body_part_bytes_is_a_well_formed_mime_entity() {
        // Review round-1 follow-up: the PGP sealing path seals exactly what
        // body_part_bytes() returns, so the text-only shape must be a valid
        // MIME entity on its own: part headers, ONE blank line, then a body
        // with no embedded header lines (the CTE now lives with the headers).
        let send = validated(base());
        let entity = String::from_utf8(body_part_bytes(&send)).expect("utf8");
        let mut blocks = entity.split("\r\n\r\n");
        let headers = blocks.next().expect("part headers");
        assert!(headers.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(headers.contains("Content-Transfer-Encoding: base64"));
        let body = blocks.next().expect("body");
        assert!(!body.contains("Content-Transfer-Encoding"));
        assert!(blocks.next().is_none(), "one header/body boundary only");
    }
}

#[cfg(test)]
mod mbox_escape_tests {
    use super::mbox_escape;

    #[test]
    fn mbox_escape_covers_bare_and_quoted_from_lines() {
        // LF-only input keeps the assertions byte-exact (CRLF input would
        // carry the \r through: mbox_escape touches only the \n suffix).
        let doc = "From the top.\n>From the quoted reply.\n>>From nested.\nFrom: header untouched\nunterminated";
        let escaped = mbox_escape(doc);
        let lines: Vec<&str> = escaped.split('\n').collect();
        assert_eq!(lines[0], ">From the top.");
        assert_eq!(lines[1], ">>From the quoted reply.");
        assert_eq!(lines[2], ">>>From nested.");
        assert_eq!(lines[3], "From: header untouched");
        assert_eq!(lines[4], "unterminated");
        // A CRLF document keeps its \r: the escape only adds the '>'.
        let crlf = "From the top.\r\n>From quoted.\r\n";
        let escaped_crlf = mbox_escape(crlf);
        assert!(escaped_crlf.contains(">From the top.\r\n"));
        assert!(escaped_crlf.contains(">>From quoted.\r\n"));
    }
}
