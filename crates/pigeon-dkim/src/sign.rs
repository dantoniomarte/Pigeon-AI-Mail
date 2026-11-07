//! `DKIM-Signature` construction (RFC 6376 §3.5 and §3.7).
//!
//! Signing input, in order:
//!
//! 1. every signed header, canonicalized relaxed, in `h=` order,
//! 2. the `DKIM-Signature` header itself, canonicalized relaxed, with an empty
//!    `b=` value and **without** its trailing CRLF.
//!
//! That byte sequence is hashed with SHA-256 and signed with RSASSA-PKCS1-v1_5.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rsa::pkcs1v15::Pkcs1v15Sign;
use sha2::{Digest, Sha256};

use crate::canonical::{relaxed_body, relaxed_header};
use crate::error::{DkimError, Result};
use crate::key::{DkimKeyPair, ALGORITHM, CANONICALIZATION};

/// Sign a message with the minimum safe header set of RFC 6376 §5.4:
/// `from`, `to`, `subject`, `date`, `message-id`.
///
/// Returns the complete `DKIM-Signature` header value; the caller prepends
/// `DKIM-Signature: ` when it serializes the message.
pub fn sign_message(
    key: &DkimKeyPair,
    from: &str,
    to: &str,
    subject: &str,
    date: &str,
    message_id: &str,
    body: &str,
) -> Result<String> {
    let headers = [
        format!("From: {from}"),
        format!("To: {to}"),
        format!("Subject: {subject}"),
        format!("Date: {date}"),
        format!("Message-ID: {message_id}"),
    ];
    let fields: Vec<&str> = headers.iter().map(String::as_str).collect();
    key.sign(&fields, body)
}

/// The core signing path behind [`DkimKeyPair::sign`].
pub(crate) fn sign_with(key: &DkimKeyPair, headers: &[&str], body: &str) -> Result<String> {
    if headers.is_empty() {
        return Err(DkimError::Sign("no headers were given to sign".into()));
    }

    let mut signed_names = Vec::with_capacity(headers.len());
    let mut canonical_headers = String::new();
    for raw in headers {
        let (name, value) = split_field(raw)?;
        signed_names.push(name.trim().to_ascii_lowercase());
        canonical_headers.push_str(&relaxed_header(name, value));
    }

    let body_hash = STANDARD.encode(Sha256::digest(relaxed_body(body).as_bytes()));

    // Built as a single line: folding is preserved on the wire by whoever
    // serializes the message, and relaxed canonicalization makes the result
    // independent of that folding.
    let unsigned = format!(
        "v=1; a={ALGORITHM}; c={CANONICALIZATION}; d={}; s={}; h={}; bh={body_hash}; b=",
        key.domain(),
        key.selector(),
        signed_names.join(":")
    );

    let mut signing_input = canonical_headers;
    signing_input.push_str(without_crlf(&relaxed_header("DKIM-Signature", &unsigned)));

    let digest = Sha256::digest(signing_input.as_bytes());
    let signature = key
        .rsa_private()
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| DkimError::Sign(format!("RSA signing failed: {e}")))?;

    Ok(format!("{unsigned}{}", STANDARD.encode(signature)))
}

/// Split a raw header field into its name and its (still folded) value.
fn split_field(raw: &str) -> Result<(&str, &str)> {
    match raw.split_once(':') {
        Some((name, value)) if !name.trim().is_empty() => Ok((name, value)),
        _ => Err(DkimError::Parse(format!(
            "header field is not in `Name: value` form: {raw:?}"
        ))),
    }
}

fn without_crlf(canonical: &str) -> &str {
    canonical.strip_suffix("\r\n").unwrap_or(canonical)
}
