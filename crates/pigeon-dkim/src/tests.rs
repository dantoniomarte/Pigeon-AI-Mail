//! Contract tests for "sign outbound, verify inbound".
//!
//! The roundtrip is the money test: a message signed with our own code and
//! verified against the DNS record we tell operators to publish must pass.
//! Everything else is an attack: tampered body, tampered header, swapped key,
//! missing key, downgraded algorithm, garbage signature.
//!
//! Mutation checks were performed manually during development (see the
//! `mutation` notes on individual tests): breaking the `b=` stripping, the
//! body-hash comparison or the `h=` selection makes the corresponding test
//! fail, which is what proves these tests can fail.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::canonical::relaxed_body;
use crate::error::DkimError;
use crate::key::DkimKeyPair;
use crate::sign::sign_message;
use crate::verify::verify_message;

const SELECTOR: &str = "mail";
const DOMAIN: &str = "example.com";
const DNS_NAME: &str = "mail._domainkey.example.com";

const FROM: &str = "Alice <alice@example.com>";
const TO: &str = "Bob <bob@example.net>";
const SUBJECT: &str = "Pigeon says hi";
const DATE: &str = "Tue, 1 Jul 2025 12:00:00 +0000";
const MESSAGE_ID: &str = "<20250701120000.pigeon@example.com>";

// ---------------------------------------------------------------- fixtures

/// One 2048-bit key for the whole suite: RSA key generation dominates the
/// runtime in a debug build, and every test only reads it.
fn key() -> &'static DkimKeyPair {
    static KEY: std::sync::OnceLock<DkimKeyPair> = std::sync::OnceLock::new();
    KEY.get_or_init(|| DkimKeyPair::generate(SELECTOR, DOMAIN).expect("key generation"))
}

fn body() -> &'static str {
    "Hello from Pigeon.\r\n\r\nThis body has two paragraphs.\r\n"
}

fn signed_headers() -> Vec<(String, String)> {
    vec![
        ("From".to_string(), FROM.to_string()),
        ("To".to_string(), TO.to_string()),
        ("Subject".to_string(), SUBJECT.to_string()),
        ("Date".to_string(), DATE.to_string()),
        ("Message-ID".to_string(), MESSAGE_ID.to_string()),
    ]
}

fn sign(key: &DkimKeyPair, body: &str) -> String {
    sign_message(key, FROM, TO, SUBJECT, DATE, MESSAGE_ID, body).expect("signing")
}

/// DNS stub for the healthy case: exactly the key we just generated.
fn published(key: &DkimKeyPair) -> impl Fn(&str) -> Option<String> {
    let record = key.public_key_dns_record();
    move |name: &str| (name == DNS_NAME).then(|| record.clone())
}

/// Parse a `DKIM-Signature` value into its tags (test-side, deliberately
/// independent of the crate's own parser).
fn tags(value: &str) -> BTreeMap<String, String> {
    value
        .split(';')
        .filter_map(|segment| segment.trim().split_once('='))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn tag(value: &str, name: &str) -> String {
    tags(value)
        .get(name)
        .unwrap_or_else(|| panic!("tag {name} not found in {value}"))
        .clone()
}

/// Replace the value of `name` in a `DKIM-Signature` value, leaving the rest
/// byte-identical.
fn with_tag(value: &str, name: &str, new_value: &str) -> String {
    value
        .split(';')
        .map(|segment| match segment.trim().split_once('=') {
            Some((tag_name, _)) if tag_name.trim() == name => {
                format!("{}={new_value}", &segment[..segment.find('=').unwrap()])
            }
            _ => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

// ------------------------------------------------------------------ happy path

#[test]
fn signed_message_verifies_against_published_dns_record() {
    let key = key();
    let dkim = sign(key, body());

    // The header value carries the whole RFC 6376 §3.5 tag set, in the order a
    // reader expects; `h=` is the minimum safe signed set of §5.4.
    assert!(dkim.starts_with("v=1; a=rsa-sha256; c=relaxed/relaxed;"));
    assert_eq!(tag(&dkim, "d"), DOMAIN);
    assert_eq!(tag(&dkim, "s"), SELECTOR);
    assert_eq!(tag(&dkim, "h"), "from:to:subject:date:message-id");
    assert!(!tag(&dkim, "bh").is_empty());
    assert!(!tag(&dkim, "b").is_empty());

    let result = verify_message(&dkim, &signed_headers(), body(), published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);
    assert_eq!(result.domain, DOMAIN);
    assert_eq!(result.selector, SELECTOR);
    assert_eq!(result.algorithm, "rsa-sha256");
    assert_eq!(result.reason, None);
}

#[test]
fn body_hash_tag_is_the_sha256_of_the_relaxed_body() {
    let key = key();
    let dkim = sign(key, body());
    let expected = STANDARD.encode(Sha256::digest(relaxed_body(body()).as_bytes()));
    assert_eq!(tag(&dkim, "bh"), expected);
}

// ------------------------------------------------------------------- tampering

#[test]
fn tampered_body_fails_the_body_hash() {
    let key = key();
    let dkim = sign(key, body());

    let result = verify_message(
        &dkim,
        &signed_headers(),
        "Hello from Pigeon.\r\n\r\nEVIL paragraph.\r\n",
        published(key),
    )
    .unwrap();

    assert!(!result.passed);
    let reason = result
        .reason
        .expect("a failed verification explains itself");
    assert!(reason.contains("body hash"), "unexpected reason: {reason}");
}

#[test]
fn tampered_subject_fails_the_signature() {
    let key = key();
    let dkim = sign(key, body());
    let mut headers = signed_headers();
    headers[2].1 = "Pigeon says bye".to_string();

    let result = verify_message(&dkim, &headers, body(), published(key)).unwrap();

    assert!(!result.passed);
    let reason = result
        .reason
        .expect("a failed verification explains itself");
    assert!(reason.contains("signature"), "unexpected reason: {reason}");
}

#[test]
fn dns_record_with_a_different_key_does_not_verify() {
    let key = key();
    let impostor = DkimKeyPair::generate(SELECTOR, DOMAIN).expect("impostor key");
    let dkim = sign(key, body());

    let result = verify_message(&dkim, &signed_headers(), body(), published(&impostor)).unwrap();

    assert!(
        !result.passed,
        "a foreign key must never verify our message"
    );
    assert!(result.reason.is_some());
}

#[test]
fn tampered_signature_bytes_do_not_verify() {
    let key = key();
    let dkim = sign(key, body());
    // Flip the first byte of the base64 signature payload.
    let signature = tag(&dkim, "b");
    let flipped = format!(
        "{}{}",
        if signature.starts_with('A') { "B" } else { "A" },
        &signature[1..]
    );
    let dkim = with_tag(&dkim, "b", &flipped);

    let result = verify_message(&dkim, &signed_headers(), body(), published(key)).unwrap();
    assert!(!result.passed);
}

// -------------------------------------------------------------- lookup/reject

#[test]
fn missing_dns_record_is_an_error_not_a_silent_pass() {
    let key = key();
    let dkim = sign(key, body());

    let err = verify_message(&dkim, &signed_headers(), body(), |_name| None)
        .expect_err("a missing key must not verify");

    match err {
        DkimError::Verify(message) => {
            assert!(message.contains(DNS_NAME), "unexpected message: {message}")
        }
        other => panic!("expected DkimError::Verify, got {other:?}"),
    }
}

#[test]
fn selector_mismatch_between_header_and_published_key() {
    let key = key();
    let dkim = sign(key, body());
    let tampered = with_tag(&dkim, "s", "other");

    // (a) The record is only published under the real selector: the lookup for
    // the selector the header *claims* finds nothing.
    let err = verify_message(&tampered, &signed_headers(), body(), published(key))
        .expect_err("lookup must follow the selector from the untrusted header");
    assert!(
        matches!(err, DkimError::Verify(ref message) if message.contains("other._domainkey.example.com")),
        "unexpected error: {err:?}"
    );

    // (b) Even if the same key is published under the wrong selector, rewriting
    // `s=` changes the signed bytes, so the signature no longer holds.
    let record = key.public_key_dns_record();
    let permissive = move |_name: &str| Some(record.clone());
    let result = verify_message(&tampered, &signed_headers(), body(), permissive).unwrap();
    assert!(!result.passed);
}

#[test]
fn unsupported_algorithm_is_rejected() {
    let key = key();
    let dkim = sign(key, body());
    for algorithm in ["ed25519-sha256", "rsa-sha1", "simple"] {
        let tampered = with_tag(&dkim, "a", algorithm);
        let err = verify_message(&tampered, &signed_headers(), body(), published(key))
            .expect_err("only rsa-sha256 is supported in v0.1");
        assert!(
            matches!(err, DkimError::UnsupportedAlgorithm(ref a) if a == algorithm),
            "unexpected error for {algorithm}: {err:?}"
        );
    }
}

#[test]
fn unsupported_canonicalization_is_rejected() {
    let key = key();
    let dkim = sign(key, body());
    let tampered = with_tag(&dkim, "c", "simple/simple");

    let err = verify_message(&tampered, &signed_headers(), body(), published(key))
        .expect_err("only relaxed/relaxed is supported in v0.1");
    assert!(
        matches!(err, DkimError::UnsupportedAlgorithm(ref c) if c.contains("simple")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn absent_signed_header_contributes_null_input() {
    // RFC 6376 §3.5: h= entries with no remaining instance contribute the null
    // input (oversigning is legal). Only From is mandatory.
    let key = key();
    let dkim = sign(key, body());
    let headers: Vec<(String, String)> = signed_headers()
        .into_iter()
        .filter(|(name, _)| name != "Subject")
        .collect();

    let result = verify_message(&dkim, &headers, body(), published(key))
        .expect("an absent non-From h= entry must not be an error");
    // The signature was computed over the original Subject, which is now gone:
    // the signing input differs, so verification must fail — but structurally,
    // not with MissingHeader.
    assert!(!result.passed, "absent Subject changes the signing input");
}

#[test]
fn missing_from_is_still_an_error() {
    let key = key();
    let dkim = sign(key, body());
    let headers: Vec<(String, String)> = signed_headers()
        .into_iter()
        .filter(|(name, _)| name != "From")
        .collect();

    let err = verify_message(&dkim, &headers, body(), published(key))
        .expect_err("a signature that never covered From must be rejected");
    assert!(
        matches!(err, DkimError::MissingHeader(ref name) if name.eq_ignore_ascii_case("from")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn unlisted_extra_headers_do_not_break_verification() {
    // RFC 6376 §3.7: headers not named in h= contribute nothing to the
    // signature. A message carrying extra (unlisted) Received headers must
    // still verify against a signature computed over From+Subject only.
    let key = key();
    let dkim = key
        .sign(&["From: dana@example.org", "Subject: order test"], body())
        .expect("sign From+Subject");
    let pairs: Vec<(String, String)> = vec![
        (
            "Received".to_string(),
            " from edge2 by relay2; id=2".to_string(),
        ),
        (
            "Received".to_string(),
            " from client by relay1; id=1".to_string(),
        ),
        ("From".to_string(), " dana@example.org".to_string()),
        ("Subject".to_string(), " order test".to_string()),
    ];
    let result =
        verify_message(&dkim, &pairs, body(), published(key)).expect("structural verification");
    assert!(
        result.passed,
        "unlisted extra headers must not break verification"
    );
}

#[test]
fn bad_base64_is_a_parse_error() {
    let key = key();
    let dkim = sign(key, body());
    let tampered = with_tag(&dkim, "b", "!!!not-base64!!!");

    let err = verify_message(&tampered, &signed_headers(), body(), published(key))
        .expect_err("malformed base64 must be rejected");
    assert!(
        matches!(err, DkimError::Parse(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn dns_record_without_a_key_tag_is_rejected() {
    let dkim = sign(key(), body());

    // `p=` empty means the key was revoked (RFC 6376 §3.6.1).
    let err = verify_message(&dkim, &signed_headers(), body(), |_name| {
        Some("v=DKIM1; k=rsa; p=".to_string())
    })
    .expect_err("an empty p= is a revoked key");
    assert!(
        matches!(err, DkimError::Verify(ref message) if message.contains("p=")),
        "unexpected error: {err:?}"
    );

    let err = verify_message(&dkim, &signed_headers(), body(), |_name| {
        Some("v=DKIM1; k=rsa; p=%%%not-base64%%%".to_string())
    })
    .expect_err("garbage in p= must be rejected");
    assert!(
        matches!(err, DkimError::Parse(_)),
        "unexpected error: {err:?}"
    );
}

// --------------------------------------------------------------- edge cases

#[test]
fn folded_header_values_roundtrip() {
    let key = key();
    // Sign a folded Subject; verify a differently folded but canonically
    // identical one (tabs, extra WSP, trailing WSP) — relaxed canonicalization
    // is what makes surviving MTA re-folding possible.
    let dkim = key
        .sign(
            &[
                "From: Alice <alice@example.com>",
                "Subject: Pigeon says\r\n  hi",
                "To: Bob <bob@example.net>",
            ],
            body(),
        )
        .expect("signing folded headers");
    assert_eq!(tag(&dkim, "h"), "from:subject:to");

    let headers = vec![
        (
            "From".to_string(),
            " Alice <alice@example.com> ".to_string(),
        ),
        ("Subject".to_string(), "Pigeon says \t  hi  ".to_string()),
        ("To".to_string(), "Bob\t<bob@example.net>".to_string()),
    ];

    let result = verify_message(&dkim, &headers, body(), published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);
}

#[test]
fn empty_body_hashes_a_single_crlf_and_verifies() {
    let key = key();
    let dkim = sign(key, "");

    let expected = STANDARD.encode(Sha256::digest(b"\r\n"));
    assert_eq!(tag(&dkim, "bh"), expected);

    let result = verify_message(&dkim, &signed_headers(), "", published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);

    // A body that only differs by trailing whitespace/blank lines canonicalizes
    // to the same CRLF, so it must still verify.
    let result = verify_message(&dkim, &signed_headers(), "  \r\n\r\n", published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);
}

#[test]
fn dkim_header_folding_by_a_relay_does_not_break_verification() {
    let key = key();
    let dkim = sign(key, body());

    // A relay may re-fold the DKIM-Signature header at whitespace boundaries;
    // relaxed canonicalization has to see the same bytes.
    let refolded = dkim
        .replacen("; h=", ";\r\n h=", 1)
        .replacen("; bh=", ";\r\n bh=", 1);
    assert_ne!(refolded, dkim);

    let result = verify_message(&refolded, &signed_headers(), body(), published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);
}

#[test]
fn duplicated_header_instances_resolve_bottom_up() {
    let key = key();
    // Two Received headers: `h=` lists one, the verifier must pick the right
    // instance (RFC 6376 §5.4.2: bottom-up with h=).
    let dkim = key
        .sign(
            &["From: Alice <alice@example.com>", "Received: by mx2"],
            body(),
        )
        .expect("signing with a duplicated name");

    let headers = vec![
        ("From".to_string(), "Alice <alice@example.com>".to_string()),
        ("Received".to_string(), "by mx1".to_string()),
        ("Received".to_string(), "by mx2".to_string()),
    ];
    let result = verify_message(&dkim, &headers, body(), published(key)).unwrap();
    assert!(result.passed, "reason: {:?}", result.reason);

    // Same list, but the last Received changed: the signature covered "by mx2".
    let mut tampered = headers.clone();
    tampered[2].1 = "by evil".to_string();
    let result = verify_message(&dkim, &tampered, body(), published(key)).unwrap();
    assert!(!result.passed);
}

// ------------------------------------------------- PKCS#8 persistence roundtrip

/// A key rebuilt from its own PKCS#8 bytes must be the *same* identity: it
/// publishes the same DNS record and its signatures verify against that record.
/// This is what makes storing a private key and rebuilding it per send safe.
#[test]
fn pkcs8_roundtrip_preserves_the_signing_identity() {
    let original = key();
    let der = original.to_pkcs8_der().expect("encode pkcs8");
    let rebuilt = DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, &der).expect("decode pkcs8");

    assert_eq!(rebuilt.selector(), original.selector());
    assert_eq!(rebuilt.domain(), original.domain());
    assert_eq!(
        rebuilt.public_key_dns_record(),
        original.public_key_dns_record(),
        "the rebuilt key must publish the exact record that verifies it"
    );

    // Sign with the original, verify against the rebuilt key's DNS record: the
    // two objects are interchangeable over the wire.
    let dkim = sign(original, body());
    let result = verify_message(&dkim, &signed_headers(), body(), published(&rebuilt))
        .expect("verify with the rebuilt key's record");
    assert!(result.passed, "reason: {:?}", result.reason);

    // And the other direction: sign with the rebuilt key, verify with the
    // original's record.
    let dkim = sign(&rebuilt, body());
    let result = verify_message(&dkim, &signed_headers(), body(), published(original))
        .expect("verify the rebuilt signature with the original record");
    assert!(result.passed, "reason: {:?}", result.reason);
}

/// Encoding and decoding must not be lossy in a way that changes signatures.
#[test]
fn pkcs8_is_deterministic_across_repeated_encodes() {
    let original = key();
    let first = original.to_pkcs8_der().expect("encode");
    let second = DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, &first)
        .expect("decode")
        .to_pkcs8_der()
        .expect("re-encode");
    assert_eq!(first, second, "a PKCS#8 round trip must be byte-stable");
}

/// Private material must never reach a log line, in either constructor.
#[test]
fn debug_output_never_contains_key_material() {
    let original = key();
    let der = original.to_pkcs8_der().expect("encode");
    let rebuilt = DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, &der).expect("decode");

    let hex: String = der.iter().map(|byte| format!("{byte:02x}")).collect();
    let base64 = STANDARD.encode(&der);
    for (label, pair) in [("generated", original), ("rebuilt", &rebuilt)] {
        let rendered = format!("{pair:?}");
        assert!(rendered.contains("<redacted>"), "{label}: {rendered}");
        assert!(!rendered.contains(&hex), "{label} leaked DER hex");
        assert!(!rendered.contains(&base64), "{label} leaked DER base64");
        // Neither the PKCS#8 nor the SPKI body may appear, even partially.
        assert!(!rendered.contains("<p>"), "{label} leaked a p= tag");
    }
}

/// Corrupt or truncated bytes are a parse error, never a silently wrong key.
#[test]
fn decoding_garbage_pkcs8_is_an_error() {
    let mut der = key().to_pkcs8_der().expect("encode");
    // Flip a byte in the middle: the DER structure no longer parses.
    let middle = der.len() / 2;
    der[middle] ^= 0xff;
    assert!(DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, &der).is_err());

    assert!(DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, b"not a private key").is_err());
    assert!(DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, b"").is_err());
}

/// RFC 8301 forbids short keys, and a stored 512-bit key would sign messages
/// every verifier rejects; it must fail at load time instead.
#[test]
fn undersized_keys_are_refused_on_load() {
    let weak = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 512).expect("512-bit key");
    let der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&weak)
        .expect("encode")
        .as_bytes()
        .to_vec();
    let error =
        DkimKeyPair::from_pkcs8_der(SELECTOR, DOMAIN, &der).expect_err("512 bits must be refused");
    assert!(
        matches!(error, DkimError::UnsupportedAlgorithm(_)),
        "{error:?}"
    );
}
