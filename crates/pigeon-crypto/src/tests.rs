//! Tests are the contract: RFC 6238 official vectors prove the TOTP core;
//! tamper / wrong-aad / key-swap / cross-domain cases prove the AEAD binding.
//!
//! Mutation checks were performed **manually during development**, not in CI —
//! e.g. breaking the RFC 4226 dynamic truncation (using the first digest byte as
//! the offset instead of the last) made the RFC 6238 vector tests fail, which is
//! what proved those tests can fail.

use crate::key::{
    b64url, b64url_decode, generate_api_key, generate_webhook_secret, hash_api_key, parse_api_key,
    verify_api_key, MasterKey, DUMMY_PHC,
};
use crate::seal::{
    generate_content_key, open_content, seal_content, unwrap_key, wrap_key, ENVELOPE_VERSION,
    MIN_BLOB_LEN, VERSION_LEN,
};
use crate::totp::{generate_totp_secret, Totp, TotpAlg, MAX_WINDOW, MIN_SECRET_LEN};

// --------------------------------------------------------------- TOTP (RFC 6238)

/// Official RFC 6238 test vectors: secret "12345678901234567890" (ASCII),
/// T0=0, step 30s, 8 digits, SHA-1.
#[test]
fn totp_rfc6238_sha1_vectors_8_digits() {
    let secret = b"12345678901234567890";
    let totp = Totp::new(secret).digits(8).unwrap();
    let cases: &[(u64, &str)] = &[
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];
    for (t, expected) in cases {
        assert_eq!(&totp.generate(*t), expected, "vector at T={t}");
    }
}

/// Same bin truncated to the Google Authenticator 6-digit profile.
/// (RFC 6238 publishes only 8-digit vectors; the 6-digit set is the same
/// truncated value mod 10^6 — verified against authenticator apps.)
#[test]
fn totp_rfc6238_sha1_vectors_6_digits() {
    let secret = b"12345678901234567890";
    let totp = Totp::new(secret); // 6 digits default
    let cases: &[(u64, &str)] = &[
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ];
    for (t, expected) in cases {
        assert_eq!(&totp.generate(*t), expected, "vector at T={t}");
    }
}

/// RFC 6238 publishes its own (different) SHA-256 vector set.
#[test]
fn totp_rfc6238_sha256_vector() {
    let secret = b"12345678901234567890123456789012";
    let totp = Totp::new(secret).alg(TotpAlg::Sha256).digits(8).unwrap();
    assert_eq!(totp.generate(59), "46119246");
    assert_eq!(totp.generate(1111111109), "68084774");
    assert_eq!(totp.generate(1234567890), "91819424");
}

#[test]
fn totp_verify_window_and_rejections() {
    let totp = Totp::new(b"0123456789abcdef0123");
    let t = 1_700_000_015; // mid-step: t / 30 = 56666667
    let counter = t / 30;
    let current = totp.generate(t);
    assert!(totp.verify(&current, t, 1), "exact step must verify");

    let prev = totp.generate(t - 30);
    let next = totp.generate(t + 30);
    assert!(
        totp.verify(&prev, t, 1),
        "counter {counter}-1 must verify within ±1"
    );
    assert!(
        totp.verify(&next, t, 1),
        "counter {counter}+1 must verify within ±1"
    );

    // Exact counter math in the message: t-90 is counter-3, outside [counter-1, counter+1].
    let old = totp.generate(t - 90);
    assert!(
        !totp.verify(&old, t, 1),
        "counter {counter}-3 (= {}) must be rejected when the accepted window is [{}, {}]",
        counter - 3,
        counter - 1,
        counter + 1
    );

    let mut off_by_one_digit = current.clone();
    let replacement = if current.as_bytes()[3] == b'0' {
        "1"
    } else {
        "0"
    };
    off_by_one_digit.replace_range(3..4, replacement);
    assert!(
        !totp.verify(&off_by_one_digit, t, 1),
        "wrong code must fail"
    );

    assert!(!totp.verify("12345", t, 1), "wrong length must fail");
    assert!(!totp.verify("12345a", t, 1), "non-digit must fail");
    assert!(!totp.verify("", t, 1), "empty must fail");
}

/// `verify` must evaluate every candidate in the window (OR-accumulated, no
/// short-circuit) — a match at the far edge still verifies, one beyond does not.
#[test]
fn totp_verify_checks_every_window_candidate() {
    let totp = Totp::new(b"0123456789abcdef0123");
    let t = 1_700_000_015;
    let counter = t / 30;
    let oldest_accepted = totp.generate(t - 90);
    assert!(
        totp.verify(&oldest_accepted, t, 3),
        "counter {}-3 must verify with window 3 (last candidate evaluated)",
        counter
    );
    let too_old = totp.generate(t - 120);
    assert!(
        !totp.verify(&too_old, t, 3),
        "counter {}-4 must be rejected with window 3",
        counter
    );
}

#[test]
fn totp_config_validation() {
    let t = Totp::new(b"secret");
    assert!(
        t.clone().digits(7).is_err(),
        "7 digits is not a supported profile"
    );
    assert!(t.clone().digits(8).is_ok());
    assert!(t.clone().step(0).is_err());
}

#[test]
fn totp_try_new_enforces_minimum_secret_length() {
    assert!(Totp::try_new(b"").is_err(), "empty secret must be rejected");
    assert!(
        Totp::try_new(b"x").is_err(),
        "1-byte secret must be rejected"
    );
    let just_below = vec![0x11u8; MIN_SECRET_LEN - 1];
    assert!(
        Totp::try_new(&just_below).is_err(),
        "15-byte secret must be rejected"
    );
    let minimum = vec![0x11u8; MIN_SECRET_LEN];
    assert!(
        Totp::try_new(&minimum).is_ok(),
        "16-byte secret is the RFC 4226 minimum"
    );
    assert!(
        Totp::try_new(&generate_totp_secret()).is_ok(),
        "generated secret must be accepted"
    );
}

#[test]
fn totp_generate_secret_is_20_random_bytes() {
    let a = generate_totp_secret();
    let b = generate_totp_secret();
    assert_eq!(a.len(), 20, "RFC 4226 R6 recommends 160-bit secrets");
    assert_ne!(a, b, "secrets must come from a CSPRNG, not a constant");
    assert!(Totp::try_new(&a).is_ok());
    // The generated secret must drive a working verifier.
    let totp = Totp::try_new(&a).unwrap();
    let code = totp.generate(1_700_000_000);
    assert!(totp.verify(&code, 1_700_000_000, 1));
}

#[test]
fn totp_verify_rejects_oversized_window() {
    let totp = Totp::new(b"0123456789abcdef0123");
    let t = 1_700_000_015;
    let code = totp.generate(t);
    assert!(
        totp.verify(&code, t, MAX_WINDOW),
        "the documented maximum window must still accept an exact-step code"
    );
    assert!(
        !totp.verify(&code, t, MAX_WINDOW + 1),
        "window {} exceeds MAX_WINDOW={MAX_WINDOW} and must be rejected without checking",
        MAX_WINDOW + 1
    );
    assert!(
        !totp.verify(&code, t, u32::MAX),
        "absurd window must be rejected immediately"
    );
}

// --------------------------------------------------------------- sealing (at rest)

#[test]
fn seal_open_roundtrip() {
    let key = generate_content_key();
    let aad = b"account:42|message:1001";
    let body = b"Hi Dana,\n\nYour invoice #2041 was paid.\n";
    let blob = seal_content(&key, body, aad).unwrap();
    assert_ne!(blob, body, "ciphertext must differ from plaintext");
    assert_eq!(blob.len(), body.len() + MIN_BLOB_LEN);
    assert_eq!(open_content(&key, &blob, aad).unwrap(), body);
}

#[test]
fn seal_unique_nonce_per_call() {
    let key = generate_content_key();
    let a1 = seal_content(&key, b"same body", b"aad").unwrap();
    let a2 = seal_content(&key, b"same body", b"aad").unwrap();
    assert_ne!(a1, a2, "random nonce must make ciphertexts differ");
}

#[test]
fn seal_tamper_fails() {
    let key = generate_content_key();
    let aad = b"ctx";
    let mut blob = seal_content(&key, b"trust the pigeon", aad).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01; // flip one bit of the tag
    assert!(matches!(
        open_content(&key, &blob, aad),
        Err(crate::CryptoError::Decrypt)
    ));
}

#[test]
fn seal_rejects_wrong_aad_and_wrong_key() {
    let key = generate_content_key();
    let blob = seal_content(&key, b"body", b"account:1").unwrap();
    // AAD mismatch: blob transplanted into another context must not decrypt.
    assert!(open_content(&key, &blob, b"account:2").is_err());
    // Key mismatch: wrong content key must not decrypt.
    let other = generate_content_key();
    assert!(open_content(&other, &blob, b"account:1").is_err());
}

#[test]
fn seal_rejects_malformed_blob() {
    let key = generate_content_key();
    let short = vec![0u8; MIN_BLOB_LEN - 1];
    assert!(matches!(
        open_content(&key, &short, b"x"),
        Err(crate::CryptoError::Malformed(_))
    ));
    assert!(open_content(&key, &[], b"x").is_err());
}

/// JD-B-017: the envelope is versioned; unknown versions are not decryptable.
#[test]
fn envelope_is_versioned() {
    assert_eq!(MIN_BLOB_LEN, 41, "version(1) + nonce(24) + tag(16)");
    assert_eq!(VERSION_LEN, 1);

    let key = generate_content_key();
    let plaintext = b"versioned envelope";
    let blob = seal_content(&key, plaintext, b"ctx").unwrap();
    assert_eq!(
        blob[0], ENVELOPE_VERSION,
        "envelope must start with version 0x01"
    );
    assert_eq!(blob.len(), plaintext.len() + MIN_BLOB_LEN);
    assert_eq!(open_content(&key, &blob, b"ctx").unwrap(), plaintext);

    // A future/foreign version byte is rejected even though the rest is intact.
    let mut future = blob.clone();
    future[0] = 0x02;
    assert!(matches!(
        open_content(&key, &future, b"ctx"),
        Err(crate::CryptoError::Decrypt)
    ));

    // Truncating into the nonce/tag region fails closed.
    assert!(matches!(
        open_content(&key, &blob[..MIN_BLOB_LEN - 1], b"ctx"),
        Err(crate::CryptoError::Malformed(_))
    ));
}

/// JD-B-001: sealing and wrapping must never be interchangeable, even with the
/// same key and the same caller AAD.
#[test]
fn seal_and_wrap_domains_are_separated() {
    let key = [0xAAu8; 32];
    let aad = b"account:7|message:1";

    let wrapped = wrap_key(&key, &[0xBBu8; 32], aad).unwrap();
    let sealed = seal_content(&key, &[0xBBu8; 32], aad).unwrap();

    assert!(
        matches!(
            unwrap_key(&key, &sealed, aad),
            Err(crate::CryptoError::Decrypt)
        ),
        "unwrap_key must reject a seal-domain blob (domain separation)"
    );
    assert!(
        matches!(
            open_content(&key, &wrapped, aad),
            Err(crate::CryptoError::Decrypt)
        ),
        "open_content must reject a wrap-domain blob (domain separation)"
    );

    // Caller-supplied AAD cannot forge the other domain's prefix.
    let forged = seal_content(&key, b"payload", b"pigeon/wrap/v1|ctx").unwrap();
    assert!(open_content(&key, &forged, b"ctx").is_err());
    assert!(unwrap_key(&key, &forged, b"ctx").is_err());
}

// --------------------------------------------------------------- key wrapping

#[test]
fn wrap_unwrap_roundtrip_and_binding() {
    let master = MasterKey::generate();
    let content = generate_content_key();
    let aad = b"account:7";
    let wrapped = wrap_key(master.bytes(), &content, aad).unwrap();
    assert_ne!(wrapped[..], content[..]);
    let unwrapped = unwrap_key(master.bytes(), &wrapped, aad).unwrap();
    assert_eq!(unwrapped, content);
    // Context transplant must fail.
    assert!(unwrap_key(master.bytes(), &wrapped, b"account:8").is_err());
}

/// JD-B-012: a wrap blob whose plaintext is not 32 bytes is a length error, not
/// a silent truncation/padding.
#[test]
fn unwrap_rejects_wrong_plaintext_length() {
    let wrapping = [0x33u8; 32];
    let aad = b"account:9";
    let blob = crate::seal::seal_wrap_domain_for_test(&wrapping, b"0123456789", aad).unwrap();
    assert!(matches!(
        unwrap_key(&wrapping, &blob, aad),
        Err(crate::CryptoError::WrongKeyLength { got: 10 })
    ));
    let msg = crate::CryptoError::WrongKeyLength { got: 10 }.to_string();
    assert!(
        msg.contains("10"),
        "the error must report the actual length: {msg}"
    );
}

// --------------------------------------------------------------- master key & API keys

#[test]
fn master_key_parse_variants() {
    let raw32: Vec<u8> = (0u8..=31).collect();
    assert!(
        MasterKey::parse(&raw32).is_ok(),
        "raw 32 bytes with non-hex bytes is a raw key"
    );

    let hex_lower = hex::encode(&raw32);
    assert!(MasterKey::parse(hex_lower.as_bytes()).is_ok());
    assert!(MasterKey::parse(hex_lower.to_uppercase().as_bytes()).is_ok());

    assert!(matches!(
        MasterKey::parse(&raw32[..31]),
        Err(crate::CryptoError::BadKeyFile(31))
    ));
    assert!(matches!(
        MasterKey::parse(b"zzzz"),
        Err(crate::CryptoError::BadKeyFile(4))
    ));
}

/// JD-B-010: 32 hex characters is a 128-bit secret — almost certainly an
/// operator who meant to paste 64 hex characters (256 bits).
#[test]
fn master_key_rejects_ambiguous_32_hex_chars() {
    assert!(matches!(
        MasterKey::parse(b"0123456789abcdef0123456789abcdef"),
        Err(crate::CryptoError::AmbiguousKeyMaterial)
    ));
    // The full 64-char form of the same value is fine.
    assert!(
        MasterKey::parse(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .is_ok()
    );
}

/// JD-B-006/011: `from_file` accepts raw and hex material, trims whitespace and
/// reports hex-looking garbage as `BadHex`.
#[test]
fn master_key_from_file_variants() {
    let raw: Vec<u8> = (0u8..32).collect(); // includes non-hex bytes on purpose
    let hex64 = hex::encode(&raw);

    let raw_path = temp_key_file(&raw);
    let hex_path = temp_key_file(hex64.as_bytes());
    let newline_path = temp_key_file(format!("{hex64}\n").as_bytes());
    let empty_path = temp_key_file(b"");
    let bad_hex_path =
        temp_key_file(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");

    let from_raw = MasterKey::from_file(&raw_path).unwrap();
    let from_hex = MasterKey::from_file(&hex_path).unwrap();
    let from_newline = MasterKey::from_file(&newline_path).unwrap();

    // All three spellings must denote the same key.
    let content = generate_content_key();
    let blob = from_raw.wrap_content_key(&content, b"account:1").unwrap();
    assert_eq!(
        from_hex.unwrap_content_key(&blob, b"account:1").unwrap(),
        content
    );
    assert_eq!(
        from_newline
            .unwrap_content_key(&blob, b"account:1")
            .unwrap(),
        content
    );

    assert!(
        matches!(
            MasterKey::from_file(&empty_path),
            Err(crate::CryptoError::BadKeyFile(0))
        ),
        "an empty key file must not silently produce a key"
    );
    assert!(
        matches!(
            MasterKey::from_file(&bad_hex_path),
            Err(crate::CryptoError::BadHex)
        ),
        "64 characters of non-hex must be reported as BadHex, not as a length error"
    );
    assert!(matches!(
        MasterKey::from_file(&temp_key_file(b"too-short")),
        Err(crate::CryptoError::BadKeyFile(9))
    ));

    for path in [raw_path, hex_path, newline_path, empty_path, bad_hex_path] {
        std::fs::remove_file(path).unwrap();
    }
}

/// JD-B-002: the master key exposes wrap/unwrap without leaking its bytes.
#[test]
fn master_key_wrap_content_key_roundtrip() {
    let master = MasterKey::generate();
    let content = generate_content_key();
    let aad = b"account:42|message:1001";
    let wrapped = master.wrap_content_key(&content, aad).unwrap();
    assert_ne!(
        wrapped,
        content.to_vec(),
        "wrapped blob must not be the raw key"
    );
    assert_eq!(wrapped[0], ENVELOPE_VERSION);
    assert_eq!(master.unwrap_content_key(&wrapped, aad).unwrap(), content);
    assert!(matches!(
        master.unwrap_content_key(&wrapped, b"account:42|message:1002"),
        Err(crate::CryptoError::Decrypt)
    ));
    let other = MasterKey::generate();
    assert!(
        other.unwrap_content_key(&wrapped, aad).is_err(),
        "wrong master key must fail"
    );
}

#[test]
fn master_key_debug_redacts() {
    let k = MasterKey::generate();
    let rendered = format!("{k:?}");
    assert!(
        rendered.contains("REDACTED"),
        "debug must not print key material: {rendered}"
    );
}

#[test]
fn api_key_format_hash_and_verify() {
    let key = generate_api_key();
    assert!(key.starts_with("pk_"));
    assert_eq!(key.len(), 3 + 43, "32 bytes → 43 unpadded base64url chars");

    let hash = hash_api_key(&key).unwrap();
    assert!(hash.starts_with("$argon2id$"), "PHC format, Argon2id");
    assert_ne!(hash, key);
    assert!(verify_api_key(&key, &hash), "correct key verifies");
    assert!(
        !verify_api_key("pk_wrong", &hash),
        "wrong key must not verify"
    );
}

/// JD-B-003: an unparseable stored hash must still pay the Argon2id cost (via a
/// fixed dummy PHC) and must always return `false`.
#[test]
fn verify_api_key_handles_unparseable_hash() {
    assert!(
        !verify_api_key("x", "not-a-phc"),
        "garbage hash must not verify"
    );
    assert!(!verify_api_key("x", ""), "empty hash must not verify");

    // The dummy hash must itself parse, or the timing fallback would silently
    // skip the KDF work it exists to perform.
    let dummy = argon2::password_hash::PasswordHash::new(DUMMY_PHC)
        .expect("DUMMY_PHC must be a valid Argon2id PHC string");
    assert!(
        !verify_api_key("x", DUMMY_PHC),
        "the dummy hash must never match"
    );
    assert!(!verify_api_key("", DUMMY_PHC));
    assert!(dummy.algorithm.as_str().eq_ignore_ascii_case("argon2id"));
}

/// JD-B-009: `parse_api_key` is the strict inverse of `generate_api_key`.
#[test]
fn parse_api_key_roundtrip_and_rejections() {
    for _ in 0..8 {
        let key = generate_api_key();
        let raw = parse_api_key(&key).unwrap();
        assert_eq!(
            b64url(&raw),
            key[3..],
            "parse must round-trip to the same text"
        );
        assert_eq!(raw.len(), 32);
    }

    let valid = generate_api_key();
    let body = &valid[3..];
    assert_eq!(body.len(), 43);

    // Missing/incorrect prefix.
    assert!(
        parse_api_key(body).is_err(),
        "missing pk_ prefix must be rejected"
    );
    assert!(
        parse_api_key(&format!("sk_{body}")).is_err(),
        "wrong prefix must be rejected"
    );
    // Wrong length.
    assert!(parse_api_key("pk_").is_err(), "empty body must be rejected");
    assert!(
        parse_api_key(&format!("pk_{}", &body[..42])).is_err(),
        "42 chars must be rejected"
    );
    assert!(
        parse_api_key(&format!("pk_{body}A")).is_err(),
        "44 chars must be rejected (never pad)"
    );
    // Invalid alphabet / padding.
    assert!(
        parse_api_key(&format!("pk_{}=", &body[..42])).is_err(),
        "padding must be rejected"
    );
    assert!(parse_api_key(&format!("pk_{}+{}", &body[..1], &body[2..])).is_err());
    // Whitespace.
    assert!(
        parse_api_key(&format!(" {valid}")).is_err(),
        "whitespace must be rejected"
    );
    assert!(
        parse_api_key(&format!("{valid}\n")).is_err(),
        "newline must be rejected"
    );
}

#[test]
fn webhook_secret_format() {
    let s = generate_webhook_secret();
    assert!(s.starts_with("whsec_"));
    assert_eq!(s.len(), 6 + 43);
}

#[test]
fn b64url_known_vectors() {
    assert_eq!(b64url(b""), "");
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
    assert_eq!(b64url(b"foob"), "Zm9vYg");
    assert_eq!(b64url(b"fooba"), "Zm9vYmE");
    assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
}

/// Encode/decode round-trip table, plus the decoder's rejection cases.
#[test]
fn b64url_decode_table() {
    let vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
        (&[0x00], "AA"),
        (&[0xff], "_w"),
        (&[0xfb, 0xef], "--8"),
        (&[0x00, 0x01, 0x02, 0x03], "AAECAw"),
    ];
    for (raw, encoded) in vectors {
        assert_eq!(&b64url(raw), encoded, "encode {raw:?}");
        assert_eq!(
            b64url_decode(encoded).as_deref(),
            Some(*raw),
            "decode {encoded} must recover {raw:?}"
        );
    }

    for bytes in [
        vec![0u8; 32],
        vec![0xAA; 32],
        (0u8..=31).collect::<Vec<_>>(),
    ] {
        let encoded = b64url(&bytes);
        assert_eq!(
            b64url_decode(&encoded).unwrap(),
            bytes,
            "round-trip {encoded}"
        );
    }

    // Rejections: impossible length, padding, standard-base64 characters, junk.
    assert_eq!(b64url_decode("Z"), None, "1 char cannot encode a byte");
    assert_eq!(
        b64url_decode("Zg=="),
        None,
        "padding is not part of the alphabet"
    );
    assert_eq!(
        b64url_decode("Zm9v+"),
        None,
        "standard base64 `+` is not base64url"
    );
    assert_eq!(
        b64url_decode("Zm9v/"),
        None,
        "standard base64 `/` is not base64url"
    );
    assert_eq!(b64url_decode("Zm 9v"), None, "whitespace is rejected");
    assert_eq!(
        b64url_decode("Zm9v*"),
        None,
        "non-alphabet characters are rejected"
    );
}

#[test]
fn encrypt_error_variant_is_wired() {
    // `seal_content`/`wrap_key` map AEAD encryption failures to `Encrypt`
    // (JD-B-013). The failure itself is unreachable with valid inputs, so this
    // guards the variant's presence and operator-facing message.
    let err = crate::CryptoError::Encrypt;
    assert_eq!(err.to_string(), "encryption failed");
}

// --------------------------------------------------------------- helpers

/// Write `contents` to a uniquely named file in the OS temp directory and
/// return its path. The caller removes it.
fn temp_key_file(contents: &[u8]) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("pigeon-crypto-test-{}-{n}.key", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}
