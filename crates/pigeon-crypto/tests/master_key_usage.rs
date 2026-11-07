//! Integration tests for the public `MasterKey` API (JD-B-002).
//!
//! These exercise the crate exactly as a consumer (server, installer) sees it:
//! generate a master key, wrap a content key, unwrap it again — no access to raw
//! key bytes from outside the crate.

use pigeon_crypto::{generate_content_key, CryptoError, MasterKey};

const CONTEXT: &[u8] = b"account:42|message:1001";

#[test]
fn generate_wrap_unwrap_roundtrip() {
    let master = MasterKey::generate();
    let content_key = generate_content_key();

    let wrapped = master.wrap_content_key(&content_key, CONTEXT).unwrap();
    assert_ne!(
        wrapped.as_slice(),
        content_key.as_slice(),
        "the wrapped blob must not contain the raw content key"
    );

    let unwrapped = master.unwrap_content_key(&wrapped, CONTEXT).unwrap();
    assert_eq!(unwrapped, content_key);
}

#[test]
fn unwrap_rejects_context_transplant() {
    let master = MasterKey::generate();
    let content_key = generate_content_key();
    let wrapped = master.wrap_content_key(&content_key, CONTEXT).unwrap();

    // Same key, different context (another account/message): must fail closed.
    assert!(matches!(
        master.unwrap_content_key(&wrapped, b"account:42|message:1002"),
        Err(CryptoError::Decrypt)
    ));

    // Same context, different master key: must fail closed.
    let other = MasterKey::generate();
    assert!(matches!(
        other.unwrap_content_key(&wrapped, CONTEXT),
        Err(CryptoError::Decrypt)
    ));
}

/// `parse` is the installer/startup path: 32 raw bytes read from a secret file.
#[test]
fn parsed_master_key_wraps_and_unwraps() {
    let parsed = MasterKey::parse(&(0u8..32).collect::<Vec<_>>()).unwrap();
    let content_key = generate_content_key();

    let wrapped = parsed.wrap_content_key(&content_key, CONTEXT).unwrap();
    assert_eq!(
        parsed.unwrap_content_key(&wrapped, CONTEXT).unwrap(),
        content_key
    );
    assert!(parsed
        .unwrap_content_key(&wrapped, b"account:43|message:1001")
        .is_err());
}
