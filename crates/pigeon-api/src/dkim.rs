//! Sealed storage of per-domain DKIM private keys.
//!
//! A DKIM private key is RSA PKCS#8 DER wrapped in the same two-layer envelope
//! every other secret in this service uses (ADR 0003):
//!
//! 1. a fresh 32-byte **content key** seals the DER
//!    ([`pigeon_crypto::seal_content`]),
//! 2. that content key is **wrapped** under the master key
//!    ([`MasterKey::wrap_content_key`]).
//!
//! The store keeps one `BLOB` per domain, so the two blobs travel together in a
//! length-prefixed envelope:
//!
//! ```text
//! wrapped_len (4 bytes, big-endian) || wrapped content key || sealed DER
//! ```
//!
//! Both layers are bound to the same associated data — [`crate::aad::dkim_key`],
//! `dkim:{domain}` — so a blob cannot be replayed onto another domain: unwrapping
//! the content key of `a.example` while claiming `b.example` fails AEAD
//! authentication instead of handing out a key.
//!
//! Storing the wrapped content key *beside* the sealed DER (rather than reusing
//! one key for every domain) means a leaked content key exposes exactly one
//! domain's signing identity.
//!
//! # Why a length prefix and not a fixed offset
//!
//! The wrapped-key envelope has a length that follows from the seal format, but
//! hard-coding it here would silently break every stored key the day that format
//! grows a field. The prefix makes the split self-describing and the parser fail
//! closed on a truncated blob.

use pigeon_crypto::{generate_content_key, open_content, seal_content, CryptoError, MasterKey};

use crate::aad;

/// Bytes of the big-endian length prefix in front of the wrapped content key.
const LEN_PREFIX: usize = 4;

/// Seal `pkcs8_der` for `domain` under `master_key`; returns the blob to store.
pub fn seal_private_key(
    master_key: &MasterKey,
    domain: &str,
    pkcs8_der: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = aad::dkim_key(domain);
    let content_key = generate_content_key();
    let sealed = seal_content(&content_key, pkcs8_der, aad.as_bytes())?;
    let wrapped = master_key.wrap_content_key(&content_key, aad.as_bytes())?;

    let mut blob = Vec::with_capacity(LEN_PREFIX + wrapped.len() + sealed.len());
    // `try_from` cannot fail for a Vec this small, but a silent `as u32` is the
    // kind of cast that hides a future format change; keep it honest.
    let wrapped_len = u32::try_from(wrapped.len()).map_err(|_| CryptoError::Encrypt)?;
    blob.extend_from_slice(&wrapped_len.to_be_bytes());
    blob.extend_from_slice(&wrapped);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Open a blob produced by [`seal_private_key`] for `domain`.
///
/// Wrong domain, wrong master key, or any tampering fails here rather than
/// yielding a wrong key: both layers are AEAD-authenticated against
/// `dkim:{domain}`.
pub fn open_private_key(
    master_key: &MasterKey,
    domain: &str,
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if blob.len() <= LEN_PREFIX {
        return Err(CryptoError::Malformed(LEN_PREFIX + 1));
    }
    let (prefix, rest) = blob.split_at(LEN_PREFIX);
    let mut length_bytes = [0u8; LEN_PREFIX];
    length_bytes.copy_from_slice(prefix);
    let wrapped_len = u32::from_be_bytes(length_bytes) as usize;
    if rest.len() <= wrapped_len {
        return Err(CryptoError::Malformed(LEN_PREFIX + wrapped_len + 1));
    }
    let (wrapped, sealed) = rest.split_at(wrapped_len);

    let aad = aad::dkim_key(domain);
    let content_key = master_key.unwrap_content_key(wrapped, aad.as_bytes())?;
    open_content(&content_key, sealed, aad.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::parse(&[5u8; 32]).expect("master key")
    }

    #[test]
    fn a_sealed_private_key_opens_to_the_same_bytes() {
        let blob = seal_private_key(&master(), "example.com", b"pkcs8-bytes").expect("seal");
        let opened = open_private_key(&master(), "example.com", &blob).expect("open");
        assert_eq!(opened, b"pkcs8-bytes");
    }

    #[test]
    fn two_seals_of_the_same_key_differ() {
        // A fresh content key and nonce per seal: identical plaintext must not
        // produce identical ciphertext.
        let first = seal_private_key(&master(), "example.com", b"same").expect("seal");
        let second = seal_private_key(&master(), "example.com", b"same").expect("seal");
        assert_ne!(first, second);
    }

    #[test]
    fn a_blob_does_not_open_for_another_domain() {
        let blob = seal_private_key(&master(), "a.example", b"secret").expect("seal");
        assert!(
            open_private_key(&master(), "b.example", &blob).is_err(),
            "the AAD must bind the blob to its domain"
        );
    }

    #[test]
    fn a_blob_does_not_open_under_another_master_key() {
        let blob = seal_private_key(&master(), "example.com", b"secret").expect("seal");
        let other = MasterKey::parse(&[6u8; 32]).expect("other key");
        assert!(open_private_key(&other, "example.com", &blob).is_err());
    }

    #[test]
    fn truncated_or_tampered_blobs_fail_closed() {
        let blob = seal_private_key(&master(), "example.com", b"secret").expect("seal");

        assert!(open_private_key(&master(), "example.com", b"").is_err());
        assert!(open_private_key(&master(), "example.com", b"\0\0\0").is_err());

        // Every truncation point must be an error, never a panic and never a
        // short plaintext.
        for cut in 1..blob.len() {
            assert!(
                open_private_key(&master(), "example.com", &blob[..cut]).is_err(),
                "truncation at {cut} must fail"
            );
        }

        let mut flipped = blob.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0xFF;
        assert!(open_private_key(&master(), "example.com", &flipped).is_err());
    }
}
