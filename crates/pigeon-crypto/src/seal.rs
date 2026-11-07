//! Content sealing — the at-rest guarantee of ADR 0003.
//!
//! A message body or attachment never touches SQL as plaintext. Each message
//! gets a random 32-byte **content key**; the body/attachments are sealed with
//! XChaCha20-Poly1305 under that key (random 24-byte nonce, prepended), and the
//! content key itself is **wrapped** under the recipient account key (or the
//! master key when no account key exists yet), bound to context (account id,
//! message id) as AEAD associated data so blobs cannot be transplanted.
//!
//! # Domain separation
//!
//! Sealing and wrapping use the same AEAD primitive, so they are separated by a
//! hard-coded domain tag mixed into the associated data:
//!
//! * [`seal_content`] / [`open_content`] authenticate `b"pigeon/seal/v1|" || aad`
//! * [`wrap_key`] / [`unwrap_key`] authenticate `b"pigeon/wrap/v1|" || aad`
//!
//! A blob produced in one domain therefore never authenticates in the other,
//! even with the same key and the same caller-supplied AAD.
//!
//! # Envelope version
//!
//! Wire format is versioned:
//! `version(1 byte, 0x01) || nonce(24) || ciphertext || tag(16)`.
//! The version byte is both checked and authenticated (it is part of the AEAD
//! associated data), so an envelope relabelled with another version fails
//! closed instead of being reinterpreted by a future layout.

use chacha20poly1305::aead::{Aead, Payload};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::key::aead;

/// Version byte of the current sealed envelope format.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// Length of the envelope version prefix.
pub const VERSION_LEN: usize = 1;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Minimum sealed blob: version + nonce + tag.
pub const MIN_BLOB_LEN: usize = VERSION_LEN + NONCE_LEN + TAG_LEN;

/// Length of a content key (XChaCha20-Poly1305 key).
pub const KEY_LEN: usize = 32;

const SEAL_DOMAIN: &[u8] = b"pigeon/seal/v1|";
const WRAP_DOMAIN: &[u8] = b"pigeon/wrap/v1|";

/// Fresh random 256-bit content key.
pub fn generate_content_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&crate::key::random_bytes(KEY_LEN));
    k
}

fn domain_aad(domain: &'static [u8], aad: &[u8]) -> Vec<u8> {
    let mut bound = Vec::with_capacity(VERSION_LEN + domain.len() + aad.len());
    // Bind the envelope version too: a relabelled envelope must not authenticate.
    bound.push(ENVELOPE_VERSION);
    bound.extend_from_slice(domain);
    bound.extend_from_slice(aad);
    bound
}

fn split(blob: &[u8]) -> Result<(&[u8], &[u8])> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(CryptoError::Malformed(MIN_BLOB_LEN));
    }
    // Unknown envelope generations are not decryptable by this implementation;
    // report them like any other authentication failure rather than guessing.
    if blob[0] != ENVELOPE_VERSION {
        return Err(CryptoError::Decrypt);
    }
    Ok((
        &blob[VERSION_LEN..VERSION_LEN + NONCE_LEN],
        &blob[VERSION_LEN + NONCE_LEN..],
    ))
}

/// Seal `plaintext` under `content_key`, bound to `aad` (context binding).
/// Returns a versioned envelope: `0x01 || nonce || ciphertext || tag`.
pub fn seal_content(content_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    seal_with_domain(content_key, plaintext, aad, SEAL_DOMAIN)
}

/// Open a blob produced by [`seal_content`]. Any tampering (bit flip, key
/// mismatch, wrong context, unknown envelope version) fails here — AEAD
/// authentication.
pub fn open_content(content_key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    open_with_domain(content_key, blob, aad, SEAL_DOMAIN)
}

/// Wrap a 32-byte content key under `wrapping_key` (master or account key),
/// bound to `aad`. Same versioned envelope as [`seal_content`], but a distinct
/// domain tag: wrap blobs never authenticate as sealed content and vice versa.
pub fn wrap_key(wrapping_key: &[u8; 32], content_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    seal_with_domain(wrapping_key, content_key, aad, WRAP_DOMAIN)
}

/// Unwrap a wrapped content key. Returns the caller-owned 32-byte key.
pub fn unwrap_key(wrapping_key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<[u8; 32]> {
    // The plaintext here *is* key material: wipe it when it goes out of scope.
    let plain = Zeroizing::new(open_with_domain(wrapping_key, blob, aad, WRAP_DOMAIN)?);
    if plain.len() != KEY_LEN {
        return Err(CryptoError::WrongKeyLength { got: plain.len() });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    Ok(key)
}

fn seal_with_domain(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    domain: &'static [u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = crate::key::random_bytes(NONCE_LEN);
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    aead(key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &domain_aad(domain, aad),
            },
        )
        .map(|ct| {
            let mut out = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ct.len());
            out.push(ENVELOPE_VERSION);
            out.extend_from_slice(nonce);
            out.extend_from_slice(&ct);
            out
        })
        .map_err(|_| CryptoError::Encrypt)
}

fn open_with_domain(
    key: &[u8; 32],
    blob: &[u8],
    aad: &[u8],
    domain: &'static [u8],
) -> Result<Vec<u8>> {
    let (nonce, ct) = split(blob)?;
    aead(key)
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &domain_aad(domain, aad),
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Test-only: seal an arbitrary payload in the *wrap* domain so the
/// wrong-plaintext-length path of [`unwrap_key`] is reachable (the public
/// [`wrap_key`] only accepts 32-byte keys).
#[cfg(test)]
pub(crate) fn seal_wrap_domain_for_test(
    wrapping_key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    seal_with_domain(wrapping_key, plaintext, aad, WRAP_DOMAIN)
}
