//! Pigeon Mail cryptography.
//!
//! Everything this crate implements today, with the guarantees promised in
//! `docs/e2ee-model.md` and ADR 0003:
//!
//! * content sealing at rest (XChaCha20-Poly1305, random 24-byte nonce per
//!   message, versioned envelope, domain-separated from key wrapping),
//! * content-key wrapping (per-message key wrapped by the account/master key),
//! * TOTP second factor (RFC 6238; SHA-1/SHA-256, 6 or 8 digits, bounded
//!   verification window — replay protection is the caller's obligation),
//! * API key generation, parsing + Argon2id verification,
//! * webhook signing secrets,
//! * the **layer-3 end-to-end** payload seal (OpenPGP, RFC 4880) — see [`pgp`].
//!
//! # The two seal layers
//!
//! [`seal`] protects data **at rest**: the server holds the key, so the guarantee
//! is "a stolen database file is unreadable". [`pgp`] protects a payload **on the
//! wire and at the far end**: only the recipient's account key opens it, so the
//! sending server, the network and the receiving server's storage are all out of
//! the trust path. `docs/e2ee-model.md` describes both.
//!
//! # Out of scope (not implemented here)
//!
//! * Webhook **HMAC signing and verification** land together with the webhooks
//!   module; this crate only generates the `whsec_` secret.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod error;
pub mod key;
pub mod pgp;
pub mod seal;
pub mod totp;

pub use error::{CryptoError, Result};
pub use key::{
    generate_api_key, generate_webhook_secret, hash_api_key, parse_api_key, verify_api_key,
    MasterKey,
};
pub use pgp::{
    can_encrypt, fingerprint_of, generate_account_key, open_payload, open_payload_with_key,
    parse_cert, parse_cert_with_fingerprint, seal_payload, seal_payload_bytes, to_binary,
    GeneratedKey, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES,
};
pub use seal::{
    generate_content_key, open_content, seal_content, unwrap_key, wrap_key, ENVELOPE_VERSION,
    MIN_BLOB_LEN, NONCE_LEN,
};
pub use totp::{generate_totp_secret, Totp, TotpAlg};

#[cfg(test)]
mod tests;
