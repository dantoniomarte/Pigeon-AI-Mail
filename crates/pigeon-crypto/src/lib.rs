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
//! * webhook signing secrets.
//!
//! # Out of scope (not implemented here)
//!
//! * The OpenPGP/WKD end-to-end layer described in `docs/e2ee-model.md` is
//!   future work: it is not part of this crate yet.
//! * Webhook **HMAC signing and verification** land together with the webhooks
//!   module; this crate only generates the `whsec_` secret.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod error;
pub mod key;
pub mod seal;
pub mod totp;

pub use error::{CryptoError, Result};
pub use key::{
    generate_api_key, generate_webhook_secret, hash_api_key, parse_api_key, verify_api_key,
    MasterKey,
};
pub use seal::{
    generate_content_key, open_content, seal_content, unwrap_key, wrap_key, ENVELOPE_VERSION,
    MIN_BLOB_LEN, NONCE_LEN,
};
pub use totp::{generate_totp_secret, Totp, TotpAlg};

#[cfg(test)]
mod tests;
