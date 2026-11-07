//! Pigeon Mail DKIM (RFC 6376): sign outbound messages, verify inbound ones.
//!
//! v0.1 implements the universally supported profile:
//!
//! * algorithm `rsa-sha256` (2048-bit keys) — Ed25519 (`ed25519-sha256`) is
//!   v0.2,
//! * canonicalization `relaxed/relaxed` (RFC 6376 §3.4.2 / §3.4.4) — survives
//!   the re-folding and whitespace rewrites MTAs do in transit,
//! * the minimum safe signed header set of RFC 6376 §5.4:
//!   `from`, `to`, `subject`, `date`, `message-id`.
//!
//! The crate is deliberately self-contained: it builds on the RSA/SHA-256
//! primitives plus its own canonicalization instead of pulling in a mail
//! stack, so the bytes that get hashed are under our control and auditable.
//!
//! ```no_run
//! use pigeon_dkim::{sign_message, verify_message, DkimKeyPair};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = DkimKeyPair::generate("mail", "example.com")?;
//! let dns_record = key.public_key_dns_record(); // publish at mail._domainkey.example.com
//! let body = "Hello from Pigeon\r\n";
//! let header = sign_message(
//!     &key,
//!     "Alice <alice@example.com>",
//!     "Bob <bob@example.net>",
//!     "Hi",
//!     "Tue, 1 Jul 2025 12:00:00 +0000",
//!     "<id@pigeon.test>",
//!     body,
//! )?;
//!
//! let headers = vec![
//!     ("From".to_string(), "Alice <alice@example.com>".to_string()),
//!     ("To".to_string(), "Bob <bob@example.net>".to_string()),
//!     ("Subject".to_string(), "Hi".to_string()),
//!     ("Date".to_string(), "Tue, 1 Jul 2025 12:00:00 +0000".to_string()),
//!     ("Message-ID".to_string(), "<id@pigeon.test>".to_string()),
//! ];
//! let result = verify_message(&header, &headers, body, |name| {
//!     (name == "mail._domainkey.example.com").then(|| dns_record.clone())
//! })?;
//! assert!(result.passed);
//! # Ok(())
//! # }
//! ```
//!
//! `unsafe` is forbidden in this crate.
//!
//! # Out of scope (v0.1)
//!
//! * Ed25519 keys and `ed25519-sha256`,
//! * `simple`/`simple` canonicalization,
//! * key storage: [`DkimKeyPair`] is in-memory only. Persisting private keys
//!   through `pigeon-crypto`'s sealed envelope is the next integration step.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod error;
pub mod key;
pub mod sign;
pub mod verify;

pub use error::{DkimError, Result};
pub use key::{DkimKeyPair, RSA_KEY_BITS};
pub use sign::sign_message;
pub use verify::{verify_message, VerifyResult};

#[cfg(test)]
mod tests;
