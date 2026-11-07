//! Errors surfaced by the SMTP engine.

use thiserror::Error;

/// Convenience alias for [`SmtpError`].
pub type Result<T> = std::result::Result<T, SmtpError>;

/// Everything that can go wrong while speaking SMTP.
///
/// The variants are split by **who has to act**:
///
/// * [`SmtpError::Io`], [`SmtpError::Timeout`], [`SmtpError::Dns`] and
///   [`SmtpError::Tls`] are transport failures — the queue retries them.
/// * [`SmtpError::Protocol`] means the peer said something no SMTP server
///   should say; the queue also retries it, because a broken peer may recover.
/// * [`SmtpError::Config`] is an operator error: retrying cannot fix it, so the
///   binary fails at startup instead.
/// * The passthroughs let call sites use `?` without losing the source error.
#[derive(Debug, Error)]
pub enum SmtpError {
    /// Socket-level failure while talking to a peer.
    #[error("smtp io error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer stopped answering within the configured budget.
    #[error("smtp timeout: {0}")]
    Timeout(String),
    /// The peer violated the protocol (garbage reply, missing banner, ...).
    #[error("smtp protocol error: {0}")]
    Protocol(String),
    /// MX resolution failed or returned nothing usable.
    #[error("mx resolution failed: {0}")]
    Dns(String),
    /// The TLS upgrade failed.
    #[error("starttls failed: {0}")]
    Tls(String),
    /// A configuration value is unusable; fail at startup, not per message.
    #[error("smtp configuration: {0}")]
    Config(String),
    /// Storage refused or failed a write.
    #[error(transparent)]
    Store(#[from] store::StoreError),
    /// A domain value (address, direction) was rejected.
    #[error(transparent)]
    Core(#[from] pigeon_core::CoreError),
    /// Sealing or opening a message body failed.
    #[error(transparent)]
    Crypto(#[from] pigeon_crypto::CryptoError),
    /// DKIM signing failed.
    #[error(transparent)]
    Dkim(#[from] pigeon_dkim::DkimError),
}
