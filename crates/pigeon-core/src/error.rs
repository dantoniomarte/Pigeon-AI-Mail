//! The error type shared by every Pigeon crate that has no more specific one.

use thiserror::Error;

/// Convenience alias for [`CoreError`].
pub type Result<T> = std::result::Result<T, CoreError>;

/// Domain-level failures that are not specific to crypto or storage.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The operator supplied an unusable configuration value.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A string could not be parsed as an email address.
    #[error("invalid email address: {0}")]
    InvalidAddress(String),
    /// A string could not be parsed as an API-key scope. The raw input is
    /// quoted (`{:?}`) so an empty or whitespace-only value is visible in the
    /// message instead of producing an empty gap after the colon.
    #[error("invalid scope: {0:?} (expected one of send, read, full)")]
    InvalidScope(String),
}
