//! Errors surfaced by the storage layer.

use thiserror::Error;

/// Convenience alias for [`StoreError`].
pub type Result<T> = std::result::Result<T, StoreError>;

/// Everything that can go wrong while persisting or loading Pigeon state.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The SQLite driver reported an error (I/O, corruption, constraint, ...).
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// A value from the domain layer was rejected (e.g. an unparsable address).
    #[error(transparent)]
    Core(#[from] pigeon_core::CoreError),
    /// The requested row does not exist.
    #[error("record not found")]
    NotFound,
    /// The write collides with an existing row (e.g. duplicate account email).
    #[error("conflict: a row with the same unique key already exists")]
    Conflict,
    /// Stored data no longer decodes (unknown enum value, bad JSON, invalid
    /// address). The row exists but cannot be trusted, so callers get evidence
    /// instead of a silent default.
    #[error("corrupt row: {0}")]
    Corrupt(String),
    /// A body handed to [`Storage::insert_message`](crate::Storage::insert_message)
    /// is not a sealed envelope (plaintext, empty, truncated or wrong version).
    #[error("message body is not a valid sealed envelope: {0}")]
    InvalidSealedBody(String),
    /// A caller-supplied argument is outside the accepted range.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Sealing/opening or key handling failed.
    #[error(transparent)]
    Crypto(#[from] pigeon_crypto::CryptoError),
    /// A queue operation was rejected (stale, already-completed or unknown claim).
    #[error("queue claim rejected: {0}")]
    QueueClaim(String),
}
