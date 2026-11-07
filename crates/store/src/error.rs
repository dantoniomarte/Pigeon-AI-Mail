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
    /// The address already belongs to a **sender alias**, so it cannot become an
    /// account address.
    ///
    /// Distinct from [`StoreError::Conflict`] because the fix is different: a
    /// duplicate account is "pick another address", this one is "delete the alias
    /// first". Both are a `409` for a client. An account created on top of an alias
    /// would silently divert mail addressed to a shared address into one person's
    /// mailbox, which is the collision this variant exists to prevent.
    #[error("{0} is a sender alias: an account cannot own that address")]
    AliasShadow(String),
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
