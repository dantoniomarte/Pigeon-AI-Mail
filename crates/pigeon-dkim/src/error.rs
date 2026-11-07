use thiserror::Error;

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, DkimError>;

/// Everything that can go wrong while generating keys, signing or verifying.
#[derive(Debug, Error)]
pub enum DkimError {
    #[error("RSA key generation failed: {0}")]
    KeyGen(String),
    #[error("DKIM signing failed: {0}")]
    Sign(String),
    #[error("DKIM verification failed: {0}")]
    Verify(String),
    #[error("malformed DKIM data: {0}")]
    Parse(String),
    #[error("unsupported DKIM algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("signed header missing from the message: {0}")]
    MissingHeader(String),
}
