use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key file must contain exactly 32 bytes of key material (hex or raw), got {0} bytes")]
    BadKeyFile(usize),
    #[error(
        "ambiguous key material: 32 hex characters encode only 128 bits; a master key needs \
         64 hex characters (256 bits) or 32 raw bytes"
    )]
    AmbiguousKeyMaterial,
    #[error("key material is 64 characters long but contains non-hex characters")]
    BadHex,
    #[error("key file not readable: {0}")]
    KeyFileIo(#[from] std::io::Error),
    #[error("decryption failed: wrong key, tampered ciphertext, or wrong associated data")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("malformed sealed blob (need at least {0} bytes)")]
    Malformed(usize),
    #[error("unwrapped payload has the wrong length: expected 32 bytes, got {got}")]
    WrongKeyLength { got: usize },
    #[error("invalid TOTP configuration: {0}")]
    TotpConfig(String),
    #[error("invalid API key format: {0}")]
    ApiKeyFormat(String),
    #[error("API key hashing failed: {0}")]
    Hashing(String),
    #[error("OpenPGP: {0}")]
    Pgp(String),
}
