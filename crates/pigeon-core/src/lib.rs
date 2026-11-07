//! Pigeon Mail core domain: configuration, errors and value types.
//!
//! This crate is deliberately free of I/O (besides reading the process
//! environment in [`config::Config::from_env`]) and of storage/crypto
//! dependencies, so any binary — API, SMTP, worker, CLI — can share the same
//! vocabulary without dragging in a database or a key file.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod types;

pub use config::{Config, StartTlsMode};
pub use error::{CoreError, Result};
pub use types::{ApiKeyScope, Direction, EmailAddress, MessageFolder, MessageId};
