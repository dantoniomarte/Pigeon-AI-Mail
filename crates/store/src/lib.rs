//! Pigeon Mail persistence.
//!
//! Blocking SQLite storage implementing the `Storage` seam from ADR 0002.
//! Bodies and attachments arrive here already sealed (ADR 0003); the crate
//! stores ciphertext and never handles plaintext mail.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod error;
pub mod migrations;
pub mod storage;

pub use error::{Result, StoreError};
pub use migrations::MIGRATIONS;
pub use storage::{
    CatchallRuleRow, ClaimedJob, DeadJob, DraftRow, InvitationRow, MessageRow, NewDraft,
    NewMessage, OrgAccountRow, OrgRow, SessionRow, SqliteStorage, Storage, TemplateRow,
    TotpEnrollmentRow, INVITATION_TTL_SECS, MAX_INVITATION_SCAN, MAX_LEASE_SECS, MAX_PAGE_LIMIT,
    MAX_SESSION_TTL_SECS, MAX_TRASH_RETENTION_DAYS,
};

#[cfg(test)]
mod tests;
