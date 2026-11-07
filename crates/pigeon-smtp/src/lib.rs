//! Pigeon Mail SMTP engine: inbound ESMTP server and outbound delivery.
//!
//! # Why a hand-rolled state machine
//!
//! ADR 0001 rejects a monolithic SMTP framework: the server has to seal inbound
//! bodies with `pigeon-crypto` *before* anything else sees them, and it has to
//! emit exactly the bytes `pigeon-dkim` signs. Both are impossible to guarantee
//! behind a framework's message object. So the protocol lives here as a small,
//! testable state machine over `tokio::net::TcpStream`, and the mail primitives
//! stay in the crates that own them:
//!
//! * [`server`] — inbound ESMTP (`PIGEON_SMTP_IN_ADDR`): banner, `EHLO`,
//!   `MAIL`/`RCPT`/`DATA`, limits, sealing and storage.
//! * [`client`] — outbound ESMTP: MX resolution, opportunistic STARTTLS, the
//!   reply-code decision (`250` sent, `4xx` deferred, `5xx` bounced).
//! * [`worker`] — the queue loop: claim, unseal, sign, deliver, back off.
//! * [`dns`] — MX lookup with a test seam and the loopback port override.
//!
//! # What v0.1 honestly does not do
//!
//! * **No STARTTLS listener.** The inbound server advertises `STARTTLS` in its
//!   `EHLO` reply (so clients can tell the capability exists in the roadmap) and
//!   answers `454 4.7.0 TLS not available` when asked for it: a self-signed
//!   certificate lifecycle is v0.2. Clients that *require* TLS simply refuse to
//!   send, which is the correct outcome.
//! * **No certificate verification outbound.** The outbound client upgrades with
//!   STARTTLS when the peer offers it, but trusts any certificate: chain
//!   verification and pinning are v0.2. `PIGEON_SMTP_OUT_STARTTLS=required`
//!   still refuses to send in clear text.
//! * **No SPF/DKIM/DMARC verification inbound.** The verdicts are recorded as
//!   `none` and logged; the DKIM verifier is wired in when domain key storage
//!   lands (see `docs/ROADMAP.md`).
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod client;
pub mod dns;
pub mod error;
pub mod server;
pub mod worker;

pub use client::{DeliveryConfig, DeliveryResult, DeliveryStatus, OutboundSmtpClient};
pub use dns::{HickoryMxSource, MxRecord, MxResolver, MxSource, DEFAULT_SMTP_PORT};
pub use error::{Result, SmtpError};
pub use server::{
    InboundSmtpServer, ServerConfig, CONNECTION_TIMEOUT, MAX_COMMANDS, MAX_LINE_LEN,
    MAX_MESSAGE_SIZE, MAX_RECIPIENTS,
};
pub use worker::{
    QueueWorker, WorkerConfig, BACKOFF_SCHEDULE_SECS, DEFAULT_LEASE_SECS, DEFAULT_POLL_INTERVAL,
};
