//! Outbound ESMTP delivery.
//!
//! The dialogue is the one every MTA speaks:
//!
//! ```text
//! connect -> 220 banner
//! EHLO pigeon-mail -> 250 (capabilities)
//!   STARTTLS offered?  -> STARTTLS -> 220 -> TLS handshake -> EHLO again
//! MAIL FROM:<sender> -> 250
//! RCPT TO:<rcpt>     -> 250            (one per recipient)
//! DATA               -> 354 -> message + "." -> 250
//! QUIT               -> 221
//! ```
//!
//! The reply **class** after `DATA` is the delivery verdict:
//!
//! * `250` → [`DeliveryStatus::Sent`],
//! * `4xx` → [`DeliveryStatus::Deferred`] (retry, the queue backs off),
//! * `5xx` → [`DeliveryStatus::Bounced`] (permanent, do not retry).
//!
//! # TLS posture (v0.1, documented honestly)
//!
//! `STARTTLS` is used whenever the peer advertises it, and the client verifies
//! that a TLS handshake completed — but **not** the certificate chain. Chain
//! verification, hostname checks and pinning are v0.2 (there is no CA store in
//! the image yet). [`pigeon_core::StartTlsMode`] still decides what happens when
//! the peer does *not* offer TLS: `required` fails the delivery, `opportunistic`
//! sends in clear text.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use pigeon_core::{EmailAddress, StartTlsMode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns::{MxRecord, MxResolver};
use crate::error::{Result, SmtpError};
use crate::server::Reply;

/// Environment variable naming a smarthost every outbound message is relayed
/// through (`host:port`), instead of resolving the recipient's MX.
///
/// This is the "outbound address" of the deployment: a fresh install can point
/// it at a provider's submission host while direct-to-MX delivery is what the
/// default (unset) does.
pub const SMTP_OUT_ADDR_ENV: &str = "PIGEON_SMTP_OUT_ADDR";

/// How long a single command may take before the attempt is abandoned.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// The name announced in `EHLO` (never used for authentication).
pub const DEFAULT_EHLO_NAME: &str = "pigeon-mail";

/// Verdict for one delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// The peer accepted the message (`250` after `DATA`).
    Sent,
    /// Temporary failure (`4xx`, timeout, connection refused): retry.
    Deferred,
    /// Permanent failure (`5xx`): do not retry, suppress the recipient.
    Bounced,
    /// Local refusal (for example `STARTTLS` required but not offered).
    Failed,
}

impl DeliveryStatus {
    /// Lowercase wire/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            DeliveryStatus::Sent => "sent",
            DeliveryStatus::Deferred => "deferred",
            DeliveryStatus::Bounced => "bounced",
            DeliveryStatus::Failed => "failed",
        }
    }

    /// Map an SMTP reply code to a verdict.
    ///
    /// Codes outside `2xx`/`4xx`/`5xx` are protocol errors at the call site;
    /// here they are treated as deferred so a broken peer cannot cause a bounce
    /// (and, with it, a suppression) for the recipient.
    pub const fn from_code(code: u16) -> Self {
        match code / 100 {
            2 => DeliveryStatus::Sent,
            5 => DeliveryStatus::Bounced,
            _ => DeliveryStatus::Deferred,
        }
    }
}

/// One delivery attempt's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    /// Verdict for the whole message: the aggregate over [`Self::groups`].
    pub status: DeliveryStatus,
    /// Mail exchanger that was tried (or the relay host). With several recipient
    /// domains this is the distinct host list, comma-separated.
    pub mx_host: String,
    /// SMTP reply code; `421` when no peer answered at all.
    pub code: u16,
    /// Reply text or transport error, for the event log.
    pub message: String,
    /// Per recipient domain detail, in the order the domains were tried.
    ///
    /// MX routing is per **recipient** domain, so one message can end with
    /// several verdicts (`example.org` accepted, `example.net` deferred). The
    /// queue, however, holds one row per message: [`Self::status`] is the
    /// aggregate, and this list is what lets the worker attribute a bounce to the
    /// recipients that actually bounced.
    pub groups: Vec<DeliveryGroup>,
}

impl DeliveryResult {
    fn new(
        status: DeliveryStatus,
        mx_host: impl Into<String>,
        code: u16,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            mx_host: mx_host.into(),
            code,
            message: message.into(),
            groups: Vec::new(),
        }
    }

    /// The recipients whose own transaction ended in `status`.
    ///
    /// Used to suppress exactly the addresses a `5xx` was received for, instead
    /// of every recipient of a multi-domain message.
    pub fn recipients_with(&self, status: DeliveryStatus) -> Vec<EmailAddress> {
        self.groups
            .iter()
            .filter(|group| group.result.status == status)
            .flat_map(|group| group.recipients.iter().cloned())
            .collect()
    }
}

/// One SMTP transaction: the recipients that share a domain, and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryGroup {
    /// Recipient domain this transaction was addressed to. Empty when the whole
    /// message went through a relay, which is not domain-scoped.
    pub domain: String,
    /// Verdict for this domain's recipients.
    pub result: DeliveryResult,
    /// The recipients carried by this transaction.
    pub recipients: Vec<EmailAddress>,
}

/// Outbound delivery tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryConfig {
    /// What to do when the peer does not offer `STARTTLS`.
    pub starttls: StartTlsMode,
    /// `EHLO` argument.
    pub ehlo_name: String,
    /// Per-command budget.
    pub timeout: Duration,
    /// Smarthost `(host, port)`; when set, MX resolution is skipped.
    pub relay: Option<(String, u16)>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            starttls: StartTlsMode::Required,
            ehlo_name: DEFAULT_EHLO_NAME.to_string(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
            relay: None,
        }
    }
}

impl DeliveryConfig {
    /// Build from the process environment: `PIGEON_SMTP_OUT_ADDR` selects a
    /// smarthost. An unusable value is a startup error, not a silent default.
    pub fn from_env(starttls: StartTlsMode) -> Result<Self> {
        let mut config = Self {
            starttls,
            ..Self::default()
        };
        match std::env::var(SMTP_OUT_ADDR_ENV) {
            Ok(raw) if raw.trim().is_empty() => {}
            Ok(raw) => config.relay = Some(parse_host_port(raw.trim())?),
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(SmtpError::Config(format!(
                    "{SMTP_OUT_ADDR_ENV} is not valid Unicode"
                )))
            }
        }
        Ok(config)
    }

    /// Relay every message through `host:port`.
    pub fn with_relay(mut self, host: impl Into<String>, port: u16) -> Self {
        self.relay = Some((host.into(), port));
        self
    }
}

/// Parse `host:port`, rejecting a missing port: guessing 25 for a smarthost
/// would silently deliver somewhere the operator did not ask for.
pub fn parse_host_port(raw: &str) -> Result<(String, u16)> {
    let (host, port) = raw.rsplit_once(':').ok_or_else(|| {
        SmtpError::Config(format!(
            "{SMTP_OUT_ADDR_ENV} must be host:port, got {raw:?}"
        ))
    })?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(SmtpError::Config(format!(
            "{SMTP_OUT_ADDR_ENV} has an empty host in {raw:?}"
        )));
    }
    let port = port.trim().parse::<u16>().map_err(|error| {
        SmtpError::Config(format!("{SMTP_OUT_ADDR_ENV} port is not a number: {error}"))
    })?;
    Ok((host.to_string(), port))
}

/// Client for outbound delivery.
pub struct OutboundSmtpClient {
    resolver: MxResolver,
    config: DeliveryConfig,
}

impl OutboundSmtpClient {
    /// Build a client over an [`MxResolver`].
    pub fn new(resolver: MxResolver, config: DeliveryConfig) -> Self {
        Self { resolver, config }
    }

    /// Delivery configuration, for tests and logging.
    pub fn config(&self) -> &DeliveryConfig {
        &self.config
    }

    /// Deliver `mime` (the exact bytes stored for the message) to every
    /// recipient, **one SMTP transaction per recipient domain**.
    ///
    /// `mime` is signed by the caller (see [`crate::worker`]) because signature
    /// generation belongs with the queue, not the socket.
    ///
    /// # Why per recipient domain
    ///
    /// MX records describe where a **recipient's** domain accepts mail. Routing a
    /// message to the sender's own MX is issue #70: every external send looked up
    /// `from.domain()`, connected to this server's own exchanger and deferred
    /// forever. Recipients are therefore grouped by their own domain, each domain
    /// is resolved separately (with the per-candidate fallback of RFC 5321 §5.1),
    /// and each transaction carries only that domain's recipients. `MAIL FROM`
    /// stays the sender on every transaction, exactly like an MTA relaying one
    /// multi-domain message.
    ///
    /// A domain that cannot be resolved defers **only its own** recipients: the
    /// remaining domains are still attempted, and the aggregate verdict keeps the
    /// message in the queue for a retry.
    ///
    /// With a smarthost ([`DeliveryConfig::relay`]) MX records do not apply at
    /// all: the relay receives the whole recipient set in one transaction, as
    /// before.
    pub async fn deliver(
        &self,
        from: &EmailAddress,
        recipients: &[EmailAddress],
        mime: &[u8],
    ) -> Result<DeliveryResult> {
        if let Some((host, port)) = &self.config.relay {
            // A relay is a single destination: one transaction, every recipient,
            // and the provider routes by domain.
            let candidates = vec![MxRecord {
                preference: 0,
                exchange: host.clone(),
            }];
            let result = self
                .deliver_candidates(host, *port, from, recipients, mime, &candidates)
                .await;
            return Ok(DeliveryResult {
                groups: vec![DeliveryGroup {
                    domain: String::new(),
                    result: result.clone(),
                    recipients: recipients.to_vec(),
                }],
                ..result
            });
        }

        let mut groups: Vec<DeliveryGroup> = Vec::new();
        for (domain, group) in group_by_domain(recipients) {
            let result = self.deliver_to_domain(&domain, from, &group, mime).await;
            groups.push(DeliveryGroup {
                domain,
                result,
                recipients: group,
            });
        }
        Ok(aggregate(groups))
    }

    /// One recipient domain: resolve it, then try its exchangers in order.
    async fn deliver_to_domain(
        &self,
        domain: &str,
        from: &EmailAddress,
        recipients: &[EmailAddress],
        mime: &[u8],
    ) -> DeliveryResult {
        let candidates = match self.resolver.resolve(domain).await {
            Ok(candidates) => candidates,
            // A failed lookup is this domain's problem only, and it is
            // retryable: report it as deferred instead of dropping the other
            // domains' deliveries.
            Err(error) => {
                return DeliveryResult::new(
                    DeliveryStatus::Deferred,
                    domain,
                    421,
                    format!("MX lookup failed: {error}"),
                )
            }
        };
        let port = self.resolver.port_for(domain);
        self.deliver_candidates(domain, port, from, recipients, mime, &candidates)
            .await
    }

    /// Try every candidate exchanger until one answers; defer when none does.
    ///
    /// `target` only names what is being delivered to — a recipient domain, or the
    /// relay host — for the log line and for the "nothing answered" verdict.
    async fn deliver_candidates(
        &self,
        target: &str,
        port: u16,
        from: &EmailAddress,
        recipients: &[EmailAddress],
        mime: &[u8],
        candidates: &[MxRecord],
    ) -> DeliveryResult {
        let mut last_error: Option<(String, String)> = None;
        for candidate in candidates {
            match self
                .deliver_to(&candidate.exchange, port, from, recipients, mime)
                .await
            {
                Ok(result) => return result,
                Err(error) => {
                    // Transport failure: try the next exchanger, remembering why
                    // this one did not work.
                    tracing::warn!(
                        target,
                        mx = %candidate.exchange,
                        %error,
                        "delivery attempt failed, trying the next mail exchanger"
                    );
                    last_error = Some((candidate.exchange.clone(), error.to_string()));
                }
            }
        }

        let (host, message) = last_error.unwrap_or_else(|| {
            (
                target.to_string(),
                "no mail exchanger available".to_string(),
            )
        });
        // Nothing answered anywhere: defer so the queue retries with backoff.
        DeliveryResult::new(
            DeliveryStatus::Deferred,
            host,
            421,
            format!("no mail exchanger accepted the connection: {message}"),
        )
    }

    /// One complete attempt against one host. `Err` means "transport failure,
    /// another exchanger may work"; every SMTP-level verdict is `Ok`.
    async fn deliver_to(
        &self,
        host: &str,
        port: u16,
        from: &EmailAddress,
        recipients: &[EmailAddress],
        mime: &[u8],
    ) -> Result<DeliveryResult> {
        let stream = tokio::time::timeout(self.config.timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| SmtpError::Timeout(format!("connecting to {host}:{port}")))??;
        let _ = stream.set_nodelay(true);

        let mut wire = Wire::new(Stream::Plain(stream), self.config.timeout);
        let banner = wire.read_reply().await?;
        if banner.code != 220 {
            return Err(SmtpError::Protocol(format!(
                "{host} greeted with {} instead of 220: {}",
                banner.code,
                banner.text()
            )));
        }

        let ehlo = wire
            .command(&format!("EHLO {}", self.config.ehlo_name))
            .await?;
        if ehlo.code != 250 {
            return Err(SmtpError::Protocol(format!(
                "{host} refused EHLO with {}: {}",
                ehlo.code,
                ehlo.text()
            )));
        }

        let mut wire = if ehlo.has_capability("STARTTLS") {
            let starttls = wire.command("STARTTLS").await?;
            // 220 means "go ahead"; anything else leaves the session unusable for
            // TLS, and `required` must then fail the delivery.
            if starttls.code != 220 {
                // Opportunistic mode falls through to plaintext when the peer
                // advertised STARTTLS but then refused the upgrade (e.g. 454 no
                // cert); required mode fails the delivery.
                if self.config.starttls == StartTlsMode::Required {
                    return Ok(self.starttls_missing(host, starttls.code, &starttls.text()));
                }
                tracing::debug!(
                    mx = %host,
                    code = starttls.code,
                    "STARTTLS advertised but refused; continuing in plaintext (opportunistic)"
                );
                // The session is still usable: the server rejected the upgrade
                // but expects the dialogue to continue (RFC 5321 §4.2.4).
                let mail = wire.command(&format!("MAIL FROM:<{from}>")).await?;
                if mail.code / 100 != 2 {
                    let status = DeliveryStatus::from_code(mail.code);
                    let _ = wire.command("QUIT").await;
                    return Ok(DeliveryResult::new(status, host, mail.code, mail.text()));
                }
                for recipient in recipients {
                    let reply = wire.command(&format!("RCPT TO:<{recipient}>")).await?;
                    if reply.code / 100 != 2 {
                        let status = DeliveryStatus::from_code(reply.code);
                        let _ = wire.command("QUIT").await;
                        return Ok(DeliveryResult::new(
                            status,
                            host,
                            reply.code,
                            format!("{recipient}: {}", reply.text()),
                        ));
                    }
                }
                let data = wire.command("DATA").await?;
                if data.code != 354 {
                    let status = DeliveryStatus::from_code(data.code);
                    let _ = wire.command("QUIT").await;
                    return Ok(DeliveryResult::new(status, host, data.code, data.text()));
                }
                wire.write_block(&dot_stuff(mime)).await?;
                let accepted = wire.read_reply().await?;
                let status = DeliveryStatus::from_code(accepted.code);
                let _ = wire.command("QUIT").await;
                return Ok(DeliveryResult::new(
                    status,
                    host,
                    accepted.code,
                    accepted.text(),
                ));
            }
            let stream = wire.into_stream();
            let tls = upgrade(stream, host).await?;
            let mut secure = Wire::new(Stream::Tls(Box::new(tls)), self.config.timeout);
            let again = secure
                .command(&format!("EHLO {}", self.config.ehlo_name))
                .await?;
            if again.code != 250 {
                return Err(SmtpError::Protocol(format!(
                    "{host} refused EHLO after STARTTLS with {}",
                    again.code
                )));
            }
            tracing::debug!(mx = %host, "delivery connection upgraded to TLS");
            secure
        } else {
            if self.config.starttls == StartTlsMode::Required {
                return Ok(self.starttls_missing(host, 250, "STARTTLS not advertised"));
            }
            tracing::debug!(mx = %host, "peer does not offer STARTTLS, sending in clear text");
            wire
        };

        let mail = wire.command(&format!("MAIL FROM:<{from}>")).await?;
        if mail.code / 100 != 2 {
            let status = DeliveryStatus::from_code(mail.code);
            let _ = wire.command("QUIT").await;
            return Ok(DeliveryResult::new(status, host, mail.code, mail.text()));
        }

        for recipient in recipients {
            let reply = wire.command(&format!("RCPT TO:<{recipient}>")).await?;
            if reply.code / 100 != 2 {
                let status = DeliveryStatus::from_code(reply.code);
                let _ = wire.command("QUIT").await;
                return Ok(DeliveryResult::new(
                    status,
                    host,
                    reply.code,
                    format!("{recipient}: {}", reply.text()),
                ));
            }
        }

        let data = wire.command("DATA").await?;
        if data.code != 354 {
            let status = DeliveryStatus::from_code(data.code);
            let _ = wire.command("QUIT").await;
            return Ok(DeliveryResult::new(status, host, data.code, data.text()));
        }

        wire.write_block(&dot_stuff(mime)).await?;
        let accepted = wire.read_reply().await?;
        let status = DeliveryStatus::from_code(accepted.code);
        let _ = wire.command("QUIT").await;
        Ok(DeliveryResult::new(
            status,
            host,
            accepted.code,
            accepted.text(),
        ))
    }

    fn starttls_missing(&self, host: &str, code: u16, text: &str) -> DeliveryResult {
        DeliveryResult::new(
            DeliveryStatus::Failed,
            host,
            code,
            format!(
                "STARTTLS is required but unavailable: {text} (PIGEON_SMTP_OUT_STARTTLS=required)"
            ),
        )
    }
}

/// Group recipients by their own domain, keeping first-appearance order so two
/// runs of the same message produce the same transaction sequence.
fn group_by_domain(recipients: &[EmailAddress]) -> Vec<(String, Vec<EmailAddress>)> {
    let mut groups: Vec<(String, Vec<EmailAddress>)> = Vec::new();
    for recipient in recipients {
        let domain = recipient.domain().to_string();
        match groups.iter_mut().find(|(known, _)| *known == domain) {
            Some((_, group)) => group.push(recipient.clone()),
            None => groups.push((domain, vec![recipient.clone()])),
        }
    }
    groups
}

/// Fold the per-domain verdicts into the one verdict the queue understands.
///
/// Precedence is `Deferred` first on purpose: the queue is per **message**, so a
/// retryable domain has to keep the job alive — reporting a bounce instead would
/// drop that recipient's mail. Among the permanent verdicts a remote `5xx`
/// (`Bounced`) outranks a local refusal (`Failed`) because it is a definitive
/// answer about the recipient.
fn aggregate(groups: Vec<DeliveryGroup>) -> DeliveryResult {
    if groups.is_empty() {
        // Unreachable from the send pipeline (validation requires one recipient),
        // but `deliver` is public: fail locally rather than invent a verdict.
        return DeliveryResult::new(
            DeliveryStatus::Failed,
            String::new(),
            0,
            "no recipients to deliver to",
        );
    };

    if groups.len() == 1 {
        // One domain: the single-domain verdict *is* the answer, unchanged.
        let single = groups[0].result.clone();
        return DeliveryResult { groups, ..single };
    }
    let first = &groups[0];
    let status = if groups
        .iter()
        .any(|group| group.result.status == DeliveryStatus::Deferred)
    {
        DeliveryStatus::Deferred
    } else if groups
        .iter()
        .any(|group| group.result.status == DeliveryStatus::Bounced)
    {
        DeliveryStatus::Bounced
    } else if groups
        .iter()
        .any(|group| group.result.status == DeliveryStatus::Failed)
    {
        DeliveryStatus::Failed
    } else {
        DeliveryStatus::Sent
    };
    let representative = groups
        .iter()
        .find(|group| group.result.status == status)
        .unwrap_or(first);

    // Distinct hosts in the order they were tried, so the event log keeps stating
    // where the message actually went.
    let mut hosts: Vec<&str> = Vec::new();
    for group in &groups {
        if !hosts.contains(&group.result.mx_host.as_str()) {
            hosts.push(&group.result.mx_host);
        }
    }

    let message = groups
        .iter()
        .map(|group| {
            format!(
                "{} via {}: code={} {}",
                group.domain, group.result.mx_host, group.result.code, group.result.message
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    DeliveryResult {
        status,
        mx_host: hosts.join(","),
        code: representative.result.code,
        message,
        groups,
    }
}

impl std::fmt::Debug for OutboundSmtpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundSmtpClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// One ESMTP transaction's socket, upgraded in place by STARTTLS.
enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

// Both variants are `Unpin`, so delegating the poll methods needs no projection
// and no `unsafe`.
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Line-oriented SMTP transport with per-operation timeouts.
struct Wire {
    stream: Stream,
    buffer: Vec<u8>,
    timeout: Duration,
}

const MAX_REPLY_BYTES: usize = 16 * 1024;

impl Wire {
    fn new(stream: Stream, timeout: Duration) -> Self {
        Self {
            stream,
            buffer: Vec::with_capacity(256),
            timeout,
        }
    }

    fn into_stream(self) -> Stream {
        self.stream
    }

    async fn command(&mut self, line: &str) -> Result<Reply> {
        let mut payload = Vec::with_capacity(line.len() + 2);
        payload.extend_from_slice(line.as_bytes());
        payload.extend_from_slice(b"\r\n");
        self.write_block(&payload).await?;
        self.read_reply().await
    }

    async fn write_block(&mut self, bytes: &[u8]) -> Result<()> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(bytes).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| SmtpError::Timeout("writing to the peer".to_string()))??;
        Ok(())
    }

    /// Read one reply, consuming exactly one CRLF-terminated line at a time.
    async fn read_reply(&mut self) -> Result<Reply> {
        let mut lines: Vec<String> = Vec::new();
        loop {
            let line = self.read_line().await?;
            let Some(line) = line else {
                return Err(SmtpError::Protocol(
                    "peer closed the connection in the middle of a reply".to_string(),
                ));
            };
            if line.len() < 3 {
                return Err(SmtpError::Protocol(format!(
                    "malformed reply line {line:?}"
                )));
            }
            lines.push(line.clone());
            let terminator = line.as_bytes().get(3) == Some(&b' ') || line.len() == 3;
            if terminator {
                return assemble_reply(&lines);
            }
        }
    }

    async fn read_line(&mut self) -> Result<Option<String>> {
        loop {
            if let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = String::from_utf8_lossy(&self.buffer[..position]).into_owned();
                self.buffer.drain(..=position);
                return Ok(Some(line.trim_end_matches('\r').to_string()));
            }
            if self.buffer.len() > MAX_REPLY_BYTES {
                return Err(SmtpError::Protocol(
                    "peer sent a reply line above the size limit".to_string(),
                ));
            }
            let mut chunk = [0u8; 1024];
            let read = tokio::time::timeout(self.timeout, self.stream.read(&mut chunk))
                .await
                .map_err(|_| SmtpError::Timeout("waiting for a reply".to_string()))??;
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Validate a complete multi-line reply.
///
/// Every line must carry the same code, and only the last one may use a space
/// separator (RFC 5321 §4.2.1). A peer that interleaves codes is broken enough
/// that guessing which code won would hide a real failure.
pub(crate) fn assemble_reply(lines: &[String]) -> Result<Reply> {
    let mut code: Option<u16> = None;
    let mut texts = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        let parsed = line
            .get(..3)
            .and_then(|prefix| prefix.parse::<u16>().ok())
            .ok_or_else(|| SmtpError::Protocol(format!("reply line without a code: {line:?}")))?;
        match code {
            Some(expected) if expected != parsed => {
                return Err(SmtpError::Protocol(format!(
                    "reply code changed mid-reply: {expected} then {parsed}"
                )))
            }
            Some(_) => {}
            None => code = Some(parsed),
        }
        texts.push(line.get(4..).unwrap_or_default().to_string());
        let last = index + 1 == lines.len();
        let separator = line.as_bytes().get(3).copied();
        if last && separator != Some(b' ') && line.len() != 3 {
            return Err(SmtpError::Protocol(format!(
                "reply did not end with a space separator: {line:?}"
            )));
        }
    }
    let code = code.ok_or_else(|| SmtpError::Protocol("empty reply".to_string()))?;
    Ok(Reply::multiline(code, texts))
}

/// Quoted-printable-proof, dot-stuffed, CRLF-normalized form of `mime`, ending
/// with the `.` terminator line.
pub(crate) fn dot_stuff(mime: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mime.len() + mime.len() / 40 + 4);
    let mut rest = mime;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|byte| *byte == b'\n') {
            Some(position) => (&rest[..position], &rest[position + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
        rest = next;
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Upgrade `stream` to TLS for `host`.
///
/// The handshake is real — a peer that cannot complete it fails the delivery —
/// but the certificate is accepted unconditionally: `AcceptAnyServerCert`
/// documents the v0.1 gap instead of disguising it.
async fn upgrade(stream: Stream, host: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let Stream::Plain(tcp) = stream else {
        return Err(SmtpError::Tls(
            "connection is already encrypted".to_string(),
        ));
    };
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| {
        SmtpError::Tls(format!("{host:?} is not a valid TLS server name: {error}"))
    })?;
    TlsConnector::from(tls_config()?)
        .connect(server_name, tcp)
        .await
        .map_err(|error| SmtpError::Tls(format!("handshake with {host} failed: {error}")))
}

/// Shared client configuration: a fresh one per connection would rebuild the
/// crypto provider on every delivery.
fn tls_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| SmtpError::Tls(format!("cannot build the TLS client config: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    let config = Arc::new(config);
    // Losing the race just means another thread stored an equivalent config.
    let _ = CONFIG.set(Arc::clone(&config));
    Ok(config)
}

/// v0.1 certificate policy: accept the handshake, verify nothing.
///
/// This is a deliberate, documented gap (see the module docs): the image ships no
/// CA bundle and pinning is v0.2. It is *not* a placeholder that silently
/// pretends to verify — `verify_server_cert` returns `assertion()` with a
/// comment, and the delivery still proves that the peer completed a TLS
/// handshake.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_from_reply_classes() {
        assert_eq!(DeliveryStatus::from_code(250), DeliveryStatus::Sent);
        assert_eq!(DeliveryStatus::from_code(251), DeliveryStatus::Sent);
        assert_eq!(DeliveryStatus::from_code(421), DeliveryStatus::Deferred);
        assert_eq!(DeliveryStatus::from_code(450), DeliveryStatus::Deferred);
        assert_eq!(DeliveryStatus::from_code(550), DeliveryStatus::Bounced);
        assert_eq!(DeliveryStatus::from_code(554), DeliveryStatus::Bounced);
        // A 3xx/1xx after DATA means the peer is confused; retrying is safe and
        // never suppresses a recipient.
        assert_eq!(DeliveryStatus::from_code(354), DeliveryStatus::Deferred);
    }

    #[test]
    fn every_status_has_a_storage_spelling() {
        for status in [
            DeliveryStatus::Sent,
            DeliveryStatus::Deferred,
            DeliveryStatus::Bounced,
            DeliveryStatus::Failed,
        ] {
            assert!(!status.as_str().is_empty());
        }
    }

    #[test]
    fn dot_stuffing_prefixes_leading_dots_and_appends_the_terminator() {
        let stuffed = dot_stuff(b"Subject: hi\r\n\r\n.line one\r\n..line two\r\n");
        assert_eq!(
            String::from_utf8(stuffed).expect("utf8"),
            "Subject: hi\r\n\r\n..line one\r\n...line two\r\n.\r\n"
        );
    }

    #[test]
    fn dot_stuffing_normalizes_bare_lf_and_missing_final_newline() {
        let stuffed = dot_stuff(b"a\nb\nc");
        assert_eq!(
            String::from_utf8(stuffed).expect("utf8"),
            "a\r\nb\r\nc\r\n.\r\n"
        );
    }

    #[test]
    fn dot_stuffing_of_an_empty_body_is_just_the_terminator() {
        assert_eq!(dot_stuff(b""), b".\r\n".to_vec());
    }

    #[test]
    fn multi_line_replies_keep_every_text_line() {
        let reply = assemble_reply(&[
            "250-mail.example greets you".to_string(),
            "250-SIZE 1024".to_string(),
            "250 STARTTLS".to_string(),
        ])
        .expect("valid reply");
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 3);
        assert!(reply.has_capability("starttls"));
        assert!(reply.has_capability("SIZE 1024"));
        assert!(!reply.has_capability("DSN"));
    }

    #[test]
    fn replies_with_inconsistent_codes_are_protocol_errors() {
        let error = assemble_reply(&[
            "250-first".to_string(),
            "550 then something else".to_string(),
        ])
        .expect_err("codes differ");
        assert!(matches!(error, SmtpError::Protocol(_)));
    }

    #[test]
    fn a_reply_without_a_numeric_code_is_a_protocol_error() {
        assert!(assemble_reply(&["hello there".to_string()]).is_err());
    }

    #[test]
    fn relay_addresses_must_carry_a_port() {
        assert_eq!(
            parse_host_port("smtp.example.com:587").expect("valid"),
            ("smtp.example.com".to_string(), 587)
        );
        assert_eq!(
            parse_host_port("[::1]:2525").expect("valid"),
            ("::1".to_string(), 2525)
        );
        assert!(parse_host_port("smtp.example.com").is_err());
        assert!(parse_host_port(":25").is_err());
        assert!(parse_host_port("host:notaport").is_err());
    }

    #[test]
    fn default_config_requires_starttls() {
        let config = DeliveryConfig::default();
        assert_eq!(config.starttls, StartTlsMode::Required);
        assert_eq!(config.ehlo_name, DEFAULT_EHLO_NAME);
        assert!(config.relay.is_none());
    }
}
