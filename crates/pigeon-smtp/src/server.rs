//! Inbound ESMTP server.
//!
//! One `tokio` task per connection, one [`Session`] state machine per task. The
//! state machine is deliberately free of I/O: [`Session::handle_line`] takes a
//! command line and returns an [`Action`], so every reply code and every
//! sequencing rule is unit-testable without a socket. The connection loop in
//! [`InboundSmtpServer::handle_connection`] is the only part that touches the
//! network or the database.
//!
//! # Session shape
//!
//! ```text
//! CONNECT  -> 220 banner
//! EHLO/HELO -> 250 (capabilities)          MAIL -> 250 -> RCPT -> 250 (xN)
//! DATA -> 354 -> raw lines -> "." -> 250   QUIT -> 221
//! ```
//!
//! # Limits (all enforced, all `pub` so the tests and the docs agree)
//!
//! | limit | value | reply when exceeded |
//! |---|---|---|
//! | message size | [`MAX_MESSAGE_SIZE`] (35 MiB) | `552` |
//! | recipients | [`MAX_RECIPIENTS`] (50) | `452` |
//! | line length | [`MAX_LINE_LEN`] (1000 bytes) | `500` |
//! | commands/connection | [`MAX_COMMANDS`] (1000) | `421` + close |
//! | idle/command timeout | [`CONNECTION_TIMEOUT`] (5 min) | `421` + close |
//!
//! # Storage
//!
//! A complete message is sealed per owning account before it reaches
//! `store` (ADR 0003). A recipient is resolved in two steps:
//!
//! 1. **Exact match** — `ApiDb::account_id_by_email`, the ordinary mailbox.
//! 2. **Catch-all** — when no account holds the address, the recipient's *domain*
//!    is looked up in [`CatchallSource`] (`store`'s `catchall_rules`). A `route`
//!    rule delivers the message into the rule's target mailbox, sealed with **that
//!    account's** AAD, so the body is only openable by the mailbox that received
//!    it. A `discard` rule accepts the message and drops it, which is the
//!    anti-enumeration answer: the sender learns nothing about which addresses
//!    exist.
//!
//! With no rule at all the answer stays `550`: a server that silently accepted
//! every unknown address would be an open relay for spam and a bounce amplifier.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pigeon_api::db::ApiDb;
use pigeon_api::time::{now_unix, rfc5322_date};
use pigeon_core::types::CatchallAction;
use pigeon_core::{Direction, EmailAddress};
use pigeon_crypto::MasterKey;
use store::{CatchallRuleRow, NewMessage, SqliteStorage, Storage};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Result, SmtpError};

/// Largest message body the inbound server accepts, in bytes (35 MiB).
pub const MAX_MESSAGE_SIZE: usize = 35 * 1024 * 1024;
/// Largest number of `RCPT TO` commands per transaction.
pub const MAX_RECIPIENTS: usize = 50;
/// Longest accepted command or data line, in bytes, CRLF included.
pub const MAX_LINE_LEN: usize = 1000;
/// Largest number of commands accepted on one connection.
pub const MAX_COMMANDS: usize = 1000;
/// How long the server waits for the client before closing the session.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// Tunables of the inbound server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Name announced in the banner and used in the `Received:` header.
    pub hostname: String,
    /// See [`MAX_MESSAGE_SIZE`].
    pub max_message_size: usize,
    /// See [`MAX_RECIPIENTS`].
    pub max_recipients: usize,
    /// See [`MAX_LINE_LEN`].
    pub max_line_len: usize,
    /// See [`MAX_COMMANDS`].
    pub max_commands: usize,
    /// See [`CONNECTION_TIMEOUT`].
    pub command_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            // `.local` never resolves publicly, so a default banner cannot be
            // mistaken for a real host identity.
            hostname: "pigeon.local".to_string(),
            max_message_size: MAX_MESSAGE_SIZE,
            max_recipients: MAX_RECIPIENTS,
            max_line_len: MAX_LINE_LEN,
            max_commands: MAX_COMMANDS,
            command_timeout: CONNECTION_TIMEOUT,
        }
    }
}

impl ServerConfig {
    /// Read `PIGEON_SMTP_HOSTNAME` when it is set, deriving it from the listen
    /// address otherwise.
    ///
    /// The listen address is only a fallback: `:25` has no host name in it, and
    /// a banner of `0.0.0.0` would be worse than a made-up one, so an
    /// unspecified bind falls back to the default hostname.
    pub fn with_hostname_from_env(mut self) -> Result<Self> {
        match std::env::var("PIGEON_SMTP_HOSTNAME") {
            Ok(value) if !value.trim().is_empty() => {
                self.hostname = sanitize_helo(value.trim());
                Ok(self)
            }
            Ok(_) => Ok(self),
            Err(std::env::VarError::NotPresent) => Ok(self),
            Err(std::env::VarError::NotUnicode(_)) => Err(SmtpError::Config(
                "PIGEON_SMTP_HOSTNAME is not valid Unicode".to_string(),
            )),
        }
    }
}

/// One SMTP reply: a status code plus one or more text lines.
///
/// Multi-line replies encode as `250-first\r\n250 last\r\n`; the last line
/// carries the code followed by a space, every earlier line a hyphen
/// (RFC 5321 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    /// A single-line reply.
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    /// A multi-line reply; an empty iterator is not representable.
    pub fn multiline(code: u16, lines: Vec<String>) -> Self {
        debug_assert!(!lines.is_empty(), "an SMTP reply needs at least one line");
        Self { code, lines }
    }

    /// Every text line joined by a single space, for logs and events.
    pub fn text(&self) -> String {
        self.lines.join(" ")
    }

    /// True when any line starts with `keyword` (ASCII-case-insensitive).
    ///
    /// This is how `EHLO` capabilities are read: `250-STARTTLS` is advertised by
    /// looking for the `STARTTLS` token, not by parsing the greeting line.
    pub fn has_capability(&self, keyword: &str) -> bool {
        self.lines.iter().any(|line| {
            line.get(..keyword.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(keyword))
        })
    }

    /// Wire form, CRLF after every line.
    pub fn encode(&self) -> String {
        let last = self.lines.len().saturating_sub(1);
        let mut out = String::with_capacity(self.lines.iter().map(String::len).sum::<usize>() + 8);
        for (index, line) in self.lines.iter().enumerate() {
            out.push_str(&self.code.to_string());
            out.push(if index == last { ' ' } else { '-' });
            out.push_str(line);
            out.push_str("\r\n");
        }
        out
    }
}

/// What the connection loop must do after a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Send the reply and read the next command.
    Reply(Reply),
    /// Send `354`, then read the message data.
    StartData,
    /// Send the reply and close the connection.
    Close(Reply),
}

/// Per-connection protocol state.
#[derive(Debug)]
pub(crate) struct Session {
    config: Arc<ServerConfig>,
    peer: SocketAddr,
    helo: Option<String>,
    /// True after `EHLO` (capabilities advertised), false after `HELO`.
    esmtp: bool,
    mail_from: Option<EmailAddress>,
    recipients: Vec<EmailAddress>,
    commands: u32,
}

impl Session {
    fn new(config: Arc<ServerConfig>, peer: SocketAddr) -> Self {
        Self {
            config,
            peer,
            helo: None,
            esmtp: false,
            mail_from: None,
            recipients: Vec::new(),
            commands: 0,
        }
    }

    /// The `220` greeting.
    fn banner(&self) -> Reply {
        Reply::new(220, format!("{} ESMTP Pigeon Mail", self.config.hostname))
    }

    fn reset_envelope(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
    }

    /// Handle one command line (CR/LF already stripped).
    fn handle_line(&mut self, line: &str) -> Action {
        self.commands += 1;
        if self.commands as usize > self.config.max_commands {
            return Action::Close(Reply::new(
                421,
                "4.7.0 too many commands on this connection",
            ));
        }

        let (verb, argument) = match line.split_once(char::is_whitespace) {
            Some((verb, argument)) => (verb, argument.trim()),
            None => (line, ""),
        };

        match verb.to_ascii_uppercase().as_str() {
            "EHLO" => self.greet(argument, true),
            "HELO" => self.greet(argument, false),
            "MAIL" => self.mail(argument),
            "RCPT" => self.rcpt(argument),
            "DATA" => self.data(),
            "RSET" => {
                self.reset_envelope();
                Action::Reply(Reply::new(250, "2.0.0 Ok"))
            }
            "NOOP" => Action::Reply(Reply::new(250, "2.0.0 Ok")),
            "QUIT" => Action::Close(Reply::new(221, "2.0.0 Bye")),
            // v0.1 has no certificate lifecycle, so the capability is
            // advertised (clients can see it is planned) but refused with a
            // temporary failure: the client may retry in clear text or give up,
            // which is its policy to decide.
            "STARTTLS" => {
                if argument.is_empty() {
                    Action::Reply(Reply::new(454, "4.7.0 TLS not available"))
                } else {
                    Action::Reply(Reply::new(501, "5.5.4 STARTTLS takes no arguments"))
                }
            }
            "VRFY" | "EXPN" | "HELP" | "TURN" | "AUTH" => {
                Action::Reply(Reply::new(502, "5.5.1 command not implemented"))
            }
            _ => Action::Reply(Reply::new(500, "5.5.2 command unrecognized")),
        }
    }

    fn greet(&mut self, argument: &str, esmtp: bool) -> Action {
        if argument.is_empty() {
            return Action::Reply(Reply::new(501, "5.5.4 HELO/EHLO requires a domain"));
        }
        self.helo = Some(sanitize_helo(argument));
        self.esmtp = esmtp;
        // A repeated EHLO starts a new session (RFC 5321 §4.1.4).
        self.reset_envelope();

        if !esmtp {
            return Action::Reply(Reply::new(
                250,
                format!("{} Hello {}", self.config.hostname, argument),
            ));
        }

        let hostname = &self.config.hostname;
        Action::Reply(Reply::multiline(
            250,
            vec![
                format!("{hostname} Hello {}", argument),
                format!("SIZE {}", self.config.max_message_size),
                "8BITMIME".to_string(),
                // Advertised so the capability is discoverable; answered with
                // 454 until v0.2 ships a certificate lifecycle.
                "STARTTLS".to_string(),
                "ENHANCEDSTATUSCODES".to_string(),
            ],
        ))
    }

    fn mail(&mut self, argument: &str) -> Action {
        if self.helo.is_none() {
            return Action::Reply(Reply::new(503, "5.5.1 send HELO/EHLO first"));
        }
        if self.mail_from.is_some() {
            return Action::Reply(Reply::new(503, "5.5.1 nested MAIL command"));
        }
        let parsed = match parse_mail_from(argument) {
            Ok(parsed) => parsed,
            Err(text) => return Action::Reply(Reply::new(501, text)),
        };
        if let Some(size) = parsed.size {
            if size > self.config.max_message_size as u64 {
                return Action::Reply(Reply::new(
                    552,
                    format!(
                        "5.3.4 message size {size} exceeds the {}-byte limit",
                        self.config.max_message_size
                    ),
                ));
            }
        }
        self.mail_from = Some(parsed.sender);
        Action::Reply(Reply::new(250, "2.1.0 Ok"))
    }

    fn rcpt(&mut self, argument: &str) -> Action {
        if self.mail_from.is_none() {
            return Action::Reply(Reply::new(503, "5.5.1 need MAIL before RCPT"));
        }
        let recipient = match parse_rcpt_to(argument) {
            Ok(recipient) => recipient,
            Err(text) => return Action::Reply(Reply::new(501, text)),
        };
        if self.recipients.len() >= self.config.max_recipients {
            return Action::Reply(Reply::new(
                452,
                format!(
                    "4.5.3 too many recipients (limit {})",
                    self.config.max_recipients
                ),
            ));
        }
        self.recipients.push(recipient);
        Action::Reply(Reply::new(250, "2.1.5 Ok"))
    }

    fn data(&mut self) -> Action {
        match (&self.mail_from, self.recipients.is_empty()) {
            (None, _) => Action::Reply(Reply::new(503, "5.5.1 need MAIL before DATA")),
            (Some(_), true) => Action::Reply(Reply::new(503, "5.5.1 need RCPT before DATA")),
            (Some(_), false) => Action::StartData,
        }
    }

    /// Envelope snapshot for the ingestion step.
    fn envelope(&self) -> Option<Envelope> {
        Some(Envelope {
            peer: self.peer,
            helo: self.helo.clone().unwrap_or_else(|| "unknown".to_string()),
            mail_from: self.mail_from.clone()?,
            recipients: self.recipients.clone(),
        })
    }
}

/// The accepted envelope of a transaction.
#[derive(Debug, Clone)]
struct Envelope {
    peer: SocketAddr,
    helo: String,
    mail_from: EmailAddress,
    recipients: Vec<EmailAddress>,
}

/// Arguments of a `MAIL FROM:` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailFromArgs {
    pub sender: EmailAddress,
    /// `SIZE=` parameter, when the client declared one.
    pub size: Option<u64>,
}

/// Strip `keyword` (ASCII-case-insensitively) and the colon that follows it.
fn strip_keyword<'a>(argument: &'a str, keyword: &str) -> Option<&'a str> {
    let trimmed = argument.trim();
    let (head, tail) = trimmed.split_at(trimmed.len().min(keyword.len()));
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    tail.strip_prefix(':')
}

/// Extract the `<addr>` of a path argument, plus whatever follows the `>`.
fn split_path(rest: &str) -> std::result::Result<(&str, &str), String> {
    let rest = rest.trim_start();
    if !rest.starts_with('<') {
        return Err("5.5.4 expected <address>".to_string());
    }
    let close = rest
        .find('>')
        .ok_or_else(|| "5.5.4 unterminated <address>".to_string())?;
    Ok((&rest[1..close], rest[close + 1..].trim()))
}

/// Parse the argument of `MAIL FROM:` (`FROM:<addr> [SIZE=n] [BODY=...]`).
pub(crate) fn parse_mail_from(argument: &str) -> std::result::Result<MailFromArgs, String> {
    let rest = strip_keyword(argument, "FROM").ok_or_else(|| "5.5.4 expected FROM:".to_string())?;
    let (address, parameters) = split_path(rest)?;
    if address.is_empty() {
        // A null reverse-path is a bounce. v0.1 has nowhere to file one (there
        // is no bounce mailbox yet), so it is refused rather than mis-stored.
        return Err("5.1.7 null reverse-path is not accepted".to_string());
    }
    let sender = EmailAddress::parse(address)
        .map_err(|error| format!("5.1.7 invalid sender address: {error}"))?;

    let mut size = None;
    for parameter in parameters.split_whitespace() {
        if let Some(value) = parameter
            .strip_prefix("SIZE=")
            .or_else(|| parameter.strip_prefix("size="))
        {
            size = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| format!("5.5.4 SIZE is not a number: {value:?}"))?,
            );
        }
    }
    Ok(MailFromArgs { sender, size })
}

/// Parse the argument of `RCPT TO:` (`TO:<addr>`), ignoring `NOTIFY`/`ORCPT`.
pub(crate) fn parse_rcpt_to(argument: &str) -> std::result::Result<EmailAddress, String> {
    let rest = strip_keyword(argument, "TO").ok_or_else(|| "5.5.4 expected TO:".to_string())?;
    let (address, _parameters) = split_path(rest)?;
    if address.is_empty() {
        return Err("5.1.3 empty recipient address".to_string());
    }
    EmailAddress::parse(address)
        .map_err(|error| format!("5.1.3 invalid recipient address: {error}"))
}

/// Where the inbound server learns what to do with a recipient it cannot resolve.
///
/// The seam exists for the same reason [`crate::worker::DkimKeySource`] does: the
/// protocol/storage code never reaches into a table itself, and a test can serve
/// rules from anywhere. The production implementation is [`StoreCatchall`].
pub trait CatchallSource: Send + Sync + std::fmt::Debug {
    /// The rule for `domain`, or `None` when the domain has none — which keeps the
    /// ordinary `550`.
    fn rule_for(&self, domain: &str) -> Result<Option<CatchallRuleRow>>;
}

/// The production [`CatchallSource`]: `store`'s `catchall_rules` row for the
/// recipient's domain.
pub struct StoreCatchall {
    store: Arc<SqliteStorage>,
}

impl StoreCatchall {
    /// Build a source over the shared store.
    pub fn new(store: Arc<SqliteStorage>) -> Self {
        Self { store }
    }
}

impl CatchallSource for StoreCatchall {
    fn rule_for(&self, domain: &str) -> Result<Option<CatchallRuleRow>> {
        // `store` lowercases the domain before matching, so a mixed-case `RCPT TO`
        // still finds the rule.
        self.store.get_catchall(domain).map_err(SmtpError::from)
    }
}

impl std::fmt::Debug for StoreCatchall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store handle is not interesting and must not print its contents.
        f.debug_struct("StoreCatchall").finish_non_exhaustive()
    }
}

/// Inbound server: owns the listener and the storage handles.
pub struct InboundSmtpServer {
    store: Arc<SqliteStorage>,
    db: Arc<ApiDb>,
    master_key: Arc<MasterKey>,
    config: Arc<ServerConfig>,
    catchall: Arc<dyn CatchallSource>,
}

impl InboundSmtpServer {
    /// Build a server from already-open storage handles.
    ///
    /// Catch-all routing reads `store`'s `catchall_rules` (see [`StoreCatchall`]),
    /// so a deployment gets the configured behaviour with no extra wiring;
    /// [`InboundSmtpServer::with_catchall`] replaces the source in tests.
    pub fn new(
        store: Arc<SqliteStorage>,
        db: Arc<ApiDb>,
        master_key: Arc<MasterKey>,
        config: ServerConfig,
    ) -> Self {
        let catchall: Arc<dyn CatchallSource> = Arc::new(StoreCatchall::new(Arc::clone(&store)));
        Self {
            store,
            db,
            master_key,
            config: Arc::new(config),
            catchall,
        }
    }

    /// Replace the catch-all source (tests, or a deployment with another store).
    pub fn with_catchall(mut self, catchall: Arc<dyn CatchallSource>) -> Self {
        self.catchall = catchall;
        self
    }

    /// Effective configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Bind the listener and return it with the address actually bound (which is
    /// how a test learns the ephemeral port).
    pub async fn bind(&self, address: &str) -> Result<(TcpListener, SocketAddr)> {
        let address = parse_listen_addr(address)?;
        let listener = TcpListener::bind(address).await?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Accept connections until `shutdown` resolves.
    pub async fn serve_with_shutdown<F>(self: Arc<Self>, listener: TcpListener, shutdown: F)
    where
        F: std::future::Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                () = &mut shutdown => {
                    tracing::info!("inbound smtp listener shutting down");
                    return;
                }
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer)) => {
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        server.handle_connection(stream, peer).await;
                    });
                }
                Err(error) => {
                    // Accept errors are per-connection (EMFILE, ECONNABORTED);
                    // the listener itself is still usable, so keep serving.
                    tracing::warn!(%error, "inbound smtp accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Run the protocol for one connection.
    async fn handle_connection(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        let timeout = self.config.command_timeout;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut session = Session::new(Arc::clone(&self.config), peer);

        if !write(&mut write_half, &session.banner()).await {
            return;
        }
        tracing::debug!(%peer, "inbound smtp session opened");

        loop {
            let line = match read_limited_line(&mut reader, self.config.max_line_len, timeout).await
            {
                Ok(LineEvent::Line(line)) => line,
                Ok(LineEvent::TooLong) => {
                    let reply = Reply::new(500, "5.5.2 line too long");
                    write(&mut write_half, &reply).await;
                    continue;
                }
                Ok(LineEvent::Eof) => break,
                Err(SmtpError::Timeout(_)) => {
                    // Announce why before hanging up: a silent close looks like a
                    // network fault to the sending MTA.
                    write(
                        &mut write_half,
                        &Reply::new(421, "4.4.2 timeout, closing connection"),
                    )
                    .await;
                    break;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "inbound smtp read ended");
                    break;
                }
            };

            match session.handle_line(&line) {
                Action::Reply(reply) => {
                    if !write(&mut write_half, &reply).await {
                        break;
                    }
                }
                Action::Close(reply) => {
                    write(&mut write_half, &reply).await;
                    break;
                }
                Action::StartData => {
                    if !write(
                        &mut write_half,
                        &Reply::new(354, "Start mail input; end with <CRLF>.<CRLF>"),
                    )
                    .await
                    {
                        break;
                    }
                    let Some(envelope) = session.envelope() else {
                        // Unreachable: DATA is only reachable with an envelope.
                        break;
                    };
                    match read_data(&mut reader, &self.config, timeout).await {
                        Ok(DataEvent::Complete(data)) => {
                            let reply = if data.line_too_long {
                                Reply::new(500, "5.5.2 line too long")
                            } else if data.oversized {
                                Reply::new(
                                    552,
                                    format!(
                                        "5.3.4 message exceeds the {}-byte limit",
                                        self.config.max_message_size
                                    ),
                                )
                            } else {
                                let raw = data.bytes;
                                self.ingest(envelope, raw).await
                            };
                            session.reset_envelope();
                            if !write(&mut write_half, &reply).await {
                                break;
                            }
                        }
                        Ok(DataEvent::Closed) | Err(_) => break,
                    }
                }
            }
        }

        tracing::debug!(%peer, commands = session.commands, "inbound smtp session closed");
    }

    /// Seal and store one received message for every local recipient account.
    async fn ingest(&self, envelope: Envelope, raw: Vec<u8>) -> Reply {
        let store = Arc::clone(&self.store);
        let db = Arc::clone(&self.db);
        let master_key = Arc::clone(&self.master_key);
        let hostname = self.config.hostname.clone();
        let catchall = Arc::clone(&self.catchall);

        let outcome = tokio::task::spawn_blocking(move || {
            ingest_message(
                &store,
                &db,
                &master_key,
                &hostname,
                catchall.as_ref(),
                &envelope,
                raw,
            )
        })
        .await;

        match outcome {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => {
                tracing::error!(%error, "inbound message could not be stored");
                // 452 is a transient failure: the sending MTA retries, which is
                // exactly right for a full/busy database.
                Reply::new(452, "4.3.1 insufficient system storage, try again later")
            }
            Err(error) => {
                tracing::error!(%error, "inbound storage task failed");
                Reply::new(452, "4.3.1 insufficient system storage, try again later")
            }
        }
    }
}

/// Store one message. Runs on the blocking pool: every call is `rusqlite`.
fn ingest_message(
    store: &SqliteStorage,
    db: &ApiDb,
    master_key: &MasterKey,
    hostname: &str,
    catchall: &dyn CatchallSource,
    envelope: &Envelope,
    raw: Vec<u8>,
) -> Result<Reply> {
    let parsed = parse_message(&raw);

    // Recipient → account, in two steps: an exact mailbox wins, and only an
    // address no account holds is offered to the domain's catch-all rule.
    //
    // Recipients with neither are not local: they are logged and dropped rather
    // than bounced (v0.1 has no outbound bounce generator); if nobody was stored
    // and nobody was deliberately discarded, the whole message is refused with
    // 550, exactly as before catch-all rules existed.
    let mut per_account: BTreeMap<i64, Vec<EmailAddress>> = BTreeMap::new();
    // One lookup per domain, not per recipient: a message addressed to ten made-up
    // local parts of one domain costs one query.
    let mut rules: BTreeMap<String, Option<CatchallRuleRow>> = BTreeMap::new();
    let mut routed_via_catchall: BTreeSet<i64> = BTreeSet::new();
    let mut discarded = 0usize;
    for recipient in &envelope.recipients {
        if let Some(account_id) = db.account_id_by_email(&recipient.normalized())? {
            per_account
                .entry(account_id)
                .or_default()
                .push(recipient.clone());
            continue;
        }
        let domain = recipient.domain().to_string();
        if !rules.contains_key(&domain) {
            let rule = catchall.rule_for(&domain)?;
            rules.insert(domain.clone(), rule);
        }
        match rules.get(&domain).and_then(Option::as_ref) {
            Some(rule) if rule.action == CatchallAction::Route => match rule.target_account_id {
                Some(target) => {
                    routed_via_catchall.insert(target);
                    per_account
                        .entry(target)
                        .or_default()
                        .push(recipient.clone());
                }
                None => tracing::warn!(
                    domain = %domain,
                    "catch-all rule routes without a target account; treating it as no rule"
                ),
            },
            Some(_) => {
                // Anti-enumeration in action: accepted, then dropped.
                discarded += 1;
                tracing::info!(
                    recipient = %recipient,
                    domain = %domain,
                    "catch-all rule discards inbound mail for an unknown local part"
                );
            }
            None => tracing::info!(
                recipient = %recipient,
                "inbound recipient has no local account; dropping it"
            ),
        }
    }
    if per_account.is_empty() && discarded == 0 {
        return Ok(Reply::new(550, "5.1.1 no such mailbox here"));
    }

    let from = parsed
        .addresses("From")
        .into_iter()
        .next()
        .unwrap_or_else(|| envelope.mail_from.clone());
    let subject = parsed.header("Subject").unwrap_or_default().to_string();

    // The stored document is the received bytes with our trace header on top, so
    // the copy a user reads shows how it arrived.
    let received = received_header(hostname, envelope);
    let mut document = Vec::with_capacity(received.len() + raw.len());
    document.extend_from_slice(received.as_bytes());
    document.extend_from_slice(&raw);

    let mut stored_ids = Vec::new();
    for (account_id, recipients) in per_account {
        let message_id = store.reserve_message_id()?;
        let message_aad = format!("account:{account_id}:message:{message_id}");
        let content_key = pigeon_crypto::generate_content_key();
        let wrapped_key = master_key
            .wrap_content_key(&content_key, message_aad.as_bytes())
            .map_err(store::StoreError::from)?;
        let sealed_body =
            pigeon_crypto::seal_content(&content_key, &document, message_aad.as_bytes())
                .map_err(store::StoreError::from)?;

        store.insert_message(
            NewMessage {
                account_id,
                direction: Direction::In,
                from_addr: from.clone(),
                to_addrs: recipients.clone(),
                subject: subject.clone(),
                sealed_body,
                idempotency_key: None,
            },
            message_id,
        )?;

        // The wrapped content key lives in `api_messages` (the API's read path
        // opens bodies from there). Without this row the body would be
        // unrecoverable, so a failure here is a failure of the whole ingest.
        db.insert_email(&pigeon_api::db::NewEmail {
            account_id,
            message_id,
            public_id: pigeon_api::ids::derived(pigeon_api::ids::MSG, message_id),
            status: "received".to_string(),
            to_addrs: recipients.iter().map(ToString::to_string).collect(),
            cc_addrs: Vec::new(),
            tags: Vec::new(),
            sandbox: false,
            e2e: pigeon_api::models::E2E_PLACEHOLDER.to_string(),
            wrapped_key,
        })?;

        // Recorded on the row so a mailbox owner can tell "this arrived because I
        // own the address" from "this arrived because the domain routes unknown
        // addresses here".
        let via = if routed_via_catchall.contains(&account_id) {
            " via=catchall"
        } else {
            ""
        };
        store.record_event(
            message_id,
            "email.received",
            &format!(
                "from={from} helo={} peer={} auth=spf:none,dkim:none,dmarc:none{via}",
                envelope.helo, envelope.peer
            ),
        )?;
        stored_ids.push(message_id);
    }

    // v0.1 evaluates nothing: the verdicts are reported as `none` so an operator
    // reading logs can tell "not checked" from "checked and failed".
    tracing::info!(
        from = %from,
        subject = %subject,
        recipients = envelope.recipients.len(),
        accounts = stored_ids.len(),
        discarded,
        spf = "none",
        dkim = "none",
        dmarc = "none",
        "inbound message accepted (authentication not evaluated in v0.1)"
    );

    let reply = if stored_ids.is_empty() {
        // Only catch-all `discard` recipients: the message is accepted so the
        // sender cannot probe which addresses exist, and nothing is stored.
        Reply::new(250, "2.0.0 Ok: accepted")
    } else {
        Reply::new(
            250,
            format!(
                "2.0.0 Ok: queued as {}",
                stored_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        )
    };
    Ok(reply)
}

/// `Received:` trace header for one delivery.
fn received_header(hostname: &str, envelope: &Envelope) -> String {
    let id = hex::encode(&pigeon_crypto::generate_content_key()[..8]);
    format!(
        "Received: from {helo} ([{ip}]) by {hostname} with ESMTP id {id} for <{rcpt}>; {date}\r\n",
        helo = sanitize_helo(&envelope.helo),
        ip = envelope.peer.ip(),
        rcpt = envelope
            .recipients
            .first()
            .map(ToString::to_string)
            .unwrap_or_default(),
        date = rfc5322_date(now_unix()),
    )
}

/// A parsed inbound message: unfolded headers plus the raw body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedMessage {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ParsedMessage {
    /// First value of `name` (ASCII-case-insensitive), flattened to one line.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Addresses found in every occurrence of `name`, in header order.
    pub(crate) fn addresses(&self, name: &str) -> Vec<EmailAddress> {
        self.headers
            .iter()
            .filter(|(field, _)| field.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| addresses_in(value))
            .collect()
    }
}

/// Split a raw message into unfolded headers and body.
///
/// Minimal on purpose (no `mail-parser`): the body is kept as opaque bytes
/// because it is sealed and forwarded untouched, and only the header block is
/// interpreted.
pub(crate) fn parse_message(raw: &[u8]) -> ParsedMessage {
    let (header_bytes, body) = match find_header_end(raw) {
        Some((end, body_start)) => (&raw[..end], raw[body_start..].to_vec()),
        None => (raw, Vec::new()),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_bytes.split(|byte| *byte == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Folded continuation: RFC 5322 replaces the fold with one space.
            if let Some((_, value)) = headers.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    ParsedMessage { headers, body }
}

/// Locate the blank line that ends the header block.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some((position, position + 4));
    }
    raw.windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| (position, position + 2))
}

/// Extract every parseable address from a header value such as
/// `"Dana" <dana@example.com>, carol@example.org`.
pub(crate) fn addresses_in(value: &str) -> Vec<EmailAddress> {
    let mut out = Vec::new();
    for part in split_address_list(value) {
        let candidate = match (part.find('<'), part.rfind('>')) {
            (Some(open), Some(close)) if close > open => part[open + 1..close].trim(),
            _ => part.trim(),
        };
        let candidate = candidate.trim_matches('"');
        if candidate.is_empty() {
            continue;
        }
        if let Ok(address) = EmailAddress::parse(candidate) {
            out.push(address);
        }
    }
    out
}

/// Split on commas that are neither inside quotes nor inside `<...>`.
fn split_address_list(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut in_angle = false;
    for (index, character) in value.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angle = true,
            '>' if !in_quotes => in_angle = false,
            ',' if !in_quotes && !in_angle => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Collapse a client-supplied greeting to something safe for a reply line and a
/// header value: no control bytes, no folding, bounded length.
pub(crate) fn sanitize_helo(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|character| !character.is_control())
        .take(255)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Outcome of one [`read_limited_line`] call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LineEvent {
    Line(String),
    /// The line exceeded the limit; the remainder was drained.
    TooLong,
    Eof,
}

/// Read one CRLF-terminated line, bounded by `max_len` bytes.
///
/// The buffer never grows past the limit: an oversized line is discarded chunk
/// by chunk, so a client cannot force unbounded allocation by sending one huge
/// line.
pub(crate) async fn read_limited_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    max_len: usize,
    timeout: Duration,
) -> Result<LineEvent> {
    tokio::time::timeout(timeout, async {
        let mut line = Vec::with_capacity(64);
        let mut too_long = false;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(if line.is_empty() && !too_long {
                    LineEvent::Eof
                } else if too_long {
                    LineEvent::TooLong
                } else {
                    // Last line without a terminator: still a line.
                    LineEvent::Line(String::from_utf8_lossy(&line).into_owned())
                });
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(position) => {
                    if line.len() + position + 1 > max_len {
                        too_long = true;
                    } else {
                        line.extend_from_slice(&available[..=position]);
                    }
                    reader.consume(position + 1);
                    if too_long {
                        return Ok(LineEvent::TooLong);
                    }
                    let text = String::from_utf8_lossy(&line);
                    return Ok(LineEvent::Line(
                        text.trim_end_matches(['\r', '\n']).to_string(),
                    ));
                }
                None => {
                    if line.len() + available.len() > max_len {
                        too_long = true;
                    } else {
                        line.extend_from_slice(available);
                    }
                    let consumed = available.len();
                    reader.consume(consumed);
                }
            }
        }
    })
    .await
    .map_err(|_| SmtpError::Timeout("no command within the timeout".to_string()))?
}

/// Accumulated `DATA` payload.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DataPayload {
    pub bytes: Vec<u8>,
    pub oversized: bool,
    pub line_too_long: bool,
}

/// Outcome of [`read_data`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DataEvent {
    /// The terminating `.` line arrived.
    Complete(DataPayload),
    /// The connection ended (EOF or timeout) before the terminator.
    Closed,
}

/// Read message data until `<CRLF>.<CRLF>`, dot-unstuffing as it goes.
///
/// Over-limit data is not a reason to hang up: the whole payload is drained so
/// the next command is read from the right place, and the caller then replies
/// `552`/`500` per the flag that was set.
pub(crate) async fn read_data(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    config: &ServerConfig,
    timeout: Duration,
) -> Result<DataEvent> {
    let mut payload = DataPayload::default();
    loop {
        let event = match read_limited_line(reader, config.max_line_len, timeout).await {
            Ok(event) => event,
            // A timeout mid-DATA ends the session: there is no state to resume.
            Err(_) => return Ok(DataEvent::Closed),
        };
        match event {
            LineEvent::Eof => return Ok(DataEvent::Closed),
            LineEvent::TooLong => {
                payload.line_too_long = true;
                // Discarded, but the message continues: the terminator decides
                // when the data phase ends.
                continue;
            }
            LineEvent::Line(line) => {
                if line == "." {
                    return Ok(DataEvent::Complete(payload));
                }
                accumulate(&mut payload, &line, config.max_message_size);
            }
        }
    }
}

/// Append one data line to `payload`, dot-unstuffing and enforcing the size cap.
///
/// Split out from [`read_data`] so the two rules that are easy to get wrong —
/// remove exactly one leading dot, stop growing past the limit — are testable
/// without a socket.
pub(crate) fn accumulate(payload: &mut DataPayload, line: &str, max_message_size: usize) {
    // Dot-stuffing: a line starting with `.` had one added by the client, so
    // remove exactly one. Two dots in the payload stay two dots.
    let content = line.strip_prefix('.').unwrap_or(line);
    if payload.oversized {
        return;
    }
    if payload.bytes.len() + content.len() + 2 > max_message_size {
        payload.oversized = true;
        // Drop what was buffered: an over-limit message is never stored, so
        // keeping megabytes around until the terminator only wastes memory.
        payload.bytes.clear();
        return;
    }
    payload.bytes.extend_from_slice(content.as_bytes());
    payload.bytes.extend_from_slice(b"\r\n");
}

/// Write one encoded reply; `false` means the peer is gone.
async fn write(stream: &mut tokio::net::tcp::OwnedWriteHalf, reply: &Reply) -> bool {
    match stream.write_all(reply.encode().as_bytes()).await {
        Ok(()) => stream.flush().await.is_ok(),
        Err(error) => {
            tracing::debug!(%error, "inbound smtp write failed");
            false
        }
    }
}

/// Parse `PIGEON_SMTP_IN_ADDR`, accepting the documented `:2525` shorthand.
pub fn parse_listen_addr(raw: &str) -> Result<SocketAddr> {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err(SmtpError::Config(
            "PIGEON_SMTP_IN_ADDR is empty".to_string(),
        ));
    }
    let candidate = if candidate.starts_with(':') {
        format!("0.0.0.0{candidate}")
    } else {
        candidate.to_string()
    };
    candidate.parse::<SocketAddr>().map_err(|error| {
        SmtpError::Config(format!(
            "PIGEON_SMTP_IN_ADDR {raw:?} is not a socket address: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        let mut session = Session::new(
            Arc::new(ServerConfig::default()),
            "127.0.0.1:1234".parse().expect("peer"),
        );
        session.handle_line("EHLO client.example");
        session
    }

    fn reply_text(action: &Action) -> String {
        match action {
            Action::Reply(reply) | Action::Close(reply) => reply.encode(),
            Action::StartData => "354 start".to_string(),
        }
    }

    fn code(action: &Action) -> u16 {
        match action {
            Action::Reply(reply) | Action::Close(reply) => reply.code,
            Action::StartData => 354,
        }
    }

    #[test]
    fn banner_is_220_with_the_hostname() {
        let session = Session::new(
            Arc::new(ServerConfig::default()),
            "127.0.0.1:1".parse().expect("peer"),
        );
        assert_eq!(session.banner().code, 220);
        assert!(session.banner().encode().starts_with("220 "));
        assert!(session.banner().encode().contains("ESMTP"));
    }

    #[test]
    fn ehlo_advertises_size_8bitmime_starttls_and_enhanced_codes() {
        let mut session = Session::new(
            Arc::new(ServerConfig::default()),
            "127.0.0.1:1".parse().expect("peer"),
        );
        let action = session.handle_line("EHLO client.example");
        let text = reply_text(&action);
        assert_eq!(code(&action), 250);
        assert!(text.starts_with("250-pigeon.local Hello client.example\r\n"));
        assert!(text.contains("250-SIZE 36700160\r\n"), "{text}");
        assert!(text.contains("250-8BITMIME\r\n"));
        assert!(text.contains("250-STARTTLS\r\n"));
        assert!(text.contains("250 ENHANCEDSTATUSCODES\r\n"), "{text}");
    }

    #[test]
    fn helo_is_answered_by_a_single_line() {
        let mut session = Session::new(
            Arc::new(ServerConfig::default()),
            "127.0.0.1:1".parse().expect("peer"),
        );
        let action = session.handle_line("HELO client.example");
        let text = reply_text(&action);
        assert_eq!(code(&action), 250);
        assert_eq!(text.matches("\r\n").count(), 1, "{text}");
    }

    #[test]
    fn starttls_is_advertised_but_answers_454() {
        let mut session = session();
        let action = session.handle_line("STARTTLS");
        assert_eq!(code(&action), 454);
        assert!(reply_text(&action).contains("4.7.0 TLS not available"));
    }

    #[test]
    fn full_transaction_reaches_data_and_quit() {
        let mut session = session();
        assert_eq!(
            code(&session.handle_line("MAIL FROM:<dana@example.org>")),
            250
        );
        assert_eq!(
            code(&session.handle_line("RCPT TO:<carol@example.com>")),
            250
        );
        assert_eq!(
            session.handle_line("DATA"),
            Action::StartData,
            "DATA starts the data phase"
        );
        let action = session.handle_line("QUIT");
        assert_eq!(code(&action), 221);
        assert!(matches!(action, Action::Close(_)));
    }

    #[test]
    fn commands_before_a_greeting_are_refused_with_503() {
        let mut session = Session::new(
            Arc::new(ServerConfig::default()),
            "127.0.0.1:1".parse().expect("peer"),
        );
        assert_eq!(code(&session.handle_line("MAIL FROM:<a@example.org>")), 503);
        assert_eq!(code(&session.handle_line("RCPT TO:<b@example.com>")), 503);
        assert_eq!(code(&session.handle_line("DATA")), 503);
    }

    #[test]
    fn rcpt_without_mail_and_data_without_rcpt_are_sequence_errors() {
        let mut session = session();
        assert_eq!(
            code(&session.handle_line("RCPT TO:<carol@example.com>")),
            503
        );
        assert_eq!(
            code(&session.handle_line("MAIL FROM:<dana@example.org>")),
            250
        );
        assert_eq!(code(&session.handle_line("DATA")), 503);
    }

    #[test]
    fn nested_mail_is_a_sequence_error() {
        let mut session = session();
        assert_eq!(code(&session.handle_line("MAIL FROM:<a@example.org>")), 250);
        assert_eq!(code(&session.handle_line("MAIL FROM:<b@example.org>")), 503);
    }

    #[test]
    fn recipient_limit_is_enforced_with_452() {
        let mut session = session();
        session.config = Arc::new(ServerConfig {
            max_recipients: 2,
            ..ServerConfig::default()
        });
        assert_eq!(
            code(&session.handle_line("MAIL FROM:<dana@example.org>")),
            250
        );
        assert_eq!(code(&session.handle_line("RCPT TO:<a@example.com>")), 250);
        assert_eq!(code(&session.handle_line("RCPT TO:<b@example.com>")), 250);
        let action = session.handle_line("RCPT TO:<c@example.com>");
        assert_eq!(code(&action), 452);
        assert!(reply_text(&action).contains("too many recipients"));
    }

    #[test]
    fn declared_oversize_message_is_refused_with_552() {
        let mut session = session();
        let action = session.handle_line("MAIL FROM:<dana@example.org> SIZE=999999999");
        assert_eq!(code(&action), 552);
        assert!(session.mail_from.is_none(), "the envelope must not open");
    }

    #[test]
    fn unknown_command_is_500_and_unimplemented_is_502() {
        let mut session = session();
        assert_eq!(code(&session.handle_line("FROBNICATE")), 500);
        assert_eq!(code(&session.handle_line("VRFY carol")), 502);
        assert_eq!(code(&session.handle_line("AUTH PLAIN x")), 502);
    }

    #[test]
    fn command_budget_closes_the_session_with_421() {
        let mut session = Session::new(
            Arc::new(ServerConfig {
                max_commands: 2,
                ..ServerConfig::default()
            }),
            "127.0.0.1:1".parse().expect("peer"),
        );
        assert_eq!(code(&session.handle_line("NOOP")), 250);
        assert_eq!(code(&session.handle_line("NOOP")), 250);
        let action = session.handle_line("NOOP");
        assert_eq!(code(&action), 421);
        assert!(matches!(action, Action::Close(_)));
    }

    #[test]
    fn rset_and_ehlo_clear_the_envelope() {
        let mut session = session();
        session.handle_line("MAIL FROM:<dana@example.org>");
        session.handle_line("RCPT TO:<carol@example.com>");
        assert_eq!(code(&session.handle_line("RSET")), 250);
        assert!(session.mail_from.is_none());
        assert!(session.recipients.is_empty());
        assert_eq!(code(&session.handle_line("DATA")), 503);
    }

    #[test]
    fn mail_from_parses_size_and_allows_spaces_around_the_path() {
        let parsed =
            parse_mail_from("FROM: <Dana@Example.org> SIZE=1024 BODY=8BITMIME").expect("parses");
        assert_eq!(parsed.sender.to_string(), "Dana@example.org");
        assert_eq!(parsed.size, Some(1024));

        let plain = parse_mail_from("from:<a@b.co>").expect("case-insensitive keyword");
        assert_eq!(plain.sender.to_string(), "a@b.co");
        assert_eq!(plain.size, None);
    }

    #[test]
    fn mail_from_rejects_the_shapes_a_client_must_not_send() {
        for argument in [
            "TO:<a@b.co>",
            "FROM:a@b.co",
            "FROM:<a@b.co",
            "FROM:<>",
            "FROM:<not-an-address>",
            "FROM:<a@b.co> SIZE=lots",
        ] {
            let error = parse_mail_from(argument).expect_err(argument);
            assert!(error.starts_with('5'), "{argument} -> {error}");
        }
    }

    #[test]
    fn rcpt_to_parses_the_path_and_ignores_notify_parameters() {
        let parsed = parse_rcpt_to("TO:<Carol@Example.com> NOTIFY=SUCCESS").expect("parses");
        assert_eq!(parsed.to_string(), "Carol@example.com");
        assert!(parse_rcpt_to("TO:<>").is_err());
        assert!(parse_rcpt_to("TO:<nonsense>").is_err());
    }

    #[test]
    fn multi_line_replies_use_hyphens_until_the_last_line() {
        let reply = Reply::multiline(250, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(reply.encode(), "250-one\r\n250 two\r\n");
    }

    #[test]
    fn parse_message_splits_headers_and_keeps_the_body_verbatim() {
        let raw = b"From: Dana <dana@example.org>\r\nTo: carol@example.com\r\nSubject: hi\r\n\tfolded\r\n\r\nbody line\r\n";
        let parsed = parse_message(raw);
        assert_eq!(parsed.header("subject"), Some("hi folded"));
        assert_eq!(parsed.body, b"body line\r\n");
        assert_eq!(
            parsed.addresses("from"),
            vec![EmailAddress::parse("dana@example.org").expect("address")]
        );
    }

    #[test]
    fn parse_message_tolerates_missing_headers_and_bare_lf() {
        // No blank line at all: RFC 5322 says the header block runs to the end,
        // so there is no body to interpret (and the raw bytes are still stored).
        let parsed = parse_message(b"just a body\nwith lines\n");
        assert!(
            parsed.headers.is_empty(),
            "a line without ':' is not a header"
        );
        assert!(parsed.body.is_empty());

        // Bare-LF separators are accepted: some relays rewrite CRLF.
        let lf_only = parse_message(b"Subject: bare\n\nbody");
        assert_eq!(lf_only.header("Subject"), Some("bare"));
        assert_eq!(lf_only.body, b"body");
    }

    #[test]
    fn addresses_in_handles_display_names_lists_and_quoted_commas() {
        let addresses = addresses_in("\"Doe, Dana\" <dana@example.org>, carol@example.com");
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].to_string(), "dana@example.org");
        assert_eq!(addresses[1].to_string(), "carol@example.com");

        assert!(addresses_in("not an address").is_empty());
        assert_eq!(addresses_in("").len(), 0);
    }

    #[test]
    fn helo_sanitizer_strips_control_bytes_and_bounds_length() {
        assert_eq!(sanitize_helo("host\r\nDATA"), "hostDATA");
        assert_eq!(sanitize_helo("   "), "unknown");
        assert_eq!(sanitize_helo(&"a".repeat(400)).len(), 255);
    }

    #[test]
    fn listen_addr_accepts_the_documented_shorthand() {
        assert_eq!(
            parse_listen_addr(":2525").expect("shorthand").to_string(),
            "0.0.0.0:2525"
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:2525")
                .expect("explicit")
                .to_string(),
            "127.0.0.1:2525"
        );
        assert!(parse_listen_addr("").is_err());
        assert!(parse_listen_addr("nonsense").is_err());
    }

    #[test]
    fn data_lines_are_dot_unstuffed_and_crlf_terminated() {
        let mut payload = DataPayload::default();
        accumulate(&mut payload, "..leading dot", usize::MAX);
        accumulate(&mut payload, "plain line", usize::MAX);
        accumulate(&mut payload, "..two dots survive as one", usize::MAX);
        assert_eq!(
            String::from_utf8(payload.bytes).expect("utf8"),
            ".leading dot\r\nplain line\r\n.two dots survive as one\r\n",
            "exactly one dot is removed from a stuffed line"
        );
        assert!(!payload.oversized);
    }

    #[test]
    fn data_accumulation_stops_at_the_size_limit() {
        let mut payload = DataPayload::default();
        accumulate(&mut payload, &"x".repeat(100), 50);
        assert!(payload.oversized);
        assert!(payload.bytes.is_empty(), "buffered bytes are dropped");
        // Further lines are ignored instead of growing the buffer.
        accumulate(&mut payload, &"y".repeat(100), 50);
        assert!(payload.bytes.is_empty());
    }

    #[test]
    fn received_header_names_the_peer_and_hostname() {
        let envelope = Envelope {
            peer: "203.0.113.7:4444".parse().expect("peer"),
            helo: "sender.example".to_string(),
            mail_from: EmailAddress::parse("dana@example.org").expect("address"),
            recipients: vec![EmailAddress::parse("carol@example.com").expect("address")],
        };
        let header = received_header("pigeon.local", &envelope);
        assert!(
            header.starts_with(
                "Received: from sender.example ([203.0.113.7]) by pigeon.local with ESMTP id "
            ),
            "{header}"
        );
        assert!(header.contains("for <carol@example.com>;"), "{header}");
        assert!(header.ends_with("\r\n"));
    }
}
