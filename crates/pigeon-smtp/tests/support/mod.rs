//! Shared helpers for the `pigeon-smtp` integration tests.
//!
//! Not a test binary: only files directly under `tests/` become test targets, so
//! this module is compiled once per test that declares `mod support;`.
//!
//! Everything here goes through the **public** API of the crates it touches —
//! `store`, `pigeon-api` and `pigeon-smtp` — so the tests exercise the same code
//! paths a deployment does.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use pigeon_api::db::{ApiDb, NewEmail};
use pigeon_api::ids;
use pigeon_core::{Direction, EmailAddress};
use pigeon_crypto::{generate_content_key, seal_content, MasterKey};
use pigeon_smtp::InboundSmtpServer;
use store::{NewMessage, SqliteStorage, Storage};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// A temporary database plus the two handles the SMTP engine needs.
pub struct TestEnv {
    /// Kept alive so the database file outlives the test body.
    _dir: tempfile::TempDir,
    /// Same file as the two handles above, for assertions `Storage` cannot make.
    pub db_path: std::path::PathBuf,
    pub store: Arc<SqliteStorage>,
    pub db: Arc<ApiDb>,
    pub master_key: Arc<MasterKey>,
}

impl TestEnv {
    /// Fresh database, fresh master key.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let store = SqliteStorage::open(&path).expect("store opens");
        let db = ApiDb::open(&path).expect("api db opens");
        let master_key = MasterKey::parse(&[7u8; 32]).expect("master key");
        Self {
            _dir: dir,
            db_path: path,
            store: Arc::new(store),
            db: Arc::new(db),
            master_key: Arc::new(master_key),
        }
    }

    /// Create an account and return its id.
    pub fn account(&self, email: &str) -> i64 {
        let address = EmailAddress::parse(email).expect("address");
        self.store.create_account(&address).expect("account")
    }

    /// Seal one outbound message exactly as `POST /v1/emails` does, queue it, and
    /// return `(message_id, public_id)`.
    pub fn queue_outbound(
        &self,
        account_id: i64,
        from: &str,
        to: &[&str],
        subject: &str,
        body: &str,
    ) -> (i64, String) {
        let from = EmailAddress::parse(from).expect("from");
        let to_addrs: Vec<EmailAddress> = to
            .iter()
            .map(|address| EmailAddress::parse(address).expect("to"))
            .collect();
        let message_id = self.store.reserve_message_id().expect("reserve id");
        let aad = format!("account:{account_id}:message:{message_id}");
        let content_key = generate_content_key();
        let wrapped_key = self
            .master_key
            .wrap_content_key(&content_key, aad.as_bytes())
            .expect("wrap key");
        let mime = format!(
            "From: {from}\r\nTo: {}\r\nSubject: {subject}\r\nDate: Fri, 06 Nov 2026 00:00:00 +0000\r\nMessage-ID: <eml_{message_id}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
            to_addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let sealed_body =
            seal_content(&content_key, mime.as_bytes(), aad.as_bytes()).expect("seal body");
        self.store
            .insert_message(
                NewMessage {
                    account_id,
                    direction: Direction::Out,
                    from_addr: from,
                    to_addrs: to_addrs.clone(),
                    subject: subject.to_string(),
                    sealed_body,
                    idempotency_key: None,
                    delivered_for: None,
                },
                message_id,
            )
            .expect("insert message");
        let public_id = ids::gen(ids::EML);
        self.db
            .insert_email(&NewEmail {
                account_id,
                message_id,
                public_id: public_id.clone(),
                status: "queued".to_string(),
                to_addrs: to_addrs.iter().map(ToString::to_string).collect(),
                cc_addrs: Vec::new(),
                tags: Vec::new(),
                sandbox: false,
                e2e: "tls_only".to_string(),
                wrapped_key,
            })
            .expect("insert email row");
        self.store
            .queue_enqueue(message_id, 0)
            .expect("queue message");
        (message_id, public_id)
    }

    /// Number of queue rows for `message_id`, read straight from SQLite.
    ///
    /// `Storage` deliberately exposes no "count the queue rows" call, so the
    /// tests that must prove a job was **settled** (rather than merely left
    /// unclaimable behind its lease) read the table directly.
    pub fn queue_rows_for(&self, message_id: i64) -> i64 {
        let conn = rusqlite::Connection::open(&self.db_path).expect("open db");
        conn.query_row(
            "SELECT COUNT(*) FROM queue WHERE message_id = ?1",
            [message_id],
            |row| row.get(0),
        )
        .expect("count queue rows")
    }

    /// Re-arm a requeued job so the next `drain` picks it up now.
    ///
    /// `queue_fail` applies the real backoff (30 s for a first failure), which is
    /// correct in production and untestable in a unit test. This is the same
    /// "time has passed" step, written straight to the row.
    pub fn make_queue_due(&self, message_id: i64) {
        let conn = rusqlite::Connection::open(&self.db_path).expect("open db");
        conn.execute(
            "UPDATE queue SET run_after = 0, claimed_at = NULL, claim_token = NULL
              WHERE message_id = ?1",
            [message_id],
        )
        .expect("make the job due");
    }

    /// `run_after` of the one queue row for `message_id`, if it still exists.
    pub fn queue_run_after(&self, message_id: i64) -> Option<i64> {
        let conn = rusqlite::Connection::open(&self.db_path).expect("open db");
        conn.query_row(
            "SELECT run_after FROM queue WHERE message_id = ?1",
            [message_id],
            |row| row.get(0),
        )
        .ok()
    }

    /// Open a sealed message body as text, through the same AAD the engine uses.
    pub fn open_body(&self, account_id: i64, message_id: i64) -> String {
        let row = self.store.get_message(message_id).expect("message row");
        let public_id = self
            .db
            .public_id_for_message(message_id)
            .expect("public id")
            .expect("public id present");
        let stored = self
            .db
            .message_by_public_id(account_id, &public_id)
            .expect("stored message")
            .expect("stored message present");
        let wrapped = stored.wrapped_key.expect("wrapped content key");
        let aad = format!("account:{account_id}:message:{message_id}");
        let content_key = self
            .master_key
            .unwrap_content_key(&wrapped, aad.as_bytes())
            .expect("unwrap");
        let plaintext = pigeon_crypto::open_content(&content_key, &row.sealed_body, aad.as_bytes())
            .expect("open body");
        String::from_utf8(plaintext).expect("body is utf-8")
    }
}

/// Start an inbound server on an ephemeral port; returns its address and the
/// shutdown trigger.
pub async fn start_inbound(server: Arc<InboundSmtpServer>) -> (SocketAddr, oneshot::Sender<()>) {
    let (listener, address) = server.bind("127.0.0.1:0").await.expect("binds");
    let (stop, stopped) = oneshot::channel();
    tokio::spawn(async move {
        server
            .serve_with_shutdown(listener, async {
                let _ = stopped.await;
            })
            .await;
    });
    (address, stop)
}

/// A minimal raw SMTP client: enough to drive the state machine from a test
/// without depending on the code under test.
pub struct RawClient {
    stream: TcpStream,
    buffer: Vec<u8>,
}

/// One parsed reply: `(code, text)`.
pub type ReplyLine = (u16, String);

impl RawClient {
    /// Connect and discard nothing: the caller reads the banner.
    pub async fn connect(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect");
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Read one complete reply, including multi-line replies.
    pub async fn read_reply(&mut self) -> ReplyLine {
        let mut lines: Vec<String> = Vec::new();
        loop {
            let line = self.read_line().await;
            let code = line
                .get(..3)
                .and_then(|prefix| prefix.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("reply line without a code: {line:?}"));
            let last = line.len() == 3 || line.as_bytes().get(3) == Some(&b' ');
            lines.push(line.get(4..).unwrap_or_default().to_string());
            if last {
                return (code, lines.join(" | "));
            }
        }
    }

    async fn read_line(&mut self) -> String {
        loop {
            if let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = String::from_utf8_lossy(&self.buffer[..position]).into_owned();
                self.buffer.drain(..=position);
                return line.trim_end_matches('\r').to_string();
            }
            let mut chunk = [0u8; 1024];
            let read = self.stream.read(&mut chunk).await.expect("read");
            assert_ne!(read, 0, "peer closed the connection unexpectedly");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Send one command line and read its reply.
    pub async fn send(&mut self, line: &str) -> ReplyLine {
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("write");
        self.stream.flush().await.expect("flush");
        self.read_reply().await
    }

    /// Send raw bytes with no line ending added.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
        self.stream.flush().await.expect("flush");
    }

    /// Run `EHLO` and return the capability lines.
    pub async fn ehlo(&mut self, name: &str) -> ReplyLine {
        self.send(&format!("EHLO {name}")).await
    }

    /// Complete the `DATA` phase: send `payload` then the terminator.
    pub async fn data(&mut self, payload: &str) -> ReplyLine {
        self.send_raw(format!("{payload}\r\n.\r\n").as_bytes())
            .await;
        self.read_reply().await
    }

    /// True when the peer closed the connection.
    pub async fn at_eof(&mut self) -> bool {
        let mut chunk = [0u8; 256];
        match self.stream.read(&mut chunk).await {
            Ok(read) => read == 0,
            Err(_) => true,
        }
    }
}

/// One SMTP transaction a [`FakeMx`] received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// Envelope sender, exactly as announced in `MAIL FROM:<...>`.
    pub mail_from: String,
    /// Envelope recipients, in the order the `RCPT TO` commands arrived.
    pub recipients: Vec<String>,
    /// The message data, as text.
    pub payload: String,
}

/// A fake MX host: speaks just enough ESMTP to accept one message per
/// connection and remembers what it received.
pub struct FakeMx {
    pub address: SocketAddr,
    pub received: Arc<Mutex<Vec<ReceivedMessage>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl FakeMx {
    /// Start a fake MX that accepts every recipient.
    ///
    /// `offer_starttls` controls whether the `EHLO` reply advertises the
    /// capability (the handler answers `454` when it does, so a `required` client
    /// fails exactly as it would against a broken peer).
    pub async fn start(offer_starttls: bool) -> Self {
        Self::start_with(offer_starttls, None).await
    }

    /// Start a fake MX that permanently rejects every recipient with `550`, so
    /// the worker's hard-bounce path runs.
    pub async fn start_rejecting_recipients(offer_starttls: bool) -> Self {
        Self::start_with(
            offer_starttls,
            Some("550 5.1.1 no such user here".to_string()),
        )
        .await
    }

    /// Start a fake MX that **temporarily** fails its first `failures` transactions
    /// (`451` after `DATA`) and accepts everything afterwards.
    ///
    /// This is the "one domain deferred, the other accepted" shape a retry has to
    /// survive without sending a duplicate copy.
    pub async fn start_deferring(failures: usize, offer_starttls: bool) -> Self {
        Self::start_full(offer_starttls, None, failures).await
    }

    async fn start_with(offer_starttls: bool, rcpt_reply: Option<String>) -> Self {
        Self::start_full(offer_starttls, rcpt_reply, 0).await
    }

    async fn start_full(
        offer_starttls: bool,
        rcpt_reply: Option<String>,
        defer_first: usize,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake mx");
        let address = listener.local_addr().expect("fake mx address");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        // A mutex rather than an atomic counter: the decrement is a
        // read-modify-write (`fetch_update` is newer than this crate's MSRV), and
        // one short critical section per connection costs nothing.
        let pending_failures = Arc::new(Mutex::new(defer_first));
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let sink = Arc::clone(&sink);
                let rcpt_reply = rcpt_reply.clone();
                let pending = Arc::clone(&pending_failures);
                tokio::spawn(async move {
                    // Each connection consumes one programmed failure.
                    let defer_this = {
                        let mut left = pending.lock().expect("lock");
                        if *left > 0 {
                            *left -= 1;
                            true
                        } else {
                            false
                        }
                    };
                    handle_fake_session(stream, sink, offer_starttls, rcpt_reply, defer_this).await;
                });
            }
        });
        Self {
            address,
            received,
            handle,
        }
    }

    /// Everything the fake MX has received so far, joined.
    pub fn delivered(&self) -> String {
        self.received
            .lock()
            .expect("lock")
            .iter()
            .map(|message| message.payload.as_str())
            .collect::<Vec<_>>()
            .join("\n---\n")
    }

    /// Number of messages accepted.
    pub fn count(&self) -> usize {
        self.received.lock().expect("lock").len()
    }

    /// The envelope recipients of every accepted transaction, in arrival order.
    pub fn recipient_sets(&self) -> Vec<Vec<String>> {
        self.received
            .lock()
            .expect("lock")
            .iter()
            .map(|message| message.recipients.clone())
            .collect()
    }

    /// The envelope senders of every accepted transaction.
    pub fn senders(&self) -> Vec<String> {
        self.received
            .lock()
            .expect("lock")
            .iter()
            .map(|message| message.mail_from.clone())
            .collect()
    }
}

impl Drop for FakeMx {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn handle_fake_session(
    stream: TcpStream,
    sink: Arc<Mutex<Vec<ReceivedMessage>>>,
    offer_starttls: bool,
    rcpt_reply: Option<String>,
    defer_data: bool,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let banner = "220 fake-mx.test ESMTP\r\n";
    if write_half.write_all(banner.as_bytes()).await.is_err() {
        return;
    }

    // Envelope state, captured from the commands so a test can assert *who* was
    // talking to this exchanger, not only what bytes arrived.
    let mut mail_from = String::new();
    let mut recipients: Vec<String> = Vec::new();

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let command = line.trim_end().to_string();
        let verb = command
            .split_once(' ')
            .map(|(verb, _)| verb)
            .unwrap_or(command.as_str())
            .to_ascii_uppercase();
        let response: String = match verb.as_str() {
            "EHLO" => {
                let mut response =
                    String::from("250-fake-mx.test greets you\r\n250-SIZE 104857600\r\n");
                if offer_starttls {
                    response.push_str("250-STARTTLS\r\n");
                }
                response.push_str("250 8BITMIME\r\n");
                response
            }
            "MAIL" => {
                mail_from = command
                    .split_once(':')
                    .map(|(_, rest)| rest.trim().trim_matches(['<', '>']).to_string())
                    .unwrap_or_default();
                "250 2.0.0 Ok\r\n".to_string()
            }
            "RCPT" => match &rcpt_reply {
                Some(reply) => format!("{reply}\r\n"),
                None => {
                    let recipient = command
                        .split_once(':')
                        .map(|(_, rest)| rest.trim().trim_matches(['<', '>']).to_string())
                        .unwrap_or_default();
                    recipients.push(recipient);
                    "250 2.0.0 Ok\r\n".to_string()
                }
            },
            "HELO" | "NOOP" => "250 2.0.0 Ok\r\n".to_string(),
            "STARTTLS" => "454 4.7.0 TLS not available here\r\n".to_string(),
            "DATA" if defer_data => {
                // A temporary failure at the end of the transaction: the peer is
                // expected to retry later, not to bounce.
                "451 4.3.2 try again later\r\n".to_string()
            }
            "DATA" => {
                if write_half.write_all(b"354 go ahead\r\n").await.is_err() {
                    return;
                }
                let mut payload = String::new();
                loop {
                    let mut data_line = String::new();
                    match reader.read_line(&mut data_line).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    if data_line == ".\r\n" || data_line == ".\n" {
                        break;
                    }
                    payload.push_str(&data_line);
                }
                sink.lock().expect("lock").push(ReceivedMessage {
                    mail_from: mail_from.clone(),
                    recipients: recipients.clone(),
                    payload,
                });
                "250 2.0.0 Ok: queued as fake\r\n".to_string()
            }
            "QUIT" => {
                let _ = write_half.write_all(b"221 2.0.0 Bye\r\n").await;
                return;
            }
            _ => "500 5.5.2 unrecognized\r\n".to_string(),
        };
        if write_half.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}
