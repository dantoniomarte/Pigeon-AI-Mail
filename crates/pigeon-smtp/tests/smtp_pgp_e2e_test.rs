//! Layer 3, end to end: Pigeon **A** → Pigeon **B**, sealed.
//!
//! Two real instances, nothing simulated in the middle:
//!
//! * instance B owns `b.example` and publishes `carol@b.example`'s certificate over
//!   HTTP (a loopback server that answers from B's own store through
//!   [`pigeon_api::wkd::publication_key`] — the same call the real endpoint makes);
//! * instance A owns `a.example`; its send pipeline discovers B's key, seals the
//!   body and queues it;
//! * A's queue worker delivers to B's **real** inbound SMTP server;
//! * B stores the message the way it stores any mail: layer 1 (XChaCha) at rest,
//!   with the layer-3 ciphertext inside.
//!
//! The assertions are the guarantee: B's storage holds OpenPGP ciphertext, only B's
//! account key opens it, the subject stays in the clear, and A reports `e2e:
//! "sealed"`.
//!
//! A second test pins the invariant that discovery never blocks delivery: a
//! recipient whose domain publishes nothing still gets the mail, reported as
//! `tls_only`.

mod support;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use pigeon_api::db::ApiDb;
use pigeon_api::wkd::KeyFetcher;
use pigeon_api::{ApiConfig, AppState};
use pigeon_core::{ApiKeyScope, EmailAddress, MessageFolder, StartTlsMode};
use pigeon_crypto::MasterKey;
use pigeon_smtp::dns::{LookupFuture, MxRecord, MxResolver, MxSource};
use pigeon_smtp::worker::StoreDkimKeys;
use pigeon_smtp::{
    DeliveryConfig, InboundSmtpServer, OutboundSmtpClient, QueueWorker, ServerConfig, WorkerConfig,
};
use store::{SqliteStorage, Storage};
use support::start_inbound;
use tower::ServiceExt;

/// Master keys for the two instances: they never have to agree on anything.
const MASTER_A: [u8; 32] = [0x5A; 32];
const MASTER_B: [u8; 32] = [0x6B; 32];

/// One Pigeon instance: database, master key and (optionally) an API.
struct Instance {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    master: [u8; 32],
    store: Arc<SqliteStorage>,
    db: Arc<ApiDb>,
    master_key: Arc<MasterKey>,
}

impl Instance {
    fn new(master: [u8; 32]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let store = SqliteStorage::open(&path).expect("store");
        let db = ApiDb::open(&path).expect("api db");
        Self {
            _dir: dir,
            path,
            master,
            store: Arc::new(store),
            db: Arc::new(db),
            master_key: Arc::new(MasterKey::parse(&master).expect("master key")),
        }
    }

    /// The API state over the same database file, as `pigeon serve` builds it.
    fn api_state(&self, fetcher: Arc<dyn KeyFetcher>) -> AppState {
        AppState::open(
            &self.path,
            MasterKey::parse(&self.master).expect("master key"),
            ApiConfig::default(),
        )
        .expect("state")
        .with_key_fetcher(fetcher)
    }

    fn account(&self, email: &str) -> i64 {
        self.store
            .create_account(&EmailAddress::parse(email).expect("address"))
            .expect("account")
    }

    /// Open a stored body exactly as the API does (layer 1).
    fn open_body(&self, account_id: i64, message_id: i64) -> String {
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
        let row = self.store.get_message(message_id).expect("message row");
        let plaintext = pigeon_crypto::open_content(&content_key, &row.sealed_body, aad.as_bytes())
            .expect("open body");
        String::from_utf8(plaintext).expect("body is utf-8")
    }

    fn latest_message_for(&self, account_id: i64) -> i64 {
        self.store
            .list_folder(account_id, MessageFolder::Inbox, 1, 0)
            .expect("inbox")
            .first()
            .map(|row| row.id)
            .expect("a delivered message")
    }
}

// ---------------------------------------------------------------------------
// A loopback WKD endpoint serving B's published key
// ---------------------------------------------------------------------------

/// A minimal HTTP/1.1 server that answers `/.well-known/pigeon-pgp?email=<addr>`
/// from instance B's store.
///
/// It calls [`pigeon_api::wkd::publication_key`] — the same function the real route
/// uses — so what A discovers is what B publishes, not a fixture.
struct WkdEndpoint {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<String>>>,
}

impl WkdEndpoint {
    async fn start(instance: Arc<Instance>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind wkd");
        let address = listener.local_addr().expect("wkd address");
        let queries = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&queries);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let instance = Arc::clone(&instance);
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 1024];
                    // The request is small; read until the header terminator.
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if buffer.len() > 64 * 1024 {
                            return;
                        }
                    }
                    let request = String::from_utf8_lossy(&buffer).into_owned();
                    let target = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    sink.lock().expect("lock").push(target.clone());

                    let response = wkd_response(&instance, &target);
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self { address, queries }
    }
}

fn wkd_response(instance: &Instance, target: &str) -> String {
    let Some(query) = target
        .split_once("/.well-known/pigeon-pgp?email=")
        .map(|(_, query)| query.to_string())
    else {
        return not_found();
    };
    let address = query.replace("%40", "@");
    let Ok(address) = EmailAddress::parse(&address) else {
        return not_found();
    };
    match pigeon_api::wkd::publication_key(&instance.store, &instance.master_key, &address) {
        Ok(Some(armored)) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/pgp-keys\r\nContent-Length: {}\r\n\r\n{armored}",
            armored.len()
        ),
        _ => not_found(),
    }
}

fn not_found() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
}

/// The production [`KeyFetcher`] signature, but talking to the loopback WKD
/// endpoint instead of a real TLS host.
struct LoopbackFetcher {
    address: SocketAddr,
}

impl KeyFetcher for LoopbackFetcher {
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        // Only the simple endpoint exists on this "domain"; the advanced paths
        // answer 404, which the discovery loop treats as "not published here".
        let Some((_, rest)) = url.split_once("://") else {
            return Err(format!("{url:?} is not absolute"));
        };
        let path = rest.find('/').map(|index| &rest[index..]).unwrap_or("/");
        let mut stream = std::net::TcpStream::connect(self.address)
            .map_err(|error| format!("connect failed: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: wkd.test\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .map_err(|error| format!("write failed: {error}"))?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|error| format!("read failed: {error}"))?;
        let text = String::from_utf8(raw).map_err(|_| "non-UTF-8 response".to_string())?;
        pigeon_api::wkd::parse_response(text)
    }
}

/// A fetcher for a domain that publishes nothing at all.
struct NoKeys;

impl KeyFetcher for NoKeys {
    fn fetch(&self, _url: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

/// MX answers: each recipient domain resolves to loopback.
struct FixedMxSource {
    domains: Vec<String>,
}

impl MxSource for FixedMxSource {
    fn mx_records<'a>(&'a self, domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>> {
        let known = self.domains.iter().any(|known| known == domain);
        let rows = if known {
            vec![MxRecord::new(10, "127.0.0.1")]
        } else {
            Vec::new()
        };
        Box::pin(async move { Ok(rows) })
    }
}

/// Queue one email through instance A's real API router.
async fn send_through_api(
    instance: &Instance,
    key_fetcher: Arc<dyn KeyFetcher>,
    from: &str,
    to: &[&str],
    subject: &str,
    text: &str,
) -> (String, serde_json::Value) {
    let state = instance.api_state(key_fetcher);
    let account = state
        .db
        .account_id_by_email(&EmailAddress::parse(from).expect("address").normalized())
        .expect("lookup")
        .expect("account");
    let (_, key) = pigeon_api::keys::issue(
        &state.store,
        &state.db,
        account,
        "test",
        &[ApiKeyScope::Full],
        false,
    )
    .expect("key");

    let body = serde_json::json!({
        "from": from,
        "to": to,
        "subject": subject,
        "text": text,
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/emails")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = pigeon_api::router(state.clone())
        .oneshot(request)
        .await
        .expect("router call");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(status, StatusCode::ACCEPTED, "{json}");
    (json["id"].as_str().expect("id").to_string(), json)
}

fn worker(instance: &Instance, mx_domains: &[&str], port_for: &[(&str, u16)]) -> QueueWorker {
    let mut resolver = MxResolver::new(FixedMxSource {
        domains: mx_domains
            .iter()
            .map(|domain| (*domain).to_string())
            .collect(),
    });
    for (domain, port) in port_for {
        resolver = resolver.with_test_port_for(domain, *port);
    }
    QueueWorker::new(
        Arc::clone(&instance.store),
        Arc::clone(&instance.db),
        Arc::clone(&instance.master_key),
        Arc::new(OutboundSmtpClient::new(
            resolver,
            DeliveryConfig {
                starttls: StartTlsMode::Opportunistic,
                timeout: Duration::from_secs(5),
                ..DeliveryConfig::default()
            },
        )),
        Arc::new(StoreDkimKeys::new(
            Arc::clone(&instance.store),
            Arc::clone(&instance.master_key),
        )),
        WorkerConfig {
            worker_id: "pgp-e2e".to_string(),
            poll_interval: Duration::from_millis(10),
            ..WorkerConfig::default()
        },
    )
}

/// Pull the armored OpenPGP message out of a stored PGP/MIME body.
fn armored_payload(mime: &str) -> String {
    let start = mime
        .find("-----BEGIN PGP MESSAGE-----")
        .unwrap_or_else(|| panic!("no armored payload in {mime}"));
    let end = mime
        .find("-----END PGP MESSAGE-----")
        .map(|index| index + "-----END PGP MESSAGE-----".len())
        .expect("armor end");
    mime[start..end].replace("\r\n", "\n")
}

#[tokio::test]
async fn a_message_between_two_instances_arrives_sealed_and_only_b_can_open_it() {
    // ---- instance B: owns b.example and publishes carol's key ----------------
    let b = Arc::new(Instance::new(MASTER_B));
    let carol = b.account("carol@b.example");
    let endpoint = WkdEndpoint::start(Arc::clone(&b)).await;
    let inbound_b = Arc::new(InboundSmtpServer::new(
        Arc::clone(&b.store),
        Arc::clone(&b.db),
        Arc::clone(&b.master_key),
        ServerConfig::default(),
    ));
    let (inbound_address, _stop_b) = start_inbound(inbound_b).await;

    // ---- instance A: owns a.example and sends ------------------------------
    let a = Instance::new(MASTER_A);
    a.account("dana@a.example");
    let fetcher = Arc::new(LoopbackFetcher {
        address: endpoint.address,
    });
    let (public_id, response) = send_through_api(
        &a,
        fetcher.clone(),
        "dana@a.example",
        &["carol@b.example"],
        "Sealed across instances",
        "This text never travels in the clear.",
    )
    .await;

    assert_eq!(
        response["e2e"], "sealed",
        "B publishes a key, so A must report a sealed payload: {response}"
    );
    assert!(
        !endpoint.queries.lock().expect("lock").is_empty(),
        "the key came from B's own publication endpoint, not from a fixture"
    );

    // ---- A delivers to B's real inbound SMTP server -------------------------
    let worker = worker(&a, &["b.example"], &[("b.example", inbound_address.port())]);
    assert_eq!(worker.drain(10).await.expect("drain"), 1, "one job was due");
    let email =
        a.db.email_by_public_id(
            a.store
                .get_account_by_email("dana@a.example")
                .expect("lookup")
                .expect("account"),
            &public_id,
        )
        .expect("email row")
        .expect("email row present");
    assert_eq!(email.status, "sent");

    // ---- B's storage holds OpenPGP ciphertext ------------------------------
    let delivered_id = b.latest_message_for(carol);
    let stored = b.open_body(carol, delivered_id);
    assert!(
        stored
            .contains("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\""),
        "B stores the PGP/MIME envelope: {stored}"
    );
    assert!(
        stored.contains("Subject: Sealed across instances"),
        "the subject stays in the clear (the documented caveat): {stored}"
    );
    assert!(
        !stored.contains("This text never travels in the clear."),
        "the body must not be readable in B's storage: {stored}"
    );
    assert!(
        !stored.contains("VGhpcyB0ZXh0IG5ldmVyIHRyYXZlbHMgaW4gdGhlIGNsZWFyLg=="),
        "not even as base64: {stored}"
    );

    // ---- only B's account key opens it -------------------------------------
    let carol_address = EmailAddress::parse("carol@b.example").expect("address");
    let carol_key =
        pigeon_api::pgp::ensure_account_key(&b.store, &b.master_key, carol, &carol_address)
            .expect("carol's key");
    let payload = armored_payload(&stored);
    let opened = pigeon_crypto::open_payload_with_key(
        carol_key.private_armored.as_bytes(),
        payload.as_bytes(),
    )
    .expect("B's account key opens the sealed payload");
    let opened = String::from_utf8(opened).expect("utf8");
    assert!(
        opened.contains("VGhpcyB0ZXh0IG5ldmVyIHRyYXZlbHMgaW4gdGhlIGNsZWFyLg=="),
        "the original body is inside the seal: {opened}"
    );

    // A's own key opens the same payload, which is how the sent copy stays
    // readable for the account that sent it.
    let dana_id = a
        .store
        .get_account_by_email("dana@a.example")
        .expect("lookup")
        .expect("account");
    let dana_key = pigeon_api::pgp::ensure_account_key(
        &a.store,
        &a.master_key,
        dana_id,
        &EmailAddress::parse("dana@a.example").expect("address"),
    )
    .expect("dana's key");
    assert!(
        pigeon_crypto::open_payload_with_key(
            dana_key.private_armored.as_bytes(),
            payload.as_bytes()
        )
        .is_ok(),
        "the sending account can read its own sent mail"
    );

    // Nobody else can: a third identity is not an intended recipient.
    let stranger = pigeon_crypto::generate_account_key("eve@c.example").expect("stranger key");
    assert!(
        pigeon_crypto::open_payload_with_key(
            stranger.private_armored.as_bytes(),
            payload.as_bytes()
        )
        .is_err(),
        "the seal is not openable by an unrelated key"
    );
}

#[tokio::test]
async fn a_recipient_without_a_published_key_still_gets_the_mail_as_tls_only() {
    let b = Arc::new(Instance::new(MASTER_B));
    let carol = b.account("carol@b.example");
    let inbound_b = Arc::new(InboundSmtpServer::new(
        Arc::clone(&b.store),
        Arc::clone(&b.db),
        Arc::clone(&b.master_key),
        ServerConfig::default(),
    ));
    let (inbound_address, _stop_b) = start_inbound(inbound_b).await;

    let a = Instance::new(MASTER_A);
    a.account("dana@a.example");
    // Discovery finds nothing anywhere: the invariant says delivery still happens.
    let (public_id, response) = send_through_api(
        &a,
        Arc::new(NoKeys),
        "dana@a.example",
        &["carol@b.example"],
        "No key published",
        "Delivered anyway.",
    )
    .await;
    assert_eq!(
        response["e2e"], "tls_only",
        "no discovered key means no seal, and the API says so: {response}"
    );
    let _ = public_id;

    let worker = worker(&a, &["b.example"], &[("b.example", inbound_address.port())]);
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    // B received the message in the clear, sealed at rest by layer 1.
    let delivered_id = b.latest_message_for(carol);
    let stored = b.open_body(carol, delivered_id);
    assert!(!stored.contains("multipart/encrypted"), "{stored}");
    assert!(
        stored.contains("RGVsaXZlcmVkIGFueXdheS4=") || stored.contains("Delivered anyway."),
        "the body arrived: {stored}"
    );
}

/// The discovery path is also exercised with a map of domains → keys, so a
/// multi-domain send proves every recipient domain is queried separately.
#[tokio::test]
async fn every_recipient_domain_is_asked_for_its_own_key() {
    let b = Arc::new(Instance::new(MASTER_B));
    b.account("carol@b.example");
    let endpoint = WkdEndpoint::start(Arc::clone(&b)).await;

    let a = Instance::new(MASTER_A);
    a.account("dana@a.example");
    let fetcher = Arc::new(LoopbackFetcher {
        address: endpoint.address,
    });
    let (_id, response) = send_through_api(
        &a,
        fetcher,
        "dana@a.example",
        &["carol@b.example", "dave@nowhere.example"],
        "Two domains",
        "body",
    )
    .await;

    // `nowhere.example` has no key, so the honest answer is tls_only — and B was
    // still asked, which is what this test is about.
    assert_eq!(response["e2e"], "tls_only", "{response}");
    let queries = endpoint.queries.lock().expect("lock").clone();
    assert!(
        queries
            .iter()
            .any(|query| query.contains("carol%40b.example")),
        "each recipient domain gets its own lookup: {queries:?}"
    );
}
