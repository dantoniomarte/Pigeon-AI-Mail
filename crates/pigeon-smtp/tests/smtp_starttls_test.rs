//! Inbound STARTTLS (RFC 3207, issue #118): the server advertises the
//! capability when a TLS acceptor is configured, upgrades the session on
//! the `STARTTLS` command, and resets the protocol state (a fresh EHLO is
//! required before MAIL). Without a certificate the capability stays
//! unadvertised (the #99 honesty rule) and the command answers 454.

mod support;

use std::sync::Arc;

use pigeon_smtp::{InboundSmtpServer, ServerConfig};
use store::Storage;
use support::{RawClient, TestEnv};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Generate a self-signed certificate and return (cert_pem, key_pem).
fn self_signed_cert() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// Write the cert/key pair to temp files and build the server config.
fn tls_config(cert_pem: &str, key_pem: &str) -> ServerConfig {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    // Leak the tempdir: the files must outlive the config build.
    std::mem::forget(dir);
    ServerConfig::default()
        .with_tls_from_files(&cert_path, &key_path)
        .expect("tls config")
}

/// Start the server with the given config on a loopback port.
async fn start(env: &TestEnv, config: ServerConfig) -> std::net::SocketAddr {
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        config,
    ));
    let (address, stop) = support::start_inbound(server).await;
    std::mem::forget(stop);
    address
}

#[tokio::test]
async fn ehlo_advertises_starttls_when_tls_is_configured() {
    let env = TestEnv::new();
    let (cert, key) = self_signed_cert();
    let address = start(&env, tls_config(&cert, &key)).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await; // banner
    let (code, capabilities) = client.ehlo("probe.example").await;
    assert_eq!(code, 250);
    assert!(capabilities.contains("STARTTLS"), "{capabilities}");
}

#[tokio::test]
async fn ehlo_does_not_advertise_starttls_without_a_cert() {
    // The #99 honesty rule: no certificate, no capability.
    let env = TestEnv::new();
    let address = start(&env, ServerConfig::default()).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await;
    let (code, capabilities) = client.ehlo("probe.example").await;
    assert_eq!(code, 250);
    assert!(!capabilities.contains("STARTTLS"), "{capabilities}");
}

#[tokio::test]
async fn starttls_upgrades_the_session_and_requires_a_fresh_ehlo() {
    let env = TestEnv::new();
    let account_id = env.account("carol@example.com");
    let (cert_pem, key_pem) = self_signed_cert();
    let address = start(&env, tls_config(&cert_pem, &key_pem)).await;

    // Plain TCP connection.
    let stream = TcpStream::connect(address).await.expect("connect");
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Banner + EHLO.
    read_reply(&mut reader).await;
    write_line(&mut writer, "EHLO probe.example").await;
    let (code, caps) = read_reply(&mut reader).await;
    assert_eq!(code, 250);
    assert!(caps.contains("STARTTLS"));

    // STARTTLS → 220.
    write_line(&mut writer, "STARTTLS").await;
    let (code, text) = read_reply(&mut reader).await;
    assert_eq!(code, 220, "{text}");

    // Reunite and perform the TLS handshake (client side).
    let plain = reader.into_inner().unsplit(writer);
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store(&cert_pem))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let tls_stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            plain,
        )
        .await
        .expect("tls handshake");
    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    // MAIL before a fresh EHLO → 503 (RFC 3207 §4).
    write_line(&mut tls_write, "MAIL FROM:<dana@example.org>").await;
    let (code, text) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 503, "{text}: MAIL must require a fresh EHLO");

    // Fresh EHLO over TLS: no STARTTLS advertised (RFC 3208 §4).
    write_line(&mut tls_write, "EHLO probe.example").await;
    let (code, caps) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 250);
    assert!(!caps.contains("STARTTLS"), "{caps}: already upgraded");

    // A second STARTTLS → 502.
    write_line(&mut tls_write, "STARTTLS").await;
    let (code, text) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 502, "{text}");

    // Full delivery over TLS: MAIL → RCPT → DATA → message → 250.
    write_line(&mut tls_write, "MAIL FROM:<dana@example.org>").await;
    let (code, text) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 250, "{text}");
    write_line(&mut tls_write, "RCPT TO:<carol@example.com>").await;
    let (code, text) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 250, "{text}");
    write_line(&mut tls_write, "DATA").await;
    let (code, _) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 354);
    write_line(
        &mut tls_write,
        "From: dana@example.org\r\nTo: carol@example.com\r\nSubject: tls test\r\n\r\nover TLS\r\n.",
    )
    .await;
    let (code, text) = read_reply(&mut tls_reader).await;
    assert_eq!(code, 250, "{text}");

    // The message was stored.
    let inbox = env
        .store
        .list_folder(account_id, pigeon_core::MessageFolder::Inbox, 10, 0)
        .expect("inbox");
    assert!(
        !inbox.is_empty(),
        "the TLS-delivered message must be stored"
    );
}

#[tokio::test]
async fn starttls_without_a_cert_answers_454() {
    let env = TestEnv::new();
    let address = start(&env, ServerConfig::default()).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await;
    let _ = client.ehlo("probe.example").await;
    let (code, text) = client.send("STARTTLS").await;
    assert_eq!(code, 454, "{text}");
}

// --- helpers ---

fn root_store(cert_pem: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        roots.add(cert.expect("parse cert")).expect("add root");
    }
    roots
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> (u16, String) {
    // Read the full reply: single-line (`250 text`) or multiline
    // (`250-first\r\n250-second\r\n250 last`).
    let mut full = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read line");
        let line = line.trim_end_matches("\r\n").to_string();
        let code: u16 = line
            .chars()
            .take(3)
            .collect::<String>()
            .parse()
            .expect("code");
        full.push_str(&line);
        full.push('\n');
        // A line like `250 text` (space after the code) ends the reply;
        // `250-text` (hyphen) continues it.
        if line.chars().nth(3) != Some('-') {
            return (code, full);
        }
    }
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, line: &str) {
    writer
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .expect("write");
    writer.flush().await.expect("flush");
}
