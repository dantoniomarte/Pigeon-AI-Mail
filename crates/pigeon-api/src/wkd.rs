//! WKD — the Web Key Directory: publication and discovery of OpenPGP keys.
//!
//! This is the discovery half of layer 3 (see `docs/e2ee-model.md`). Two
//! directions live here, deliberately together, because they are two sides of one
//! contract:
//!
//! ## Publication (this instance serves its users' keys)
//!
//! * `GET /.well-known/pigeon-pgp?email=<address>` — the **simple** endpoint, the
//!   Pigeon-to-Pigeon contract. Returns the armored certificate.
//! * `GET /.well-known/openpgpkey/<domain>/hu/<hash>` — the advanced WKD path
//!   (draft-koch-openpgp-webkey-service): the same certificate, binary, keyed by
//!   `z-base-32(SHA-1(lowercased local part))`.
//!
//! Both answer only for **accounts of this instance**. A sender alias publishes
//! nothing: it has several owners and no identity of its own, so sealing "to the
//! alias" would hand the mail to one arbitrary person.
//!
//! ## Discovery (this instance finds other people's keys)
//!
//! [`discover`] is called by the send pipeline before queueing. For every
//! recipient address that is not a local account it tries, in order:
//!
//! 1. the simple endpoint on the recipient's domain,
//! 2. the advanced path on `openpgpkey.<domain>` (the specified virtual host),
//! 3. the advanced path on `<domain>` itself (the direct method).
//!
//! ### Trust on first use
//!
//! The first key seen for an address is **pinned** ([`store::Storage::pin_pgp_peer_key`]).
//! Later discoveries never replace it: an endpoint that starts serving a different
//! key is reported (`mismatch:<fingerprint>`, plus a `warn` line) and the pinned
//! key keeps being used. Automatic rotation on a silent change is exactly the
//! attack a key directory enables, so this is a deliberate refusal to be helpful.
//!
//! ### Cost
//!
//! Discovery runs inside the send request ([`discover`] is called from
//! `handlers::send::accept`), because the `e2e` value the API reports has to be the
//! truth of what was stored. Each address costs at most three HTTPS requests, and
//! each request is bounded by [`DEFAULT_FETCH_DEADLINE`] of **wall clock** for the
//! whole exchange — resolve, connect, handshake, read — not by a per-read timeout,
//! which a drip-feeding peer would keep resetting. All of it happens on the
//! handler's blocking thread, so a hostile recipient domain can delay a send by
//! seconds but never indefinitely, and never turns into a delivery failure. Result
//! caching across requests is not implemented: the pin records *which* key is
//! trusted, and re-checking that the endpoint still serves it is what makes the
//! mismatch warning possible.
//!
//! ### Discovery never blocks delivery
//!
//! Every failure — DNS, TLS, timeout, HTML instead of a key, a certificate with no
//! encryption subkey — ends up as "no key for this address", and the message is
//! sent `tls_only` exactly as before. `docs/e2ee-model.md` states this invariant
//! and the tests pin it.
//!
//! ## Why the fetcher is a seam
//!
//! [`KeyFetcher`] is a trait so tests can serve keys from a loopback HTTP server
//! (one Pigeon instance talking to another) without a CA-signed certificate for
//! `127.0.0.1`. The production implementation [`HttpsFetcher`] refuses any URL
//! that is not `https` — a key directory that can be answered in the clear is a
//! key directory an on-path attacker controls.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pigeon_core::EmailAddress;
use sequoia_openpgp::Cert;
use sha1::{Digest, Sha1};
use store::{SqliteStorage, Storage};

use crate::pgp;
use crate::state::AppState;

/// Path of the simple endpoint Pigeon instances publish under.
pub const SIMPLE_PATH: &str = "/.well-known/pigeon-pgp";
/// Host label the advanced WKD method uses (`openpgpkey.<domain>`).
pub const ADVANCED_HOST_LABEL: &str = "openpgpkey";
/// Largest key response accepted from a peer.
pub const MAX_KEY_RESPONSE_BYTES: usize = 1024 * 1024;
/// Wall-clock budget for one discovery request, connection included.
///
/// This bounds the *whole* request, not each read: a peer that dribbles one byte
/// every few hundred milliseconds would otherwise keep resetting a per-read
/// timeout and stall a send for as long as it liked. The send pipeline calls
/// discovery synchronously, so an unbounded fetch is an unbounded send.
pub const DEFAULT_FETCH_DEADLINE: Duration = Duration::from_secs(10);

/// Where a discovered key came from, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `/.well-known/pigeon-pgp` — the Pigeon-to-Pigeon contract.
    Simple,
    /// The advanced WKD path on `openpgpkey.<domain>`.
    AdvancedHost,
    /// The advanced WKD path on the domain itself.
    AdvancedDirect,
    /// Reused from the local pin because the endpoint was unreachable or when the
    /// pin is what the sender must keep using after a mismatch.
    Pinned,
}

impl KeySource {
    /// Stored spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeySource::Simple => "pigeon-pgp",
            KeySource::AdvancedHost => "wkd-advanced",
            KeySource::AdvancedDirect => "wkd-advanced-direct",
            KeySource::Pinned => "pin",
        }
    }
}

/// A discovered recipient key, already parsed and checked for usability.
#[derive(Debug, Clone)]
pub struct DiscoveredKey {
    /// Normalized address the key was found for.
    pub address: EmailAddress,
    /// Uppercase hex fingerprint of the primary key.
    pub fingerprint: String,
    /// Parsed certificate, ready to be an encryption recipient.
    pub certificate: Cert,
    /// Where it came from.
    pub source: KeySource,
}

/// The result of asking WKD about a whole recipient list.
///
/// Never an error: discovery is best effort by contract, so every address lands in
/// exactly one of these buckets.
#[derive(Debug, Clone, Default)]
pub struct Discovery {
    /// Addresses with a usable key.
    pub keys: Vec<DiscoveredKey>,
    /// Addresses that are accounts of **this** instance. They receive the message
    /// over SMTP inside this deployment, where layer 1 (at-rest sealing) already
    /// applies, so they are not a reason to seal the payload — and sealing would
    /// make the mail unreadable in the webmail without adding a guarantee (the
    /// operator holds both keys).
    pub local: Vec<EmailAddress>,
    /// Addresses with no discoverable key.
    pub missing: Vec<EmailAddress>,
    /// Pins whose endpoint now serves a different key: reported, never followed.
    pub mismatches: Vec<String>,
}

impl Discovery {
    /// True when every recipient can be sealed to and every one of them is
    /// external.
    pub fn every_recipient_is_sealable(&self) -> bool {
        !self.keys.is_empty() && self.missing.is_empty() && self.local.is_empty()
    }

    /// The certificates to seal to, in recipient order.
    pub fn certificates(&self) -> Vec<Cert> {
        self.keys
            .iter()
            .map(|key| key.certificate.clone())
            .collect()
    }
}

/// How discovery fetches one URL.
///
/// `Ok(None)` is "not published here" (a `404`/`410`), which is a normal answer;
/// `Err` is a transport or protocol problem. Both end the same way for the send
/// pipeline, but they are logged differently.
///
/// Every fetch is bounded by [`DEFAULT_FETCH_DEADLINE`] of wall clock
/// ([`read_with_deadline`]): a peer that dribbles bytes cannot stretch one lookup,
/// and therefore cannot stall a send.
pub trait KeyFetcher: Send + Sync {
    /// Fetch `url`.
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>, String>;
}

impl std::fmt::Debug for dyn KeyFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyFetcher")
    }
}

/// Percent-encode a query value (addresses contain `@`, which must be escaped).
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'%' => {
                out.push(char::from(byte))
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// z-base-32 of `SHA-1(lowercased local part)` — the advanced WKD key hash.
///
/// The draft is explicit that the hash is over the **local part only**, lowercased,
/// and encoded in z-base-32 (not RFC 4648 base32: the alphabets differ, which is
/// why this lives here instead of reusing [`crate::base32`]).
pub fn zbase32_sha1(local_part: &str) -> String {
    let digest = Sha1::digest(local_part.to_lowercase().as_bytes());
    zbase32(&digest)
}

/// z-base-32 (Zooko) encoding, unpadded.
pub fn zbase32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// The URLs to try for `address`, in order.
pub fn discovery_urls(address: &EmailAddress) -> Vec<(KeySource, String)> {
    let domain = address.domain();
    let normalized = address.normalized();
    let local = normalized
        .split_once('@')
        .map(|(local, _)| local.to_string())
        .unwrap_or_else(|| normalized.clone());
    let hash = zbase32_sha1(&local);
    vec![
        (
            KeySource::Simple,
            format!(
                "https://{domain}{SIMPLE_PATH}?email={}",
                encode_query_value(&normalized)
            ),
        ),
        (
            KeySource::AdvancedHost,
            format!(
                "https://{ADVANCED_HOST_LABEL}.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}"
            ),
        ),
        (
            KeySource::AdvancedDirect,
            format!("https://{domain}/.well-known/openpgpkey/{domain}/hu/{hash}"),
        ),
    ]
}

/// Ask WKD about every address in `addresses`.
///
/// Local accounts are answered from this instance's own store (no network);
/// everything else is fetched. Never fails: an address that cannot be resolved to a
/// usable key ends up in [`Discovery::missing`].
pub fn discover(
    store: &SqliteStorage,
    fetcher: &dyn KeyFetcher,
    addresses: &[EmailAddress],
) -> Discovery {
    let mut discovery = Discovery::default();
    for address in addresses {
        let normalized = address.normalized();
        match store.get_account_by_email(&normalized) {
            Ok(Some(_)) => {
                // Delivered inside this deployment: layer 1 covers storage.
                discovery.local.push(address.clone());
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, address = %normalized, "cannot tell whether the address is local");
                discovery.missing.push(address.clone());
                continue;
            }
        }

        let pin = match store.get_pgp_peer_key(&normalized) {
            Ok(pin) => pin,
            Err(error) => {
                tracing::warn!(%error, address = %normalized, "cannot read the pinned key");
                None
            }
        };

        let fetched = fetch_first_available(fetcher, address);
        match (fetched, pin) {
            // A pinned key stays the pin, whatever the endpoint says now.
            (Some((source, fingerprint, certificate)), Some(pin)) => {
                if pin.fingerprint != fingerprint {
                    if let Err(error) = store.pin_pgp_peer_key(
                        &normalized,
                        &fingerprint,
                        &armor_or_empty(&certificate),
                        source.as_str(),
                    ) {
                        tracing::warn!(%error, "cannot record the key mismatch");
                    }
                    tracing::warn!(
                        address = %normalized,
                        pinned = %pin.fingerprint,
                        served = %fingerprint,
                        "the published key changed: keeping the pinned key and NOT rotating"
                    );
                    discovery.mismatches.push(format!(
                        "{normalized}: pinned {}, served {fingerprint}",
                        pin.fingerprint
                    ));
                } else if let Err(error) = store.pin_pgp_peer_key(
                    &normalized,
                    &fingerprint,
                    &armor_or_empty(&certificate),
                    source.as_str(),
                ) {
                    tracing::warn!(%error, "cannot refresh the pinned key");
                }
                // Use the pinned material, not what was just served.
                match pigeon_crypto::parse_cert(pin.public_armored.as_bytes()) {
                    Ok(cert) if pigeon_crypto::can_encrypt(&cert) => {
                        discovery.keys.push(DiscoveredKey {
                            address: address.clone(),
                            fingerprint: pin.fingerprint,
                            certificate: cert,
                            source: KeySource::Pinned,
                        })
                    }
                    _ => {
                        tracing::warn!(
                            address = %normalized,
                            "the pinned key is unusable; treating the recipient as unsealable"
                        );
                        discovery.missing.push(address.clone());
                    }
                }
            }
            // First contact: this is the trust decision.
            (Some((source, fingerprint, certificate)), None) => {
                if let Err(error) = store.pin_pgp_peer_key(
                    &normalized,
                    &fingerprint,
                    &armor_or_empty(&certificate),
                    source.as_str(),
                ) {
                    tracing::warn!(%error, "cannot pin the discovered key");
                }
                tracing::info!(
                    address = %normalized,
                    fingerprint = %fingerprint,
                    source = source.as_str(),
                    "pinned a recipient key on first contact"
                );
                discovery.keys.push(DiscoveredKey {
                    address: address.clone(),
                    fingerprint,
                    certificate,
                    source,
                });
            }
            // The endpoint is unreachable or publishes nothing.
            (None, Some(pin)) => match pigeon_crypto::parse_cert(pin.public_armored.as_bytes()) {
                Ok(cert) if pigeon_crypto::can_encrypt(&cert) => {
                    // The pin is what lets delivery stay sealed while the peer's
                    // directory is down.
                    tracing::info!(
                        address = %normalized,
                        fingerprint = %pin.fingerprint,
                        "key discovery unavailable: using the pinned key"
                    );
                    discovery.keys.push(DiscoveredKey {
                        address: address.clone(),
                        fingerprint: pin.fingerprint,
                        certificate: cert,
                        source: KeySource::Pinned,
                    });
                }
                _ => discovery.missing.push(address.clone()),
            },
            (None, None) => {
                tracing::info!(
                    address = %normalized,
                    "no OpenPGP key discovered: delivering tls_only"
                );
                discovery.missing.push(address.clone());
            }
        }
    }
    discovery
}

fn armor_or_empty(cert: &Cert) -> String {
    use sequoia_openpgp::serialize::SerializeInto;
    match cert.armored().to_vec() {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Try every URL for one address; first usable key wins.
fn fetch_first_available(
    fetcher: &dyn KeyFetcher,
    address: &EmailAddress,
) -> Option<(KeySource, String, Cert)> {
    for (source, url) in discovery_urls(address) {
        let body = match fetcher.fetch(&url) {
            Ok(Some(body)) => body,
            Ok(None) => {
                tracing::debug!(url = %url, "WKD: not published here");
                continue;
            }
            Err(error) => {
                tracing::debug!(url = %url, %error, "WKD: fetch failed");
                continue;
            }
        };
        match pigeon_crypto::parse_cert_with_fingerprint(&body) {
            Ok((cert, fingerprint)) => {
                if !pigeon_crypto::can_encrypt(&cert) {
                    tracing::warn!(
                        url = %url,
                        fingerprint = %fingerprint,
                        "WKD: the published certificate has no encryption subkey"
                    );
                    continue;
                }
                // A published certificate must name the address it is published
                // for; anything else is a directory serving somebody else's key.
                if !cert_mentions(&cert, &address.normalized()) {
                    tracing::warn!(
                        url = %url,
                        address = %address.normalized(),
                        "WKD: the certificate does not name this address"
                    );
                    continue;
                }
                return Some((source, fingerprint, cert));
            }
            Err(error) => {
                tracing::warn!(url = %url, %error, "WKD: response is not a certificate");
            }
        }
    }
    None
}

/// True when the certificate carries a user id **equal** to `address`.
///
/// Equality, not containment: a certificate for `evil-carol@example.org` contains
/// the string `carol@example.org`, and a substring test would happily accept it as
/// the recipient's key. The comparison is case-insensitive and also strips a
/// display name (`Carol <carol@example.org>`), because that is how a real PGP
/// client may spell the same identity.
fn cert_mentions(cert: &Cert, address: &str) -> bool {
    let wanted = address.trim().to_lowercase();
    cert.userids().any(|userid| {
        let value = String::from_utf8_lossy(userid.userid().value()).into_owned();
        let value = value.trim();
        let candidate = match (value.rfind('<'), value.ends_with('>')) {
            (Some(open), true) => &value[open + 1..value.len() - 1],
            _ => value,
        };
        candidate.trim().eq_ignore_ascii_case(&wanted)
    })
}

/// Production [`KeyFetcher`]: HTTPS with real certificate verification.
#[derive(Debug, Clone)]
pub struct HttpsFetcher {
    deadline: Duration,
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_FETCH_DEADLINE,
        }
    }
}

impl HttpsFetcher {
    /// Build with an explicit wall-clock budget per request.
    pub fn with_deadline(deadline: Duration) -> Self {
        Self { deadline }
    }
}

impl KeyFetcher for HttpsFetcher {
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        let target = HttpsTarget::parse(url)?;
        // One budget for the whole request: resolve, connect, handshake and read.
        let deadline = Instant::now() + self.deadline;
        https_get(&target.host, target.port, &target.path, deadline).and_then(parse_response)
    }
}

/// A parsed `https://host[:port]/path` discovery URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsTarget {
    /// Host to connect to (and the name verified against its certificate).
    pub host: String,
    /// Port, defaulting to 443.
    pub port: u16,
    /// Request path, including any query string.
    pub path: String,
}

impl HttpsTarget {
    /// Parse `url`, refusing anything that is not HTTPS.
    ///
    /// A key directory answered in the clear is a key directory an on-path
    /// attacker controls, so this is a hard rule rather than a preference.
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("{url:?} is not an absolute URL"))?;
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(format!(
                "{url:?} is not HTTPS: a key directory must be fetched over TLS"
            ));
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], rest[index..].to_string()),
            None => (rest, "/".to_string()),
        };
        if authority.contains('@') {
            return Err(format!("{url:?} carries user info"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|_| format!("{url:?} has an invalid port"))?,
            ),
            _ => (authority.to_string(), 443),
        };
        if host.is_empty() {
            return Err(format!("{url:?} has no host"));
        }
        Ok(HttpsTarget { host, port, path })
    }
}

/// Remaining time before `deadline`, or an error when it has already passed.
fn remaining(deadline: Instant) -> Result<Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("discovery deadline exceeded".to_string());
    }
    Ok(deadline - now)
}

fn connect(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {host}: {error}"))?
        .collect::<Vec<_>>();
    let mut last = format!("{host}:{port} did not resolve");
    for address in addresses {
        let budget = remaining(deadline)?;
        match TcpStream::connect_timeout(&address, budget) {
            Ok(stream) => {
                // The socket timeouts are a backstop for a silent peer; the
                // deadline check inside `read_with_deadline` is what bounds a peer
                // that answers one byte at a time.
                let left = remaining(deadline).unwrap_or(Duration::from_millis(1));
                let _ = stream.set_read_timeout(Some(left));
                let _ = stream.set_write_timeout(Some(left));
                return Ok(stream);
            }
            Err(error) => last = format!("connect to {address} failed: {error}"),
        }
    }
    Err(last)
}

/// Read a response body under one wall-clock `deadline`.
///
/// The loop re-checks the clock between reads, so a peer that sends one byte every
/// few hundred milliseconds hits the deadline instead of resetting a per-read
/// timeout forever. `limit` caps the buffered size (see
/// [`MAX_KEY_RESPONSE_BYTES`]).
pub fn read_with_deadline<R: Read>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "discovery deadline exceeded after {} bytes",
                out.len()
            ));
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(read) => {
                out.extend_from_slice(&chunk[..read]);
                if out.len() > limit {
                    return Err(format!(
                        "response is above the {limit} byte limit (read {} so far)",
                        out.len()
                    ));
                }
            }
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                return Err(format!("discovery read timed out: {error}"))
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("cannot read the response: {error}")),
        }
    }
}

fn request_bytes(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pigeon-mail/wkd\r\nAccept: application/pgp-keys, application/octet-stream\r\nConnection: close\r\n\r\n"
    )
}

fn https_get(host: &str, port: u16, path: &str, deadline: Instant) -> Result<String, String> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    let config = match CONFIG.get() {
        Some(config) => Arc::clone(config),
        None => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| format!("cannot build the TLS client config: {error}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let config = Arc::new(config);
            let _ = CONFIG.set(Arc::clone(&config));
            config
        }
    };
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|error| format!("{host:?} is not a TLS server name: {error}"))?;
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|error| format!("TLS setup failed: {error}"))?;
    let socket = connect(host, port, deadline)?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.write_all(request_bytes(host, path).as_bytes())
        .map_err(|error| format!("cannot send the request: {error}"))?;
    // `read_with_deadline`, not `read_to_end`: the deadline has to hold even when
    // every individual read succeeds.
    let raw = read_with_deadline(&mut tls, MAX_KEY_RESPONSE_BYTES, deadline)?;
    String::from_utf8(raw).map_err(|_| "the response is not UTF-8/HTTP".to_string())
}

/// Interpret a raw HTTP/1.1 response.
///
/// `Ok(Some(body))` for `2xx`, `Ok(None)` for "not published" (`404`/`410`), `Err`
/// for everything else. Handles both `Content-Length` and chunked responses, and
/// refuses a body above [`MAX_KEY_RESPONSE_BYTES`] — a peer must not be able to
/// make the server buffer gigabytes.
pub fn parse_response(raw: String) -> Result<Option<Vec<u8>>, String> {
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return Err("malformed HTTP response: no header terminator".to_string());
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed status line {status_line:?}"));
    }
    let code: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;

    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let payload = if chunked {
        dechunk(body.as_bytes())?
    } else {
        match length {
            Some(length) if body.len() < length => {
                return Err(format!(
                    "truncated response: {} of {length} bytes",
                    body.len()
                ))
            }
            Some(length) => body.as_bytes()[..length].to_vec(),
            None => body.as_bytes().to_vec(),
        }
    };
    if payload.len() > MAX_KEY_RESPONSE_BYTES {
        return Err(format!(
            "response is {} bytes, above the {MAX_KEY_RESPONSE_BYTES} limit",
            payload.len()
        ));
    }

    match code / 100 {
        2 => Ok(Some(payload)),
        4 if code == 404 || code == 410 => Ok(None),
        _ => Err(format!("HTTP {code}")),
    }
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let Some(position) = body.windows(2).position(|window| window == b"\r\n") else {
            // Some servers omit the final CRLF after the last chunk.
            if body.is_empty() {
                return Ok(out);
            }
            return Err("malformed chunked body".to_string());
        };
        let size_line = std::str::from_utf8(&body[..position])
            .map_err(|_| "malformed chunk size".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("malformed chunk size {size_hex:?}"))?;
        body = &body[position + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size {
            return Err("truncated chunk".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if body.starts_with(b"\r\n") {
            body = &body[2..];
        }
    }
}

/// True when `domain` is one this deployment serves (an account domain or a DKIM
/// identity).
///
/// Both publication endpoints gate on this before they look anything up, so a
/// request for a foreign domain cannot be told apart from a request for a
/// non-existent address: same `404`, same body. Without the gate the simple
/// endpoint would answer purely from the account table, which is a slower and
/// subtly different oracle than the advanced path.
pub fn served_domain(store: &SqliteStorage, domain: &str) -> store::Result<bool> {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Ok(false);
    }
    Ok(store
        .served_domains()?
        .iter()
        .any(|served| served.eq_ignore_ascii_case(&domain)))
}

/// The published armored key for `address`, or `None` when this instance does not
/// serve it.
///
/// Called by the HTTP endpoint; kept here so the rules (served domain, local
/// accounts only, generate on first use) have one home.
pub fn publication_key(
    store: &SqliteStorage,
    master_key: &pigeon_crypto::MasterKey,
    address: &EmailAddress,
) -> store::Result<Option<String>> {
    if !served_domain(store, address.domain())? {
        return Ok(None);
    }
    Ok(pgp::published_key_for(store, master_key, address)?.map(|key| key.public_armored))
}

/// The published **binary** key for an advanced-WKD hash lookup.
///
/// `hash` is matched against every local account's hash; the domain must be one
/// this instance serves, so a request cannot enumerate addresses of foreign
/// domains.
pub fn publication_key_by_hash(
    store: &SqliteStorage,
    master_key: &pigeon_crypto::MasterKey,
    domain: &str,
    hash: &str,
) -> store::Result<Option<Vec<u8>>> {
    if !served_domain(store, domain)? {
        return Ok(None);
    }
    let domain = domain.to_ascii_lowercase();
    let wanted = hash.trim().to_ascii_lowercase();
    for (account_id, address) in store.accounts_on_domain(&domain)? {
        let local = address
            .normalized()
            .split_once('@')
            .map(|(local, _)| local.to_string())
            .unwrap_or_default();
        if zbase32_sha1(&local) != wanted {
            continue;
        }
        let key = pgp::ensure_account_key(store, master_key, account_id, &address)?;
        let cert = pigeon_crypto::parse_cert(key.public_armored.as_bytes())?;
        return Ok(Some(pigeon_crypto::to_binary(&cert)?));
    }
    Ok(None)
}

/// Discovery entry point used by the send pipeline.
pub fn discover_for(state: &AppState, addresses: &[EmailAddress]) -> Discovery {
    discover(&state.store, state.key_fetcher.as_ref(), addresses)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Mutex;

    use store::Storage;

    use super::*;

    fn address(raw: &str) -> EmailAddress {
        EmailAddress::parse(raw).expect("address")
    }

    /// A store with one local account (`owner@example.com`) and its own master key.
    fn store_fixture() -> (tempfile::TempDir, SqliteStorage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteStorage::open(dir.path().join("pigeon.db")).expect("open store");
        store
            .create_account(&address("owner@example.com"))
            .expect("account");
        (dir, store)
    }

    /// A key directory whose answers the test dictates: one body per call, in order.
    struct ScriptedFetcher {
        answers: Mutex<Vec<Result<Option<Vec<u8>>, String>>>,
        urls: Mutex<Vec<String>>,
    }

    impl ScriptedFetcher {
        fn new(answers: Vec<Result<Option<Vec<u8>>, String>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                urls: Mutex::new(Vec::new()),
            }
        }

        /// The same answer for every URL.
        fn always(answer: Result<Option<Vec<u8>>, String>) -> Self {
            Self::new(vec![answer; 3])
        }
    }

    impl KeyFetcher for ScriptedFetcher {
        fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.urls.lock().expect("lock").push(url.to_string());
            let mut answers = self.answers.lock().expect("lock");
            if answers.is_empty() {
                return Ok(None);
            }
            answers.remove(0)
        }
    }

    #[test]
    fn the_advanced_hash_matches_the_drafts_definition() {
        // Vector computed from SHA-1("test") in z-base-32, pinned so a change of
        // alphabet or of the hash input (local part vs. whole address) fails here.
        assert_eq!(zbase32_sha1("test"), "iffe93qcsgp4c8ncbb378rxjo6cn9q6u");
        // Case folding is part of the contract: WKD hashes the lowercased local
        // part, so two spellings of one address share a hash.
        assert_eq!(zbase32_sha1("Test"), zbase32_sha1("test"));
        assert_ne!(zbase32_sha1("test"), zbase32_sha1("other"));
    }

    #[test]
    fn zbase32_uses_the_zooko_alphabet() {
        assert_eq!(zbase32(&[]), "");
        assert_eq!(zbase32(&[0x00]), "yy");
        assert_eq!(zbase32(&[0xff]), "9h");
        for character in zbase32(b"any bytes at all").chars() {
            assert!("ybndrfg8ejkmcpqxot1uwisza345h769".contains(character));
        }
    }

    #[test]
    fn discovery_tries_the_simple_endpoint_then_both_advanced_forms() {
        let urls = discovery_urls(&address("Carol@Example.ORG"));
        assert_eq!(urls.len(), 3);
        assert_eq!(
            urls[0].1, "https://example.org/.well-known/pigeon-pgp?email=carol%40example.org",
            "the address is percent-encoded and normalized"
        );
        assert_eq!(urls[0].0, KeySource::Simple);
        assert!(urls[1]
            .1
            .starts_with("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/"));
        assert_eq!(urls[1].0, KeySource::AdvancedHost);
        assert!(urls[2]
            .1
            .starts_with("https://example.org/.well-known/openpgpkey/example.org/hu/"));
        assert_eq!(urls[2].0, KeySource::AdvancedDirect);
    }

    #[test]
    fn a_url_without_tls_is_refused() {
        assert!(HttpsTarget::parse("http://example.org/.well-known/pigeon-pgp").is_err());
        assert!(HttpsTarget::parse("ftp://example.org/key").is_err());
        assert!(HttpsTarget::parse("not-a-url").is_err());
        assert!(HttpsTarget::parse("https://user:pass@example.org/key").is_err());
        assert_eq!(
            HttpsTarget::parse("https://example.org/key?email=a%40b").expect("parses"),
            HttpsTarget {
                host: "example.org".to_string(),
                port: 443,
                path: "/key?email=a%40b".to_string()
            }
        );
        assert_eq!(
            HttpsTarget::parse("https://127.0.0.1:8443/hu/abc").expect("parses"),
            HttpsTarget {
                host: "127.0.0.1".to_string(),
                port: 8443,
                path: "/hu/abc".to_string()
            }
        );
    }

    #[test]
    fn responses_are_interpreted_with_length_and_chunking() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_string();
        assert_eq!(parse_response(ok).expect("parses"), Some(b"hello".to_vec()));

        let missing = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string();
        assert_eq!(parse_response(missing).expect("parses"), None);

        let gone = "HTTP/1.1 410 Gone\r\n\r\n".to_string();
        assert_eq!(parse_response(gone).expect("parses"), None);

        let error = "HTTP/1.1 500 Server Error\r\n\r\n".to_string();
        assert!(parse_response(error).is_err());

        let chunked =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_string();
        assert_eq!(
            parse_response(chunked).expect("parses"),
            Some(b"hello".to_vec())
        );

        let truncated = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello".to_string();
        assert!(parse_response(truncated).is_err());
        assert!(parse_response("garbage".to_string()).is_err());
    }

    /// First use pins; a later, different key is reported and the **pin** keeps
    /// being used, because adopting it silently is the attack a key directory
    /// enables.
    #[test]
    fn a_changed_key_is_reported_and_the_pin_keeps_being_used() {
        let (_dir, store) = store_fixture();
        let pinned = pigeon_crypto::generate_account_key("carol@example.org").expect("pin key");
        let rotated = pigeon_crypto::generate_account_key("carol@example.org").expect("new key");
        store
            .pin_pgp_peer_key(
                "carol@example.org",
                &pinned.fingerprint,
                &pinned.public_armored,
                "pigeon-pgp",
            )
            .expect("pin");

        // The endpoint now serves a different certificate for the same address.
        let fetcher = ScriptedFetcher::always(Ok(Some(rotated.public_armored.into_bytes())));
        let discovery = discover(&store, &fetcher, &[address("carol@example.org")]);

        assert_eq!(
            discovery.mismatches.len(),
            1,
            "the operator must be told: {discovery:?}"
        );
        assert!(discovery.mismatches[0].contains(&pinned.fingerprint));
        assert!(discovery.mismatches[0].contains(&rotated.fingerprint));
        assert_eq!(
            discovery.keys.len(),
            1,
            "the address is still sealable, with the pinned key"
        );
        assert_eq!(
            discovery.keys[0].fingerprint, pinned.fingerprint,
            "never rotate silently: the pin wins"
        );

        // Proven by use: the sealed payload opens with the PINNED key only.
        let sealed = pigeon_crypto::seal_payload(b"body", &discovery.certificates())
            .expect("seal to the pin");
        assert!(pigeon_crypto::open_payload_with_key(
            pinned.private_armored.as_bytes(),
            sealed.as_bytes()
        )
        .is_ok());
        assert!(
            pigeon_crypto::open_payload_with_key(
                rotated.private_armored.as_bytes(),
                sealed.as_bytes()
            )
            .is_err(),
            "the freshly served key must not be able to open the message"
        );

        // And the mismatch is recorded, not just logged.
        let row = store
            .get_pgp_peer_key("carol@example.org")
            .expect("get")
            .expect("row");
        assert_eq!(row.fingerprint, pinned.fingerprint);
        assert_eq!(
            row.pin_status.as_deref(),
            Some(format!("mismatch:{}", rotated.fingerprint).as_str())
        );
        assert!(row.last_checked_at.is_some(), "the re-check is timestamped");
    }

    /// The pin is also what keeps delivery sealed while the peer's directory is
    /// down.
    #[test]
    fn an_unreachable_endpoint_falls_back_to_the_pin() {
        let (_dir, store) = store_fixture();
        let pinned = pigeon_crypto::generate_account_key("carol@example.org").expect("key");
        store
            .pin_pgp_peer_key(
                "carol@example.org",
                &pinned.fingerprint,
                &pinned.public_armored,
                "pigeon-pgp",
            )
            .expect("pin");

        for failure in ["connection refused", "TLS handshake failed"] {
            let fetcher = ScriptedFetcher::always(Err(failure.to_string()));
            let discovery = discover(&store, &fetcher, &[address("carol@example.org")]);
            assert!(
                discovery.missing.is_empty(),
                "a pinned address stays sealable when the directory is down: {discovery:?}"
            );
            assert_eq!(discovery.keys.len(), 1);
            assert_eq!(discovery.keys[0].fingerprint, pinned.fingerprint);
            assert_eq!(discovery.keys[0].source, KeySource::Pinned);
            assert!(discovery.every_recipient_is_sealable());
        }

        // A 404 for every path is the same story: the pin is the fallback.
        let discovery = discover(
            &store,
            &ScriptedFetcher::always(Ok(None)),
            &[address("carol@example.org")],
        );
        assert_eq!(discovery.keys.len(), 1);
    }

    /// Without a pin there is nothing to fall back to: `tls_only`, and delivery
    /// still happens.
    #[test]
    fn an_unreachable_endpoint_without_a_pin_is_tls_only() {
        let (_dir, store) = store_fixture();
        let fetcher = ScriptedFetcher::always(Err("deadline exceeded".to_string()));
        let discovery = discover(&store, &fetcher, &[address("carol@example.org")]);
        assert!(discovery.keys.is_empty());
        assert_eq!(discovery.missing, vec![address("carol@example.org")]);
        assert!(
            !discovery.every_recipient_is_sealable(),
            "no key means tls_only, never a false `sealed`"
        );
        assert!(
            store
                .get_pgp_peer_key("carol@example.org")
                .expect("get")
                .is_none(),
            "a failed lookup pins nothing"
        );
    }

    /// Local accounts need no network, and a mixed list is not sealable.
    #[test]
    fn local_recipients_are_answered_without_discovery() {
        let (_dir, store) = store_fixture();
        let fetcher = ScriptedFetcher::always(Err("must not be called for a local account".into()));
        let discovery = discover(&store, &fetcher, &[address("owner@example.com")]);
        assert_eq!(discovery.local.len(), 1);
        assert!(discovery.keys.is_empty());
        assert!(
            fetcher.urls.lock().expect("lock").is_empty(),
            "a local address never reaches the network"
        );
    }

    /// A peer that answers one byte at a time cannot stretch a lookup: the deadline
    /// is wall-clock, not per-read.
    #[test]
    fn a_drip_feeding_peer_cannot_outlive_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        // 1 byte every 200 ms, forever: every individual read succeeds, so only a
        // wall-clock deadline can stop it.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                std::thread::spawn(move || {
                    // Ten bytes at 200 ms each, then EOF: bounded on purpose, so a
                    // regression fails this test instead of hanging the suite.
                    for _ in 0..10 {
                        if stream.write_all(b"X").is_err() {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                });
            }
        });

        let mut stream = TcpStream::connect(address).expect("connect");
        let started = Instant::now();
        let deadline = started + Duration::from_secs(1);
        let result = read_with_deadline(&mut stream, MAX_KEY_RESPONSE_BYTES, deadline);
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a drip-feeding peer must not be read forever"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the deadline is wall-clock, took {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "it did read for a while"
        );
    }

    /// The same bound, seen from `discover()`: a hostile directory makes the lookup
    /// slow, never unbounded, and the message still goes out `tls_only`.
    #[test]
    fn discover_returns_within_the_deadline_against_a_drip_feeding_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let drip_address = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                std::thread::spawn(move || {
                    // Bounded drip (10 bytes), so a regression makes the test fail
                    // rather than hang.
                    for _ in 0..10 {
                        if stream.write_all(b"X").is_err() {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                });
            }
        });

        /// Stands in for [`HttpsFetcher`]: same scoring function, same deadline
        /// enforcement, only the transport (plain loopback) differs.
        struct DripFetcher {
            address: std::net::SocketAddr,
            deadline: Duration,
        }

        impl KeyFetcher for DripFetcher {
            fn fetch(&self, _url: &str) -> Result<Option<Vec<u8>>, String> {
                let mut stream = TcpStream::connect(self.address)
                    .map_err(|error| format!("cannot connect: {error}"))?;
                let raw = read_with_deadline(
                    &mut stream,
                    MAX_KEY_RESPONSE_BYTES,
                    Instant::now() + self.deadline,
                )?;
                parse_response(String::from_utf8(raw).unwrap_or_default())
            }
        }

        let (_dir, store) = store_fixture();
        let fetcher = DripFetcher {
            address: drip_address,
            deadline: Duration::from_millis(300),
        };
        let started = Instant::now();
        let discovery = discover(&store, &fetcher, &[address("carol@example.org")]);
        let elapsed = started.elapsed();

        assert!(
            discovery.keys.is_empty() && discovery.missing.len() == 1,
            "nothing usable: the send falls back to tls_only: {discovery:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "three URLs with a 300 ms budget each must finish quickly, took {elapsed:?}"
        );
    }

    #[test]
    fn a_certificate_only_counts_for_the_address_it_names() {
        let generated = pigeon_crypto::generate_account_key("carol@example.org").expect("key");
        let cert = pigeon_crypto::parse_cert(generated.public_armored.as_bytes()).expect("cert");
        assert!(cert_mentions(&cert, "carol@example.org"));
        assert!(cert_mentions(&cert, "CAROL@example.org"));
        assert!(cert_mentions(&cert, "  carol@example.org  "));
        assert!(!cert_mentions(&cert, "dave@example.org"));
        // Equality, not containment: a lookalike address that merely contains the
        // wanted one is a different identity, and accepting it would seal the
        // message to a stranger.
        assert!(!cert_mentions(&cert, "carol"));
        assert!(!cert_mentions(&cert, "example.org"));
        let lookalike = pigeon_crypto::generate_account_key("evil-carol@example.org").expect("key");
        let lookalike =
            pigeon_crypto::parse_cert(lookalike.public_armored.as_bytes()).expect("cert");
        assert!(
            !cert_mentions(&lookalike, "carol@example.org"),
            "a substring match would hand the message to evil-carol"
        );
        assert!(cert_mentions(&lookalike, "evil-carol@example.org"));
    }

    #[test]
    fn a_sealable_recipient_set_needs_no_missing_and_no_local_addresses() {
        let mut discovery = Discovery::default();
        assert!(!discovery.every_recipient_is_sealable());

        let generated = pigeon_crypto::generate_account_key("carol@example.org").expect("key");
        discovery.keys.push(DiscoveredKey {
            address: address("carol@example.org"),
            fingerprint: generated.fingerprint,
            certificate: pigeon_crypto::parse_cert(generated.public_armored.as_bytes())
                .expect("cert"),
            source: KeySource::Simple,
        });
        assert!(discovery.every_recipient_is_sealable());
        assert_eq!(discovery.certificates().len(), 1);

        discovery.local.push(address("dave@pigeonmail.dev"));
        assert!(!discovery.every_recipient_is_sealable());
    }
}
