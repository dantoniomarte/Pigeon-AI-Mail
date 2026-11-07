//! `DKIM-Signature` verification (RFC 6376 §3.5, §3.7 and §6.1).
//!
//! The verifier trusts **nothing** in the header it is handed: the selector and
//! domain used for the DNS lookup come from that header, the `h=` tag decides
//! which headers get hashed, and every structural problem (unknown algorithm,
//! unsupported canonicalization, bad base64, missing signed header, no
//! published key) is an [`DkimError`] rather than a `passed: false` result — a
//! caller must never be able to mistake "could not check" for "checked and
//! fine".
//!
//! Only an actual cryptographic mismatch (body hash, RSA signature) comes back
//! as `Ok(VerifyResult { passed: false, .. })` with a human-readable reason.
//!
//! # Not implemented in v0.1
//!
//! * `l=` (body length limit): a signature that carries it fails the body-hash
//!   check instead of being verified over a body prefix — we fail closed
//!   rather than silently accept a truncated body.
//! * `t=` / `x=` (signature timestamp and expiry) are neither parsed nor
//!   enforced; replay/expiry policy belongs to the caller.
//! * `i=` (agent or user identifier) is not cross-checked against `d=`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

use crate::canonical::{relaxed_body, relaxed_header};
use crate::error::{DkimError, Result};
use crate::key::{ALGORITHM, CANONICALIZATION};

/// Outcome of a DKIM verification.
///
/// `passed == false` always carries a `reason`; a `passed == false` result means
/// the message reached us intact enough to check and the check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// Whether the signature is valid for the given headers and body.
    pub passed: bool,
    /// Signing domain (`d=`), taken from the signature header.
    pub domain: String,
    /// Selector (`s=`), taken from the signature header.
    pub selector: String,
    /// Algorithm (`a=`), normalized to lowercase.
    pub algorithm: String,
    /// Why verification failed, when it did.
    pub reason: Option<String>,
}

/// Verify `dkim_header_value` (the bare `DKIM-Signature` value, without the
/// field name) against the message headers, the body and the published key.
///
/// `dns_txt_lookup` is called with the fully qualified
/// `<selector>._domainkey.<domain>` name from the signature header; returning
/// `None` means no key is published and aborts verification with
/// [`DkimError::Verify`].
pub fn verify_message(
    dkim_header_value: &str,
    headers: &[(String, String)],
    body: &str,
    dns_txt_lookup: impl Fn(&str) -> Option<String>,
) -> Result<VerifyResult> {
    let tags = parse_tags(dkim_header_value)?;

    let version = required(&tags, "v")?;
    if version != "1" {
        return Err(DkimError::Parse(format!(
            "unsupported DKIM version `v={version}`"
        )));
    }

    let algorithm = required(&tags, "a")?.to_ascii_lowercase();
    if algorithm != ALGORITHM {
        return Err(DkimError::UnsupportedAlgorithm(algorithm));
    }

    // RFC 6376 §3.5 defaults to `simple/simple` when `c=` is absent; v0.1
    // implements relaxed/relaxed only.
    let canonicalization = match tags.get("c") {
        Some(value) => value.to_ascii_lowercase(),
        None => {
            return Err(DkimError::UnsupportedAlgorithm(
                "c=absent (the RFC 6376 default is simple/simple)".into(),
            ))
        }
    };
    if canonicalization != CANONICALIZATION {
        return Err(DkimError::UnsupportedAlgorithm(format!(
            "c={canonicalization}"
        )));
    }

    let domain = required(&tags, "d")?.to_string();
    let selector = required(&tags, "s")?.to_string();
    let signed_names = parse_signed_names(required(&tags, "h")?)?;
    let claimed_body_hash = decode_base64(required(&tags, "bh")?, "bh")?;
    let signature = decode_base64(required(&tags, "b")?, "b")?;

    let mut result = VerifyResult {
        passed: false,
        domain,
        selector,
        algorithm,
        reason: None,
    };

    // RFC 6376 §5.4: a signature that does not cover From is worthless.
    if !signed_names.iter().any(|name| name == "from") {
        result.reason = Some("From is not covered by the h= tag (RFC 6376 §5.4)".into());
        return Ok(result);
    }

    let public_key = lookup_public_key(&dns_txt_lookup, &result.selector, &result.domain)?;
    let signed_headers = select_headers(&signed_names, headers)?;

    let body_hash = Sha256::digest(relaxed_body(body).as_bytes());
    if body_hash.as_slice() != claimed_body_hash.as_slice() {
        result.reason = Some(
            "body hash mismatch: the body was modified in transit or the bh= tag is wrong".into(),
        );
        return Ok(result);
    }

    let mut signing_input = String::new();
    for (name, value) in signed_headers {
        signing_input.push_str(&relaxed_header(name, value));
    }
    // The signature covers this header too, with an empty b= value and no
    // trailing CRLF (§3.7).
    let blanked = blank_b_tag(dkim_header_value);
    signing_input.push_str(without_crlf(&relaxed_header("DKIM-Signature", &blanked)));

    let digest = Sha256::digest(signing_input.as_bytes());
    if public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .is_err()
    {
        result.reason = Some(
            "RSA signature mismatch: a signed header, the DKIM-Signature header or the published \
             key is not the one that signed this message"
                .into(),
        );
        return Ok(result);
    }

    result.passed = true;
    Ok(result)
}

/// Parse `tag=value; tag=value` into a map, rejecting duplicates and garbage.
fn parse_tags(value: &str) -> Result<BTreeMap<String, String>> {
    let mut tags = BTreeMap::new();
    for segment in value.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (name, tag_value) = segment.split_once('=').ok_or_else(|| {
            DkimError::Parse(format!("tag specification without `=`: {segment:?}"))
        })?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(DkimError::Parse(
                "tag specification with an empty name".into(),
            ));
        }
        if tags
            .insert(name.clone(), tag_value.trim().to_string())
            .is_some()
        {
            return Err(DkimError::Parse(format!("duplicate tag `{name}=`")));
        }
    }

    if tags.is_empty() {
        return Err(DkimError::Parse("empty DKIM-Signature header".into()));
    }
    Ok(tags)
}

fn required<'a>(tags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    match tags.get(name) {
        Some(value) if !value.is_empty() => Ok(value.as_str()),
        Some(_) => Err(DkimError::Parse(format!("tag `{name}=` is empty"))),
        None => Err(DkimError::Parse(format!("missing tag `{name}=`"))),
    }
}

/// `h=` is a colon-separated list of header names, lowercased for lookup.
fn parse_signed_names(value: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in value.split(':') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(DkimError::Parse(format!("empty header name in h={value}")));
        }
        names.push(name);
    }
    Ok(names)
}

fn decode_base64(value: &str, tag: &str) -> Result<Vec<u8>> {
    // FWS is allowed anywhere inside a base64 tag value (§3.5).
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(&compact)
        .map_err(|e| DkimError::Parse(format!("tag `{tag}=` is not valid base64: {e}")))
}

/// Pick the header instance for each `h=` entry.
///
/// RFC 6376 §5.4.2: names are matched against the message header list from the
/// bottom up, and `h=` is walked right to left, so the last `Received` in the
/// message answers the last `received` in `h=`.
fn select_headers<'a>(
    names: &[String],
    headers: &'a [(String, String)],
) -> Result<Vec<(&'a str, &'a str)>> {
    let mut used = vec![false; headers.len()];
    let mut chosen: Vec<Option<usize>> = vec![None; names.len()];

    // RFC 6376 §5.4.2: h= is processed LEFT-TO-RIGHT, and each name takes the
    // bottom-most (physically last) unused instance — so the leftmost h= entry
    // pairs with the LAST occurrence in the message.
    for index in 0..names.len() {
        let candidate = (0..headers.len()).rev().find(|&slot| {
            !used[slot] && headers[slot].0.trim().eq_ignore_ascii_case(&names[index])
        });
        match candidate {
            Some(slot) => {
                used[slot] = true;
                chosen[index] = Some(slot);
            }
            // RFC 6376 §3.5: names in h= that have no instance left contribute
            // the null input; oversigning (h=from:from with one From) is legal.
            // Only From itself is mandatory (guard below).
            None => {
                if names[index].eq_ignore_ascii_case("from") {
                    return Err(DkimError::MissingHeader(names[index].clone()));
                }
                chosen[index] = None;
            }
        }
    }

    // Absent entries contribute the null input (RFC 6376 §3.5) — i.e. zero
    // bytes — so they are simply omitted from the resolved set.
    Ok(chosen
        .into_iter()
        .flatten()
        .map(|slot| (headers[slot].0.as_str(), headers[slot].1.as_str()))
        .collect())
}

/// Re-create the DKIM-Signature header as it was signed: byte-identical except
/// that the `b=` value is dropped (the value itself is not part of the input).
fn blank_b_tag(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (index, segment) in value.split(';').enumerate() {
        if index > 0 {
            out.push(';');
        }
        let Some(equals) = segment.find('=') else {
            out.push_str(segment);
            continue;
        };
        if !segment[..equals].trim().eq_ignore_ascii_case("b") {
            out.push_str(segment);
            continue;
        }
        // RFC 6376 §3.7: delete the b= value "including all surrounding
        // whitespace" — everything from after `=` through the next `;` is
        // removed (trailing WSP included), leaving a bare `b=`.
        out.push_str(&segment[..=equals]);
    }
    out
}

fn lookup_public_key(
    dns_txt_lookup: &impl Fn(&str) -> Option<String>,
    selector: &str,
    domain: &str,
) -> Result<RsaPublicKey> {
    // The selector/domain come from the untrusted DKIM-Signature header and are
    // interpolated into a DNS name — constrain them to DNS-label characters.
    fn is_dns_name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    }
    if !is_dns_name(selector) || !is_dns_name(domain) {
        return Err(DkimError::Parse(format!(
            "selector/domain `{selector}`/`{domain}` are not valid DNS names"
        )));
    }
    let name = format!("{selector}._domainkey.{domain}");
    let record = dns_txt_lookup(&name)
        .ok_or_else(|| DkimError::Verify(format!("no DKIM key is published at {name}")))?;
    parse_dns_record(&record, &name)
}

/// Parse a `v=DKIM1; k=rsa; p=<base64 DER>` TXT record.
fn parse_dns_record(record: &str, name: &str) -> Result<RsaPublicKey> {
    let tags = parse_tags(record)?;

    if let Some(version) = tags.get("v") {
        if !version.eq_ignore_ascii_case("DKIM1") {
            return Err(DkimError::Parse(format!(
                "unsupported key record version `v={version}` at {name}"
            )));
        }
    }

    let key_type = tags
        .get("k")
        .map(|k| k.to_ascii_lowercase())
        .unwrap_or_else(|| "rsa".to_string());
    if key_type != "rsa" {
        return Err(DkimError::UnsupportedAlgorithm(format!(
            "k={key_type} (only rsa keys are supported in v0.1)"
        )));
    }

    let encoded = match tags.get("p") {
        Some(value) => value,
        None => {
            return Err(DkimError::Verify(format!(
                "the DKIM key record at {name} has no `p=` tag"
            )))
        }
    };
    if encoded.is_empty() {
        return Err(DkimError::Verify(format!(
            "the DKIM key at {name} was revoked (empty `p=`)"
        )));
    }

    let der = decode_base64(encoded, "p")?;
    let key = RsaPublicKey::from_public_key_der(&der).map_err(|e| {
        DkimError::Parse(format!(
            "`p=` at {name} is not a DER-encoded RSA public key: {e}"
        ))
    })?;
    // RFC 8301 §3.2: verifiers MUST NOT accept signatures made with RSA keys
    // shorter than 1024 bits.
    if key.size() < 128 {
        return Err(DkimError::Verify(format!(
            "the DKIM key at {name} is {} bits; RFC 8301 requires at least 1024",
            key.size() * 8
        )));
    }
    Ok(key)
}

fn without_crlf(canonical: &str) -> &str {
    canonical.strip_suffix("\r\n").unwrap_or(canonical)
}
