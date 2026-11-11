//! Minimal read-side MIME extraction over stored message documents.
//!
//! Every stored body is a complete RFC822 document: the inbound SMTP path
//! seals the received bytes with our trace header on top, and the API send
//! path seals [`crate::mime::build`] output. Clients should read a message,
//! not the wire, so this module walks the document and extracts the first
//! `text/plain` and the first `text/html` part, decoding the
//! Content-Transfer-Encoding (base64, quoted-printable) and honoring a
//! charset when it is trivially decodable (UTF-8, ISO-8859-1).
//!
//! Deliberately minimal, like the SMTP-side parser: no `mail-parser`
//! dependency, no re-encoding, no attachment extraction. Embedded parts that
//! are not text are ignored — and nothing is lost, because the stored
//! document stays sealed verbatim; this module only shapes what a reader
//! sees.

/// First `text/plain` and first `text/html` part of an RFC822 document.
///
/// Returns `(None, None)` when the document holds no readable text part
/// (PGP/MIME armor, binary bodies): the caller falls back to exposing the
/// payload verbatim rather than silently truncating it.
pub(crate) fn extract_parts(document: &[u8]) -> (Option<String>, Option<String>) {
    let mut found = Found::default();
    walk(split_entity(document), 0, &mut found);
    (found.text, found.html)
}

/// Hard cap on multipart/message nesting. Real mail nests a handful of levels;
/// past the cap nothing is claimed as content and the caller's verbatim
/// fallback keeps the bytes visible instead of risking unbounded recursion.
const MAX_MIME_DEPTH: usize = 32;

#[derive(Default)]
struct Found {
    text: Option<String>,
    html: Option<String>,
}

/// A parsed entity: unfolded headers plus the raw body slice.
struct Entity<'a> {
    headers: Vec<(String, String)>,
    body: &'a [u8],
}

/// Split a document into unfolded headers and body. A document without a
/// header block is a bare body with no headers at all.
fn split_entity(document: &[u8]) -> Entity<'_> {
    let Some((headers_raw, body)) = header_split(document) else {
        return Entity {
            headers: Vec::new(),
            body: document,
        };
    };
    let headers = parse_headers(headers_raw);
    if headers.is_empty() {
        // A block with no `name:` field was never a header block (e.g. a bare
        // content line before a blank line): the whole document is the body.
        return Entity {
            headers: Vec::new(),
            body: document,
        };
    }
    Entity { headers, body }
}

/// Locate the blank line that ends the header block, tolerating mixed CRLF/LF
/// in every combination (r1 finding 2: a block ending LF closed by CRLF).
fn header_split(document: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    while i < document.len() {
        match document[i] {
            b'\r' if document.get(i + 1) == Some(&b'\n') => {
                // A CR LF followed by any lone CR or LF starts the body: that
                // byte belongs to the sender's blank line, whatever ending it
                // used. The body therefore begins after the full blank line.
                match document.get(i + 2) {
                    Some(b'\r') => {
                        if document.get(i + 3) == Some(&b'\n') {
                            return Some((&document[..i], &document[i + 4..]));
                        }
                        return Some((&document[..i], &document[i + 3..]));
                    }
                    Some(b'\n') => return Some((&document[..i], &document[i + 3..])),
                    _ => {
                        i += 2;
                        continue;
                    }
                }
            }
            b'\n' if document.get(i + 1) == Some(&b'\n') => {
                return Some((&document[..i], &document[i + 2..]));
            }
            b'\n' if document.get(i + 1) == Some(&b'\r') && document.get(i + 2) == Some(&b'\n') => {
                return Some((&document[..i], &document[i + 3..]));
            }
            _ => i += 1,
        }
    }
    None
}

/// Unfold and split the header block into `(name, value)` pairs.
fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
    let block = String::from_utf8_lossy(raw);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in block.split('\n') {
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
    headers
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The `type/subtype` of a Content-Type value, lowercased, plus its
/// parameters (keys lowercased, quotes stripped).
fn parse_content_type(value: &str) -> (String, Vec<(String, String)>) {
    let mut segments = value.split(';');
    let ctype = segments
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mut params = Vec::new();
    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if let Some((key, param)) = segment.split_once('=') {
            let param = param.trim();
            let param = param
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(param);
            params.push((key.trim().to_ascii_lowercase(), param.to_string()));
        }
    }
    (ctype, params)
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Decode Content-Transfer-Encoding: base64, quoted-printable, or identity.
fn decode_cte(body: &[u8], cte: Option<&str>) -> Vec<u8> {
    match cte.map(|value| value.trim().to_ascii_lowercase()) {
        Some(ref value) if value == "base64" => decode_base64(body),
        Some(ref value) if value == "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(),
    }
}

/// Tolerant base64: whitespace and line wraps are not part of the alphabet.
fn decode_base64(body: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .unwrap_or_else(|_| body.to_vec())
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'=' {
            // Soft line break: an encoded line never ends with `=`.
            if body.get(i + 1) == Some(&b'\r') && body.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if body.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if let (Some(high), Some(low)) = (body.get(i + 1), body.get(i + 2)) {
                if let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low)) {
                    out.push(high * 16 + low);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(body[i]);
        i += 1;
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode bytes with the part's charset when it is trivially decodable;
/// anything else falls back to lossy UTF-8 rather than crashing a read.
/// Exactly one trailing wire line break is removed (r1 finding 8): the
/// part's own trailing blank lines are content and must survive.
fn charset_to_string(bytes: &[u8], charset: Option<&str>) -> String {
    let decoded = match charset.map(|value| value.trim().to_ascii_lowercase()) {
        Some(ref value) if value == "iso-8859-1" || value == "latin1" || value == "latin-1" => {
            bytes.iter().map(|byte| *byte as char).collect()
        }
        Some(ref value) if value == "windows-1252" => {
            bytes.iter().map(|byte| CP1252[*byte as usize]).collect()
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    };
    trim_one_line_break(&decoded)
}

/// Remove exactly one trailing CRLF, LF or CR.
fn trim_one_line_break(value: &str) -> String {
    // Exactly one break: CRLF counts as one, so a lone-CR suffix must not
    // cascade into a second removal (r2 finding 1: "keep\r\r" keeps one CR).
    if let Some(rest) = value.strip_suffix("\r\n") {
        rest.to_string()
    } else if let Some(rest) = value.strip_suffix('\n') {
        rest.to_string()
    } else if let Some(rest) = value.strip_suffix('\r') {
        rest.to_string()
    } else {
        value.to_string()
    }
}

/// windows-1252 maps 0x80-0x9F through the vendor table (€ “ ” œ …), not to
/// C1 controls (r1 finding 7). 0x81, 0x8D, 0x8F, 0x90, 0x9D are undefined and
/// stay controls.
const CP1252: [char; 256] = build_cp1252();

const fn build_cp1252() -> [char; 256] {
    let mut table = ['\0'; 256];
    let mut byte = 0usize;
    while byte < 256 {
        table[byte] = byte as u8 as char;
        byte += 1;
    }
    table[0x80] = '\u{20AC}';
    table[0x82] = '\u{201A}';
    table[0x83] = '\u{0192}';
    table[0x84] = '\u{201E}';
    table[0x85] = '\u{2026}';
    table[0x86] = '\u{2020}';
    table[0x87] = '\u{2021}';
    table[0x88] = '\u{02C6}';
    table[0x89] = '\u{2030}';
    table[0x8A] = '\u{0160}';
    table[0x8B] = '\u{2039}';
    table[0x8C] = '\u{0152}';
    table[0x8E] = '\u{017D}';
    table[0x91] = '\u{2018}';
    table[0x92] = '\u{2019}';
    table[0x93] = '\u{201C}';
    table[0x94] = '\u{201D}';
    table[0x95] = '\u{2022}';
    table[0x96] = '\u{2013}';
    table[0x97] = '\u{2014}';
    table[0x98] = '\u{02DC}';
    table[0x99] = '\u{2122}';
    table[0x9A] = '\u{0161}';
    table[0x9B] = '\u{203A}';
    table[0x9C] = '\u{0153}';
    table[0x9E] = '\u{017E}';
    table[0x9F] = '\u{0178}';
    table
}

/// Walk one entity, collecting the first text and the first html part.
fn walk(entity: Entity<'_>, depth: usize, found: &mut Found) {
    if depth > MAX_MIME_DEPTH {
        return;
    }
    let content_type = header_value(&entity.headers, "Content-Type")
        .map(str::to_string)
        .unwrap_or_else(|| "text/plain".to_string());
    let (ctype, params) = parse_content_type(&content_type);

    if ctype.starts_with("multipart/") {
        if let Some(boundary) = param(&params, "boundary") {
            for part in split_multipart(entity.body, boundary) {
                walk(split_entity(part), depth + 1, found);
            }
            return;
        }
        // A multipart without a boundary is unreadable wire; fall through to
        // the text branches so the caller's verbatim fallback keeps it.
    }
    if ctype == "message/rfc822" {
        walk(split_entity(entity.body), depth + 1, found);
        return;
    }
    if ctype == "text/plain" && found.text.is_none() {
        let charset = param(&params, "charset");
        let text = charset_to_string(
            &decode_cte(
                entity.body,
                header_value(&entity.headers, "Content-Transfer-Encoding"),
            ),
            charset,
        );
        // An empty part (marketing mail ships empty text alternatives) is not
        // a finding: a later part may carry the real content.
        if !text.trim().is_empty() {
            found.text = Some(text);
        }
        return;
    }
    if ctype == "text/html" && found.html.is_none() {
        let charset = param(&params, "charset");
        let html = charset_to_string(
            &decode_cte(
                entity.body,
                header_value(&entity.headers, "Content-Transfer-Encoding"),
            ),
            charset,
        );
        if !html.trim().is_empty() {
            found.html = Some(html);
        }
    }
}

/// Split a multipart body into its parts as byte ranges: from the line after
/// each `--boundary` delimiter to the last content line before the next one.
/// RFC 2046 allows trailing linear whitespace on the boundary delimiter and
/// close-delimiter lines, and an epilogue may follow the close delimiter.
/// Streaming: one forward scan holding only the current part's range — no
/// per-line offset vector, so memory stays O(part) on any body size
/// (r1 finding 3).
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delimiter = format!("--{boundary}");
    let closing = format!("{delimiter}--");

    let mut parts = Vec::new();
    let mut current: Option<(usize, usize)> = None;
    let mut cursor = 0usize;
    while cursor < body.len() {
        let start = cursor;
        let mut end = start;
        while end < body.len() && body[end] != b'\n' {
            end += 1;
        }
        cursor = if end < body.len() {
            end + 1
        } else {
            body.len()
        };
        let line = trim_line(&body[start..end]);
        let delimiter_line = trim_trailing_space_tab(line);
        if delimiter_line == closing.as_bytes() {
            if let Some((part_start, part_end)) = current.take() {
                parts.push(&body[part_start..part_end]);
            }
            break;
        }
        if delimiter_line == delimiter.as_bytes() {
            if let Some((part_start, part_end)) = current.take() {
                parts.push(&body[part_start..part_end]);
            }
            // The part begins after its delimiter line, and the slice keeps
            // the line terminators: an empty-bodied part must still parse as
            // "headers + empty body", not as a bare body.
            current = Some((cursor, cursor));
            continue;
        }
        if let Some((_, part_end)) = current.as_mut() {
            // Full line end including the terminator: part slices keep their
            // line breaks (an empty-bodied part must still parse as headers +
            // empty body), and the boundary's own CRLF is backed off on close.
            *part_end = cursor;
        }
    }
    if let Some((part_start, part_end)) = current {
        parts.push(&body[part_start..part_end]);
    }
    parts.retain(|part| !part.is_empty());
    parts
}

/// RFC 2046 boundary delimiters may carry trailing linear whitespace.
fn trim_trailing_space_tab(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\t') {
        end -= 1;
    }
    &line[..end]
}

/// Strip a trailing CRLF/LF (and a lone CR) from one raw line.
fn trim_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_alternative_yields_both_decoded_parts() {
        let document = b"Received: from mail.example.org by mx.test\r\n\
            Content-Type: multipart/alternative; boundary=\"alt-1\"\r\n\
            \r\n\
            --alt-1\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            SG9sYSBkZSBsYSBwcnVlYmE=\r\n\
            --alt-1\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Content-Transfer-Encoding: quoted-printable\r\n\
            \r\n\
            <p>Hola=2C qu=C3=A9 tal</p>\r\n\
            --alt-1--\r\n";
        let (text, html) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("Hola de la prueba"));
        assert_eq!(html.as_deref(), Some("<p>Hola, qué tal</p>"));
    }

    #[test]
    fn folded_content_type_is_unfolded_before_parsing() {
        let document = b"Content-Type: multipart/mixed;\r\n \
            boundary=\"mix\"\r\n\
            \r\n\
            --mix\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            body\r\n\
            --mix--\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("body"));
    }

    #[test]
    fn mixed_documents_take_first_text_and_html_and_skip_attachments() {
        let document = b"Content-Type: multipart/mixed; boundary=\"mix\"\r\n\
            \r\n\
            --mix\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            first\r\n\
            --mix\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <p>html</p>\r\n\
            --mix\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            ignored-second\r\n\
            --mix\r\n\
            Content-Type: application/pdf\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            JVBERi0=\r\n\
            --mix--\r\n";
        let (text, html) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("first"));
        assert_eq!(html.as_deref(), Some("<p>html</p>"));
    }

    #[test]
    fn quoted_printable_soft_breaks_vanish() {
        let document = b"Content-Type: text/plain\r\n\
            Content-Transfer-Encoding: quoted-printable\r\n\
            \r\n\
            line one=\r\n\
            line two=0Aend\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("line oneline two\nend"));
    }

    #[test]
    fn iso_8859_1_charset_decodes_byte_per_byte() {
        let document = b"Content-Type: text/plain; charset=iso-8859-1\r\n\
            \r\n\
            espa\xF1ol\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("español"));
    }

    #[test]
    fn html_only_documents_leave_text_absent() {
        let document = b"Content-Type: text/html; charset=utf-8\r\n\
            \r\n\
            <p>only</p>\r\n";
        let (text, html) = extract_parts(document);
        assert!(text.is_none());
        assert_eq!(html.as_deref(), Some("<p>only</p>"));
    }

    #[test]
    fn documents_without_a_header_block_are_bare_text() {
        let (text, html) = extract_parts(b"plain body");
        assert_eq!(text.as_deref(), Some("plain body"));
        assert!(html.is_none());
    }

    #[test]
    fn empty_text_alternative_does_not_shadow_real_parts() {
        // Marketing mail ships an empty text/plain alternative; its delimiter
        // slice must not masquerade as the text part and shadow the real ones.
        let document = b"Content-Type: multipart/alternative; boundary=\"b\"\r\n\
            \r\n\
            --b\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            --b\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <p>x</p>\r\n\
            --b--\r\n";
        let (text, html) = extract_parts(document);
        assert!(text.is_none(), "got {text:?}");
        assert_eq!(html.as_deref(), Some("<p>x</p>"));
    }

    #[test]
    fn delimiter_trailing_whitespace_still_closes_the_part() {
        let document = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\
            \r\n\
            --b  \r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            body\r\n\
            --b--  \r\n\
            epilogue\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("body"));
    }

    #[test]
    fn headerless_part_content_survives_the_blank_line_before_the_next_delimiter() {
        // A part with no header block (bare content line + blank line before
        // the next delimiter) must stay a bare body, not dissolve into an
        // empty header block.
        let document = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\
            \r\n\
            --b\r\n\
            hello\r\n\
            \r\n\
            --b\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <p>x</p>\r\n\
            --b--\r\n";
        let (text, html) = extract_parts(document);
        // The content survives (the r2 regression lost it entirely). The
        // trailing line break is the structural blank line before the next
        // delimiter, minus the single wire break trim: a part's trailing
        // blank lines are content under the one-break trim rule.
        assert_eq!(text.as_deref(), Some("hello\r\n"));
        assert_eq!(html.as_deref(), Some("<p>x</p>"));
    }

    #[test]
    fn header_block_ending_lf_crlf_still_splits() {
        // Real senders mix line endings: a header block that ends with LF and
        // is closed by a CRLF blank line must still split (r1 finding 2).
        let document = b"Content-Type: text/plain\n\r\nbody\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("body"));
    }

    #[test]
    fn deeply_nested_multiparts_stop_at_the_depth_cap() {
        // 64 nested multiparts exceed the walk cap: no overflow, no crash,
        // and nothing superficial is claimed as content (r1 finding 9).
        let mut document =
            String::from("Content-Type: multipart/mixed; boundary=\"b0\"\r\n\r\n--b0\r\n");
        for level in 1..64 {
            document.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
            ));
        }
        document.push_str("Content-Type: text/plain\r\n\r\ncore\r\n");
        for level in (0..64).rev() {
            document.push_str(&format!("--b{level}--\r\n"));
        }
        let (text, html) = extract_parts(document.as_bytes());
        assert!(text.is_none(), "deep core must not surface: {text:?}");
        assert!(html.is_none());
    }

    #[test]
    fn nested_multipart_inner_text_is_found() {
        // Within the cap, nesting resolves to the inner text part.
        let mut document =
            String::from("Content-Type: multipart/mixed; boundary=\"o0\"\r\n\r\n--o0\r\n");
        for level in 1..10 {
            document.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"o{level}\"\r\n\r\n--o{level}\r\n"
            ));
        }
        document.push_str("Content-Type: text/plain\r\n\r\ncore\r\n");
        for level in (0..10).rev() {
            document.push_str(&format!("--o{level}--\r\n"));
        }
        let (text, _) = extract_parts(document.as_bytes());
        assert_eq!(text.as_deref(), Some("core"));
    }

    #[test]
    fn message_rfc822_wrapper_yields_inner_parts() {
        let document = b"Content-Type: multipart/mixed; boundary=\"m\"\r\n\
            \r\n\
            --m\r\n\
            Content-Type: message/rfc822\r\n\
            \r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            forwarded words\r\n\
            --m\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <p>wrapped</p>\r\n\
            --m--\r\n";
        let (text, html) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("forwarded words"));
        assert_eq!(html.as_deref(), Some("<p>wrapped</p>"));
    }

    #[test]
    fn missing_close_delimiter_keeps_the_last_part() {
        let document = b"Content-Type: multipart/mixed; boundary=\"m\"\r\n\
            \r\n\
            --m\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            dangling part\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("dangling part"));
    }

    #[test]
    fn corrupt_base64_falls_back_to_raw_bytes() {
        let document = b"Content-Type: text/plain\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            !!!not base64!!!\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("!!!not base64!!!"));
    }

    #[test]
    fn windows_1252_specials_decode_via_the_table() {
        // 0x80 = €, 0x93/0x94 = “ ”, 0x92 = ’ — the C1 range must map through
        // the cp1252 table, not surface as controls (r1 finding 7).
        let document = b"Content-Type: text/plain; charset=windows-1252\r\n\
            \r\n\
            premio \x80 100, \x93citado\x94 y o\x92clock\r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(
            text.as_deref(),
            Some("premio \u{20ac} 100, \u{201c}citado\u{201d} y o\u{2019}clock")
        );
    }

    #[test]
    fn trailing_blank_lines_of_a_part_survive() {
        // Only the final wire line break is trimmed: the part's own trailing
        // blank lines are content (r1 finding 8).
        let document = b"Content-Type: text/plain\r\n\
            \r\n\
            keep\r\n\
            \r\n\
            \r\n\
            \r\n";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("keep\r\n\r\n\r\n"));
    }

    #[test]
    fn trailing_bare_carriage_returns_lose_exactly_one_break() {
        // Lone-CR wire artifacts: exactly one trailing break is removed, so
        // "keep\r\r" must keep its second CR (r2 finding 1).
        let document = b"Content-Type: text/plain\r\n\
            \r\n\
            keep\r\r";
        let (text, _) = extract_parts(document);
        assert_eq!(text.as_deref(), Some("keep\r"));
    }

    #[test]
    fn pgp_armor_yields_no_readable_parts() {
        let document = b"Content-Type: multipart/encrypted; boundary=\"pgp\"\r\n\
            \r\n\
            --pgp\r\n\
            Content-Type: application/pgp-encrypted\r\n\
            \r\n\
            Version: 1\r\n\
            --pgp\r\n\
            Content-Type: application/octet-stream\r\n\
            \r\n\
            -----BEGIN PGP MESSAGE-----\r\n\
            hQEMA\r\n\
            --pgp--\r\n";
        let (text, html) = extract_parts(document);
        assert!(text.is_none());
        assert!(html.is_none());
    }
}
