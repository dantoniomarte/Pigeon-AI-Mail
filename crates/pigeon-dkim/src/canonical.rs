//! RFC 6376 §3.4 relaxed canonicalization for headers and body.
//!
//! v0.1 implements **relaxed/relaxed** only. Relaxed tolerates the rewrites
//! real MTAs perform in transit (re-folding, tab/space changes, trailing
//! whitespace), which is why it is the modern default; `simple` would break on
//! any relay that re-wraps a header.
//!
//! `relaxed_header` and `relaxed_body` return the exact byte sequence that goes
//! into the SHA-256 / RSA input, including the terminating CRLF(s) — callers
//! only concatenate.

/// Whitespace (WSP in RFC 5322) inside a header field or body line.
fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Unfold a header value: RFC 6376 §3.4.2 deletes the CRLF that introduces a
/// folded continuation line. The leading WSP of the continuation survives and
/// is collapsed with the rest in [`collapse_wsp`]; a bare (non-foldable) line
/// break is treated as a fold too, since a value handed to us is already a
/// single logical field.
fn unfold(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\r' || c == '\n' {
            continue;
        }
        out.push(c);
    }
    out
}

/// Collapse every run of WSP to a single SP, keeping leading WSP.
fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_wsp = false;
    for c in s.chars() {
        if is_wsp(c) {
            if !prev_wsp {
                out.push(' ');
            }
            prev_wsp = true;
        } else {
            out.push(c);
            prev_wsp = false;
        }
    }
    out
}

/// RFC 6376 §3.4.2 relaxed header canonicalization.
///
/// * the field name is lowercased,
/// * folded continuation lines are unfolded,
/// * every WSP run becomes a single SP,
/// * WSP around the colon and at the end of the value is removed.
///
/// Returns `name:value\r\n`.
pub fn relaxed_header(name: &str, value: &str) -> String {
    let name = name.trim_matches(is_wsp).to_ascii_lowercase();
    // Unfold first, then collapse: the WSP that followed a fold becomes part of
    // the run it now sits in.
    let unfolded = collapse_wsp(&unfold(value));
    let value = unfolded.trim_matches(' ');

    let mut out = String::with_capacity(name.len() + value.len() + 3);
    out.push_str(&name);
    out.push(':');
    out.push_str(value);
    out.push_str("\r\n");
    out
}

/// RFC 6376 §3.4.4 relaxed body canonicalization.
///
/// * WSP runs inside a line become a single SP,
/// * WSP at the end of every line is removed,
/// * empty lines at the end of the body are removed,
/// * CRLF terminates every remaining line; an empty body canonicalizes to a
///   single CRLF.
pub fn relaxed_body(body: &str) -> String {
    // Split into lines, normalizing CRLF *and* bare LF input to a single line
    // break so callers may hand us either. Each line loses its WSP run
    // structure and its trailing WSP (§3.4.4), but keeps leading WSP.
    let mut lines: Vec<String> = body
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .map(|line| {
            let collapsed = collapse_wsp(line);
            collapsed.trim_end_matches(' ').to_string()
        })
        .collect();

    // Drop trailing empty lines (§3.4.4).
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }

    let mut canonical = String::with_capacity(body.len() + 2);
    for line in &lines {
        canonical.push_str(line);
        canonical.push_str("\r\n");
    }

    // A message with no body (or a body of only whitespace) still
    // canonicalizes to a single CRLF.
    if canonical.is_empty() {
        canonical.push_str("\r\n");
    }
    canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_lowercased_and_space_after_colon_removed() {
        assert_eq!(
            relaxed_header("Subject", " Hello world"),
            "subject:Hello world\r\n"
        );
    }

    #[test]
    fn header_folds_are_unfolded_and_wsp_collapsed() {
        // Continuation line introduced by CRLF + two spaces, plus a tab run.
        assert_eq!(
            relaxed_header("Subject", " Hello\r\n  world\t\tagain"),
            "subject:Hello world again\r\n"
        );
    }

    #[test]
    fn header_tabs_and_spaces_are_equivalent() {
        assert_eq!(
            relaxed_header("To", " a@example.com,\t\tb@example.com "),
            "to:a@example.com, b@example.com\r\n"
        );
    }

    #[test]
    fn header_trailing_wsp_is_stripped() {
        assert_eq!(
            relaxed_header("From", " Alice <a@x.test>  \t"),
            "from:Alice <a@x.test>\r\n"
        );
    }

    #[test]
    fn header_name_with_surrounding_wsp_and_empty_value() {
        assert_eq!(relaxed_header("  X-Empty \t", "   "), "x-empty:\r\n");
    }

    #[test]
    fn body_strips_end_of_line_wsp_and_keeps_inner_collapse() {
        assert_eq!(
            relaxed_body("foo  \t bar  \r\nbaz\t\r\n"),
            "foo bar\r\nbaz\r\n"
        );
    }

    #[test]
    fn body_adds_missing_trailing_crlf() {
        assert_eq!(relaxed_body("foo"), "foo\r\n");
    }

    #[test]
    fn body_trailing_empty_lines_are_removed() {
        assert_eq!(relaxed_body("foo\r\n\r\n   \r\n\t\r\n"), "foo\r\n");
    }

    #[test]
    fn empty_body_is_a_single_crlf() {
        assert_eq!(relaxed_body(""), "\r\n");
        assert_eq!(relaxed_body("\r\n"), "\r\n");
        assert_eq!(relaxed_body(" \t\r\n\r\n"), "\r\n");
    }

    #[test]
    fn body_leading_wsp_is_preserved_as_a_single_space() {
        // RFC 6376 §3.4.4 only removes WSP at the *end* of a line.
        assert_eq!(relaxed_body("  indented\r\n"), " indented\r\n");
    }
}
