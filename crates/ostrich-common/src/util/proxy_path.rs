//! Raw-path validation for BFF reverse proxies.
//!
//! A backend-for-frontend (web-ui, npe-portal) that forwards `/{svc}/...` to a
//! backend must build the backend path from the **raw**, still percent-encoded
//! request path, never from a framework's percent-decoded `{*path}` capture:
//! decoding first lets `%2F`, `%3F` or `%2E%2E` change which backend resource
//! (or query) the proxy requests on the signed-in user's behalf. This module
//! derives and validates that remainder. It is pure `std`; the rejection
//! logging stays in each service, which owns its session and request context.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - canonical, strict
//!   path validation at the BFF boundary
//! - NIST 800-53: AC-3 (Access Enforcement) - the proxy cannot be steered to a
//!   backend resource other than the one the URL names (confused deputy)
//! - NIST 800-53: AC-4 (Information Flow Enforcement) - requests flow only to
//!   the backend resource the URL names
//! - NIAP PP-CA: FDP_ACF.1 (supporting) - ensures the backend's access control
//!   decision is made on the object named by the request
//! - RFC 3986 §2.1 (percent-encoding), §3.3 (path segments), §5.2.4 (dot segments)

/// Why a proxied request path was refused. The `reason()` strings are stable,
/// non-secret tokens suitable for the audit/security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    /// The raw path does not start with `/{svc}/` (or `/api/{svc}/`).
    MissingServicePrefix,
    /// An empty segment (`//`, trailing `/`, or nothing after the prefix).
    EmptySegment,
    /// A `.` or `..` segment, literal or percent-encoded.
    DotSegment,
    /// A `%` not followed by two hex digits.
    MalformedPercentEncoding,
    /// A segment that decodes to `/`, `?`, `#` or `\` (a delimiter that was
    /// smuggled in percent-encoded form).
    EncodedDelimiter,
    /// A segment that decodes to a C0 control character or DEL (incl. NUL).
    ControlCharacter,
}

impl PathRejection {
    /// Stable, non-secret reason token for the security log.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::MissingServicePrefix => "missing_service_prefix",
            Self::EmptySegment => "empty_segment",
            Self::DotSegment => "dot_segment",
            Self::MalformedPercentEncoding => "malformed_percent_encoding",
            Self::EncodedDelimiter => "encoded_delimiter",
            Self::ControlCharacter => "control_character",
        }
    }
}

/// Strictly percent-decode one path segment (RFC 3986 §2.1). Any `%` not
/// followed by exactly two hex digits is an error rather than being passed
/// through, so ambiguous input cannot be interpreted differently by the backend.
///
/// # Errors
///
/// [`PathRejection::MalformedPercentEncoding`] on a truncated or non-hex escape.
pub fn percent_decode_segment(segment: &str) -> Result<Vec<u8>, PathRejection> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex);
            let lo = bytes.next().and_then(hex);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                _ => return Err(PathRejection::MalformedPercentEncoding),
            }
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

/// Derive the backend path from the **raw** (still percent-encoded) request
/// path and validate it.
///
/// `raw_path` is `request.uri().path()` as seen inside the proxy router. Both
/// BFFs mount their proxy with `.nest("/api", ...)`, so axum has already
/// stripped `/api` and the path is `/{svc}/...`; `/api/{svc}/...` is accepted
/// too in case the mount changes. On success the remainder after the prefix is
/// returned unchanged (still encoded) so the backend decodes it exactly once,
/// as it would for a direct request.
///
/// Each segment is percent-decoded only for inspection; the request is
/// refused if any segment is empty, is `.`/`..` (literal or encoded), contains
/// a malformed escape, decodes to a delimiter (`/`, `?`, `#`, `\`), or decodes
/// to a control character (0x00-0x1F, 0x7F). This stops an encoded
/// `%2F`/`%3F`/`%2E%2E` from changing which backend resource (or query) the
/// proxy requests on the signed-in user's behalf.
///
/// # Errors
///
/// The first [`PathRejection`] found; callers must fail closed (no backend
/// contact) on any error.
pub fn validate_backend_path<'a>(raw_path: &'a str, svc: &str) -> Result<&'a str, PathRejection> {
    let rest = raw_path
        .strip_prefix("/api")
        .filter(|r| r.starts_with('/'))
        .unwrap_or(raw_path);
    let rest = rest
        .strip_prefix('/')
        .and_then(|r| r.strip_prefix(svc))
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(PathRejection::MissingServicePrefix)?;

    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(PathRejection::EmptySegment);
        }
        let decoded = percent_decode_segment(segment)?;
        if decoded == b"." || decoded == b".." {
            return Err(PathRejection::DotSegment);
        }
        for &b in &decoded {
            match b {
                b'/' | b'?' | b'#' | b'\\' => return Err(PathRejection::EncodedDelimiter),
                0x00..=0x1F | 0x7F => return Err(PathRejection::ControlCharacter),
                _ => {}
            }
        }
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- percent_decode_segment ----

    #[test]
    fn percent_decode_segment_decodes_and_rejects_malformed() {
        assert_eq!(percent_decode_segment("%41"), Ok(b"A".to_vec()));
        assert_eq!(percent_decode_segment("a%2fB"), Ok(b"a/B".to_vec()));
        assert_eq!(percent_decode_segment(""), Ok(Vec::new()));
        // Multibyte UTF-8 escape round-trips to the original bytes.
        assert_eq!(
            percent_decode_segment("caf%C3%A9"),
            Ok("café".as_bytes().to_vec())
        );
        for s in ["%", "%4", "%G1", "a%1", "%%41", "%\u{ff10}0"] {
            assert_eq!(
                percent_decode_segment(s),
                Err(PathRejection::MalformedPercentEncoding),
                "{s}"
            );
        }
    }

    #[test]
    fn normal_paths_are_forwarded_verbatim() {
        assert_eq!(
            validate_backend_path("/ca/api/v1/certificates", "ca"),
            Ok("api/v1/certificates")
        );
        assert_eq!(validate_backend_path("/kra/x", "kra"), Ok("x"));
        // Defensive: un-stripped `/api` mount prefix.
        assert_eq!(
            validate_backend_path("/api/ca/api/v1/certificates", "ca"),
            Ok("api/v1/certificates")
        );
        // Single dots inside a segment and dot-prefixed names are fine.
        assert_eq!(
            validate_backend_path("/est/.well-known/est/cacerts", "est"),
            Ok(".well-known/est/cacerts")
        );
        assert_eq!(validate_backend_path("/ca/a/...", "ca"), Ok("a/..."));
        assert_eq!(validate_backend_path("/ca/v1.2/x", "ca"), Ok("v1.2/x"));
    }

    #[test]
    fn legit_encoded_characters_are_forwarded_still_encoded() {
        assert_eq!(
            validate_backend_path("/ca/users/a%20b/x%40example.com", "ca"),
            Ok("users/a%20b/x%40example.com")
        );
        assert_eq!(
            validate_backend_path("/ca/users/caf%C3%A9", "ca"),
            Ok("users/caf%C3%A9")
        );
        // Double-encoding is forwarded raw; the backend decodes once to the
        // literal `%2F`, exactly as for a direct request.
        assert_eq!(validate_backend_path("/ca/a%252Fb", "ca"), Ok("a%252Fb"));
    }

    #[test]
    fn encoded_slash_is_rejected() {
        for p in ["/ca/a%2Fb", "/ca/a%2fb", "/ca/%2F", "/ca/v1/%2F..%2Fadmin"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
    }

    #[test]
    fn encoded_backslash_query_and_fragment_are_rejected() {
        for p in [
            "/ca/a%5Cb",
            "/ca/a%3Fadmin=1",
            "/ca/a%3fb",
            "/ca/a%23frag",
            "/ca/v1%3F",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
    }

    #[test]
    fn literal_and_encoded_dot_segments_are_rejected() {
        for p in [
            "/ca/..",
            "/ca/../admin",
            "/ca/v1/./x",
            "/ca/v1/.",
            "/ca/%2E%2E/admin",
            "/ca/%2e%2e/admin",
            "/ca/.%2E/admin",
            "/ca/%2E./admin",
            "/ca/%2E/admin",
            "/ca/v1/%2e",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::DotSegment),
                "{p}"
            );
        }
    }

    #[test]
    fn empty_segments_are_rejected() {
        for p in ["/ca/", "/ca//x", "/ca/a//b", "/ca/a/"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EmptySegment),
                "{p}"
            );
        }
    }

    #[test]
    fn control_characters_and_malformed_escapes_are_rejected() {
        for p in [
            "/ca/a%00b",
            "/ca/a%0Ab",
            "/ca/a%0d%0aX-Injected:1",
            "/ca/%7F",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::ControlCharacter),
                "{p}"
            );
        }
        for p in ["/ca/a%", "/ca/a%2", "/ca/a%zz", "/ca/a%G0/b"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MalformedPercentEncoding),
                "{p}"
            );
        }
    }

    #[test]
    fn wrong_or_missing_service_prefix_is_rejected() {
        for p in ["/acme/x", "/cax/x", "/ca", "ca/x", "/", ""] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MissingServicePrefix),
                "{p}"
            );
        }
    }

    // ---- QA additions (POAM-2026-10-23-43) ----

    #[test]
    fn qa_mixed_case_and_partial_encoded_dot_segments_are_rejected() {
        // Mixed-case hex in a single escape pair and partial encodings; the
        // url crate (WHATWG) and many backends treat all of these as `..`/`.`.
        for p in [
            "/ca/%2e%2E/admin",
            "/ca/%2E%2e/admin",
            "/ca/.%2e/admin",
            "/ca/%2e./admin",
            "/ca/v1/%2e%2E",
            "/ca/v1/.%2E",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::DotSegment),
                "{p}"
            );
        }
        // Three (or more) dots, encoded or not, are an ordinary segment name in
        // RFC 3986 §5.2.4 and are forwarded raw.
        assert_eq!(
            validate_backend_path("/ca/%2E%2E%2E", "ca"),
            Ok("%2E%2E%2E")
        );
        assert_eq!(validate_backend_path("/ca/..%2e.", "ca"), Ok("..%2e."));
        // A dot-dot followed by other characters is not a dot segment.
        assert_eq!(validate_backend_path("/ca/..a", "ca"), Ok("..a"));
    }

    #[test]
    fn qa_lowercase_and_extra_delimiter_escapes_are_rejected() {
        for p in ["/ca/a%5cb", "/ca/%2f", "/ca/%23", "/ca/x%2F%2F"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
        // A literal backslash (should http::Uri ever accept one) is also
        // refused: WHATWG URL parsers treat `\` as `/` for special schemes.
        assert_eq!(
            validate_backend_path("/ca/a\\..\\admin", "ca"),
            Err(PathRejection::EncodedDelimiter)
        );
        for p in ["/ca/a%09b", "/ca/a%1Fb", "/ca/a%7fb", "/ca/a%0d"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::ControlCharacter),
                "{p}"
            );
        }
        // Malformed: escape split across a `/` boundary, and a non-ASCII hex
        // lookalike after `%`.
        for p in ["/ca/a%2/F", "/ca/a%/2F", "/ca/a%\u{ff10}0"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MalformedPercentEncoding),
                "{p}"
            );
        }
    }

    #[test]
    fn qa_overlong_utf8_slash_and_dot_are_forwarded_raw_not_decoded() {
        // Documented behaviour: overlong UTF-8 encodings of `/` (%C0%AF,
        // %E0%80%AF) and `.` (%C0%AE) are NOT rejected. Their decoded bytes are
        // >= 0x80, never 0x2F/0x2E, so they cannot form a delimiter or dot
        // segment for an RFC 3986 parser; they are forwarded still encoded and
        // a conforming (UTF-8 strict) backend rejects them as invalid UTF-8.
        for (p, want) in [
            ("/ca/a%C0%AFb", "a%C0%AFb"),
            ("/ca/%C0%AF", "%C0%AF"),
            ("/ca/a%E0%80%AFb", "a%E0%80%AFb"),
            ("/ca/%C0%AE%C0%AE/admin", "%C0%AE%C0%AE/admin"),
            ("/ca/%FF%FE", "%FF%FE"),
        ] {
            assert_eq!(validate_backend_path(p, "ca"), Ok(want), "{p}");
        }
    }

    #[test]
    fn qa_trailing_slash_and_service_prefix_edge_cases() {
        // Trailing slash yields an empty final segment and is refused (no
        // proxied BFF route uses one).
        for p in ["/ca/api/v1/certificates/", "/est/.well-known/est/"] {
            let svc = if p.starts_with("/est") { "est" } else { "ca" };
            assert_eq!(
                validate_backend_path(p, svc),
                Err(PathRejection::EmptySegment),
                "{p}"
            );
        }
        // Service prefix match is exact and case-sensitive, and an encoded
        // prefix is not accepted as the prefix.
        for p in ["/CA/x", "/%63a/x", "/api/CA/x", "/apica/x", "/api"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MissingServicePrefix),
                "{p}"
            );
        }
        // `/api/` fallback is only taken for a real `/api/` segment.
        assert_eq!(
            validate_backend_path("/api/ca/x", "ca"),
            Ok("x"),
            "defensive /api fallback"
        );
    }

    // ---- QA additions (POAM-2026-10-23-46) ----

    /// Exhaustive single-byte escape table: every `%XX` (0x00-0xFF, upper- and
    /// lower-case hex) inside a segment is classified exactly as documented,
    /// and an accepted path is returned byte-for-byte (never decoded).
    #[test]
    fn qa_every_single_byte_escape_is_classified_per_spec() {
        for b in 0u8..=255 {
            let expected_err = match b {
                b'/' | b'?' | b'#' | b'\\' => Some(PathRejection::EncodedDelimiter),
                0x00..=0x1F | 0x7F => Some(PathRejection::ControlCharacter),
                _ => None,
            };
            for raw in [format!("/ca/a%{b:02X}b"), format!("/ca/a%{b:02x}b")] {
                let got = validate_backend_path(&raw, "ca");
                match expected_err {
                    Some(e) => assert_eq!(got, Err(e), "{raw}"),
                    None => assert_eq!(got, Ok(&raw["/ca/".len()..]), "{raw}"),
                }
            }
            // A segment that is exactly one escape: `%2E` alone is a dot segment.
            let alone = format!("/est/x/%{b:02X}");
            let want_alone = if b == b'.' {
                Err(PathRejection::DotSegment)
            } else if let Some(e) = expected_err {
                Err(e)
            } else {
                Ok(&alone["/est/".len()..])
            };
            assert_eq!(validate_backend_path(&alone, "est"), want_alone, "{alone}");
        }
    }

    /// The accepted remainder is always a suffix (sub-slice) of the raw input:
    /// the validator never rewrites, normalises or decodes what it forwards.
    #[test]
    fn qa_accepted_remainder_is_an_unmodified_suffix_of_the_input() {
        for raw in [
            "/ca/api/v1/certificates",
            "/api/ca/api/v1/certificates",
            "/est/.well-known/est/simpleenroll",
            "/ca/users/a%20b/x%40example.com",
            "/ca/a%252Fb",
            "/ca/%2E%2E%2E",
        ] {
            let svc = if raw.contains("/est/") { "est" } else { "ca" };
            let out = validate_backend_path(raw, svc).expect(raw);
            assert!(raw.ends_with(out), "{raw} -> {out}");
            assert_eq!(out.as_ptr(), raw[raw.len() - out.len()..].as_ptr());
        }
    }

    #[test]
    fn qa_est_service_and_api_prefix_variants_fail_closed() {
        for (p, want) in [
            ("/api/est/%2E%2E", PathRejection::DotSegment),
            ("/api/est/a%2fb", PathRejection::EncodedDelimiter),
            ("/est/a%5Cb", PathRejection::EncodedDelimiter),
            ("/est/a%00", PathRejection::ControlCharacter),
            ("/est/a%zz", PathRejection::MalformedPercentEncoding),
            ("/est/a/", PathRejection::EmptySegment),
            // A doubled slash after `/api` is not a service prefix.
            ("/api//est/x", PathRejection::MissingServicePrefix),
            // The CA prefix does not satisfy the EST check (no cross-service).
            ("/ca/x", PathRejection::MissingServicePrefix),
        ] {
            assert_eq!(validate_backend_path(p, "est"), Err(want), "{p}");
        }
        // The first offending segment wins; later segments are not reached.
        assert_eq!(
            validate_backend_path("/ca/%2E%2E/a%2Fb", "ca"),
            Err(PathRejection::DotSegment)
        );
        assert_eq!(
            validate_backend_path("/ca/a%2Fb/..", "ca"),
            Err(PathRejection::EncodedDelimiter)
        );
    }

    #[test]
    fn qa_rejection_reason_tokens_are_stable() {
        assert_eq!(
            PathRejection::MissingServicePrefix.reason(),
            "missing_service_prefix"
        );
        assert_eq!(PathRejection::EmptySegment.reason(), "empty_segment");
        assert_eq!(PathRejection::DotSegment.reason(), "dot_segment");
        assert_eq!(
            PathRejection::MalformedPercentEncoding.reason(),
            "malformed_percent_encoding"
        );
        assert_eq!(
            PathRejection::EncodedDelimiter.reason(),
            "encoded_delimiter"
        );
        assert_eq!(
            PathRejection::ControlCharacter.reason(),
            "control_character"
        );
    }
}
