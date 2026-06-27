//! EST profile-label parsing (RFC 7030 §3.2.2 arbitrary label).
//!
//! A label encodes the desired certificate profile and constraints in the
//! well-known path: `/.well-known/est/{label}/simpleenroll`. The scheme is:
//!
//! ```text
//!   PT<ptval>[-AK<akval>][-VP<vpval>][-CC<ccval>]
//! ```
//!
//! - `ptval` — profile type: `DEV`, `TLS`, `DC`, `EMAIL`, `IPSEC`, `MCAUTH`,
//!   `MCKEY`, `KERB`. Selects the certificate profile.
//! - `akval` (optional) — key algorithm: `2048` (RSA-2048) or `P384` (EC P-384).
//!   Selects which CA backend issues (e.g. an RSA CA vs an EC CA).
//! - `vpval` (optional) — requested validity in days.
//! - `ccval` (optional) — Combatant Command / Service / Agency code.
//!
//! Parsing is strict (SI-10): unknown prefixes, duplicate fields, out-of-range
//! values, or unknown profile/key tokens are rejected so a label can never
//! resolve to an unintended profile or backend.
//!
//! COMPLIANCE MAPPING:
//! - RFC 7030 §3.2.2 - arbitrary-label path segment
//! - NIST 800-53: SI-10 (input validation), AC-3 (the resolved profile/backend
//!   gates issuance)

use thiserror::Error;

/// Maximum accepted requested-validity in days (sanity bound).
const MAX_VALIDITY_DAYS: u32 = 1185; // ~39 months, the CABF maximum era ceiling
/// Maximum accepted CC/S/A code length.
const MAX_CCSA_LEN: usize = 16;

/// Errors from parsing an EST profile label.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabelError {
    #[error("empty label")]
    Empty,
    #[error("label must begin with a PT<profile-type> segment")]
    MissingProfileType,
    #[error("unknown profile type '{0}'")]
    UnknownProfileType(String),
    #[error("profile type '{0}' is recognized but not yet supported for issuance")]
    UnsupportedProfileType(String),
    #[error("unknown key algorithm '{0}' (expected 2048 or P384)")]
    UnknownKeyAlgorithm(String),
    #[error("invalid validity '{0}' (expected 1..={1} days)")]
    InvalidValidity(String, u32),
    #[error("invalid CC/S/A code '{0}'")]
    InvalidCcsa(String),
    #[error("unknown or duplicate label segment '{0}'")]
    BadSegment(String),
}

/// The key algorithm a label requests; used to select the issuing CA backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgo {
    /// RSA-2048.
    Rsa2048,
    /// EC P-384.
    EcP384,
}

impl KeyAlgo {
    /// The canonical token as it appears in the label (`2048` / `P384`).
    pub fn token(self) -> &'static str {
        match self {
            KeyAlgo::Rsa2048 => "2048",
            KeyAlgo::EcP384 => "P384",
        }
    }

    /// Parse a key-algorithm token, or `None` if unrecognized. The single source
    /// of truth for which AK tokens exist (used by the parser and by config
    /// validation so an operator can't map an unreachable token to a backend).
    pub fn from_token(token: &str) -> Option<KeyAlgo> {
        match token {
            "2048" => Some(KeyAlgo::Rsa2048),
            "P384" => Some(KeyAlgo::EcP384),
            _ => None,
        }
    }
}

/// A parsed, validated EST profile label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLabel {
    /// Raw, validated profile-type token (e.g. "TLS").
    pub profile_type: String,
    /// Requested key algorithm (selects the CA backend), if specified.
    pub key_algo: Option<KeyAlgo>,
    /// Requested validity in days, if specified.
    pub validity_days: Option<u32>,
    /// CC/S/A code, if specified.
    pub ccsa: Option<String>,
}

/// Recognized profile-type tokens (whether or not currently issuable).
const KNOWN_PROFILE_TYPES: [&str; 8] = [
    "DEV", "TLS", "DC", "EMAIL", "IPSEC", "MCAUTH", "MCKEY", "KERB",
];

impl ParsedLabel {
    /// Map the profile type to an OstrichPKI certificate profile name.
    ///
    /// Only the profile types backed by a registered profile are issuable today;
    /// the rest are recognized but rejected (so the label scheme is forward
    /// compatible without silently mis-issuing).
    pub fn profile_name(&self) -> Result<&'static str, LabelError> {
        match self.profile_type.as_str() {
            "DEV" => Ok("tls_client"),
            "TLS" => Ok("tls_server"),
            "DC" => Ok("tls_server_client"),
            other => Err(LabelError::UnsupportedProfileType(other.to_string())),
        }
    }
}

/// Parse a label string into a validated [`ParsedLabel`].
pub fn parse_label(raw: &str) -> Result<ParsedLabel, LabelError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(LabelError::Empty);
    }

    let mut segments = raw.split('-');

    // First segment is mandatory: PT<ptval>.
    let first = segments.next().ok_or(LabelError::MissingProfileType)?;
    let ptval = first
        .strip_prefix("PT")
        .ok_or(LabelError::MissingProfileType)?;
    if !KNOWN_PROFILE_TYPES.contains(&ptval) {
        return Err(LabelError::UnknownProfileType(ptval.to_string()));
    }

    let mut key_algo = None;
    let mut validity_days = None;
    let mut ccsa = None;

    for seg in segments {
        if let Some(v) = seg.strip_prefix("AK") {
            if key_algo.is_some() {
                return Err(LabelError::BadSegment(seg.to_string()));
            }
            key_algo = Some(
                KeyAlgo::from_token(v)
                    .ok_or_else(|| LabelError::UnknownKeyAlgorithm(v.to_string()))?,
            );
        } else if let Some(v) = seg.strip_prefix("VP") {
            if validity_days.is_some() {
                return Err(LabelError::BadSegment(seg.to_string()));
            }
            let days: u32 = v
                .parse()
                .map_err(|_| LabelError::InvalidValidity(v.to_string(), MAX_VALIDITY_DAYS))?;
            if days == 0 || days > MAX_VALIDITY_DAYS {
                return Err(LabelError::InvalidValidity(v.to_string(), MAX_VALIDITY_DAYS));
            }
            validity_days = Some(days);
        } else if let Some(v) = seg.strip_prefix("CC") {
            if ccsa.is_some() {
                return Err(LabelError::BadSegment(seg.to_string()));
            }
            if v.is_empty()
                || v.len() > MAX_CCSA_LEN
                || !v.chars().all(|c| c.is_ascii_alphanumeric())
            {
                return Err(LabelError::InvalidCcsa(v.to_string()));
            }
            ccsa = Some(v.to_string());
        } else {
            return Err(LabelError::BadSegment(seg.to_string()));
        }
    }

    Ok(ParsedLabel {
        profile_type: ptval.to_string(),
        key_algo,
        validity_days,
        ccsa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_label() {
        let p = parse_label("PTTLS-AKP384-VP397-CCUSAF").unwrap();
        assert_eq!(p.profile_type, "TLS");
        assert_eq!(p.key_algo, Some(KeyAlgo::EcP384));
        assert_eq!(p.validity_days, Some(397));
        assert_eq!(p.ccsa.as_deref(), Some("USAF"));
        assert_eq!(p.profile_name().unwrap(), "tls_server");
    }

    #[test]
    fn parses_minimal_label() {
        let p = parse_label("PTDEV").unwrap();
        assert_eq!(p.profile_type, "DEV");
        assert_eq!(p.key_algo, None);
        assert_eq!(p.validity_days, None);
        assert_eq!(p.ccsa, None);
        assert_eq!(p.profile_name().unwrap(), "tls_client");
    }

    #[test]
    fn key_algo_selects_backend_token() {
        assert_eq!(
            parse_label("PTDC-AK2048").unwrap().key_algo,
            Some(KeyAlgo::Rsa2048)
        );
        assert_eq!(parse_label("PTDC").unwrap().profile_name().unwrap(), "tls_server_client");
    }

    #[test]
    fn rejects_unknown_profile_type() {
        assert_eq!(
            parse_label("PTBOGUS"),
            Err(LabelError::UnknownProfileType("BOGUS".to_string()))
        );
    }

    #[test]
    fn recognized_but_unsupported_profile_type_errs_on_resolve() {
        let p = parse_label("PTKERB").unwrap();
        assert_eq!(
            p.profile_name(),
            Err(LabelError::UnsupportedProfileType("KERB".to_string()))
        );
    }

    #[test]
    fn rejects_missing_pt_prefix() {
        assert_eq!(parse_label("TLS-AKP384"), Err(LabelError::MissingProfileType));
    }

    #[test]
    fn rejects_unknown_key_algo() {
        assert_eq!(
            parse_label("PTTLS-AK9999"),
            Err(LabelError::UnknownKeyAlgorithm("9999".to_string()))
        );
    }

    #[test]
    fn rejects_out_of_range_validity() {
        assert!(matches!(
            parse_label("PTTLS-VP0"),
            Err(LabelError::InvalidValidity(_, _))
        ));
        assert!(matches!(
            parse_label("PTTLS-VP99999"),
            Err(LabelError::InvalidValidity(_, _))
        ));
        assert!(matches!(
            parse_label("PTTLS-VPxyz"),
            Err(LabelError::InvalidValidity(_, _))
        ));
    }

    #[test]
    fn rejects_bad_ccsa_and_duplicates() {
        assert!(matches!(
            parse_label("PTTLS-CC$$$"),
            Err(LabelError::InvalidCcsa(_))
        ));
        assert!(matches!(
            parse_label("PTTLS-AKP384-AK2048"),
            Err(LabelError::BadSegment(_))
        ));
        assert!(matches!(
            parse_label("PTTLS-XX1"),
            Err(LabelError::BadSegment(_))
        ));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(parse_label("   "), Err(LabelError::Empty));
    }

    #[test]
    fn key_algo_from_token_roundtrip() {
        assert_eq!(KeyAlgo::from_token("2048"), Some(KeyAlgo::Rsa2048));
        assert_eq!(KeyAlgo::from_token("P384"), Some(KeyAlgo::EcP384));
        assert_eq!(KeyAlgo::from_token("4096"), None);
        for a in [KeyAlgo::Rsa2048, KeyAlgo::EcP384] {
            assert_eq!(KeyAlgo::from_token(a.token()), Some(a));
        }
    }
}
