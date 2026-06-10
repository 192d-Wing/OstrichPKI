//! Minimal DER TLV encode/decode helpers for OCSP structures
//!
//! The OCSP responder hand-rolls its DER so that the to-be-signed
//! ResponseData bytes are produced exactly once and embedded verbatim in the
//! BasicOCSPResponse (RFC 6960 §4.2.1 requires the signature to cover the
//! DER encoding of tbsResponseData — any re-encoding divergence breaks
//! verification).
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - **RFC 6960 §4.2.1**: BasicOCSPResponse / ResponseData DER encoding
//! - **ITU-T X.690**: DER encoding rules (definite-length, minimal lengths)
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FDP_OCSPG_EXT.1**: Properly formatted OCSP responses per RFC 6960
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **SC-17**: PKI Certificates - standards-conformant status responses
//! - **SI-10**: Information Input Validation - strict TLV parsing helpers

use chrono::{DateTime, Datelike, Timelike, Utc};

// Universal tags
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_ENUMERATED: u8 = 0x0A;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

/// Encode a DER definite length (X.690 §8.1.3: short form < 128, otherwise
/// minimal long form).
pub(crate) fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    // Long form: minimal number of base-256 octets
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut out = Vec::with_capacity(1 + bytes.len() - first);
    out.push(0x80 | (bytes.len() - first) as u8);
    out.extend_from_slice(&bytes[first..]);
    out
}

/// Encode a complete TLV: tag, DER length, content.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = der_length(content.len());
    let mut out = Vec::with_capacity(1 + len.len() + content.len());
    out.push(tag);
    out.extend_from_slice(&len);
    out.extend_from_slice(content);
    out
}

/// SEQUENCE wrapper.
pub(crate) fn seq(content: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, content)
}

/// OBJECT IDENTIFIER from dotted string.
pub(crate) fn oid(dotted: &str) -> crate::Result<Vec<u8>> {
    let oid = der::asn1::ObjectIdentifier::new(dotted)
        .map_err(|e| crate::Error::InternalError(format!("Invalid OID '{}': {}", dotted, e)))?;
    Ok(tlv(TAG_OID, oid.as_bytes()))
}

/// OCTET STRING.
pub(crate) fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, bytes)
}

/// NULL.
pub(crate) fn null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

/// ENUMERATED with a single-octet value.
pub(crate) fn enumerated(value: u8) -> Vec<u8> {
    tlv(TAG_ENUMERATED, &[value])
}

/// Positive INTEGER from unsigned magnitude bytes (RFC 5280 §4.1.2.2 serial
/// numbers are positive). Canonicalizes per X.690 §8.3: minimal length, a
/// leading 0x00 only when the high bit of the magnitude is set.
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|&b| b != 0);
    let content: Vec<u8> = match first {
        None => vec![0x00],
        Some(i) => {
            let stripped = &magnitude[i..];
            if stripped[0] & 0x80 != 0 {
                let mut v = Vec::with_capacity(stripped.len() + 1);
                v.push(0x00);
                v.extend_from_slice(stripped);
                v
            } else {
                stripped.to_vec()
            }
        }
    };
    tlv(TAG_INTEGER, &content)
}

/// GeneralizedTime in DER form: YYYYMMDDHHMMSSZ (X.690 §11.7 - UTC, no
/// fractional seconds).
///
/// NIAP PP-CA: FPT_STM.1 - reliable timestamps in OCSP responses.
pub(crate) fn generalized_time(dt: &DateTime<Utc>) -> Vec<u8> {
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    tlv(TAG_GENERALIZED_TIME, s.as_bytes())
}

/// BIT STRING with zero unused bits (signature values are octet-aligned).
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0x00); // unused bits
    content.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &content)
}

/// Read one TLV from `input`.
///
/// Returns `(tag, content, rest)` where `content` is the value octets and
/// `rest` is everything after the TLV. Returns `None` on truncated or
/// non-DER input (indefinite lengths, over-long length encodings).
///
/// NIST 800-53: SI-10 - strict input validation of DER structures.
pub(crate) fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let first_len = input[1];
    let (len, header): (usize, usize) = if first_len < 0x80 {
        (first_len as usize, 2)
    } else {
        let num_octets = (first_len & 0x7F) as usize;
        // Reject indefinite (0x80) and unreasonable lengths (DoS guard)
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut len: usize = 0;
        for &b in &input[2..2 + num_octets] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + num_octets)
    };
    if input.len() < header + len {
        return None;
    }
    Some((tag, &input[header..header + len], &input[header + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_der_length_short_form() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(1), vec![0x01]);
        assert_eq!(der_length(127), vec![0x7F]);
    }

    #[test]
    fn test_der_length_long_form() {
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xFF]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(65535), vec![0x82, 0xFF, 0xFF]);
        assert_eq!(der_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_tlv_roundtrip_short() {
        let encoded = tlv(TAG_OCTET_STRING, &[0xDE, 0xAD]);
        assert_eq!(encoded, vec![0x04, 0x02, 0xDE, 0xAD]);
        let (tag, content, rest) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, TAG_OCTET_STRING);
        assert_eq!(content, &[0xDE, 0xAD]);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_tlv_roundtrip_long_form() {
        let payload = vec![0xAB; 300];
        let encoded = tlv(TAG_SEQUENCE, &payload);
        assert_eq!(&encoded[..4], &[0x30, 0x82, 0x01, 0x2C]);
        let (tag, content, rest) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert_eq!(content, payload.as_slice());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_read_tlv_truncated() {
        assert!(read_tlv(&[]).is_none());
        assert!(read_tlv(&[0x30]).is_none());
        assert!(read_tlv(&[0x30, 0x05, 0x01]).is_none()); // declared 5, got 1
        assert!(read_tlv(&[0x30, 0x80, 0x00]).is_none()); // indefinite length
    }

    #[test]
    fn test_unsigned_integer_canonicalization() {
        // Zero
        assert_eq!(unsigned_integer(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(unsigned_integer(&[0x00, 0x00]), vec![0x02, 0x01, 0x00]);
        // Simple positive
        assert_eq!(unsigned_integer(&[0x05]), vec![0x02, 0x01, 0x05]);
        // Leading zeros stripped
        assert_eq!(unsigned_integer(&[0x00, 0x05]), vec![0x02, 0x01, 0x05]);
        // High bit set requires 0x00 prefix to stay positive
        assert_eq!(unsigned_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(
            unsigned_integer(&[0x00, 0x00, 0xFF, 0x01]),
            vec![0x02, 0x03, 0x00, 0xFF, 0x01]
        );
    }

    #[test]
    fn test_generalized_time_format() {
        let dt = Utc.with_ymd_and_hms(2026, 6, 10, 12, 34, 56).unwrap();
        let encoded = generalized_time(&dt);
        assert_eq!(encoded[0], TAG_GENERALIZED_TIME);
        assert_eq!(encoded[1], 15);
        assert_eq!(&encoded[2..], b"20260610123456Z");
    }

    #[test]
    fn test_bit_string_zero_unused_bits() {
        let encoded = bit_string(&[0xAA, 0xBB]);
        assert_eq!(encoded, vec![0x03, 0x03, 0x00, 0xAA, 0xBB]);
    }

    #[test]
    fn test_oid_encoding() {
        // sha256WithRSAEncryption 1.2.840.113549.1.1.11
        let encoded = oid("1.2.840.113549.1.1.11").unwrap();
        assert_eq!(
            encoded,
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            ]
        );
    }

    #[test]
    fn test_enumerated() {
        assert_eq!(enumerated(0), vec![0x0A, 0x01, 0x00]);
        assert_eq!(enumerated(6), vec![0x0A, 0x01, 0x06]);
    }
}
