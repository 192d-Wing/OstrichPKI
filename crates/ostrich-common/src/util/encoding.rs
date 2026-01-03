// RFC 7468: PEM encoding
// RFC 4648 §5: Base64url encoding (for JWS/JWT)
// NIST 800-53: SI-10 - Information input validation

use crate::error::{Error, Result};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

/// Encode bytes to base64
pub fn encode_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 to bytes
/// NIST 800-53: SI-10 - Validate input
pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(data)
        .map_err(|e| Error::Decoding(format!("Base64 decode error: {}", e)))
}

/// Encode bytes to base64url (RFC 4648 §5)
/// Used for JWS/JWT encoding - no padding, URL-safe alphabet
pub fn encode_base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url to bytes (RFC 4648 §5)
/// Used for JWS/JWT decoding - no padding, URL-safe alphabet
/// NIST 800-53: SI-10 - Validate input
pub fn decode_base64url(data: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| Error::Decoding(format!("Base64url decode error: {}", e)))
}

/// Encode bytes to hexadecimal
pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hexadecimal to bytes
/// NIST 800-53: SI-10 - Validate input
pub fn decode_hex(data: &str) -> Result<Vec<u8>> {
    hex::decode(data).map_err(|e| Error::Decoding(format!("Hex decode error: {}", e)))
}

/// Encode DER data to PEM format
/// RFC 7468 §2 - PEM encoding
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = STANDARD.encode(der);
    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        chunk_string(&encoded, 64),
        label
    )
}

/// Decode PEM data to DER format
/// RFC 7468 §2 - PEM decoding
/// NIST 800-53: SI-10 - Validate input
pub fn pem_to_der(pem: &str, expected_label: Option<&str>) -> Result<Vec<u8>> {
    let pem = pem.trim();

    // Find BEGIN and END markers
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";

    let begin_idx = pem
        .find(begin_marker)
        .ok_or_else(|| Error::InvalidPem("Missing BEGIN marker".to_string()))?;

    let end_idx = pem
        .find(end_marker)
        .ok_or_else(|| Error::InvalidPem("Missing END marker".to_string()))?;

    // Extract label
    let label_start = begin_idx + begin_marker.len();
    let label_end = pem[label_start..]
        .find("-----")
        .ok_or_else(|| Error::InvalidPem("Malformed BEGIN marker".to_string()))?
        + label_start;
    let label = &pem[label_start..label_end];

    // Validate label if expected
    if let Some(expected) = expected_label
        && label != expected
    {
        return Err(Error::InvalidPem(format!(
            "Expected label '{}', got '{}'",
            expected, label
        )));
    }

    // Extract base64 content
    let content_start = label_end + 5; // "-----"
    let content = &pem[content_start..end_idx];

    // Remove whitespace and decode
    let content_clean: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    decode_base64(&content_clean)
}

/// Split a string into chunks of a given size with newlines
fn chunk_string(s: &str, chunk_size: usize) -> String {
    s.as_bytes()
        .chunks(chunk_size)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode_hex(data);
        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_pem_roundtrip() {
        let der = b"This is DER data";
        let pem = der_to_pem(der, "TEST DATA");
        assert!(pem.contains("-----BEGIN TEST DATA-----"));
        assert!(pem.contains("-----END TEST DATA-----"));

        let decoded = pem_to_der(&pem, Some("TEST DATA")).unwrap();
        assert_eq!(der.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_pem_invalid_label() {
        let pem = "-----BEGIN FOO-----\nZGF0YQ==\n-----END FOO-----\n";
        let result = pem_to_der(pem, Some("BAR"));
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode_base64url(data);
        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());

        // Verify no padding
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_base64url_vs_base64() {
        // Test data with characters that differ between base64 and base64url
        let data = &[0xfb, 0xff, 0xbf]; // Results in '+' and '/' in standard base64

        let standard = encode_base64(data);
        let url_safe = encode_base64url(data);

        // Standard base64 uses + and /
        // Base64url uses - and _
        assert_ne!(standard, url_safe);

        // Both should decode to same data
        assert_eq!(decode_base64(&standard).unwrap(), data);
        assert_eq!(decode_base64url(&url_safe).unwrap(), data);
    }

    #[test]
    fn test_base64url_rfc_example() {
        // RFC 7515 Appendix C example
        let data = b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
        let encoded = encode_base64url(data);

        // Should not contain padding
        assert!(!encoded.contains('='));

        // Should decode correctly
        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }
}
