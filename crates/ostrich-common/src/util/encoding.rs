// RFC 7468: PEM encoding
// NIST 800-53: SI-10 - Information input validation

use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};

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
}
