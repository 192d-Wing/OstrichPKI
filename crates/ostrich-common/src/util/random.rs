// NIST 800-53: SC-13 - Cryptographic protection
// RFC 5280 §4.1.2.2 - Serial number generation

use crate::error::Result;
// rand 0.10: `fill_bytes` lives on the base `Rng` trait (`RngCore` is deprecated).
use rand::{CryptoRng, Rng, rng};

/// Generate cryptographically secure random bytes
/// NIST 800-53: SC-13 - Use cryptographically secure RNG
pub fn secure_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a random serial number suitable for X.509 certificates
/// RFC 5280 §4.1.2.2 - Serial number must be positive and ≤ 20 octets
pub fn generate_serial_number() -> Result<Vec<u8>> {
    // Generate 16 bytes (128 bits) of random data
    let mut bytes = secure_random_bytes(16);

    // Ensure the high bit is not set (must be positive)
    bytes[0] &= 0x7F;

    // Ensure not all zeros
    if bytes.iter().all(|&b| b == 0) {
        bytes[0] = 0x01;
    }

    Ok(bytes)
}

/// Generate random bytes using a custom RNG
pub fn random_bytes_with_rng<R: Rng + CryptoRng>(rng: &mut R, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_bytes() {
        let bytes1 = secure_random_bytes(32);
        let bytes2 = secure_random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Extremely unlikely to be the same
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_generate_serial_number() {
        let sn = generate_serial_number().unwrap();

        // Should be 16 bytes
        assert_eq!(sn.len(), 16);

        // High bit must not be set (positive)
        assert_eq!(sn[0] & 0x80, 0);

        // Should not be all zeros
        assert!(sn.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_serial_numbers_are_unique() {
        let sn1 = generate_serial_number().unwrap();
        let sn2 = generate_serial_number().unwrap();

        // Extremely unlikely to be the same
        assert_ne!(sn1, sn2);
    }
}
