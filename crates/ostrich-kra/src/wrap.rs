//! Key-encryption-key (KEK) wrapping for escrowed private keys
//!
//! Escrowed private keys are encrypted with a per-escrow 256-bit KEK using
//! AES-256-GCM (NIST SP 800-38D). The KEK itself is never stored; it is split
//! into M-of-N Shamir shares and distributed to recovery agents. The escrow
//! record's certificate ID is bound into the ciphertext as AEAD associated
//! data, so a wrapped key cannot be swapped between escrow records without
//! detection.
//!
//! Wire format of a wrapped key: `nonce (12 bytes) || ciphertext || GCM tag (16 bytes)`.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: SC-13 (Cryptographic Protection) - AES-256-GCM via ring
//! - NIST 800-53: SI-12 - KEK and plaintext key material zeroized after use
//! - NIAP PP-CA: FCS_COP.1 - approved symmetric algorithm for key wrapping
//! - NIAP PP-CA: FCS_CKM.4 - Zeroizing wrappers destroy key material on drop
//! - FIPS 197 / SP 800-38D: AES-256 in Galois/Counter Mode

use crate::{Error, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

/// KEK length in bytes (AES-256)
pub const KEK_LEN: usize = 32;

/// Generate a fresh random 256-bit KEK.
///
/// Uses the OS CSPRNG via ring's `SystemRandom`. The returned buffer is
/// zeroized on drop; callers must not copy it out of the `Zeroizing` wrapper.
pub fn generate_kek() -> Result<Zeroizing<Vec<u8>>> {
    let mut kek = Zeroizing::new(vec![0u8; KEK_LEN]);
    SystemRandom::new()
        .fill(&mut kek)
        .map_err(|_| Error::KeyWrap("Failed to generate KEK".to_string()))?;
    Ok(kek)
}

/// Encrypt (wrap) a private key under the given KEK.
///
/// `aad` binds context into the ciphertext (the escrow's certificate ID);
/// unwrapping with different associated data fails authentication.
pub fn wrap_key(kek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = gcm_key(kek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| Error::KeyWrap("Failed to generate nonce".to_string()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::KeyWrap("Key wrapping failed".to_string()))?;

    let mut wrapped = Vec::with_capacity(NONCE_LEN + in_out.len());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.append(&mut in_out);
    Ok(wrapped)
}

/// Decrypt (unwrap) a private key under the given KEK.
///
/// Fails closed on any authentication failure: wrong KEK, tampered
/// ciphertext, or mismatched associated data all return `Error::KeyWrap`
/// without distinguishing the cause (NIST 800-53: SI-11).
pub fn unwrap_key(kek: &[u8], wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(Error::KeyWrap("Wrapped key too short".to_string()));
    }
    let key = gcm_key(kek)?;

    let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| Error::KeyWrap("Invalid nonce".to_string()))?;

    let mut in_out = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::KeyWrap("Key unwrapping failed".to_string()))?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

fn gcm_key(kek: &[u8]) -> Result<LessSafeKey> {
    if kek.len() != KEK_LEN {
        return Err(Error::KeyWrap(format!(
            "KEK must be {} bytes, got {}",
            KEK_LEN,
            kek.len()
        )));
    }
    let unbound = UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|_| Error::KeyWrap("Invalid KEK".to_string()))?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = generate_kek().unwrap();
        let plaintext = b"-----BEGIN PRIVATE KEY----- test material";
        let aad = b"certificate-id-1234";

        let wrapped = wrap_key(&kek, plaintext, aad).unwrap();
        assert_ne!(&wrapped[NONCE_LEN..], plaintext.as_slice());

        let unwrapped = unwrap_key(&kek, &wrapped, aad).unwrap();
        assert_eq!(unwrapped.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn unwrap_fails_with_wrong_kek() {
        let kek = generate_kek().unwrap();
        let other_kek = generate_kek().unwrap();
        let wrapped = wrap_key(&kek, b"secret", b"aad").unwrap();
        assert!(unwrap_key(&other_kek, &wrapped, b"aad").is_err());
    }

    #[test]
    fn unwrap_fails_with_tampered_ciphertext() {
        let kek = generate_kek().unwrap();
        let mut wrapped = wrap_key(&kek, b"secret", b"aad").unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(unwrap_key(&kek, &wrapped, b"aad").is_err());
    }

    #[test]
    fn unwrap_fails_with_wrong_aad() {
        let kek = generate_kek().unwrap();
        let wrapped = wrap_key(&kek, b"secret", b"escrow-a").unwrap();
        assert!(unwrap_key(&kek, &wrapped, b"escrow-b").is_err());
    }

    #[test]
    fn wrap_produces_unique_nonces() {
        let kek = generate_kek().unwrap();
        let a = wrap_key(&kek, b"secret", b"aad").unwrap();
        let b = wrap_key(&kek, b"secret", b"aad").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn rejects_bad_kek_length() {
        assert!(wrap_key(&[0u8; 16], b"secret", b"aad").is_err());
        assert!(unwrap_key(&[0u8; 16], &[0u8; 64], b"aad").is_err());
    }
}
