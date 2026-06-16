//! Shamir's Secret Sharing implementation
//!
//! Implements (M, N) threshold secret sharing where:
//! - N = total number of shares
//! - M = minimum shares needed to reconstruct secret
//!
//! Based on Shamir's Secret Sharing algorithm using polynomial interpolation
//! over finite field GF(256).
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FCS_CKM.2**: Cryptographic Key Distribution
//!   - [`ShamirSecretSharing::split`]: Splits secret into N shares with M threshold
//!   - Enables distributed key storage across multiple recovery agents
//!   - No single agent can recover the key; requires M-of-N cooperation
//!
//! - **FCS_COP.1**: Cryptographic Operations
//!   - Uses polynomial interpolation over GF(256) finite field
//!   - Mathematically proven information-theoretic security
//!   - Any M-1 shares reveal no information about the secret
//!
//! - **FDP_IFC.1**: Information Flow Control
//!   - Secret is only reconstructable with threshold number of shares
//!   - Enforces split-knowledge principle for sensitive key material
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-12(3)**: Asymmetric Keys - Supports key splitting for protection
//! - **SC-28(1)**: Protection of Cryptographic Keys
//!
//! ## Algorithm Reference
//!
//! - Adi Shamir, "How to Share a Secret", Communications of the ACM, 1979

use crate::{Error, Result};
// rand 0.10: `fill_bytes` is on the base `Rng` trait; thread RNG is `rand::rng()`.
use rand::Rng;

/// Share in Shamir's Secret Sharing scheme
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Share index (x-coordinate, 1-indexed)
    pub index: u8,
    /// Share value (y-coordinate)
    pub value: Vec<u8>,
}

/// Shamir's Secret Sharing implementation
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Split a secret into N shares, requiring M shares to reconstruct
    ///
    /// # Arguments
    /// * `secret` - The secret to split
    /// * `threshold` - Minimum shares needed (M)
    /// * `num_shares` - Total shares to create (N)
    ///
    /// # Returns
    /// Vector of N shares
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FCS_CKM.2**: Key distribution via threshold splitting. The secret (typically
    ///   a key encryption key) is split such that M shares are required to reconstruct.
    /// - **FCS_COP.1**: Uses random polynomial generation with secure RNG for coefficients.
    ///
    /// # Security Properties
    ///
    /// - Information-theoretic security: Any M-1 shares reveal zero information
    /// - Perfect secrecy: All possible secrets are equally likely given M-1 shares
    pub fn split(secret: &[u8], threshold: usize, num_shares: usize) -> Result<Vec<Share>> {
        if threshold > num_shares {
            return Err(Error::InvalidRequest(format!(
                "Threshold {} cannot exceed number of shares {}",
                threshold, num_shares
            )));
        }

        if threshold == 0 {
            return Err(Error::InvalidRequest(
                "Threshold must be at least 1".to_string(),
            ));
        }

        if num_shares == 0 || num_shares > 255 {
            return Err(Error::InvalidRequest(format!(
                "Number of shares must be between 1 and 255, got {}",
                num_shares
            )));
        }

        let mut shares: Vec<Share> = (1..=num_shares)
            .map(|i| Share {
                index: i as u8,
                value: Vec::with_capacity(secret.len()),
            })
            .collect();

        let mut rng = rand::rng();

        // For each byte in the secret, create a polynomial and evaluate at all share indices
        for &secret_byte in secret {
            // Generate random coefficients for polynomial of degree (threshold - 1)
            // The secret byte is the constant term (coefficient for x^0)
            let mut coefficients = vec![secret_byte];
            for _ in 1..threshold {
                let mut coef = [0u8; 1];
                rng.fill_bytes(&mut coef);
                coefficients.push(coef[0]);
            }

            // Evaluate polynomial at each share index x = 1, 2, ..., num_shares
            for share in shares.iter_mut() {
                let y = Self::evaluate_polynomial(&coefficients, share.index);
                share.value.push(y);
            }
        }

        Ok(shares)
    }

    /// Reconstruct secret from M or more shares
    ///
    /// # Arguments
    /// * `shares` - At least M shares
    /// * `threshold` - Minimum shares needed (M)
    ///
    /// # Returns
    /// The reconstructed secret
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FCS_CKM.2**: Key reconstruction requires M authorized shares from recovery agents.
    /// - **FDP_ACC.1**: Threshold enforcement - reconstruction fails if fewer than M shares provided.
    ///
    /// # Security Note
    ///
    /// The reconstructed secret should be zeroized after use per FCS_CKM.4.
    pub fn reconstruct(shares: &[Share], threshold: usize) -> Result<Vec<u8>> {
        if shares.len() < threshold {
            return Err(Error::InsufficientShares {
                required: threshold,
                provided: shares.len(),
            });
        }

        // Use first threshold shares
        let shares_to_use = &shares[..threshold];

        // Verify all shares have same length
        let secret_len = shares_to_use[0].value.len();
        if !shares_to_use.iter().all(|s| s.value.len() == secret_len) {
            return Err(Error::InvalidShare);
        }

        let mut secret = Vec::with_capacity(secret_len);

        // Reconstruct each byte using Lagrange interpolation
        for byte_idx in 0..secret_len {
            let points: Vec<(u8, u8)> = shares_to_use
                .iter()
                .map(|share| (share.index, share.value[byte_idx]))
                .collect();

            let reconstructed_byte = Self::lagrange_interpolate(&points, 0);
            secret.push(reconstructed_byte);
        }

        Ok(secret)
    }

    /// Evaluate polynomial at given x using coefficients
    fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        let mut x_power = 1u8;

        for &coef in coefficients {
            result = Self::gf_add(result, Self::gf_mul(coef, x_power));
            x_power = Self::gf_mul(x_power, x);
        }

        result
    }

    /// Lagrange interpolation to find y at x=0
    fn lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
        let mut result = 0u8;

        for (i, &(xi, yi)) in points.iter().enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, &(xj, _)) in points.iter().enumerate() {
                if i != j {
                    numerator = Self::gf_mul(numerator, Self::gf_sub(x, xj));
                    denominator = Self::gf_mul(denominator, Self::gf_sub(xi, xj));
                }
            }

            let lagrange_basis = Self::gf_div(numerator, denominator);
            let term = Self::gf_mul(yi, lagrange_basis);
            result = Self::gf_add(result, term);
        }

        result
    }

    /// GF(256) addition (XOR)
    #[inline]
    fn gf_add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// GF(256) subtraction (same as addition in GF(2^8))
    #[inline]
    fn gf_sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// GF(256) multiplication using peasant multiplication
    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;

        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }

            let high_bit_set = a & 0x80 != 0;
            a <<= 1;

            if high_bit_set {
                a ^= 0x1B; // Irreducible polynomial x^8 + x^4 + x^3 + x + 1
            }

            b >>= 1;
        }

        result
    }

    /// GF(256) division
    fn gf_div(a: u8, b: u8) -> u8 {
        if b == 0 {
            panic!("Division by zero in GF(256)");
        }
        Self::gf_mul(a, Self::gf_inv(b))
    }

    /// GF(256) multiplicative inverse using extended Euclidean algorithm
    fn gf_inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }

        // Use lookup table for efficiency
        // This is a simplified version - production should use precomputed table
        let mut t = 0u16;
        let mut newt = 1u16;
        let mut r = 0x11Bu16; // Polynomial x^8 + x^4 + x^3 + x + 1 = 283
        let mut newr = a as u16;

        while newr != 0 {
            let quotient = Self::gf_div_u16(r, newr);
            let temp = t;
            t = newt;
            newt = temp ^ Self::gf_mul_u16(quotient, newt);

            let temp = r;
            r = newr;
            newr = temp ^ Self::gf_mul_u16(quotient, newr);
        }

        (t & 0xFF) as u8
    }

    /// Helper for GF division on u16
    fn gf_div_u16(a: u16, b: u16) -> u16 {
        if b == 0 {
            return 0;
        }

        let mut quotient = 0u16;
        let mut remainder = a;
        let divisor_bits = 16 - b.leading_zeros();

        for _ in 0..(16 - divisor_bits + 1) {
            let remainder_bits = 16 - remainder.leading_zeros();
            if remainder_bits < divisor_bits {
                break;
            }

            let shift = remainder_bits - divisor_bits;
            quotient ^= 1 << shift;
            remainder ^= b << shift;
        }

        quotient
    }

    /// Helper for GF multiplication on u16
    fn gf_mul_u16(a: u16, b: u16) -> u16 {
        let mut result = 0u16;
        let mut a = a;
        let mut b = b;

        while b != 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            a <<= 1;
            b >>= 1;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"Hello, World!";
        let threshold = 3;
        let num_shares = 5;

        let shares = ShamirSecretSharing::split(secret, threshold, num_shares).unwrap();
        assert_eq!(shares.len(), num_shares);

        // Reconstruct with exactly threshold shares
        let reconstructed =
            ShamirSecretSharing::reconstruct(&shares[0..threshold], threshold).unwrap();
        assert_eq!(reconstructed, secret);

        // Reconstruct with more than threshold shares
        let reconstructed =
            ShamirSecretSharing::reconstruct(&shares[0..num_shares], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Secret";
        let threshold = 3;
        let num_shares = 5;

        let shares = ShamirSecretSharing::split(secret, threshold, num_shares).unwrap();

        // Try to reconstruct with fewer than threshold shares
        let result = ShamirSecretSharing::reconstruct(&shares[0..2], threshold);
        assert!(matches!(result, Err(Error::InsufficientShares { .. })));
    }

    #[test]
    fn test_gf_operations() {
        // Test basic GF operations
        assert_eq!(ShamirSecretSharing::gf_add(5, 3), 6); // 5 XOR 3
        assert_eq!(ShamirSecretSharing::gf_sub(5, 3), 6); // same as add
        assert_eq!(ShamirSecretSharing::gf_mul(0, 5), 0);
        assert_eq!(ShamirSecretSharing::gf_mul(1, 5), 5);
    }
}
