//! OCSP request parsing
//!
//! RFC 6960 §4.1: Request Syntax

use crate::{Error, Result};
use sha2::{Digest, Sha256};

/// OCSP Request
///
/// Simplified structure for basic OCSP request handling.
/// Full ASN.1 parsing would use x509-ocsp crate when available.
#[derive(Debug, Clone)]
pub struct OcspRequest {
    /// Certificate serial number being queried
    pub serial_number: Vec<u8>,

    /// Issuer name hash (SHA-256)
    pub issuer_name_hash: Vec<u8>,

    /// Issuer key hash (SHA-256)
    pub issuer_key_hash: Vec<u8>,

    /// Hash algorithm OID
    pub hash_algorithm: HashAlgorithm,

    /// Nonce for replay protection (optional)
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl OcspRequest {
    /// Parse OCSP request from DER-encoded bytes
    ///
    /// Note: This is a simplified parser. Production use would require
    /// full ASN.1 parsing of OCSPRequest structure.
    pub fn from_der(_der: &[u8]) -> Result<Self> {
        // TODO: Implement full ASN.1 parsing using der crate
        // For now, return a placeholder error
        Err(Error::MalformedRequest)
    }

    /// Create a simple OCSP request for testing
    pub fn new(serial_number: Vec<u8>, issuer_name: &[u8], issuer_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(issuer_name);
        let issuer_name_hash = hasher.finalize().to_vec();

        let mut hasher = Sha256::new();
        hasher.update(issuer_key);
        let issuer_key_hash = hasher.finalize().to_vec();

        Self {
            serial_number,
            issuer_name_hash,
            issuer_key_hash,
            hash_algorithm: HashAlgorithm::Sha256,
            nonce: None,
        }
    }

    /// Set nonce for replay protection
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl HashAlgorithm {
    pub fn oid(&self) -> &'static str {
        match self {
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }
}
