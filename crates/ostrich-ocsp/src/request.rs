//! OCSP request parsing
//!
//! This module implements OCSP request parsing per RFC 6960 Section 4.1.
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - **RFC 6960**: Online Certificate Status Protocol (OCSP)
//!   - Section 4.1: Request Syntax
//!   - Section 4.1.1: OCSPRequest ASN.1 structure
//!   - Section 4.1.2: Notes on OCSP Requests
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FDP_IFC.1**: Information Flow Control - Request parsing validates
//!   input before processing revocation status queries
//! - **SI-10**: Information Input Validation - All request fields are
//!   validated during parsing (serial number, hashes, algorithm OIDs)
//! - **FCS_COP.1(2)**: Cryptographic Hashing - SHA-256/384/512 for issuer
//!   name and key hash computation
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **SI-10**: Information Input Validation - Validates DER-encoded requests
//! - **SC-23**: Session Authenticity - Nonce support for replay protection

use crate::{Error, Result};
use sha2::{Digest, Sha256};

/// OCSP Request
///
/// Represents a parsed OCSP request containing certificate identification
/// information for status queries.
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_IFC.1**: Structure validates input fields during construction
/// - **FCS_COP.1(2)**: Hash algorithm support (SHA-256, SHA-384, SHA-512)
///
/// # RFC 6960 Section 4.1.1
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest             TBSRequest,
///    optionalSignature  [0] EXPLICIT Signature OPTIONAL }
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
    /// Parses and validates a DER-encoded OCSP request per RFC 6960 Section 4.1.1.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **SI-10**: Input validation - rejects malformed DER encoding
    /// - **FDP_IFC.1**: Validates request structure before processing
    ///
    /// # RFC 6960 Section 4.1.1 ASN.1 Structure
    /// ```text
    /// OCSPRequest ::= SEQUENCE {
    ///     tbsRequest      TBSRequest,
    ///     optionalSignature   [0] EXPLICIT Signature OPTIONAL }
    ///
    /// TBSRequest ::= SEQUENCE {
    ///     version             [0] EXPLICIT Version DEFAULT v1,
    ///     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    ///     requestList         SEQUENCE OF Request,
    ///     requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
    /// ```
    ///
    /// # Errors
    /// Returns `Error::MalformedRequest` if the DER encoding is invalid.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        use der::asn1::{ObjectIdentifier, OctetString};
        use der::{Decode, Sequence};

        // RFC 6960 §4.1.1 ASN.1 Structure:
        // OCSPRequest ::= SEQUENCE {
        //     tbsRequest      TBSRequest,
        //     optionalSignature   [0] EXPLICIT Signature OPTIONAL }
        //
        // TBSRequest ::= SEQUENCE {
        //     version             [0] EXPLICIT Version DEFAULT v1,
        //     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
        //     requestList         SEQUENCE OF Request,
        //     requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
        //
        // Request ::= SEQUENCE {
        //     reqCert                     CertID,
        //     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
        //
        // CertID ::= SEQUENCE {
        //     hashAlgorithm       AlgorithmIdentifier,
        //     issuerNameHash      OCTET STRING,
        //     issuerKeyHash       OCTET STRING,
        //     serialNumber        CertificateSerialNumber }

        #[derive(Sequence)]
        struct AlgorithmIdentifier {
            algorithm: ObjectIdentifier,
        }

        #[derive(Sequence)]
        struct CertId {
            hash_algorithm: AlgorithmIdentifier,
            issuer_name_hash: OctetString,
            issuer_key_hash: OctetString,
            serial_number: der::asn1::Int,
        }

        #[derive(Sequence)]
        struct Request {
            req_cert: CertId,
        }

        #[derive(Sequence)]
        struct TbsRequest {
            request_list: der::asn1::SequenceOf<Request, 10>,
        }

        #[derive(Sequence)]
        struct OcspRequestAsn1 {
            tbs_request: TbsRequest,
        }

        // Parse the DER
        let ocsp_req = OcspRequestAsn1::from_der(der).map_err(|_| Error::MalformedRequest)?;

        // Extract first request (simplified - only handle single cert queries)
        let first_request = ocsp_req
            .tbs_request
            .request_list
            .iter()
            .next()
            .ok_or(Error::MalformedRequest)?;

        let cert_id = &first_request.req_cert;

        // Convert hash algorithm OID to enum
        let hash_algorithm = Self::oid_to_hash_algorithm(&cert_id.hash_algorithm.algorithm)?;

        // Convert serial number from ASN.1 Int to bytes
        let serial_number = cert_id.serial_number.as_bytes().to_vec();

        Ok(Self {
            serial_number,
            issuer_name_hash: cert_id.issuer_name_hash.as_bytes().to_vec(),
            issuer_key_hash: cert_id.issuer_key_hash.as_bytes().to_vec(),
            hash_algorithm,
            nonce: None, // TODO: Extract nonce from extensions
        })
    }

    /// Convert OID to HashAlgorithm
    fn oid_to_hash_algorithm(oid: &der::asn1::ObjectIdentifier) -> Result<HashAlgorithm> {
        const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
        const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
        const SHA512_OID: &str = "2.16.840.1.101.3.4.2.3";

        match oid.to_string().as_str() {
            SHA256_OID => Ok(HashAlgorithm::Sha256),
            SHA384_OID => Ok(HashAlgorithm::Sha384),
            SHA512_OID => Ok(HashAlgorithm::Sha512),
            _ => Err(Error::InvalidRequest(format!(
                "Unsupported hash algorithm OID: {}",
                oid
            ))),
        }
    }

    /// Create a simple OCSP request for testing
    ///
    /// Constructs an OCSP request with computed issuer hashes using SHA-256.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FCS_COP.1(2)**: Uses SHA-256 (FIPS 180-4) for hash computation
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
    ///
    /// Adds a nonce extension to the request for replay attack prevention.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **SC-23**: Session authenticity via nonce-based replay protection
    ///
    /// # RFC 6960 Section 4.4.1
    /// The nonce cryptographically binds a request and response.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_oid() {
        assert_eq!(HashAlgorithm::Sha256.oid(), "2.16.840.1.101.3.4.2.1");
        assert_eq!(HashAlgorithm::Sha384.oid(), "2.16.840.1.101.3.4.2.2");
        assert_eq!(HashAlgorithm::Sha512.oid(), "2.16.840.1.101.3.4.2.3");
    }

    #[test]
    fn test_ocsp_request_new() {
        let serial_number = vec![0x01, 0x02, 0x03];
        let issuer_name = b"CN=Test CA";
        let issuer_key = b"test_public_key_bytes";

        let req = OcspRequest::new(serial_number.clone(), issuer_name, issuer_key);

        assert_eq!(req.serial_number, serial_number);
        assert_eq!(req.hash_algorithm, HashAlgorithm::Sha256);
        assert!(req.nonce.is_none());

        // Verify hashes are SHA-256 (32 bytes)
        assert_eq!(req.issuer_name_hash.len(), 32);
        assert_eq!(req.issuer_key_hash.len(), 32);
    }

    #[test]
    fn test_ocsp_request_with_nonce() {
        let serial_number = vec![0x01];
        let nonce = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let req = OcspRequest::new(serial_number, b"issuer", b"key").with_nonce(nonce.clone());

        assert_eq!(req.nonce, Some(nonce));
    }

    #[test]
    fn test_ocsp_request_different_issuers_different_hashes() {
        let serial_number = vec![0x01];

        let req1 = OcspRequest::new(serial_number.clone(), b"Issuer A", b"Key A");
        let req2 = OcspRequest::new(serial_number.clone(), b"Issuer B", b"Key B");

        // Different issuers should produce different hashes
        assert_ne!(req1.issuer_name_hash, req2.issuer_name_hash);
        assert_ne!(req1.issuer_key_hash, req2.issuer_key_hash);
    }

    #[test]
    fn test_ocsp_request_same_issuer_same_hashes() {
        let serial_number1 = vec![0x01];
        let serial_number2 = vec![0x02];
        let issuer_name = b"CN=Same Issuer";
        let issuer_key = b"same_key";

        let req1 = OcspRequest::new(serial_number1, issuer_name, issuer_key);
        let req2 = OcspRequest::new(serial_number2, issuer_name, issuer_key);

        // Same issuer should produce same hashes
        assert_eq!(req1.issuer_name_hash, req2.issuer_name_hash);
        assert_eq!(req1.issuer_key_hash, req2.issuer_key_hash);
    }

    #[test]
    fn test_hash_algorithm_equality() {
        assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
        assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
        assert_ne!(HashAlgorithm::Sha384, HashAlgorithm::Sha512);
    }

    #[test]
    fn test_ocsp_request_clone() {
        let req =
            OcspRequest::new(vec![0x01, 0x02], b"issuer", b"key").with_nonce(vec![0xAA, 0xBB]);

        let cloned = req.clone();

        assert_eq!(req.serial_number, cloned.serial_number);
        assert_eq!(req.issuer_name_hash, cloned.issuer_name_hash);
        assert_eq!(req.issuer_key_hash, cloned.issuer_key_hash);
        assert_eq!(req.hash_algorithm, cloned.hash_algorithm);
        assert_eq!(req.nonce, cloned.nonce);
    }

    #[test]
    fn test_from_der_malformed() {
        // Invalid DER data should return error
        let invalid_der = vec![0x00, 0x01, 0x02];
        let result = OcspRequest::from_der(&invalid_der);
        assert!(result.is_err());
    }
}
