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
    /// SHA-1. RFC 6960 §4.3 requires responders to support SHA-1 CertIDs, and
    /// it is the default for OpenSSL and most clients. The hash covers the
    /// issuer name and key (an identifier), not security-sensitive data, so
    /// SHA-1 here is not a collision-resistance concern.
    Sha1,
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
    pub fn from_der(input: &[u8]) -> Result<Self> {
        use crate::der_util::read_tlv;

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
        //
        // Parsing is tolerant of the optional version [0], requestorName [1]
        // and optionalSignature [0] fields: they are skipped, not rejected.
        // NIST 800-53: SI-10 - structural validation of every consumed TLV.

        // OCSPRequest ::= SEQUENCE { ... }
        let (tag, ocsp_content, _trailing) = read_tlv(input).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        // tbsRequest ::= SEQUENCE { ... } (optionalSignature [0] after it is ignored)
        let (tag, tbs_content, _sig) = read_tlv(ocsp_content).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        // Skip version [0] EXPLICIT and requestorName [1] EXPLICIT if present
        let mut cursor = tbs_content;
        for skip_tag in [0xA0u8, 0xA1u8] {
            if let Some((tag, _, rest)) = read_tlv(cursor)
                && tag == skip_tag
            {
                cursor = rest;
            }
        }

        // requestList SEQUENCE OF Request
        let (tag, request_list, after_list) = read_tlv(cursor).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        // First Request (simplified - only handle single cert queries)
        let (tag, request_content, _) = read_tlv(request_list).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        // reqCert CertID ::= SEQUENCE { hashAlgorithm, nameHash, keyHash, serial }
        let (tag, cert_id, _) = read_tlv(request_content).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        // hashAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID, params OPTIONAL }
        let (tag, alg_id, after_alg) = read_tlv(cert_id).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }
        let (tag, oid_bytes, _params) = read_tlv(alg_id).ok_or(Error::MalformedRequest)?;
        if tag != 0x06 {
            return Err(Error::MalformedRequest);
        }
        let oid = der::asn1::ObjectIdentifier::from_bytes(oid_bytes)
            .map_err(|_| Error::MalformedRequest)?;
        let hash_algorithm = Self::oid_to_hash_algorithm(&oid)?;

        // issuerNameHash OCTET STRING
        let (tag, issuer_name_hash, after_name) =
            read_tlv(after_alg).ok_or(Error::MalformedRequest)?;
        if tag != 0x04 {
            return Err(Error::MalformedRequest);
        }

        // issuerKeyHash OCTET STRING
        let (tag, issuer_key_hash, after_key) =
            read_tlv(after_name).ok_or(Error::MalformedRequest)?;
        if tag != 0x04 {
            return Err(Error::MalformedRequest);
        }

        // serialNumber INTEGER (content bytes kept as-is)
        let (tag, serial_number, _) = read_tlv(after_key).ok_or(Error::MalformedRequest)?;
        if tag != 0x02 || serial_number.is_empty() {
            return Err(Error::MalformedRequest);
        }

        // requestExtensions [2] EXPLICIT Extensions OPTIONAL - scan for the
        // nonce extension (RFC 6960 §4.4.1 / RFC 8954).
        // NIST 800-53: SC-23 - nonce provides replay protection.
        let mut nonce = None;
        if let Some((0xA2, ext_explicit, _)) = read_tlv(after_list) {
            nonce = Self::find_nonce_extension(ext_explicit)?;
        }

        Ok(Self {
            serial_number: serial_number.to_vec(),
            issuer_name_hash: issuer_name_hash.to_vec(),
            issuer_key_hash: issuer_key_hash.to_vec(),
            hash_algorithm,
            nonce,
        })
    }

    /// Scan an Extensions SEQUENCE for id-pkix-ocsp-nonce, returning the raw
    /// extnValue content bytes (echoed verbatim in the response per RFC 8954).
    ///
    /// Extensions ::= SEQUENCE OF Extension
    /// Extension  ::= SEQUENCE {
    ///     extnID      OBJECT IDENTIFIER,
    ///     critical    BOOLEAN DEFAULT FALSE,
    ///     extnValue   OCTET STRING }
    fn find_nonce_extension(extensions_tlv: &[u8]) -> Result<Option<Vec<u8>>> {
        use crate::der_util::read_tlv;

        // id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
        const NONCE_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

        let (tag, mut cursor, _) = read_tlv(extensions_tlv).ok_or(Error::MalformedRequest)?;
        if tag != 0x30 {
            return Err(Error::MalformedRequest);
        }

        while !cursor.is_empty() {
            let (tag, ext_content, rest) = read_tlv(cursor).ok_or(Error::MalformedRequest)?;
            cursor = rest;
            if tag != 0x30 {
                return Err(Error::MalformedRequest);
            }

            let (tag, ext_oid, after_oid) = read_tlv(ext_content).ok_or(Error::MalformedRequest)?;
            if tag != 0x06 {
                return Err(Error::MalformedRequest);
            }

            // Skip optional critical BOOLEAN
            let mut value_cursor = after_oid;
            if let Some((0x01, _, rest)) = read_tlv(value_cursor) {
                value_cursor = rest;
            }

            let (tag, extn_value, _) = read_tlv(value_cursor).ok_or(Error::MalformedRequest)?;
            if tag != 0x04 {
                return Err(Error::MalformedRequest);
            }

            if ext_oid == NONCE_OID {
                return Ok(Some(extn_value.to_vec()));
            }
        }

        Ok(None)
    }

    /// Convert OID to HashAlgorithm
    fn oid_to_hash_algorithm(oid: &der::asn1::ObjectIdentifier) -> Result<HashAlgorithm> {
        // SHA-1 is RFC 6960 §4.3 MANDATORY and the OpenSSL/client default.
        const SHA1_OID: &str = "1.3.14.3.2.26";
        const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
        const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
        const SHA512_OID: &str = "2.16.840.1.101.3.4.2.3";

        match oid.to_string().as_str() {
            SHA1_OID => Ok(HashAlgorithm::Sha1),
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
            Self::Sha1 => "1.3.14.3.2.26",
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

    /// Build a DER OCSPRequest for tests (mirrors what `openssl ocsp` emits).
    fn build_request_der(nonce_extn_value: Option<&[u8]>, with_version: bool) -> Vec<u8> {
        use crate::der_util::{null, octet_string, oid, seq, tlv, unsigned_integer};

        // CertID
        let mut alg = oid("2.16.840.1.101.3.4.2.1").unwrap();
        alg.extend_from_slice(&null());
        let mut cert_id = seq(&alg);
        cert_id.extend_from_slice(&octet_string(&[0x11; 32]));
        cert_id.extend_from_slice(&octet_string(&[0x22; 32]));
        cert_id.extend_from_slice(&unsigned_integer(&[0x01, 0x02, 0x03]));
        let cert_id = seq(&cert_id);

        // Request ::= SEQUENCE { reqCert }
        let request = seq(&cert_id);
        // requestList ::= SEQUENCE OF Request
        let request_list = seq(&request);

        let mut tbs = Vec::new();
        if with_version {
            // version [0] EXPLICIT INTEGER 0
            tbs.extend_from_slice(&tlv(0xA0, &[0x02, 0x01, 0x00]));
        }
        tbs.extend_from_slice(&request_list);

        if let Some(nonce_value) = nonce_extn_value {
            // Extension ::= SEQUENCE { extnID, extnValue }
            let mut ext = oid("1.3.6.1.5.5.7.48.1.2").unwrap();
            ext.extend_from_slice(&octet_string(nonce_value));
            let extensions = seq(&seq(&ext));
            // requestExtensions [2] EXPLICIT Extensions
            tbs.extend_from_slice(&tlv(0xA2, &extensions));
        }

        // OCSPRequest ::= SEQUENCE { tbsRequest }
        seq(&seq(&tbs))
    }

    #[test]
    fn test_from_der_parses_cert_id() {
        let der = build_request_der(None, false);
        let req = OcspRequest::from_der(&der).unwrap();

        assert_eq!(req.serial_number, vec![0x01, 0x02, 0x03]);
        assert_eq!(req.issuer_name_hash, vec![0x11; 32]);
        assert_eq!(req.issuer_key_hash, vec![0x22; 32]);
        assert_eq!(req.hash_algorithm, HashAlgorithm::Sha256);
        assert!(req.nonce.is_none());
    }

    // RFC 6960 §4.4.1 / RFC 8954 - nonce extracted from requestExtensions [2]
    #[test]
    fn test_from_der_extracts_nonce() {
        // RFC 8954: extnValue content is an OCTET STRING wrapping the nonce
        let nonce_extn_value = vec![0x04, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        let der = build_request_der(Some(&nonce_extn_value), false);

        let req = OcspRequest::from_der(&der).unwrap();
        assert_eq!(req.nonce, Some(nonce_extn_value));
    }

    #[test]
    fn test_from_der_tolerates_explicit_version() {
        let nonce_extn_value = vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let der = build_request_der(Some(&nonce_extn_value), true);

        let req = OcspRequest::from_der(&der).unwrap();
        assert_eq!(req.serial_number, vec![0x01, 0x02, 0x03]);
        assert_eq!(req.nonce, Some(nonce_extn_value));
    }
}
