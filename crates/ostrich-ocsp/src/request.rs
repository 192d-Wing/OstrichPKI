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
    /// RFC 6960 §4.1.1: OCSPRequest structure
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
