//! OCSP response generation
//!
//! This module implements OCSP response structures and DER encoding
//! per RFC 6960 Section 4.2.
//!
//! The to-be-signed ResponseData is encoded exactly once
//! ([`encode_tbs_response_data`]); the responder signs those bytes and the
//! same bytes are embedded verbatim into the BasicOCSPResponse by
//! [`OcspResponse::to_der`]. This guarantees the signature always verifies
//! against the emitted encoding.
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - **RFC 6960**: Online Certificate Status Protocol (OCSP)
//!   - Section 4.2: Response Syntax
//!   - Section 4.2.1: BasicOCSPResponse
//!   - Section 4.2.2: Response Extensions
//! - **RFC 8954**: OCSP Nonce Extension (request nonce echoed in response)
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FDP_OCSPG_EXT.1**: OCSP Response Generation - Response structure and
//!   encoding per RFC 6960 requirements
//! - **FDP_CSI_EXT.1**: Certificate Status Information - Proper status codes
//!   (good, revoked, unknown) with revocation reasons
//! - **FCS_COP.1(1)**: Cryptographic Operation - Response signature structure
//! - **FPT_STM.1**: Reliable Time Stamps - thisUpdate, nextUpdate, producedAt
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **SC-13**: Cryptographic Protection - Signed response structure
//! - **SC-17**: PKI Certificates - RFC 6960 conformant status responses
//! - **AU-10**: Non-repudiation - Digitally signed responses

use crate::der_util;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// id-pkix-ocsp-basic (RFC 6960 §4.2.1)
const ID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
/// id-pkix-ocsp-nonce (RFC 6960 §4.4.1 / RFC 8954)
const ID_PKIX_OCSP_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";

/// OCSP Response Status
///
/// Indicates the processing status of an OCSP request per RFC 6960 Section 4.2.1.
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: Response status codes per RFC 6960
///
/// # RFC 6960 Section 4.2.1
/// OCSPResponseStatus ::= ENUMERATED {
///     successful            (0),  -- Response has valid confirmations
///     malformedRequest      (1),  -- Illegal confirmation request
///     internalError         (2),  -- Internal error in issuer
///     tryLater              (3),  -- Try again later
///     sigRequired           (5),  -- Must sign the request
///     unauthorized          (6)   -- Request unauthorized }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Response has valid confirmations
    Successful = 0,
    /// Illegal confirmation request
    MalformedRequest = 1,
    /// Internal error in issuer
    InternalError = 2,
    /// Try again later
    TryLater = 3,
    /// Must sign the request
    SigRequired = 5,
    /// Request unauthorized
    Unauthorized = 6,
}

/// Certificate Status
///
/// Indicates the revocation status of a certificate per RFC 6960 Section 4.2.1.
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_CSI_EXT.1**: Certificate status information per RFC 6960
/// - **FDP_OCSPG_EXT.1**: Proper status encoding in OCSP responses
///
/// # RFC 6960 Section 4.2.1
/// CertStatus ::= CHOICE {
///     good        [0]     IMPLICIT NULL,
///     revoked     [1]     IMPLICIT RevokedInfo,
///     unknown     [2]     IMPLICIT UnknownInfo }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        revocation_time: DateTime<Utc>,
        revocation_reason: Option<u8>,
    },
    /// Status is unknown
    Unknown,
}

/// Single OCSP response for one certificate
///
/// Contains the status information for a single certificate query. The
/// CertID fields (hash algorithm, issuer name hash, issuer key hash, serial)
/// must echo the request's CertID exactly (RFC 6960 §4.2.1: the responder
/// identifies the certificate using the same CertID the requester supplied).
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: Single response structure per RFC 6960
/// - **FPT_STM.1**: thisUpdate and nextUpdate timestamps from reliable source
///
/// # RFC 6960 Section 4.2.1
/// SingleResponse ::= SEQUENCE {
///    certID                       CertID,
///    certStatus                   CertStatus,
///    thisUpdate                   GeneralizedTime,
///    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleResponse {
    /// Certificate serial number (unsigned big-endian magnitude, echoed from
    /// the request CertID)
    pub serial_number: Vec<u8>,

    /// Issuer name hash echoed from the request CertID
    pub issuer_name_hash: Vec<u8>,

    /// Issuer key hash echoed from the request CertID
    pub issuer_key_hash: Vec<u8>,

    /// Dotted OID of the CertID hash algorithm echoed from the request
    /// (e.g. "2.16.840.1.101.3.4.2.1" for SHA-256)
    pub hash_algorithm: String,

    /// Certificate status
    pub cert_status: CertStatus,

    /// Time of this update
    pub this_update: DateTime<Utc>,

    /// Time of next update (optional)
    pub next_update: Option<DateTime<Utc>>,
}

/// OCSP Response
///
/// Complete OCSP response containing status information and digital signature.
///
/// `tbs_response_data` holds the exact DER bytes of ResponseData that were
/// signed; [`to_der`](OcspResponse::to_der) embeds them verbatim so the
/// signature always verifies against the emitted encoding.
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: Complete OCSP response per RFC 6960
/// - **FCS_COP.1(1)**: Contains cryptographic signature for authentication
/// - **FCO_NRO_EXT.2**: Provides proof of origin via digital signature
/// - **FPT_STM.1**: producedAt timestamp from reliable time source
///
/// # RFC 6960 Section 4.2.1
/// OCSPResponse ::= SEQUENCE {
///    responseStatus         OCSPResponseStatus,
///    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponse {
    /// Response status
    pub response_status: ResponseStatus,

    /// Responses for individual certificates
    pub responses: Vec<SingleResponse>,

    /// Exact DER bytes of the signed ResponseData (tbsResponseData)
    pub tbs_response_data: Vec<u8>,

    /// Response signature over `tbs_response_data`
    pub signature: Vec<u8>,

    /// DER-encoded BasicOCSPResponse.signatureAlgorithm AlgorithmIdentifier.
    /// RFC 6960 §4.2.1 / RFC 5280 §4.1.1.2 - flows from the chosen signing
    /// algorithm so the declared and actual algorithms match (RSA / ECDSA /
    /// Ed25519). Empty for error responses (no signature).
    pub signature_algorithm: Vec<u8>,

    /// Signing (CA) certificate, DER-encoded - included in the certs field of
    /// BasicOCSPResponse so verifiers have the responder certificate
    pub signing_cert: Vec<u8>,

    /// Produced at time
    pub produced_at: DateTime<Utc>,

    /// Nonce extnValue bytes echoed from the request (if present)
    pub nonce: Option<Vec<u8>>,
}

/// Encode CertID per RFC 6960 §4.1.1, echoing the request's CertID fields.
///
/// CertID ::= SEQUENCE {
///     hashAlgorithm       AlgorithmIdentifier,
///     issuerNameHash      OCTET STRING,
///     issuerKeyHash       OCTET STRING,
///     serialNumber        CertificateSerialNumber }
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: CertID in the response matches the request
fn encode_cert_id(resp: &SingleResponse) -> crate::Result<Vec<u8>> {
    // AlgorithmIdentifier with explicit NULL parameters
    let mut alg_id = der_util::oid(&resp.hash_algorithm)?;
    alg_id.extend_from_slice(&der_util::null());
    let alg_id = der_util::seq(&alg_id);

    let mut content = alg_id;
    content.extend_from_slice(&der_util::octet_string(&resp.issuer_name_hash));
    content.extend_from_slice(&der_util::octet_string(&resp.issuer_key_hash));
    // RFC 5280 §4.1.2.2 - serial number is a positive INTEGER
    content.extend_from_slice(&der_util::unsigned_integer(&resp.serial_number));
    Ok(der_util::seq(&content))
}

/// Encode the CertStatus CHOICE per RFC 6960 §4.2.1.
///
/// CertStatus ::= CHOICE {
///     good        [0] IMPLICIT NULL,        -- 0x80 00
///     revoked     [1] IMPLICIT RevokedInfo, -- 0xA1 { revocationTime,
///                                           --   [0] EXPLICIT CRLReason OPT }
///     unknown     [2] IMPLICIT UnknownInfo  -- 0x82 00 }
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_CSI_EXT.1**: Status codes encoded per RFC 6960
fn encode_cert_status(status: &CertStatus) -> Vec<u8> {
    match status {
        // good [0] IMPLICIT NULL - primitive context tag 0, empty content
        CertStatus::Good => der_util::tlv(0x80, &[]),
        // revoked [1] IMPLICIT RevokedInfo - constructed context tag 1
        CertStatus::Revoked {
            revocation_time,
            revocation_reason,
        } => {
            let mut content = der_util::generalized_time(revocation_time);
            if let Some(reason) = revocation_reason {
                // revocationReason [0] EXPLICIT CRLReason (ENUMERATED) OPTIONAL
                // RFC 5280 §5.3.1 - CRLReason codes
                content.extend_from_slice(&der_util::tlv(0xA0, &der_util::enumerated(*reason)));
            }
            der_util::tlv(0xA1, &content)
        }
        // unknown [2] IMPLICIT UnknownInfo (NULL) - primitive context tag 2
        CertStatus::Unknown => der_util::tlv(0x82, &[]),
    }
}

/// Encode a SingleResponse per RFC 6960 §4.2.1.
///
/// SingleResponse ::= SEQUENCE {
///    certID                       CertID,
///    certStatus                   CertStatus,
///    thisUpdate                   GeneralizedTime,
///    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL }
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FPT_STM.1**: thisUpdate/nextUpdate from reliable time source
fn encode_single_response(resp: &SingleResponse) -> crate::Result<Vec<u8>> {
    let mut content = encode_cert_id(resp)?;
    content.extend_from_slice(&encode_cert_status(&resp.cert_status));
    content.extend_from_slice(&der_util::generalized_time(&resp.this_update));
    if let Some(next_update) = &resp.next_update {
        // nextUpdate [0] EXPLICIT GeneralizedTime
        content.extend_from_slice(&der_util::tlv(
            0xA0,
            &der_util::generalized_time(next_update),
        ));
    }
    Ok(der_util::seq(&content))
}

/// Encode the to-be-signed ResponseData per RFC 6960 §4.2.1.
///
/// These exact bytes must be signed and embedded verbatim into the
/// BasicOCSPResponse - they are the single source of truth.
///
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1, -- omitted (DER)
///    responderID              ResponderID,                 -- byName [1]
///    producedAt               GeneralizedTime,
///    responses                SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
///
/// `responder_name_der` is the raw DER of the responder (CA) subject Name,
/// embedded as ResponderID byName [1]. `nonce` is the exact extnValue bytes
/// from the request's nonce extension, echoed per RFC 8954.
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: ResponseData per RFC 6960 §4.2.1 (responderID
///   present; DEFAULT version omitted per DER)
/// - **FPT_STM.1**: producedAt from reliable time source
///
/// # NIST 800-53 Rev 5 Controls
/// - **SC-23**: Session Authenticity - nonce echo binds response to request
pub(crate) fn encode_tbs_response_data(
    responder_name_der: &[u8],
    produced_at: DateTime<Utc>,
    responses: &[SingleResponse],
    nonce: Option<&[u8]>,
) -> crate::Result<Vec<u8>> {
    // version: DEFAULT v1 - MUST NOT be encoded in DER (X.690 §11.5)

    // responderID byName [1] EXPLICIT Name
    let mut content = der_util::tlv(0xA1, responder_name_der);

    // producedAt GeneralizedTime (RFC 6960 §4.2.1 - producedAt is mandatory)
    content.extend_from_slice(&der_util::generalized_time(&produced_at));

    // responses SEQUENCE OF SingleResponse
    let mut responses_content = Vec::new();
    for resp in responses {
        responses_content.extend_from_slice(&encode_single_response(resp)?);
    }
    content.extend_from_slice(&der_util::seq(&responses_content));

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL - only when a
    // nonce must be echoed (RFC 8954 §3.2)
    if let Some(nonce_value) = nonce {
        // Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }
        let mut ext = der_util::oid(ID_PKIX_OCSP_NONCE)?;
        ext.extend_from_slice(&der_util::octet_string(nonce_value));
        let extension = der_util::seq(&ext);
        // Extensions ::= SEQUENCE OF Extension
        let extensions = der_util::seq(&extension);
        content.extend_from_slice(&der_util::tlv(0xA1, &extensions));
    }

    Ok(der_util::seq(&content))
}

impl OcspResponse {
    /// Create a successful OCSP response
    ///
    /// `tbs_response_data` must be the exact DER bytes produced by
    /// [`encode_tbs_response_data`] that `signature` was computed over.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FDP_OCSPG_EXT.1**: Successful response construction
    /// - **FCS_COP.1(1)**: Includes signature from signing operation
    /// - **FPT_STM.1**: Sets producedAt to current UTC time
    pub fn successful(
        responses: Vec<SingleResponse>,
        tbs_response_data: Vec<u8>,
        signature: Vec<u8>,
        signature_algorithm: Vec<u8>,
        signing_cert: Vec<u8>,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            response_status: ResponseStatus::Successful,
            responses,
            tbs_response_data,
            signature,
            signature_algorithm,
            signing_cert,
            produced_at: Utc::now(),
            nonce,
        }
    }

    /// Create an error response
    ///
    /// Constructs an OCSP error response without status information.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FDP_OCSPG_EXT.1**: Error response per RFC 6960 Section 4.2.1
    pub fn error(status: ResponseStatus) -> Self {
        Self {
            response_status: status,
            responses: Vec::new(),
            tbs_response_data: Vec::new(),
            signature: Vec::new(),
            signature_algorithm: Vec::new(),
            signing_cert: Vec::new(),
            produced_at: Utc::now(),
            nonce: None,
        }
    }

    /// Encode response to DER format
    ///
    /// Encodes the complete OCSP response per RFC 6960 Section 4.2.1,
    /// embedding the previously signed `tbs_response_data` bytes verbatim.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FDP_OCSPG_EXT.1**: Proper DER encoding of OCSP response
    /// - **FCS_COP.1(1)**: Signature included in encoded response
    ///
    /// # RFC 6960 Section 4.2.1 ASN.1 Structure
    /// ```text
    /// OCSPResponse ::= SEQUENCE {
    ///    responseStatus         OCSPResponseStatus,
    ///    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
    ///
    /// ResponseBytes ::= SEQUENCE {
    ///    responseType   OBJECT IDENTIFIER,  -- id-pkix-ocsp-basic
    ///    response       OCTET STRING }      -- BasicOCSPResponse DER
    ///
    /// BasicOCSPResponse ::= SEQUENCE {
    ///    tbsResponseData      ResponseData,         -- exact signed bytes
    ///    signatureAlgorithm   AlgorithmIdentifier,  -- sha256WithRSAEncryption
    ///    signature            BIT STRING,
    ///    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    /// ```
    pub fn to_der(&self) -> crate::Result<Vec<u8>> {
        // Error responses: OCSPResponse with responseStatus only, no
        // responseBytes (RFC 6960 §4.2.1: responseBytes present only when
        // responseStatus is successful)
        if self.response_status != ResponseStatus::Successful {
            return Ok(der_util::seq(&der_util::enumerated(
                self.response_status.as_u8(),
            )));
        }

        if self.tbs_response_data.is_empty() {
            // Fail closed: a "successful" response without signed TBS bytes
            // is an internal invariant violation, never emit it.
            return Err(crate::Error::InternalError(
                "Successful OCSP response is missing signed tbsResponseData".to_string(),
            ));
        }

        // signatureAlgorithm AlgorithmIdentifier (RFC 6960 §4.2.1).
        // The pre-encoded DER flows from the signing algorithm the responder
        // chose (RSA / ECDSA / Ed25519) so the declared and actual algorithms
        // match (RFC 5280 §4.1.1.2). Fail closed if it is missing.
        if self.signature_algorithm.is_empty() {
            return Err(crate::Error::InternalError(
                "Successful OCSP response is missing signatureAlgorithm".to_string(),
            ));
        }
        let sig_alg = &self.signature_algorithm;

        // BasicOCSPResponse - tbsResponseData embedded byte-for-byte
        let mut basic = self.tbs_response_data.clone();
        basic.extend_from_slice(sig_alg);
        basic.extend_from_slice(&der_util::bit_string(&self.signature));
        if !self.signing_cert.is_empty() {
            // certs [0] EXPLICIT SEQUENCE OF Certificate - include the CA
            // certificate so verifiers have the responder certificate
            let certs_seq = der_util::seq(&self.signing_cert);
            basic.extend_from_slice(&der_util::tlv(0xA0, &certs_seq));
        }
        let basic = der_util::seq(&basic);

        // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
        let mut response_bytes = der_util::oid(ID_PKIX_OCSP_BASIC)?;
        response_bytes.extend_from_slice(&der_util::octet_string(&basic));
        let response_bytes = der_util::seq(&response_bytes);

        // OCSPResponse ::= SEQUENCE { ENUMERATED successful, [0] EXPLICIT ResponseBytes }
        let mut content = der_util::enumerated(ResponseStatus::Successful.as_u8());
        content.extend_from_slice(&der_util::tlv(0xA0, &response_bytes));
        Ok(der_util::seq(&content))
    }
}

impl ResponseStatus {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der_util::read_tlv;
    use chrono::Duration;

    /// Test helper: SingleResponse with realistic CertID fields
    fn test_single_response(serial: Vec<u8>, status: CertStatus) -> SingleResponse {
        SingleResponse {
            serial_number: serial,
            issuer_name_hash: vec![0x11; 32],
            issuer_key_hash: vec![0x22; 32],
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(),
            cert_status: status,
            this_update: Utc::now(),
            next_update: None,
        }
    }

    #[test]
    fn test_response_status_values() {
        assert_eq!(ResponseStatus::Successful.as_u8(), 0);
        assert_eq!(ResponseStatus::MalformedRequest.as_u8(), 1);
        assert_eq!(ResponseStatus::InternalError.as_u8(), 2);
        assert_eq!(ResponseStatus::TryLater.as_u8(), 3);
        assert_eq!(ResponseStatus::SigRequired.as_u8(), 5);
        assert_eq!(ResponseStatus::Unauthorized.as_u8(), 6);
    }

    #[test]
    fn test_cert_status_good() {
        let status = CertStatus::Good;
        assert!(matches!(status, CertStatus::Good));
    }

    #[test]
    fn test_cert_status_revoked() {
        let now = Utc::now();
        let status = CertStatus::Revoked {
            revocation_time: now,
            revocation_reason: Some(1),
        };
        assert!(matches!(status, CertStatus::Revoked { .. }));
    }

    #[test]
    fn test_cert_status_unknown() {
        let status = CertStatus::Unknown;
        assert!(matches!(status, CertStatus::Unknown));
    }

    // RFC 6960 §4.2.1 - CertStatus CHOICE tag/encoding checks
    #[test]
    fn test_cert_status_choice_good_encoding() {
        // good [0] IMPLICIT NULL -> 0x80 0x00
        assert_eq!(encode_cert_status(&CertStatus::Good), vec![0x80, 0x00]);
    }

    #[test]
    fn test_cert_status_choice_unknown_encoding() {
        // unknown [2] IMPLICIT NULL -> 0x82 0x00
        assert_eq!(encode_cert_status(&CertStatus::Unknown), vec![0x82, 0x00]);
    }

    #[test]
    fn test_cert_status_choice_revoked_encoding() {
        let now = Utc::now();
        let encoded = encode_cert_status(&CertStatus::Revoked {
            revocation_time: now,
            revocation_reason: Some(1), // keyCompromise
        });
        // revoked [1] IMPLICIT RevokedInfo -> constructed context tag 1
        let (tag, content, rest) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, 0xA1);
        assert!(rest.is_empty());
        // revocationTime GeneralizedTime
        let (tag, _, after_time) = read_tlv(content).unwrap();
        assert_eq!(tag, 0x18);
        // revocationReason [0] EXPLICIT ENUMERATED
        let (tag, reason_content, rest) = read_tlv(after_time).unwrap();
        assert_eq!(tag, 0xA0);
        assert!(rest.is_empty());
        assert_eq!(reason_content, &[0x0A, 0x01, 0x01]);
    }

    #[test]
    fn test_cert_status_choice_revoked_without_reason() {
        let encoded = encode_cert_status(&CertStatus::Revoked {
            revocation_time: Utc::now(),
            revocation_reason: None,
        });
        let (tag, content, _) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, 0xA1);
        // Only the GeneralizedTime, no [0] reason wrapper
        let (tag, _, rest) = read_tlv(content).unwrap();
        assert_eq!(tag, 0x18);
        assert!(rest.is_empty());
    }

    // RFC 6960 §4.2.1 - nextUpdate [0] EXPLICIT wrapper checks
    #[test]
    fn test_single_response_next_update_wrapper_present() {
        let mut resp = test_single_response(vec![0x01], CertStatus::Good);
        resp.next_update = Some(resp.this_update + Duration::hours(1));

        let encoded = encode_single_response(&resp).unwrap();
        let (tag, content, _) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, 0x30);
        // certID
        let (tag, _, after_certid) = read_tlv(content).unwrap();
        assert_eq!(tag, 0x30);
        // certStatus (good -> 0x80)
        let (tag, _, after_status) = read_tlv(after_certid).unwrap();
        assert_eq!(tag, 0x80);
        // thisUpdate GeneralizedTime
        let (tag, _, after_this) = read_tlv(after_status).unwrap();
        assert_eq!(tag, 0x18);
        // nextUpdate [0] EXPLICIT { GeneralizedTime }
        let (tag, nu_content, rest) = read_tlv(after_this).unwrap();
        assert_eq!(tag, 0xA0);
        assert!(rest.is_empty());
        let (tag, _, rest) = read_tlv(nu_content).unwrap();
        assert_eq!(tag, 0x18);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_single_response_next_update_wrapper_absent() {
        let resp = test_single_response(vec![0x01], CertStatus::Good);
        let encoded = encode_single_response(&resp).unwrap();
        let (_, content, _) = read_tlv(&encoded).unwrap();
        let (_, _, after_certid) = read_tlv(content).unwrap();
        let (_, _, after_status) = read_tlv(after_certid).unwrap();
        let (tag, _, rest) = read_tlv(after_status).unwrap();
        assert_eq!(tag, 0x18); // thisUpdate
        assert!(rest.is_empty(), "no nextUpdate must mean no [0] wrapper");
    }

    // RFC 6960 §4.1.1 - CertID echoes request fields
    #[test]
    fn test_cert_id_echoes_request_fields() {
        let resp = test_single_response(vec![0x7F], CertStatus::Good);
        let encoded = encode_cert_id(&resp).unwrap();
        let (tag, content, _) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, 0x30);
        // hashAlgorithm AlgorithmIdentifier with NULL params
        let (tag, alg_content, after_alg) = read_tlv(content).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, _, null_rest) = read_tlv(alg_content).unwrap();
        assert_eq!(tag, 0x06);
        let (tag, null_content, _) = read_tlv(null_rest).unwrap();
        assert_eq!(tag, 0x05);
        assert!(null_content.is_empty());
        // issuerNameHash / issuerKeyHash echoed
        let (tag, name_hash, after_name) = read_tlv(after_alg).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(name_hash, &[0x11; 32]);
        let (tag, key_hash, after_key) = read_tlv(after_name).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(key_hash, &[0x22; 32]);
        // serialNumber INTEGER
        let (tag, serial, rest) = read_tlv(after_key).unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(serial, &[0x7F]);
        assert!(rest.is_empty());
    }

    // RFC 8954 - nonce echo in responseExtensions [1]
    #[test]
    fn test_tbs_response_data_nonce_echo() {
        // Minimal Name: SEQUENCE {} (empty RDNSequence)
        let name_der = vec![0x30, 0x00];
        let resp = test_single_response(vec![0x01], CertStatus::Good);
        // RFC 8954: extnValue content is itself an OCTET STRING of the nonce
        let nonce_extn_value = vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

        let tbs = encode_tbs_response_data(
            &name_der,
            Utc::now(),
            std::slice::from_ref(&resp),
            Some(&nonce_extn_value),
        )
        .unwrap();

        let (tag, content, _) = read_tlv(&tbs).unwrap();
        assert_eq!(tag, 0x30);
        // responderID [1] EXPLICIT Name - raw Name bytes embedded
        let (tag, rid_content, after_rid) = read_tlv(content).unwrap();
        assert_eq!(tag, 0xA1);
        assert_eq!(rid_content, name_der.as_slice());
        // producedAt
        let (tag, _, after_produced) = read_tlv(after_rid).unwrap();
        assert_eq!(tag, 0x18);
        // responses
        let (tag, _, after_responses) = read_tlv(after_produced).unwrap();
        assert_eq!(tag, 0x30);
        // responseExtensions [1] EXPLICIT Extensions
        let (tag, ext_explicit, rest) = read_tlv(after_responses).unwrap();
        assert_eq!(tag, 0xA1);
        assert!(rest.is_empty());
        let (tag, extensions, _) = read_tlv(ext_explicit).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, extension, _) = read_tlv(extensions).unwrap();
        assert_eq!(tag, 0x30);
        // extnID = id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
        let (tag, oid_bytes, after_oid) = read_tlv(extension).unwrap();
        assert_eq!(tag, 0x06);
        assert_eq!(
            oid_bytes,
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]
        );
        // extnValue OCTET STRING = exact request extnValue bytes
        let (tag, extn_value, _) = read_tlv(after_oid).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(extn_value, nonce_extn_value.as_slice());
    }

    #[test]
    fn test_tbs_response_data_no_nonce_no_extensions() {
        let name_der = vec![0x30, 0x00];
        let resp = test_single_response(vec![0x01], CertStatus::Good);
        let tbs =
            encode_tbs_response_data(&name_der, Utc::now(), std::slice::from_ref(&resp), None)
                .unwrap();
        let (_, content, _) = read_tlv(&tbs).unwrap();
        let (_, _, after_rid) = read_tlv(content).unwrap();
        let (_, _, after_produced) = read_tlv(after_rid).unwrap();
        let (tag, _, rest) = read_tlv(after_produced).unwrap();
        assert_eq!(tag, 0x30); // responses
        assert!(rest.is_empty(), "no nonce must mean no responseExtensions");
    }

    /// Full successful response: outer OCSPResponse structure and verbatim
    /// TBS embedding (the signed bytes must equal the emitted bytes).
    #[test]
    fn test_full_response_der_structure() {
        let name_der = vec![0x30, 0x00];
        let resp = test_single_response(vec![0x42], CertStatus::Good);
        let tbs =
            encode_tbs_response_data(&name_der, Utc::now(), std::slice::from_ref(&resp), None)
                .unwrap();

        let fake_cert = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // placeholder "certificate"
        // sha256WithRSAEncryption AlgorithmIdentifier: SEQUENCE { OID, NULL }
        let rsa_sig_alg = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        let response = OcspResponse::successful(
            vec![resp],
            tbs.clone(),
            vec![0xAA; 256], // fake signature
            rsa_sig_alg,
            fake_cert.clone(),
            None,
        );

        let der = response.to_der().unwrap();

        // OCSPResponse ::= SEQUENCE
        let (tag, content, rest) = read_tlv(&der).unwrap();
        assert_eq!(tag, 0x30);
        assert!(rest.is_empty());
        // responseStatus ENUMERATED 0 (successful)
        let (tag, status, after_status) = read_tlv(content).unwrap();
        assert_eq!(tag, 0x0A);
        assert_eq!(status, &[0x00]);
        // responseBytes [0] EXPLICIT
        let (tag, rb_explicit, rest) = read_tlv(after_status).unwrap();
        assert_eq!(tag, 0xA0);
        assert!(rest.is_empty());
        // ResponseBytes ::= SEQUENCE { OID, OCTET STRING }
        let (tag, rb_content, _) = read_tlv(rb_explicit).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, rt_oid, after_oid) = read_tlv(rb_content).unwrap();
        assert_eq!(tag, 0x06);
        // id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
        assert_eq!(
            rt_oid,
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
        );
        let (tag, basic_der, _) = read_tlv(after_oid).unwrap();
        assert_eq!(tag, 0x04);
        // BasicOCSPResponse ::= SEQUENCE
        let (tag, basic_content, _) = read_tlv(basic_der).unwrap();
        assert_eq!(tag, 0x30);
        // tbsResponseData - the EXACT signed bytes, verbatim
        assert!(
            basic_content.starts_with(&tbs),
            "tbsResponseData must be the exact signed bytes"
        );
        let after_tbs = &basic_content[tbs.len()..];
        // signatureAlgorithm SEQUENCE { OID sha256WithRSAEncryption, NULL }
        let (tag, sig_alg, after_alg) = read_tlv(after_tbs).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, alg_oid, after_alg_oid) = read_tlv(sig_alg).unwrap();
        assert_eq!(tag, 0x06);
        assert_eq!(
            alg_oid,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
        );
        let (tag, _, _) = read_tlv(after_alg_oid).unwrap();
        assert_eq!(tag, 0x05); // NULL params
        // signature BIT STRING with zero unused bits
        let (tag, sig, after_sig) = read_tlv(after_alg).unwrap();
        assert_eq!(tag, 0x03);
        assert_eq!(sig[0], 0x00);
        assert_eq!(&sig[1..], &[0xAA; 256][..]);
        // certs [0] EXPLICIT SEQUENCE OF Certificate
        let (tag, certs_explicit, rest) = read_tlv(after_sig).unwrap();
        assert_eq!(tag, 0xA0);
        assert!(rest.is_empty());
        let (tag, certs_seq, _) = read_tlv(certs_explicit).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(certs_seq, fake_cert.as_slice());
    }

    #[test]
    fn test_error_response_der_is_status_only() {
        let response = OcspResponse::error(ResponseStatus::MalformedRequest);
        let der = response.to_der().unwrap();
        // SEQUENCE { ENUMERATED 1 } - no responseBytes
        assert_eq!(der, vec![0x30, 0x03, 0x0A, 0x01, 0x01]);
    }

    #[test]
    fn test_successful_response_without_tbs_fails_closed() {
        let response = OcspResponse::successful(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        );
        assert!(response.to_der().is_err());
    }

    #[test]
    fn test_single_response_structure() {
        let now = Utc::now();
        let mut response = test_single_response(vec![0x01, 0x02, 0x03], CertStatus::Good);
        response.next_update = Some(now + Duration::hours(1));

        assert_eq!(response.serial_number, vec![0x01, 0x02, 0x03]);
        assert!(matches!(response.cert_status, CertStatus::Good));
        assert!(response.next_update.is_some());
    }

    #[test]
    fn test_single_response_without_next_update() {
        let response = test_single_response(vec![0x01], CertStatus::Unknown);
        assert!(response.next_update.is_none());
    }

    #[test]
    fn test_ocsp_response_successful() {
        let now = Utc::now();
        let mut single_response = test_single_response(vec![0x01], CertStatus::Good);
        single_response.next_update = Some(now + Duration::hours(24));

        let response = OcspResponse::successful(
            vec![single_response],
            vec![0x30, 0x00],       // tbs
            vec![0xAA, 0xBB, 0xCC], // signature
            vec![0x30, 0x00],       // signatureAlgorithm (placeholder DER)
            vec![0xDE, 0xAD],       // signing_cert
            Some(vec![0x12, 0x34]), // nonce
        );

        assert_eq!(response.response_status, ResponseStatus::Successful);
        assert_eq!(response.responses.len(), 1);
        assert!(!response.tbs_response_data.is_empty());
        assert!(!response.signature.is_empty());
        assert!(!response.signing_cert.is_empty());
        assert!(response.nonce.is_some());
    }

    #[test]
    fn test_ocsp_response_error() {
        let response = OcspResponse::error(ResponseStatus::MalformedRequest);

        assert_eq!(response.response_status, ResponseStatus::MalformedRequest);
        assert!(response.responses.is_empty());
        assert!(response.signature.is_empty());
        assert!(response.signing_cert.is_empty());
        assert!(response.nonce.is_none());
    }

    #[test]
    fn test_ocsp_response_internal_error() {
        let response = OcspResponse::error(ResponseStatus::InternalError);
        assert_eq!(response.response_status, ResponseStatus::InternalError);
    }

    #[test]
    fn test_ocsp_response_unauthorized() {
        let response = OcspResponse::error(ResponseStatus::Unauthorized);
        assert_eq!(response.response_status, ResponseStatus::Unauthorized);
    }

    #[test]
    fn test_cert_status_revoked_reasons() {
        // RFC 5280 §5.3.1 - Reason codes
        let reasons = [
            (0u8, "unspecified"),
            (1u8, "keyCompromise"),
            (2u8, "cACompromise"),
            (3u8, "affiliationChanged"),
            (4u8, "superseded"),
            (5u8, "cessationOfOperation"),
            (6u8, "certificateHold"),
        ];

        for (code, _name) in reasons {
            let status = CertStatus::Revoked {
                revocation_time: Utc::now(),
                revocation_reason: Some(code),
            };
            if let CertStatus::Revoked {
                revocation_reason, ..
            } = status
            {
                assert_eq!(revocation_reason, Some(code));
            }
        }
    }

    #[test]
    fn test_cert_status_revoked_without_reason() {
        let status = CertStatus::Revoked {
            revocation_time: Utc::now(),
            revocation_reason: None,
        };
        if let CertStatus::Revoked {
            revocation_reason, ..
        } = status
        {
            assert!(revocation_reason.is_none());
        }
    }

    #[test]
    fn test_ocsp_response_serialization() {
        let single_response = test_single_response(vec![0x01], CertStatus::Good);

        let response = OcspResponse::successful(
            vec![single_response],
            vec![0x30, 0x00],
            vec![0xAA],
            vec![0x30, 0x00],
            vec![0xBB],
            None,
        );

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Successful"));

        let deserialized: OcspResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.response_status, ResponseStatus::Successful);
    }

    #[test]
    fn test_response_status_equality() {
        assert_eq!(ResponseStatus::Successful, ResponseStatus::Successful);
        assert_ne!(ResponseStatus::Successful, ResponseStatus::InternalError);
    }

    #[test]
    fn test_cert_status_equality() {
        assert_eq!(CertStatus::Good, CertStatus::Good);
        assert_eq!(CertStatus::Unknown, CertStatus::Unknown);
        assert_ne!(CertStatus::Good, CertStatus::Unknown);
    }

    #[test]
    fn test_multiple_responses() {
        let now = Utc::now();
        let responses = vec![
            test_single_response(vec![0x01], CertStatus::Good),
            test_single_response(
                vec![0x02],
                CertStatus::Revoked {
                    revocation_time: now,
                    revocation_reason: Some(1),
                },
            ),
            test_single_response(vec![0x03], CertStatus::Unknown),
        ];

        let ocsp_response =
            OcspResponse::successful(responses, vec![0x30, 0x00], vec![], vec![], vec![], None);

        assert_eq!(ocsp_response.responses.len(), 3);
        assert!(matches!(
            ocsp_response.responses[0].cert_status,
            CertStatus::Good
        ));
        assert!(matches!(
            ocsp_response.responses[1].cert_status,
            CertStatus::Revoked { .. }
        ));
        assert!(matches!(
            ocsp_response.responses[2].cert_status,
            CertStatus::Unknown
        ));
    }
}
