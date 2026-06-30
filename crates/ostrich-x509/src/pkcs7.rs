//! PKCS#7 / CMS certs-only (degenerate `SignedData`) encoding.
//!
//! A "certs-only" PKCS#7 carries one or more certificates and no signed
//! content — the standard container for shipping a certificate plus its issuing
//! chain (a `.p7b` / `.p7c` bundle). Used by EST (RFC 7030 §4.x responses) and
//! by the management API's certificate download.
//!
//! # Compliance Mapping
//! - RFC 5652 §5 — CMS `SignedData` structure
//! - RFC 7030 §4.1.3 — EST CA-certificates response format (degenerate PKCS#7)
//! - NIAP PP-CA: FCS_COP.1 — Cryptographic operation (CMS encoding)

use der::{
    Decode, Encode,
    asn1::{ObjectIdentifier, SetOfVec},
};
use x509_cert::Certificate;

use crate::error::{Error, Result};

// RFC 5652 §5: id-signedData content type OID.
const SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
// RFC 5652 §3: id-data content type OID.
const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// Encode DER-encoded certificates as a degenerate certs-only PKCS#7 (CMS
/// `SignedData` with no content and no signers), returning DER bytes.
///
/// Certificate order is preserved as given (leaf first, then chain). An empty
/// input yields a valid `SignedData` with an absent `certificates` field.
pub fn encode_certs_only_pkcs7(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    use cms::{content_info::ContentInfo, signed_data::SignedData};

    let mut cert_choices = SetOfVec::new();
    for cert_der in certs {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| Error::Der(format!("invalid certificate DER: {e}")))?;
        let choice = cms::cert::CertificateChoices::Certificate(cert);
        cert_choices
            .insert(choice)
            .map_err(|e| Error::Encoding(format!("too many certificates: {e}")))?;
    }

    let signed_data = SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms: SetOfVec::new(),
        encap_content_info: cms::signed_data::EncapsulatedContentInfo {
            econtent_type: DATA_OID,
            econtent: None,
        },
        certificates: if cert_choices.is_empty() {
            None
        } else {
            Some(cert_choices.into())
        },
        crls: None,
        signer_infos: SetOfVec::new().into(),
    };

    let content_info = ContentInfo {
        content_type: SIGNED_DATA_OID,
        content: der::Any::encode_from(&signed_data)
            .map_err(|e| Error::Encoding(format!("failed to encode SignedData: {e}")))?,
    };

    content_info
        .to_der()
        .map_err(|e| Error::Encoding(format!("failed to encode PKCS#7: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_encodes_valid_pkcs7() {
        // RFC 7030 §4.1.3 — a degenerate SignedData with no certs is still valid.
        let der = encode_certs_only_pkcs7(&[]).expect("encode empty");
        // Re-parse to confirm it is well-formed ContentInfo carrying SignedData.
        let ci = cms::content_info::ContentInfo::from_der(&der).expect("parse ContentInfo");
        assert_eq!(ci.content_type, SIGNED_DATA_OID);
    }
}
