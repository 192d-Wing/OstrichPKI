//! TAMP status codes (RFC 5934 §5 / Appendix A.1 `StatusCode`).
//!
//! `StatusCode ::= ENUMERATED { ... }` — the full set of result codes returned
//! in confirm and error messages. Transcribed verbatim from the normative
//! ASN.1 module so that confirm/error encodings are bits-on-the-wire correct.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 §5 - Status codes
//! - NIST 800-53: AU-3 (audit content) - outcome codes recorded per operation

use der::Enumerated;

/// TAMP `StatusCode` result code.
///
/// The discriminants are the on-the-wire ENUMERATED values defined in
/// RFC 5934 Appendix A.1 and MUST NOT be reordered or renumbered.
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq, Default)]
#[asn1(type = "ENUMERATED")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum StatusCode {
    #[default]
    Success = 0,
    DecodeFailure = 1,
    BadContentInfo = 2,
    BadSignedData = 3,
    BadEncapContent = 4,
    BadCertificate = 5,
    BadSignerInfo = 6,
    BadSignedAttrs = 7,
    BadUnsignedAttrs = 8,
    MissingContent = 9,
    NoTrustAnchor = 10,
    NotAuthorized = 11,
    BadDigestAlgorithm = 12,
    BadSignatureAlgorithm = 13,
    UnsupportedKeySize = 14,
    UnsupportedParameters = 15,
    SignatureFailure = 16,
    InsufficientMemory = 17,
    UnsupportedTampMsgType = 18,
    ApexTampAnchor = 19,
    ImproperTaAddition = 20,
    SeqNumFailure = 21,
    ContingencyPublicKeyDecrypt = 22,
    IncorrectTarget = 23,
    CommunityUpdateFailed = 24,
    TrustAnchorNotFound = 25,
    UnsupportedTaAlgorithm = 26,
    UnsupportedTaKeySize = 27,
    UnsupportedContinPubKeyDecryptAlg = 28,
    MissingSignature = 29,
    ResourcesBusy = 30,
    VersionNumberMismatch = 31,
    MissingPolicySet = 32,
    RevokedCertificate = 33,
    UnsupportedTrustAnchorFormat = 34,
    ImproperTaChange = 35,
    Malformed = 36,
    CmsError = 37,
    UnsupportedTargetIdentifier = 38,
    Other = 127,
}

impl StatusCode {
    /// Whether the code denotes successful application of an operation.
    pub fn is_success(self) -> bool {
        matches!(self, StatusCode::Success)
    }

    /// Stable snake_case label for audit records and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            StatusCode::Success => "success",
            StatusCode::DecodeFailure => "decode_failure",
            StatusCode::BadContentInfo => "bad_content_info",
            StatusCode::BadSignedData => "bad_signed_data",
            StatusCode::BadEncapContent => "bad_encap_content",
            StatusCode::BadCertificate => "bad_certificate",
            StatusCode::BadSignerInfo => "bad_signer_info",
            StatusCode::BadSignedAttrs => "bad_signed_attrs",
            StatusCode::BadUnsignedAttrs => "bad_unsigned_attrs",
            StatusCode::MissingContent => "missing_content",
            StatusCode::NoTrustAnchor => "no_trust_anchor",
            StatusCode::NotAuthorized => "not_authorized",
            StatusCode::BadDigestAlgorithm => "bad_digest_algorithm",
            StatusCode::BadSignatureAlgorithm => "bad_signature_algorithm",
            StatusCode::UnsupportedKeySize => "unsupported_key_size",
            StatusCode::UnsupportedParameters => "unsupported_parameters",
            StatusCode::SignatureFailure => "signature_failure",
            StatusCode::InsufficientMemory => "insufficient_memory",
            StatusCode::UnsupportedTampMsgType => "unsupported_tamp_msg_type",
            StatusCode::ApexTampAnchor => "apex_tamp_anchor",
            StatusCode::ImproperTaAddition => "improper_ta_addition",
            StatusCode::SeqNumFailure => "seq_num_failure",
            StatusCode::ContingencyPublicKeyDecrypt => "contingency_public_key_decrypt",
            StatusCode::IncorrectTarget => "incorrect_target",
            StatusCode::CommunityUpdateFailed => "community_update_failed",
            StatusCode::TrustAnchorNotFound => "trust_anchor_not_found",
            StatusCode::UnsupportedTaAlgorithm => "unsupported_ta_algorithm",
            StatusCode::UnsupportedTaKeySize => "unsupported_ta_key_size",
            StatusCode::UnsupportedContinPubKeyDecryptAlg => {
                "unsupported_contin_pub_key_decrypt_alg"
            }
            StatusCode::MissingSignature => "missing_signature",
            StatusCode::ResourcesBusy => "resources_busy",
            StatusCode::VersionNumberMismatch => "version_number_mismatch",
            StatusCode::MissingPolicySet => "missing_policy_set",
            StatusCode::RevokedCertificate => "revoked_certificate",
            StatusCode::UnsupportedTrustAnchorFormat => "unsupported_trust_anchor_format",
            StatusCode::ImproperTaChange => "improper_ta_change",
            StatusCode::Malformed => "malformed",
            StatusCode::CmsError => "cms_error",
            StatusCode::UnsupportedTargetIdentifier => "unsupported_target_identifier",
            StatusCode::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    #[test]
    fn status_code_der_round_trip() {
        for code in [
            StatusCode::Success,
            StatusCode::NotAuthorized,
            StatusCode::SeqNumFailure,
            StatusCode::ImproperTaChange,
            StatusCode::UnsupportedTargetIdentifier,
            StatusCode::Other,
        ] {
            let der = code.to_der().unwrap();
            let decoded = StatusCode::from_der(&der).unwrap();
            assert_eq!(code, decoded);
        }
    }

    #[test]
    fn other_is_127() {
        // RFC 5934 §5: other(127) is the catch-all.
        let der = StatusCode::Other.to_der().unwrap();
        // ENUMERATED, length 1, value 0x7f
        assert_eq!(der, vec![0x0a, 0x01, 0x7f]);
    }
}
