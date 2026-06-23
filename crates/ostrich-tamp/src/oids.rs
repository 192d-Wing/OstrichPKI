//! Object identifiers for the Trust Anchor Management Protocol (RFC 5934).
//!
//! All arcs are transcribed verbatim from the normative ASN.1 module in
//! RFC 5934 Appendix A.1. Note that the TAMP content-type arc is rooted under
//! the U.S. DoD `infosec` formats arc (`2.16.840.1.101.2.1.2`), NOT under the
//! PKCS#9 S/MIME arc — a common mistake.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 Appendix A.1 - TAMP-Protocol-v2 ASN.1 module
//! - RFC 5934 §2 - CMS content types used to wrap TAMP messages
//! - RFC 5652 §5 - id-signedData content type
//! - NIST 800-53: SC-17 (PKI certificates) - protocol object identifiers

use const_oid::ObjectIdentifier;

/// `id-tamp` — arc for TAMP message content types.
///
/// `{ joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
///    dod(2) infosec(1) formats(2) 77 }`
pub const ID_TAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77");

/// `id-ct-TAMP-statusQuery ::= { id-tamp 1 }`
pub const ID_CT_TAMP_STATUS_QUERY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.1");

/// `id-ct-TAMP-statusResponse ::= { id-tamp 2 }`
pub const ID_CT_TAMP_STATUS_RESPONSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.2");

/// `id-ct-TAMP-update ::= { id-tamp 3 }`
pub const ID_CT_TAMP_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.3");

/// `id-ct-TAMP-updateConfirm ::= { id-tamp 4 }`
pub const ID_CT_TAMP_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.4");

/// `id-ct-TAMP-apexUpdate ::= { id-tamp 5 }`
pub const ID_CT_TAMP_APEX_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.5");

/// `id-ct-TAMP-apexUpdateConfirm ::= { id-tamp 6 }`
pub const ID_CT_TAMP_APEX_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.6");

/// `id-ct-TAMP-communityUpdate ::= { id-tamp 7 }`
pub const ID_CT_TAMP_COMMUNITY_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.7");

/// `id-ct-TAMP-communityUpdateConfirm ::= { id-tamp 8 }`
pub const ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.8");

/// `id-ct-TAMP-error ::= { id-tamp 9 }`
pub const ID_CT_TAMP_ERROR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.9");

/// `id-ct-TAMP-seqNumAdjust ::= { id-tamp 10 }`
pub const ID_CT_TAMP_SEQ_NUM_ADJUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.10");

/// `id-ct-TAMP-seqNumAdjustConfirm ::= { id-tamp 11 }`
pub const ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.11");

/// `id-attributes ::= { joint-iso-ccitt(2) country(16) us(840)
///   organization(1) gov(101) dod(2) infosec(1) 5 }`
pub const ID_ATTRIBUTES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.5");

/// `id-aa-TAMP-contingencyPublicKeyDecryptKey ::= { id-attributes 63 }`
///
/// Unsigned CMS attribute carrying the plaintext symmetric key used to unwrap
/// the apex contingency public key (RFC 5934 §2.2.4.1).
pub const ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.5.63");

/// `id-pe-wrappedApexContinKey ::= { id-pkix pe(1) 20 }`
///
/// Certificate extension carrying the wrapped apex contingency key
/// (RFC 5934 Appendix A.1).
pub const ID_PE_WRAPPED_APEX_CONTIN_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.20");

/// `id-signedData ::= { iso(1) member-body(2) us(840) rsadsi(113549)
///   pkcs(1) pkcs7(7) 2 }` — RFC 5652 §5.1.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// `id-data ::= { iso(1) member-body(2) us(840) rsadsi(113549)
///   pkcs(1) pkcs7(7) 1 }` — RFC 5652 §4.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// Map a TAMP content-type OID to its human-readable message name, for logging
/// and audit. Returns `None` for OIDs outside the `id-tamp` arc.
pub fn tamp_content_type_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    match *oid {
        ID_CT_TAMP_STATUS_QUERY => Some("TAMPStatusQuery"),
        ID_CT_TAMP_STATUS_RESPONSE => Some("TAMPStatusResponse"),
        ID_CT_TAMP_UPDATE => Some("TAMPUpdate"),
        ID_CT_TAMP_UPDATE_CONFIRM => Some("TAMPUpdateConfirm"),
        ID_CT_TAMP_APEX_UPDATE => Some("TAMPApexUpdate"),
        ID_CT_TAMP_APEX_UPDATE_CONFIRM => Some("TAMPApexUpdateConfirm"),
        ID_CT_TAMP_COMMUNITY_UPDATE => Some("TAMPCommunityUpdate"),
        ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM => Some("TAMPCommunityUpdateConfirm"),
        ID_CT_TAMP_ERROR => Some("TAMPError"),
        ID_CT_TAMP_SEQ_NUM_ADJUST => Some("SequenceNumberAdjust"),
        ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM => Some("SequenceNumberAdjustConfirm"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamp_content_type_arcs_are_sequential() {
        // RFC 5934 Appendix A.1: id-tamp 1..11 (9 is reserved for error).
        assert_eq!(
            ID_CT_TAMP_STATUS_QUERY.to_string(),
            "2.16.840.1.101.2.1.2.77.1"
        );
        assert_eq!(
            ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM.to_string(),
            "2.16.840.1.101.2.1.2.77.11"
        );
        assert_eq!(ID_CT_TAMP_ERROR.to_string(), "2.16.840.1.101.2.1.2.77.9");
    }

    #[test]
    fn content_type_names_resolve() {
        assert_eq!(
            tamp_content_type_name(&ID_CT_TAMP_UPDATE),
            Some("TAMPUpdate")
        );
        assert_eq!(tamp_content_type_name(&ID_DATA), None);
    }
}
