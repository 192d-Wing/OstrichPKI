//! CMS `SignedData` wrapping and verification for TAMP messages.
//!
//! RFC 5934 §2.2 requires every TAMP message to be carried inside a CMS
//! `SignedData` (RFC 5652) with **exactly one** `SignerInfo`, whose
//! `SignerIdentifier` uses the **subjectKeyIdentifier** form so the recipient
//! can locate the signing trust anchor by key id. The signed attributes carry
//! the `content-type` and `message-digest` attributes (RFC 5652 §11).
//!
//! As the TAMP *manager*, OstrichPKI [`sign_message`]s outbound messages with an
//! apex/management key held by the [`CryptoProvider`], and [`parse`]s + [`verify`]s
//! the signed confirmations and status responses returned by targets.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 §2.2 - CMS protection of TAMP messages (single SignerInfo, SKI sid)
//! - RFC 5652 §5 - SignedData; §5.4 - signed-attributes signing input
//! - NIST 800-53: SC-13 (FIPS-validated signing/verification), SI-10 (DER validation)
//! - NIAP PP-CA: FCS_COP.1 - cryptographic operation (signature gen/verify)

use crate::error::{Error, Result};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::oids::ID_SIGNED_DATA;

/// `id-contentType` CMS attribute (RFC 5652 §11.1).
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest` CMS attribute (RFC 5652 §11.2).
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `id-sha256` digest algorithm (FIPS 180-4).
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

fn sha256_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    }
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| Error::Cms(format!("attribute value set: {e}")))?;
    Ok(Attribute { oid, values })
}

/// Build the `SignedAttributes` SET (`content-type` + `message-digest`).
///
/// RFC 5652 §5.3 - both attributes are mandatory when signedAttrs are present.
fn build_signed_attrs(
    content_type: ObjectIdentifier,
    content: &[u8],
) -> Result<SetOfVec<Attribute>> {
    let digest = Sha256::digest(content);
    let digest_os =
        OctetString::new(digest.to_vec()).map_err(|e| Error::Cms(format!("digest octets: {e}")))?;

    let ct_value = Any::encode_from(&content_type)
        .map_err(|e| Error::Cms(format!("content-type any: {e}")))?;
    let md_value =
        Any::encode_from(&digest_os).map_err(|e| Error::Cms(format!("message-digest any: {e}")))?;

    let mut attrs = SetOfVec::new();
    attrs
        .insert(attribute(ID_CONTENT_TYPE, ct_value)?)
        .map_err(|e| Error::Cms(format!("insert content-type: {e}")))?;
    attrs
        .insert(attribute(ID_MESSAGE_DIGEST, md_value)?)
        .map_err(|e| Error::Cms(format!("insert message-digest: {e}")))?;
    Ok(attrs)
}

/// Build the optional CMS `UnsignedAttributes` SET from `(oid, value)` pairs.
fn build_unsigned_attrs(attrs: &[(ObjectIdentifier, Any)]) -> Result<Option<SetOfVec<Attribute>>> {
    if attrs.is_empty() {
        return Ok(None);
    }
    let mut set = SetOfVec::new();
    for (oid, value) in attrs {
        set.insert(attribute(*oid, value.clone())?)
            .map_err(|e| Error::Cms(format!("insert unsigned attr: {e}")))?;
    }
    Ok(Some(set))
}

/// Sign a TAMP message body, producing a DER-encoded CMS `ContentInfo`
/// (`SignedData`) ready for transport.
///
/// * `content_type` — the `id-ct-TAMP-*` OID identifying `content`.
/// * `content` — the DER encoding of the TAMP message (the eContent).
/// * `signer_ski` — subjectKeyIdentifier of the signing trust anchor.
/// * `signing_algorithm` — signature algorithm matching `key`.
///
/// RFC 5934 §2.2.1 - one SignerInfo, SKI signer identifier, v3.
pub async fn sign_message(
    provider: &dyn CryptoProvider,
    key: &KeyHandle,
    signer_ski: &[u8],
    content_type: ObjectIdentifier,
    content: &[u8],
    signing_algorithm: Algorithm,
) -> Result<Vec<u8>> {
    sign_message_with_unsigned_attrs(
        provider,
        key,
        signer_ski,
        content_type,
        content,
        signing_algorithm,
        &[],
    )
    .await
}

/// Like [`sign_message`], but attaches CMS *unsigned* attributes to the single
/// SignerInfo (RFC 5652 §5.3). TAMP uses this to carry the apex contingency
/// public-key decrypt key (`id-aa-TAMP-contingencyPublicKeyDecryptKey`,
/// RFC 5934 §2.2.4.1), which is deliberately delivered outside the signature.
#[allow(clippy::too_many_arguments)]
pub async fn sign_message_with_unsigned_attrs(
    provider: &dyn CryptoProvider,
    key: &KeyHandle,
    signer_ski: &[u8],
    content_type: ObjectIdentifier,
    content: &[u8],
    signing_algorithm: Algorithm,
    unsigned_attrs: &[(ObjectIdentifier, Any)],
) -> Result<Vec<u8>> {
    let signed_attrs = build_signed_attrs(content_type, content)?;

    // RFC 5652 §5.4: the signature is computed over the DER encoding of the
    // SignedAttributes value with an explicit SET OF tag (which `SetOfVec`
    // produces), NOT the IMPLICIT [0] form stored in the SignerInfo.
    let tbs = signed_attrs
        .to_der()
        .map_err(|e| Error::Cms(format!("encode signed attrs: {e}")))?;

    let raw_sig = provider.sign(key, signing_algorithm, &tbs).await?;
    // Providers emit ECDSA as fixed r||s; CMS requires the DER Ecdsa-Sig-Value.
    let sig = ostrich_x509::signing::encode_x509_signature(signing_algorithm, raw_sig)
        .map_err(|e| Error::Cms(format!("encode signature value: {e}")))?;
    let sig_alg = ostrich_x509::signing::algorithm_identifier(signing_algorithm)
        .map_err(|e| Error::Cms(format!("signature algorithm id: {e}")))?;

    let ski = SubjectKeyIdentifier(
        OctetString::new(signer_ski.to_vec())
            .map_err(|e| Error::Cms(format!("ski octets: {e}")))?,
    );

    let signer_info = SignerInfo {
        version: CmsVersion::V3,
        sid: SignerIdentifier::SubjectKeyIdentifier(ski),
        digest_alg: sha256_alg_id(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: sig_alg,
        signature: OctetString::new(sig)
            .map_err(|e| Error::Cms(format!("signature octets: {e}")))?,
        unsigned_attrs: build_unsigned_attrs(unsigned_attrs)?,
    };

    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms
        .insert(sha256_alg_id())
        .map_err(|e| Error::Cms(format!("digest alg set: {e}")))?;

    let econtent = Any::encode_from(
        &OctetString::new(content.to_vec())
            .map_err(|e| Error::Cms(format!("econtent octets: {e}")))?,
    )
    .map_err(|e| Error::Cms(format!("econtent any: {e}")))?;

    let mut signer_infos = SetOfVec::new();
    signer_infos
        .insert(signer_info)
        .map_err(|e| Error::Cms(format!("signer info set: {e}")))?;

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: content_type,
            econtent: Some(econtent),
        },
        certificates: None,
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data)
            .map_err(|e| Error::Cms(format!("encode SignedData: {e}")))?,
    };
    content_info
        .to_der()
        .map_err(|e| Error::Cms(format!("encode ContentInfo: {e}")))
}

/// A TAMP message extracted from a verified-or-unverified CMS envelope.
#[derive(Clone, Debug)]
pub struct ParsedTampMessage {
    /// `eContentType` — the `id-ct-TAMP-*` content type OID.
    pub content_type: ObjectIdentifier,
    /// `eContent` — the DER bytes of the inner TAMP message.
    pub content: Vec<u8>,
    /// subjectKeyIdentifier of the (single) signer.
    pub signer_ski: Vec<u8>,
    /// DER of the SignedAttributes SET (the bytes that were signed).
    signed_attrs_der: Vec<u8>,
    /// Signature value (DER form for ECDSA).
    signature: Vec<u8>,
    /// Signature algorithm OID from the SignerInfo.
    signature_alg_oid: ObjectIdentifier,
}

/// Parse a CMS `ContentInfo` carrying a TAMP message, extracting the eContent
/// and the single SignerInfo's verification material.
///
/// RFC 5934 §2.2.1 - rejects envelopes that do not have exactly one SignerInfo
/// or that do not use the subjectKeyIdentifier signer form. SI-10: strict DER.
pub fn parse(content_info_der: &[u8]) -> Result<ParsedTampMessage> {
    let ci = ContentInfo::from_der(content_info_der)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(Error::Cms("outer content type is not id-signedData".into()));
    }
    let signed_data: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Cms(format!("decode SignedData: {e}")))?;

    // eContent must be present (RFC 5934 messages are never detached).
    let econtent = signed_data
        .encap_content_info
        .econtent
        .ok_or_else(|| Error::Cms("missing eContent".into()))?;
    let content_os: OctetString = econtent
        .decode_as()
        .map_err(|e| Error::Cms(format!("eContent is not an OCTET STRING: {e}")))?;
    let content_type = signed_data.encap_content_info.econtent_type;

    let signer_infos = signed_data.signer_infos.0.as_slice();
    let [signer] = signer_infos else {
        return Err(Error::Cms(format!(
            "expected exactly one SignerInfo, found {}",
            signer_infos.len()
        )));
    };

    let signer_ski = match &signer.sid {
        SignerIdentifier::SubjectKeyIdentifier(ski) => ski.0.as_bytes().to_vec(),
        SignerIdentifier::IssuerAndSerialNumber(_) => {
            return Err(Error::Cms(
                "SignerIdentifier must be subjectKeyIdentifier (RFC 5934 §2.2.1)".into(),
            ));
        }
    };

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Cms("missing signed attributes".into()))?;
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| Error::Cms(format!("re-encode signed attrs: {e}")))?;

    Ok(ParsedTampMessage {
        content_type,
        content: content_os.as_bytes().to_vec(),
        signer_ski,
        signed_attrs_der,
        signature: signer.signature.as_bytes().to_vec(),
        signature_alg_oid: signer.signature_algorithm.oid,
    })
}

/// Map a CMS signature-algorithm OID to the crate's [`Algorithm`].
fn map_signature_alg(oid: ObjectIdentifier) -> Result<Algorithm> {
    // ecdsa-with-SHA256 / -SHA384 (RFC 5758 §3.2)
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    // sha{256,384,512}WithRSAEncryption (RFC 4055)
    const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    // id-Ed25519 (RFC 8410)
    const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

    match oid {
        ECDSA_SHA256 => Ok(Algorithm::EcdsaP256Sha256),
        ECDSA_SHA384 => Ok(Algorithm::EcdsaP384Sha384),
        RSA_SHA256 => Ok(Algorithm::RsaPkcs1Sha256),
        RSA_SHA384 => Ok(Algorithm::RsaPkcs1Sha384),
        RSA_SHA512 => Ok(Algorithm::RsaPkcs1Sha512),
        ED25519 => Ok(Algorithm::Ed25519),
        other => Err(Error::Cms(format!(
            "unsupported CMS signature algorithm OID {other}"
        ))),
    }
}

/// Verify the signature on a parsed TAMP message against a trust anchor's
/// SubjectPublicKeyInfo, and confirm the bound `message-digest` matches the
/// eContent.
///
/// RFC 5652 §5.4 / §5.6 - signature verification over the signed attributes,
/// with the message-digest attribute bound to the eContent.
pub fn verify(parsed: &ParsedTampMessage, signer_spki_der: &[u8]) -> Result<()> {
    // Re-derive and check the message-digest binding before touching the
    // signature (cheap, and fails closed on content/attr mismatch).
    let bound_digest = extract_message_digest(&parsed.signed_attrs_der)?;
    let actual = Sha256::digest(&parsed.content);
    if bound_digest != actual.as_slice() {
        return Err(Error::SignatureFailure(
            "message-digest attribute does not match eContent".into(),
        ));
    }

    let algorithm = map_signature_alg(parsed.signature_alg_oid)?;
    // CMS ECDSA signatures are ASN.1 DER (ecdsa_fixed = false).
    let ok = ostrich_crypto::verify_with_spki(
        signer_spki_der,
        algorithm,
        &parsed.signed_attrs_der,
        &parsed.signature,
        false,
    )?;
    if ok {
        Ok(())
    } else {
        Err(Error::SignatureFailure("signature did not verify".into()))
    }
}

/// Pull the `message-digest` attribute value out of an encoded SignedAttributes
/// SET, for binding verification.
fn extract_message_digest(signed_attrs_der: &[u8]) -> Result<Vec<u8>> {
    let attrs = SetOfVec::<Attribute>::from_der(signed_attrs_der)?;
    for attr in attrs.iter() {
        if attr.oid == ID_MESSAGE_DIGEST {
            let value = attr
                .values
                .iter()
                .next()
                .ok_or_else(|| Error::Cms("empty message-digest attribute".into()))?;
            let os: OctetString = value
                .decode_as()
                .map_err(|e| Error::Cms(format!("message-digest value: {e}")))?;
            return Ok(os.as_bytes().to_vec());
        }
    }
    Err(Error::Cms("no message-digest attribute".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oids::ID_CT_TAMP_STATUS_QUERY;
    use ostrich_crypto::{CryptoProviderFactory, KeyType};

    // Sign a payload with a freshly generated ECDSA P-256 key, then verify it
    // round-trips through parse + verify against the key's own SPKI.
    #[tokio::test]
    async fn sign_parse_verify_round_trip_ecdsa() {
        let provider = CryptoProviderFactory::create_software_provider();
        let key = provider
            .generate_key_pair(KeyType::EcP256, "tamp-test", true)
            .await
            .unwrap();
        let spki = provider.export_public_key(&key).await.unwrap();
        // SKI is the SHA-1 of the SPKI subjectPublicKey; any stable id works for
        // this test since we hand the same SPKI to verify().
        let ski = Sha256::digest(&spki)[..20].to_vec();

        let payload = b"\x30\x03\x02\x01\x2a"; // arbitrary DER (INTEGER 42 in a SEQ)
        let envelope = sign_message(
            provider.as_ref(),
            &key,
            &ski,
            ID_CT_TAMP_STATUS_QUERY,
            payload,
            Algorithm::EcdsaP256Sha256,
        )
        .await
        .unwrap();

        let parsed = parse(&envelope).unwrap();
        assert_eq!(parsed.content_type, ID_CT_TAMP_STATUS_QUERY);
        assert_eq!(parsed.content, payload);
        assert_eq!(parsed.signer_ski, ski);
        verify(&parsed, &spki).unwrap();
    }

    #[tokio::test]
    async fn tampered_content_fails_verification() {
        let provider = CryptoProviderFactory::create_software_provider();
        let key = provider
            .generate_key_pair(KeyType::EcP256, "tamp-test", true)
            .await
            .unwrap();
        let spki = provider.export_public_key(&key).await.unwrap();
        let ski = Sha256::digest(&spki)[..20].to_vec();

        let envelope = sign_message(
            provider.as_ref(),
            &key,
            &ski,
            ID_CT_TAMP_STATUS_QUERY,
            b"\x30\x03\x02\x01\x2a",
            Algorithm::EcdsaP256Sha256,
        )
        .await
        .unwrap();

        let mut parsed = parse(&envelope).unwrap();
        let last = parsed.content.len() - 1;
        parsed.content[last] ^= 0xff; // flip a byte
        assert!(verify(&parsed, &spki).is_err());
    }

    // The contingency-key decrypt material is carried as an UNSIGNED attribute
    // (RFC 5934 §2.2.4.1). Verify it is attached to the SignerInfo, signature
    // still verifies, and the round-trip recovers the exact key bytes.
    #[tokio::test]
    async fn unsigned_contingency_attribute_is_attached_and_recoverable() {
        use crate::oids::ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY;
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;

        let provider = CryptoProviderFactory::create_software_provider();
        let key = provider
            .generate_key_pair(KeyType::EcP256, "tamp-test", true)
            .await
            .unwrap();
        let spki = provider.export_public_key(&key).await.unwrap();
        let ski = Sha256::digest(&spki)[..20].to_vec();

        let decrypt_key = vec![0x11u8; 32];
        let attr_value = Any::encode_from(&OctetString::new(decrypt_key.clone()).unwrap()).unwrap();
        let envelope = sign_message_with_unsigned_attrs(
            provider.as_ref(),
            &key,
            &ski,
            crate::oids::ID_CT_TAMP_APEX_UPDATE,
            b"\x30\x03\x02\x01\x2a",
            Algorithm::EcdsaP256Sha256,
            &[(ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY, attr_value)],
        )
        .await
        .unwrap();

        // The signed content still verifies (unsigned attrs are outside the sig).
        let parsed = parse(&envelope).unwrap();
        verify(&parsed, &spki).unwrap();

        // The unsigned attribute is present and carries the exact key bytes.
        let ci = ContentInfo::from_der(&envelope).unwrap();
        let sd: SignedData = ci.content.decode_as().unwrap();
        let signer = &sd.signer_infos.0.as_slice()[0];
        let unsigned = signer
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs present");
        let attr = unsigned
            .iter()
            .find(|a| a.oid == ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY)
            .expect("contingency attribute present");
        let recovered: OctetString = attr.values.iter().next().unwrap().decode_as().unwrap();
        assert_eq!(recovered.as_bytes(), decrypt_key.as_slice());
    }
}
