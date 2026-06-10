//! PKCS#10 Certification Request (CSR) builder.
//!
//! The rest of the codebase only *parses* CSRs; this builds them. It is used by
//! EST server-side key generation (RFC 7030 §4.4): the server generates a key
//! pair and must produce a CSR signed by that key so the CA can verify
//! proof-of-possession (RFC 2986) before issuing.
//!
//! Two-phase, mirroring `CertificateBuilder`:
//!   1. [`build_csr_info_der`] returns the `CertificationRequestInfo` DER to sign.
//!   2. the caller signs it with the private key (async, via the crypto provider).
//!   3. [`assemble_csr`] wraps the info, algorithm, and signature into a CSR.
//!
//! COMPLIANCE MAPPING:
//! - RFC 2986 - PKCS#10 Certification Request Syntax
//! - RFC 5280 §4.2.1.6 - Subject Alternative Name (carried via extensionRequest)
//! - NIST 800-53: SC-12 / SI-10

use crate::extensions::SubjectAltName;
use crate::{Error, Result};
use der::{Encode, asn1::OctetString};
use ostrich_common::types::DistinguishedName;
use ostrich_crypto::Algorithm;

/// Build the `CertificationRequestInfo` DER — the to-be-signed portion of a CSR.
///
/// `spki_der` is the DER SubjectPublicKeyInfo of the requester's key. When
/// `sans` is non-empty an `extensionRequest` attribute carrying a Subject
/// Alternative Name extension is included (RFC 2986 §4.1 / RFC 5280 §4.2.1.6).
pub fn build_csr_info_der(
    subject: &DistinguishedName,
    spki_der: &[u8],
    sans: &[SubjectAltName],
) -> Result<Vec<u8>> {
    use x509_cert::request::{CertReqInfo, ExtensionReq, Version};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let subject_name = dn_to_x509_name(subject)?;
    let public_key = SubjectPublicKeyInfoOwned::try_from(spki_der)
        .map_err(|e| Error::Encoding(format!("Invalid SubjectPublicKeyInfo: {}", e)))?;

    let mut attributes = x509_cert::attr::Attributes::default();
    if let Some(ext) = san_extension(sans)? {
        let attr = x509_cert::attr::Attribute::try_from(ExtensionReq(vec![ext]))
            .map_err(|e| Error::Encoding(format!("Failed to build extensionRequest: {}", e)))?;
        attributes
            .insert(attr)
            .map_err(|e| Error::Encoding(format!("Failed to add CSR attribute: {}", e)))?;
    }

    let info = CertReqInfo {
        version: Version::V1,
        subject: subject_name,
        public_key,
        attributes,
    };

    info.to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode CertReqInfo: {}", e)))
}

/// Assemble a complete DER PKCS#10 CSR from its signed info, signature
/// algorithm, and the X.509-encoded signature (ECDSA DER, RSA/Ed25519 raw).
pub fn assemble_csr(info_der: &[u8], sig_alg: Algorithm, signature: &[u8]) -> Result<Vec<u8>> {
    use der::{Decode, asn1::BitString};
    use x509_cert::request::{CertReq, CertReqInfo};

    let info = CertReqInfo::from_der(info_der)
        .map_err(|e| Error::Encoding(format!("Failed to re-parse CertReqInfo: {}", e)))?;
    let algorithm = crate::signing::algorithm_identifier(sig_alg)?;
    let signature = BitString::from_bytes(signature)
        .map_err(|e| Error::Encoding(format!("Failed to encode signature: {}", e)))?;

    CertReq {
        info,
        algorithm,
        signature,
    }
    .to_der()
    .map_err(|e| Error::Encoding(format!("Failed to encode CSR: {}", e)))
}

/// Build the SubjectAltName extension for a CSR's extensionRequest, or None when
/// there are no SANs.
fn san_extension(sans: &[SubjectAltName]) -> Result<Option<x509_cert::ext::Extension>> {
    use const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME;
    use der::asn1::Ia5StringRef;
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::SubjectAltName as X509San;
    use x509_cert::ext::pkix::name::GeneralName;

    let mut names = Vec::new();
    for san in sans {
        let gn = match san {
            SubjectAltName::DnsName(dns) => GeneralName::DnsName(
                Ia5StringRef::new(dns)
                    .map_err(|e| Error::Encoding(format!("Invalid DNS name: {}", e)))?
                    .into(),
            ),
            SubjectAltName::Rfc822Name(email) => GeneralName::Rfc822Name(
                Ia5StringRef::new(email)
                    .map_err(|e| Error::Encoding(format!("Invalid email: {}", e)))?
                    .into(),
            ),
            SubjectAltName::UniformResourceIdentifier(uri) => {
                GeneralName::UniformResourceIdentifier(
                    Ia5StringRef::new(uri)
                        .map_err(|e| Error::Encoding(format!("Invalid URI: {}", e)))?
                        .into(),
                )
            }
            SubjectAltName::IpAddress(ip) => {
                let octets = match ip {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                GeneralName::IpAddress(
                    OctetString::new(octets)
                        .map_err(|e| Error::Encoding(format!("Invalid IP: {}", e)))?,
                )
            }
            SubjectAltName::DirectoryName(_) => continue,
        };
        names.push(gn);
    }

    if names.is_empty() {
        return Ok(None);
    }

    let san_der = X509San(names)
        .to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode SAN: {}", e)))?;
    Ok(Some(Extension {
        extn_id: ID_CE_SUBJECT_ALT_NAME,
        critical: false,
        extn_value: OctetString::new(san_der)
            .map_err(|e| Error::Encoding(format!("Failed to wrap SAN: {}", e)))?,
    }))
}

/// Convert an ostrich `DistinguishedName` to an x509-cert `Name` (RFC 4514).
fn dn_to_x509_name(dn: &DistinguishedName) -> Result<x509_cert::name::Name> {
    use const_oid::db::rfc4519::{C, CN, L, O, OU, SERIAL_NUMBER, ST};
    use der::Any;
    use der::asn1::{PrintableStringRef, SetOfVec, Utf8StringRef};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::name::{Name, RelativeDistinguishedName};

    // Helper: push a single-attribute RDN as a UTF8String value.
    fn push_utf8(
        rdns: &mut Vec<RelativeDistinguishedName>,
        oid: der::asn1::ObjectIdentifier,
        val: &str,
    ) -> Result<()> {
        let value = Utf8StringRef::new(val)
            .map_err(|e| Error::Encoding(format!("Invalid DN attribute: {}", e)))?;
        let atv = AttributeTypeAndValue {
            oid,
            value: Any::encode_from(&value)
                .map_err(|e| Error::Encoding(format!("Failed to encode DN attribute: {}", e)))?,
        };
        let set = SetOfVec::try_from(vec![atv])
            .map_err(|e| Error::Encoding(format!("Failed to create RDN SET: {}", e)))?;
        rdns.push(RelativeDistinguishedName::from(set));
        Ok(())
    }

    let mut rdns = Vec::new();

    // RFC 4514 order: most-significant (C) first.
    if let Some(c) = &dn.country {
        // Country is a PrintableString per RFC 5280.
        let value = PrintableStringRef::new(c.as_bytes())
            .map_err(|e| Error::Encoding(format!("Invalid country: {}", e)))?;
        let atv = AttributeTypeAndValue {
            oid: C,
            value: Any::encode_from(&value)
                .map_err(|e| Error::Encoding(format!("Failed to encode country: {}", e)))?,
        };
        let set = SetOfVec::try_from(vec![atv])
            .map_err(|e| Error::Encoding(format!("Failed to create RDN SET: {}", e)))?;
        rdns.push(RelativeDistinguishedName::from(set));
    }
    if let Some(st) = &dn.state_or_province {
        push_utf8(&mut rdns, ST, st)?;
    }
    if let Some(l) = &dn.locality {
        push_utf8(&mut rdns, L, l)?;
    }
    if let Some(o) = &dn.organization {
        push_utf8(&mut rdns, O, o)?;
    }
    if let Some(ou) = &dn.organizational_unit {
        push_utf8(&mut rdns, OU, ou)?;
    }
    if let Some(cn) = &dn.common_name {
        push_utf8(&mut rdns, CN, cn)?;
    }
    if let Some(sn) = &dn.serial_number {
        push_utf8(&mut rdns, SERIAL_NUMBER, sn)?;
    }

    Ok(Name::from(rdns))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_crypto::{CryptoProvider, KeyType, software::SoftwareProvider};
    use std::sync::Arc;

    /// A CSR built here parses back with the expected subject/SANs/key and its
    /// signature verifies (proof-of-possession) — RFC 2986.
    #[tokio::test]
    async fn build_parse_and_verify_csr() {
        let provider: Arc<dyn CryptoProvider> = Arc::new(SoftwareProvider::new());
        let key = provider
            .generate_key_pair(KeyType::EcP256, "csr-test", true)
            .await
            .unwrap();
        let spki = provider.export_public_key(&key).await.unwrap();

        let subject = DistinguishedName {
            common_name: Some("leaf.example.com".to_string()),
            organization: Some("OstrichPKI".to_string()),
            ..Default::default()
        };
        let sans = vec![SubjectAltName::DnsName("leaf.example.com".to_string())];

        let info_der = build_csr_info_der(&subject, &spki, &sans).unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        let raw_sig = provider.sign(&key, alg, &info_der).await.unwrap();
        let x509_sig = crate::signing::encode_x509_signature(alg, raw_sig).unwrap();
        let csr_der = assemble_csr(&info_der, alg, &x509_sig).unwrap();

        // Parses back with the expected fields.
        let parsed = crate::parser::parse_csr(&csr_der).expect("CSR parses");
        assert!(parsed.subject_dn.contains("leaf.example.com"));
        assert_eq!(parsed.public_key, spki);
        assert!(
            parsed
                .subject_alternative_names
                .iter()
                .any(|s| s.contains("leaf.example.com"))
        );

        // Proof-of-possession: the self-signature verifies.
        assert!(
            crate::parser::verify_csr_signature(&parsed, &provider)
                .await
                .unwrap(),
            "built CSR signature must verify"
        );
    }
}
