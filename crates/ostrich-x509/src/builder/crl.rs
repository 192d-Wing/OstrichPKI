//! CRL builder
//!
//! RFC 5280 §5 - Certificate revocation lists

use crate::{Error, Result, parser::RevocationReason};
use chrono::{DateTime, Duration, Utc};
use ostrich_common::types::DistinguishedName;

/// CRL builder
///
/// RFC 5280 §5.1 - CRL fields
pub struct CrlBuilder {
    /// Issuer DN
    issuer: Option<DistinguishedName>,
    /// This update time
    this_update: Option<DateTime<Utc>>,
    /// Next update time
    next_update: Option<DateTime<Utc>>,
    /// CRL number
    crl_number: Option<u64>,
    /// Revoked certificates
    revoked_certificates: Vec<RevokedEntry>,
    /// Authority key identifier
    authority_key_id: Option<Vec<u8>>,
    /// Signature algorithm the issuing CA will sign with (RFC 5280 §5.1.1.2).
    /// When unset, falls back to the historical sha256WithRSAEncryption default.
    signature_algorithm: Option<ostrich_crypto::Algorithm>,
    /// Base CRL number this is a delta against (RFC 5280 §5.2.4). When set, the
    /// CRL is a delta CRL carrying a critical Delta CRL Indicator extension.
    base_crl_number: Option<u64>,
    /// URL of the delta CRL distribution point, emitted as the Freshest CRL
    /// extension on a full (base) CRL (RFC 5280 §5.2.6).
    freshest_crl_url: Option<String>,
    /// Mark the CRL as an indirect CRL via the Issuing Distribution Point
    /// extension (RFC 5280 §5.2.5).
    indirect_crl: bool,
}

impl CrlBuilder {
    /// Create a new CRL builder
    pub fn new() -> Self {
        Self {
            issuer: None,
            this_update: None,
            next_update: None,
            crl_number: None,
            revoked_certificates: Vec::new(),
            authority_key_id: None,
            signature_algorithm: None,
            base_crl_number: None,
            freshest_crl_url: None,
            indirect_crl: false,
        }
    }

    /// Mark this as a delta CRL relative to `base_crl_number` (RFC 5280 §5.2.4).
    /// Emits a critical Delta CRL Indicator extension carrying the BaseCRLNumber.
    pub fn delta_crl_indicator(mut self, base_crl_number: u64) -> Self {
        self.base_crl_number = Some(base_crl_number);
        self
    }

    /// Set the delta CRL distribution URL, emitted as the Freshest CRL extension
    /// on a full CRL so relying parties can locate the delta (RFC 5280 §5.2.6).
    pub fn freshest_crl(mut self, url: impl Into<String>) -> Self {
        self.freshest_crl_url = Some(url.into());
        self
    }

    /// Mark this CRL as an indirect CRL (RFC 5280 §5.2.5): emits a critical
    /// Issuing Distribution Point extension with the indirectCRL flag set.
    pub fn indirect_crl(mut self) -> Self {
        self.indirect_crl = true;
        self
    }

    /// Set issuer DN
    pub fn issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Set this update time (defaults to now)
    pub fn this_update(mut self, time: DateTime<Utc>) -> Self {
        self.this_update = Some(time);
        self
    }

    /// Set next update time
    pub fn next_update(mut self, time: DateTime<Utc>) -> Self {
        self.next_update = Some(time);
        self
    }

    /// Set next update in hours from now
    pub fn next_update_hours(mut self, hours: u32) -> Self {
        let now = self.this_update.unwrap_or_else(Utc::now);
        let next = now + Duration::try_hours(hours as i64).unwrap();
        self.next_update = Some(next);
        self
    }

    /// Set CRL number
    ///
    /// RFC 5280 §5.2.3 - CRL number
    pub fn crl_number(mut self, number: u64) -> Self {
        self.crl_number = Some(number);
        self
    }

    /// Add a revoked certificate entry
    pub fn add_revoked(
        mut self,
        serial_number: Vec<u8>,
        revocation_time: DateTime<Utc>,
        reason: Option<RevocationReason>,
    ) -> Self {
        self.revoked_certificates.push(RevokedEntry {
            serial_number,
            revocation_time,
            reason,
        });
        self
    }

    /// Set authority key identifier
    pub fn authority_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.authority_key_id = Some(key_id);
        self
    }

    /// Set the signature algorithm the issuing CA will sign with.
    ///
    /// RFC 5280 §5.1.1.2 / §5.1.2.2 - the inner `signature` and outer
    /// `signatureAlgorithm` AlgorithmIdentifiers must be identical and match the
    /// CA private key's actual signing algorithm. When unset, the builder falls
    /// back to sha256WithRSAEncryption for backwards compatibility.
    pub fn signature_algorithm(mut self, alg: ostrich_crypto::Algorithm) -> Self {
        self.signature_algorithm = Some(alg);
        self
    }

    /// Build the CRL (returns TBS CRL - to be signed)
    ///
    /// RFC 5280 §5.1 - TBSCertList
    pub fn build_tbs(self) -> Result<TbsCrl> {
        let issuer = self
            .issuer
            .ok_or_else(|| Error::Build("Issuer is required".to_string()))?;

        let this_update = self.this_update.unwrap_or_else(Utc::now);

        let next_update = self
            .next_update
            .ok_or_else(|| Error::Build("Next update is required".to_string()))?;

        // Validate update times
        if next_update <= this_update {
            return Err(Error::Build(
                "Next update must be later than this update".to_string(),
            ));
        }

        Ok(TbsCrl {
            issuer,
            this_update,
            next_update,
            crl_number: self.crl_number,
            revoked_certificates: self.revoked_certificates,
            authority_key_id: self.authority_key_id,
            signature_algorithm: self.signature_algorithm,
            base_crl_number: self.base_crl_number,
            freshest_crl_url: self.freshest_crl_url,
            indirect_crl: self.indirect_crl,
        })
    }
}

impl Default for CrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Revoked certificate entry
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// Serial number of revoked certificate
    pub serial_number: Vec<u8>,
    /// Revocation time
    pub revocation_time: DateTime<Utc>,
    /// Revocation reason
    pub reason: Option<RevocationReason>,
}

/// To-Be-Signed CRL
///
/// RFC 5280 §5.1 - TBSCertList
#[derive(Debug, Clone)]
pub struct TbsCrl {
    pub issuer: DistinguishedName,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub crl_number: Option<u64>,
    pub revoked_certificates: Vec<RevokedEntry>,
    pub authority_key_id: Option<Vec<u8>>,
    /// Signature algorithm chosen by the issuer (RFC 5280 §5.1.1.2). When
    /// `None`, [`TbsCrl::get_signature_algorithm`] uses the RSA default.
    pub signature_algorithm: Option<ostrich_crypto::Algorithm>,
    /// Base CRL number for a delta CRL (RFC 5280 §5.2.4).
    pub base_crl_number: Option<u64>,
    /// Delta CRL distribution URL for the Freshest CRL extension (§5.2.6).
    pub freshest_crl_url: Option<String>,
    /// Whether this is an indirect CRL (§5.2.5 Issuing Distribution Point).
    pub indirect_crl: bool,
}

impl TbsCrl {
    /// Encode to DER format for signing
    ///
    /// RFC 5280 §5.1 - TBSCertList structure
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use der::Encode;
        use x509_cert::crl::{RevokedCert, TbsCertList};
        use x509_cert::serial_number::SerialNumber as X509SerialNumber;

        // Convert issuer DN to X.509 Name (reuse logic from certificate builder)
        let issuer = self.dn_to_name(&self.issuer)?;

        // Convert times
        let this_update = self.datetime_to_time(self.this_update)?;
        let next_update = Some(self.datetime_to_time(self.next_update)?);

        // Convert revoked certificates
        let mut revoked_certs = Vec::new();
        for entry in &self.revoked_certificates {
            let serial = X509SerialNumber::new(&entry.serial_number)
                .map_err(|e| Error::Encoding(format!("Invalid serial number: {}", e)))?;

            let revocation_time = self.datetime_to_time(entry.revocation_time)?;

            // Build CRL entry extensions (revocation reason)
            // COMPLIANCE MAPPING:
            // - RFC 5280 §5.3.1 - Reason Code
            // - NIAP PP-CA: FAU_GEN.1 - Audit revocation reason
            let crl_entry_extensions = if let Some(reason) = &entry.reason {
                use const_oid::db::rfc5280;
                use der::asn1::OctetString;
                use x509_cert::ext::Extension;

                // Map revocation reason to ASN.1 enumerated value
                let reason_code: u8 = match reason {
                    RevocationReason::Unspecified => 0,
                    RevocationReason::KeyCompromise => 1,
                    RevocationReason::CaCompromise => 2,
                    RevocationReason::AffiliationChanged => 3,
                    RevocationReason::Superseded => 4,
                    RevocationReason::CessationOfOperation => 5,
                    RevocationReason::CertificateHold => 6,
                    // 7 is not used
                    RevocationReason::RemoveFromCrl => 8,
                    RevocationReason::PrivilegeWithdrawn => 9,
                    RevocationReason::AaCompromise => 10,
                };

                // Encode reason as ENUMERATED ASN.1 type
                // For reason codes, we need to create a simple integer value
                let reason_bytes = vec![0x0A, 0x01, reason_code]; // 0x0A = ENUMERATED tag, 0x01 = length

                let ext = Extension {
                    extn_id: rfc5280::ID_CE_CRL_REASONS,
                    critical: false, // RFC 5280: reason code is non-critical
                    extn_value: OctetString::new(reason_bytes)?,
                };

                Some(vec![ext])
            } else {
                None
            };

            // Build revoked cert entry
            let revoked = RevokedCert {
                serial_number: serial,
                revocation_date: revocation_time,
                crl_entry_extensions,
            };

            revoked_certs.push(revoked);
        }

        // Build TBS CRL structure
        let tbs = TbsCertList {
            version: x509_cert::Version::V2, // V2 for extensions
            signature: self.get_signature_algorithm()?,
            issuer,
            this_update,
            next_update,
            revoked_certificates: if revoked_certs.is_empty() {
                None
            } else {
                Some(revoked_certs)
            },
            crl_extensions: self.build_extensions()?,
        };

        // Encode to DER
        tbs.to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode TBS CRL: {}", e)))
    }

    /// Convert DistinguishedName to X.509 Name
    /// (Same implementation as in certificate builder)
    fn dn_to_name(&self, dn: &DistinguishedName) -> Result<x509_cert::name::Name> {
        use const_oid::db::rfc4519::{C, CN, L, O, OU, SERIAL_NUMBER, ST};
        use der::Any;
        use der::asn1::{PrintableStringRef, SetOfVec, Utf8StringRef};
        use x509_cert::attr::AttributeTypeAndValue;
        use x509_cert::name::{Name, RelativeDistinguishedName};

        let mut rdns = Vec::new();

        // Build RDNs in reverse order (root to leaf)
        if let Some(c) = &dn.country {
            let value = PrintableStringRef::new(c.as_bytes())
                .map_err(|e| Error::Encoding(format!("Invalid country: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: C,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode country: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(st) = &dn.state_or_province {
            let value = Utf8StringRef::new(st)
                .map_err(|e| Error::Encoding(format!("Invalid state: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: ST,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode state: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(l) = &dn.locality {
            let value = Utf8StringRef::new(l)
                .map_err(|e| Error::Encoding(format!("Invalid locality: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: L,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode locality: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(o) = &dn.organization {
            let value = Utf8StringRef::new(o)
                .map_err(|e| Error::Encoding(format!("Invalid organization: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: O,
                value: Any::encode_from(&value).map_err(|e| {
                    Error::Encoding(format!("Failed to encode organization: {}", e))
                })?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(ou) = &dn.organizational_unit {
            let value = Utf8StringRef::new(ou)
                .map_err(|e| Error::Encoding(format!("Invalid OU: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: OU,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode OU: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(cn) = &dn.common_name {
            let value = Utf8StringRef::new(cn)
                .map_err(|e| Error::Encoding(format!("Invalid CN: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: CN,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode CN: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        if let Some(sn) = &dn.serial_number {
            let value = PrintableStringRef::new(sn.as_bytes())
                .map_err(|e| Error::Encoding(format!("Invalid serial number: {}", e)))?;
            let atv = AttributeTypeAndValue {
                oid: SERIAL_NUMBER,
                value: Any::encode_from(&value)
                    .map_err(|e| Error::Encoding(format!("Failed to encode serial: {}", e)))?,
            };
            let set = SetOfVec::try_from(vec![atv])
                .map_err(|e| Error::Encoding(format!("Failed to create SET: {}", e)))?;
            rdns.push(RelativeDistinguishedName::from(set));
        }

        Ok(Name::from(rdns))
    }

    /// Convert DateTime to X.509 Time (UtcTime or GeneralizedTime)
    /// (Same implementation as in certificate builder)
    fn datetime_to_time(&self, dt: DateTime<Utc>) -> Result<x509_cert::time::Time> {
        use chrono::Datelike;
        use der::asn1::{GeneralizedTime, UtcTime};
        use x509_cert::time::Time;

        // RFC 5280: dates through 2049 use UTCTime, dates thereafter use GeneralizedTime
        if dt.year() <= 2049 {
            let utc_time =
                UtcTime::from_unix_duration(std::time::Duration::from_secs(dt.timestamp() as u64))
                    .map_err(|e| Error::Encoding(format!("Invalid UTC time: {}", e)))?;
            Ok(Time::UtcTime(utc_time))
        } else {
            let gen_time = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                dt.timestamp() as u64,
            ))
            .map_err(|e| Error::Encoding(format!("Invalid generalized time: {}", e)))?;
            Ok(Time::GeneralTime(gen_time))
        }
    }

    /// Get signature algorithm identifier
    ///
    /// RFC 5280 §5.1.1.2 - when the issuer set a signature algorithm (via
    /// `CrlBuilder::signature_algorithm`), the AlgorithmIdentifier is derived
    /// from it through the shared `signing` module so the TBS `signature` and
    /// the actual signing algorithm stay identical (RSA / ECDSA / Ed25519).
    /// When unset, falls back to the historical sha256WithRSAEncryption default.
    fn get_signature_algorithm(&self) -> Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        if let Some(alg) = self.signature_algorithm {
            return crate::signing::algorithm_identifier(alg)
                .map_err(|e| Error::Encoding(format!("signature algorithm: {}", e)));
        }

        // Backwards-compatible default: sha256WithRSAEncryption (PKCS#1 v1.5).
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;

        Ok(x509_cert::spki::AlgorithmIdentifierOwned {
            oid: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: None,
        })
    }

    /// Build CRL extensions
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §5.2 - CRL Extensions
    /// - NIST 800-53: SC-17 - PKI Certificates (CRL management)
    /// - NIAP PP-CA: FMT_SMF.1 - Certificate revocation list generation
    fn build_extensions(&self) -> Result<Option<x509_cert::ext::Extensions>> {
        use const_oid::db::rfc5280;
        use der::Encode;
        use der::asn1::OctetString;
        use x509_cert::ext::Extension;

        let mut extensions = Vec::new();

        // RFC 5280 §5.2.3 - CRL Number (MUST be present in conforming CRLs)
        // NIAP PP-CA: FMT_SMF.1 - CRL versioning for revocation tracking
        if let Some(crl_num) = self.crl_number {
            use der::asn1::Uint;

            let crl_number = Uint::new(&crl_num.to_be_bytes())
                .map_err(|e| Error::Encoding(format!("Invalid CRL number: {}", e)))?;

            let ext = Extension {
                extn_id: rfc5280::ID_CE_CRL_NUMBER,
                critical: false, // RFC 5280: CRL number is non-critical
                extn_value: OctetString::new(crl_number.to_der().map_err(|e| {
                    Error::Encoding(format!("Failed to encode CRL number: {}", e))
                })?)?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §5.2.1 - Authority Key Identifier
        // NIAP PP-CA: FCS_CKM.1 - Link CRL to CA key
        if let Some(auth_key_id) = &self.authority_key_id {
            use x509_cert::ext::pkix::AuthorityKeyIdentifier;

            let aki = AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(auth_key_id.clone())?),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            };

            let ext = Extension {
                extn_id: rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
                critical: false,
                extn_value: OctetString::new(
                    aki.to_der()
                        .map_err(|e| Error::Encoding(format!("Failed to encode AKI: {}", e)))?,
                )?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §5.2.4 - Delta CRL Indicator (critical). Carries the
        // BaseCRLNumber: the CRL number of the full CRL this delta is relative to.
        if let Some(base) = self.base_crl_number {
            use x509_cert::ext::pkix::crl::BaseCrlNumber;

            let base_num = der::asn1::Uint::new(&base.to_be_bytes())
                .map_err(|e| Error::Encoding(format!("Invalid base CRL number: {}", e)))?;
            let ext = Extension {
                extn_id: rfc5280::ID_CE_DELTA_CRL_INDICATOR,
                critical: true, // RFC 5280 §5.2.4: the delta CRL indicator is critical
                extn_value: OctetString::new(BaseCrlNumber(base_num).to_der().map_err(|e| {
                    Error::Encoding(format!("Failed to encode delta CRL indicator: {}", e))
                })?)?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §5.2.6 - Freshest CRL: where to find the delta CRL. Same
        // syntax as CRL Distribution Points; placed on the full (base) CRL.
        if let Some(url) = &self.freshest_crl_url {
            use der::asn1::Ia5StringRef;
            use x509_cert::ext::pkix::FreshestCrl;
            use x509_cert::ext::pkix::crl::dp::DistributionPoint;
            use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

            let gn = GeneralName::UniformResourceIdentifier(
                Ia5StringRef::new(url)
                    .map_err(|e| Error::Encoding(format!("Invalid freshest CRL URI: {}", e)))?
                    .into(),
            );
            let dp = DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![gn])),
                reasons: None,
                crl_issuer: None,
            };
            let ext = Extension {
                extn_id: rfc5280::ID_CE_FRESHEST_CRL,
                critical: false, // RFC 5280 §5.2.6: freshest CRL is non-critical
                extn_value: OctetString::new(FreshestCrl(vec![dp]).to_der().map_err(|e| {
                    Error::Encoding(format!("Failed to encode freshest CRL: {}", e))
                })?)?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §5.2.5 - Issuing Distribution Point (critical) marking an
        // indirect CRL: one whose entries may be for certificates issued by an
        // authority other than the CRL issuer.
        if self.indirect_crl {
            use x509_cert::ext::pkix::crl::dp::IssuingDistributionPoint;

            let idp = IssuingDistributionPoint {
                distribution_point: None,
                only_contains_user_certs: false,
                only_contains_ca_certs: false,
                only_some_reasons: None,
                indirect_crl: true,
                only_contains_attribute_certs: false,
            };
            let ext = Extension {
                extn_id: rfc5280::ID_CE_ISSUING_DISTRIBUTION_POINT,
                critical: true, // RFC 5280 §5.2.5: IDP is critical
                extn_value: OctetString::new(
                    idp.to_der()
                        .map_err(|e| Error::Encoding(format!("Failed to encode IDP: {}", e)))?,
                )?,
            };
            extensions.push(ext);
        }

        if extensions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(extensions))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_builder() {
        let builder = CrlBuilder::new()
            .issuer(DistinguishedName::new())
            .this_update(Utc::now())
            .next_update_hours(24)
            .crl_number(1)
            .add_revoked(
                vec![1, 2, 3],
                Utc::now(),
                Some(RevocationReason::KeyCompromise),
            );

        let result = builder.build_tbs();
        assert!(result.is_ok());
        let tbs_crl = result.unwrap();
        assert_eq!(tbs_crl.crl_number, Some(1));
        assert_eq!(tbs_crl.revoked_certificates.len(), 1);
    }

    #[test]
    fn test_crl_builder_invalid_times() {
        let now = Utc::now();
        let past = now - Duration::try_hours(1).unwrap();

        let builder = CrlBuilder::new()
            .issuer(DistinguishedName::new())
            .this_update(now)
            .next_update(past); // Invalid: next_update before this_update

        let result = builder.build_tbs();
        assert!(result.is_err());
    }

    /// A delta CRL built with the new extensions is parsed by openssl, which
    /// reports the Delta CRL Indicator, Freshest CRL, and Issuing Distribution
    /// Point (indirect) extensions — RFC 5280 §5.2.4 / §5.2.5 / §5.2.6.
    #[tokio::test]
    async fn delta_crl_extensions_verified_by_openssl() {
        use ostrich_crypto::{Algorithm, CryptoProvider, KeyType, software::SoftwareProvider};
        use std::io::Write as _;
        use std::process::Command;

        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("openssl not found; skipping");
            return;
        }

        let provider = SoftwareProvider::new();
        let key = provider
            .generate_key_pair(KeyType::EcP256, "crl-key", true)
            .await
            .unwrap();
        let alg = Algorithm::EcdsaP256Sha256;

        let tbs = CrlBuilder::new()
            .issuer(DistinguishedName::new_cn("OstrichPKI Delta CRL Test CA"))
            .this_update(Utc::now())
            .next_update_hours(24)
            .crl_number(7)
            .delta_crl_indicator(5)
            .freshest_crl("http://crl.example.com/delta.crl")
            .indirect_crl()
            .add_revoked(
                vec![0x12, 0x34],
                Utc::now(),
                Some(RevocationReason::KeyCompromise),
            )
            .signature_algorithm(alg)
            .build_tbs()
            .unwrap();
        let tbs_der = tbs.to_der().unwrap();
        let raw = provider.sign(&key, alg, &tbs_der).await.unwrap();
        let sig = crate::signing::encode_x509_signature(alg, raw).unwrap();

        let crl_der = {
            use der::{Decode, Encode, asn1::BitString};
            use x509_cert::crl::{CertificateList, TbsCertList};
            let tbs = TbsCertList::from_der(&tbs_der).unwrap();
            let signature_algorithm = tbs.signature.clone();
            CertificateList {
                tbs_cert_list: tbs,
                signature_algorithm,
                signature: BitString::from_bytes(&sig).unwrap(),
            }
            .to_der()
            .unwrap()
        };

        let path = std::env::temp_dir().join("ostrich-delta-crl-test.crl");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&crl_der)
            .unwrap();
        let out = Command::new("openssl")
            .args([
                "crl",
                "-inform",
                "DER",
                "-in",
                path.to_str().unwrap(),
                "-text",
                "-noout",
            ])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "openssl crl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        assert!(
            text.contains("Delta CRL Indicator"),
            "missing delta indicator:\n{text}"
        );
        assert!(
            text.contains("Freshest CRL"),
            "missing freshest CRL:\n{text}"
        );
        assert!(
            text.contains("Issuing Distribution Point"),
            "missing IDP:\n{text}"
        );
    }
}
