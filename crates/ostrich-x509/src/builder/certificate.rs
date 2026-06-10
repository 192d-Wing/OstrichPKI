//! X.509 certificate builder
//!
//! RFC 5280 §4.1 - Basic certificate fields

use crate::{
    Error, Result,
    extensions::{AuthorityInfoAccess, CertificatePolicy, CrlDistributionPoint, SubjectAltName},
    profile::{CertificateProfile, ExtendedKeyUsage, KeyUsage},
};
use chrono::{DateTime, Duration, Utc};
use ostrich_common::types::{DistinguishedName, SerialNumber};

/// X.509 certificate builder
///
/// RFC 5280 §4.1 - Certificate structure
pub struct CertificateBuilder {
    /// Serial number
    serial_number: Option<SerialNumber>,
    /// Subject DN
    subject: Option<DistinguishedName>,
    /// Issuer DN
    issuer: Option<DistinguishedName>,
    /// Not before
    not_before: Option<DateTime<Utc>>,
    /// Not after
    not_after: Option<DateTime<Utc>>,
    /// Public key (DER-encoded SubjectPublicKeyInfo)
    public_key: Option<Vec<u8>>,
    /// Key usage
    key_usage: Vec<KeyUsage>,
    /// Extended key usage
    extended_key_usage: Vec<ExtendedKeyUsage>,
    /// Basic constraints - is CA
    basic_constraints_ca: bool,
    /// Basic constraints - path length
    basic_constraints_path_len: Option<u8>,
    /// Subject alternative names
    subject_alt_names: Vec<SubjectAltName>,
    /// Authority information access
    authority_info_access: Vec<AuthorityInfoAccess>,
    /// CRL distribution points
    crl_distribution_points: Vec<CrlDistributionPoint>,
    /// Certificate policies
    certificate_policies: Vec<CertificatePolicy>,
    /// Authority key identifier
    authority_key_id: Option<Vec<u8>>,
    /// Subject key identifier
    subject_key_id: Option<Vec<u8>>,
    /// Signature algorithm the issuing CA will sign with (RFC 5280 §4.1.1.2).
    /// When unset, falls back to the historical sha256WithRSAEncryption default.
    signature_algorithm: Option<ostrich_crypto::Algorithm>,
}

impl CertificateBuilder {
    /// Create a new certificate builder
    pub fn new() -> Self {
        Self {
            serial_number: None,
            subject: None,
            issuer: None,
            not_before: None,
            not_after: None,
            public_key: None,
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            basic_constraints_ca: false,
            basic_constraints_path_len: None,
            subject_alt_names: Vec::new(),
            authority_info_access: Vec::new(),
            crl_distribution_points: Vec::new(),
            certificate_policies: Vec::new(),
            authority_key_id: None,
            subject_key_id: None,
            signature_algorithm: None,
        }
    }

    /// Create a builder from a certificate profile
    ///
    /// NIST 800-53: CM-2 - Use baseline configuration
    pub fn from_profile(profile: &CertificateProfile) -> Self {
        let now = Utc::now();
        let not_after = now + Duration::try_days(profile.validity_days as i64).unwrap();

        let mut builder = Self::new();
        builder.not_before = Some(now);
        builder.not_after = Some(not_after);
        builder.key_usage = profile.key_usage.clone();
        builder.extended_key_usage = profile.extended_key_usage.clone();
        builder.basic_constraints_ca = profile.basic_constraints_ca;
        builder.basic_constraints_path_len = profile.basic_constraints_path_len;
        builder
    }

    /// Set serial number
    pub fn serial_number(mut self, serial: SerialNumber) -> Self {
        self.serial_number = Some(serial);
        self
    }

    /// Set subject DN
    pub fn subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Set issuer DN
    pub fn issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Set validity period
    pub fn validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        self.not_before = Some(not_before);
        self.not_after = Some(not_after);
        self
    }

    /// Set validity period in days from now
    pub fn validity_days(mut self, days: u32) -> Self {
        let now = Utc::now();
        let not_after = now + Duration::try_days(days as i64).unwrap();
        self.not_before = Some(now);
        self.not_after = Some(not_after);
        self
    }

    /// Set public key (DER-encoded SubjectPublicKeyInfo)
    pub fn public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Add key usage
    pub fn add_key_usage(mut self, usage: KeyUsage) -> Self {
        if !self.key_usage.contains(&usage) {
            self.key_usage.push(usage);
        }
        self
    }

    /// Add extended key usage
    pub fn add_extended_key_usage(mut self, usage: ExtendedKeyUsage) -> Self {
        if !self.extended_key_usage.contains(&usage) {
            self.extended_key_usage.push(usage);
        }
        self
    }

    /// Set basic constraints
    pub fn basic_constraints(mut self, is_ca: bool, path_len: Option<u8>) -> Self {
        self.basic_constraints_ca = is_ca;
        self.basic_constraints_path_len = path_len;
        self
    }

    /// Add subject alternative name
    pub fn add_subject_alt_name(mut self, san: SubjectAltName) -> Self {
        self.subject_alt_names.push(san);
        self
    }

    /// Add CRL distribution point
    pub fn add_crl_distribution_point(mut self, cdp: CrlDistributionPoint) -> Self {
        self.crl_distribution_points.push(cdp);
        self
    }

    /// Add authority information access
    pub fn add_authority_info_access(mut self, aia: AuthorityInfoAccess) -> Self {
        self.authority_info_access.push(aia);
        self
    }

    /// Set authority key identifier
    pub fn authority_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.authority_key_id = Some(key_id);
        self
    }

    /// Set subject key identifier
    pub fn subject_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.subject_key_id = Some(key_id);
        self
    }

    /// Set the signature algorithm the issuing CA will sign with.
    ///
    /// RFC 5280 §4.1.1.2 - this drives the AlgorithmIdentifier written into
    /// `tbsCertificate.signature` (and, downstream, the outer
    /// `signatureAlgorithm`), so it MUST match the algorithm the CA private key
    /// actually signs with. When unset, the builder falls back to
    /// sha256WithRSAEncryption for backwards compatibility.
    pub fn signature_algorithm(mut self, alg: ostrich_crypto::Algorithm) -> Self {
        self.signature_algorithm = Some(alg);
        self
    }

    /// Build the certificate (returns TBS certificate - to be signed)
    ///
    /// RFC 5280 §4.1 - TBSCertificate
    pub fn build_tbs(self) -> Result<TbsCertificate> {
        // Validate required fields
        let serial_number = self
            .serial_number
            .ok_or_else(|| Error::Build("Serial number is required".to_string()))?;

        let subject = self
            .subject
            .ok_or_else(|| Error::Build("Subject is required".to_string()))?;

        let issuer = self
            .issuer
            .ok_or_else(|| Error::Build("Issuer is required".to_string()))?;

        let not_before = self
            .not_before
            .ok_or_else(|| Error::Build("Not before time is required".to_string()))?;

        let not_after = self
            .not_after
            .ok_or_else(|| Error::Build("Not after time is required".to_string()))?;

        let public_key = self
            .public_key
            .ok_or_else(|| Error::Build("Public key is required".to_string()))?;

        // Validate validity period
        if not_after <= not_before {
            return Err(Error::Build(
                "Not after must be later than not before".to_string(),
            ));
        }

        Ok(TbsCertificate {
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            public_key,
            key_usage: self.key_usage,
            extended_key_usage: self.extended_key_usage,
            basic_constraints_ca: self.basic_constraints_ca,
            basic_constraints_path_len: self.basic_constraints_path_len,
            subject_alt_names: self.subject_alt_names,
            authority_info_access: self.authority_info_access,
            crl_distribution_points: self.crl_distribution_points,
            certificate_policies: self.certificate_policies,
            authority_key_id: self.authority_key_id,
            subject_key_id: self.subject_key_id,
            signature_algorithm: self.signature_algorithm,
        })
    }
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// To-Be-Signed Certificate
///
/// RFC 5280 §4.1 - TBSCertificate
#[derive(Debug, Clone)]
pub struct TbsCertificate {
    pub serial_number: SerialNumber,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key: Vec<u8>,
    pub key_usage: Vec<KeyUsage>,
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    pub basic_constraints_ca: bool,
    pub basic_constraints_path_len: Option<u8>,
    pub subject_alt_names: Vec<SubjectAltName>,
    pub authority_info_access: Vec<AuthorityInfoAccess>,
    pub crl_distribution_points: Vec<CrlDistributionPoint>,
    pub certificate_policies: Vec<CertificatePolicy>,
    pub authority_key_id: Option<Vec<u8>>,
    pub subject_key_id: Option<Vec<u8>>,
    /// Signature algorithm chosen by the issuer (RFC 5280 §4.1.1.2). When
    /// `None`, [`TbsCertificate::get_signature_algorithm`] uses the RSA default.
    pub signature_algorithm: Option<ostrich_crypto::Algorithm>,
}

impl TbsCertificate {
    /// Encode to DER format for signing
    ///
    /// RFC 5280 §4.1.1.2 - signatureAlgorithm
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use der::Encode;
        use spki::SubjectPublicKeyInfoOwned;
        use x509_cert::serial_number::SerialNumber as X509SerialNumber;

        // Convert our types to x509-cert types

        // Parse serial number - RFC 5280 requires positive integer
        let serial = X509SerialNumber::new(self.serial_number.as_bytes())
            .map_err(|e| Error::Encoding(format!("Invalid serial number: {}", e)))?;

        // Convert issuer DN to X.509 Name
        let issuer = self.dn_to_name(&self.issuer)?;

        // Convert subject DN to X.509 Name
        let subject = self.dn_to_name(&self.subject)?;

        // Convert validity period to X.509 Time
        let not_before = self.datetime_to_time(self.not_before)?;
        let not_after = self.datetime_to_time(self.not_after)?;
        let validity = x509_cert::time::Validity {
            not_before,
            not_after,
        };

        // Parse SubjectPublicKeyInfo from DER
        let subject_public_key_info =
            SubjectPublicKeyInfoOwned::try_from(self.public_key.as_slice())
                .map_err(|e| Error::Encoding(format!("Invalid public key: {}", e)))?;

        // Build TBS certificate structure
        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: serial,
            signature: self.get_signature_algorithm()?,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: self.build_extensions()?,
        };

        // Encode to DER
        tbs.to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode TBS certificate: {}", e)))
    }

    /// Convert DistinguishedName to X.509 Name
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
    /// RFC 5280 §4.1.1.2 - when the issuer set a signature algorithm (via
    /// `CertificateBuilder::signature_algorithm`), the AlgorithmIdentifier is
    /// derived from it through the shared `signing` module so the TBS
    /// `signature` and the actual signing algorithm stay identical (RSA / ECDSA
    /// P-256/P-384 / Ed25519). When unset, it falls back to the historical
    /// sha256WithRSAEncryption default so existing RSA callers/tests keep
    /// working. ML-DSA selection plugs in via `signing::algorithm_identifier`.
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

    /// Build X.509 extensions
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2 - Standard Extensions for Certificates
    /// - NIST 800-53: SC-17 - PKI Certificates
    /// - NIAP PP-CA: FCS_COP.1 - Cryptographic Operations (key usage enforcement)
    fn build_extensions(&self) -> Result<Option<x509_cert::ext::Extensions>> {
        use const_oid::db::rfc5280;
        use der::Encode;
        use der::asn1::{BitString, OctetString};
        use x509_cert::ext::Extension;

        let mut extensions = Vec::new();

        // RFC 5280 §4.2.1.3 - Key Usage (CRITICAL)
        // NIAP PP-CA: FCS_COP.1.1 - Support cryptographic key usage enforcement
        if !self.key_usage.is_empty() {
            let mut bits = 0u16;
            for usage in &self.key_usage {
                bits |= match usage {
                    KeyUsage::DigitalSignature => 0x80 << 8,
                    KeyUsage::NonRepudiation => 0x40 << 8,
                    KeyUsage::KeyEncipherment => 0x20 << 8,
                    KeyUsage::DataEncipherment => 0x10 << 8,
                    KeyUsage::KeyAgreement => 0x08 << 8,
                    KeyUsage::KeyCertSign => 0x04 << 8,
                    KeyUsage::CrlSign => 0x02 << 8,
                    KeyUsage::EncipherOnly => 0x01 << 8,
                    KeyUsage::DecipherOnly => 0x01,
                };
            }

            let key_usage_bytes = bits.to_be_bytes();
            let bit_string = BitString::from_bytes(&key_usage_bytes)
                .map_err(|e| Error::Encoding(format!("Invalid key usage bits: {}", e)))?;

            let ext =
                Extension {
                    extn_id: rfc5280::ID_CE_KEY_USAGE,
                    critical: true, // RFC 5280: Key Usage SHOULD be critical
                    extn_value: OctetString::new(bit_string.to_der().map_err(|e| {
                        Error::Encoding(format!("Failed to encode key usage: {}", e))
                    })?)?,
                };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.1.9 - Basic Constraints (CRITICAL for CAs)
        // NIAP PP-CA: FMT_SMF.1 - CA certificate management functions
        if self.basic_constraints_ca || self.basic_constraints_path_len.is_some() {
            use x509_cert::ext::pkix::BasicConstraints;

            let bc = BasicConstraints {
                ca: self.basic_constraints_ca,
                path_len_constraint: self.basic_constraints_path_len,
            };

            let ext = Extension {
                extn_id: rfc5280::ID_CE_BASIC_CONSTRAINTS,
                critical: self.basic_constraints_ca, // Critical for CA certs
                extn_value: OctetString::new(bc.to_der().map_err(|e| {
                    Error::Encoding(format!("Failed to encode basic constraints: {}", e))
                })?)?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.1.12 - Extended Key Usage
        if !self.extended_key_usage.is_empty() {
            use const_oid::ObjectIdentifier;

            let mut ekus = Vec::new();
            for eku in &self.extended_key_usage {
                let oid = match eku {
                    ExtendedKeyUsage::ServerAuth => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.1").unwrap()
                    }
                    ExtendedKeyUsage::ClientAuth => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.2").unwrap()
                    }
                    ExtendedKeyUsage::CodeSigning => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.3").unwrap()
                    }
                    ExtendedKeyUsage::EmailProtection => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.4").unwrap()
                    }
                    ExtendedKeyUsage::TimeStamping => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.8").unwrap()
                    }
                    ExtendedKeyUsage::OcspSigning => {
                        ObjectIdentifier::new("1.3.6.1.5.5.7.3.9").unwrap()
                    }
                    ExtendedKeyUsage::Custom(oid_str) => ObjectIdentifier::new(oid_str)
                        .map_err(|e| Error::Encoding(format!("Invalid custom EKU OID: {}", e)))?,
                };
                ekus.push(oid);
            }

            // RFC 5280 §4.2.1.12: ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId.
            // Vec<T> encodes as SEQUENCE OF; an earlier version used SetOfVec
            // (SET OF, tag 0x31), which produced a malformed extension that
            // OpenSSL rejects during chain validation.
            let ext = Extension {
                extn_id: rfc5280::ID_CE_EXT_KEY_USAGE,
                critical: false,
                extn_value: OctetString::new(ekus.to_der().map_err(|e| {
                    Error::Encoding(format!("Failed to encode extended key usage: {}", e))
                })?)?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.1.6 - Subject Alternative Name
        if !self.subject_alt_names.is_empty() {
            use der::asn1::Ia5StringRef;
            use x509_cert::ext::pkix::SubjectAltName as X509San;
            use x509_cert::ext::pkix::name::GeneralName;

            let mut san_entries = Vec::new();
            for san in &self.subject_alt_names {
                let general_name = match san {
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
                            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                        };
                        GeneralName::IpAddress(OctetString::new(octets)?)
                    }
                    SubjectAltName::DirectoryName(_) => {
                        // TODO: Implement directory name parsing
                        continue;
                    }
                };
                san_entries.push(general_name);
            }

            if !san_entries.is_empty() {
                let san = X509San(san_entries);
                let ext = Extension {
                    extn_id: rfc5280::ID_CE_SUBJECT_ALT_NAME,
                    critical: false,
                    extn_value: OctetString::new(
                        san.to_der()
                            .map_err(|e| Error::Encoding(format!("Failed to encode SAN: {}", e)))?,
                    )?,
                };
                extensions.push(ext);
            }
        }

        // RFC 5280 §4.2.1.1 - Authority Key Identifier
        // NIAP PP-CA: FCS_CKM.1 - Link certificate to CA key
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

        // RFC 5280 §4.2.1.2 - Subject Key Identifier
        if let Some(subj_key_id) = &self.subject_key_id {
            let ext = Extension {
                extn_id: rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
                critical: false,
                extn_value: OctetString::new(
                    OctetString::new(subj_key_id.clone())?
                        .to_der()
                        .map_err(|e| Error::Encoding(format!("Failed to encode SKI: {}", e)))?,
                )?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.1.13 - CRL Distribution Points
        // NIAP PP-CA: FMT_SMF.1 - Certificate revocation distribution
        if !self.crl_distribution_points.is_empty() {
            use der::asn1::Ia5StringRef;
            use x509_cert::ext::pkix::CrlDistributionPoints;
            use x509_cert::ext::pkix::crl::dp::DistributionPoint;
            use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

            let mut dps = Vec::new();
            for cdp in &self.crl_distribution_points {
                let general_name = GeneralName::UniformResourceIdentifier(
                    Ia5StringRef::new(&cdp.uri)
                        .map_err(|e| Error::Encoding(format!("Invalid CRL URI: {}", e)))?
                        .into(),
                );

                let dp = DistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![general_name])),
                    reasons: None,
                    crl_issuer: None,
                };
                dps.push(dp);
            }

            let crl_dps = CrlDistributionPoints(dps);
            let ext =
                Extension {
                    extn_id: rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS,
                    critical: false,
                    extn_value: OctetString::new(crl_dps.to_der().map_err(|e| {
                        Error::Encoding(format!("Failed to encode CRL DPs: {}", e))
                    })?)?,
                };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.2.1 - Authority Information Access
        // NIAP PP-CA: FMT_SMF.1 - OCSP responder location
        if !self.authority_info_access.is_empty() {
            use const_oid::ObjectIdentifier;
            use der::asn1::Ia5StringRef;
            use x509_cert::ext::pkix::name::GeneralName;
            use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};

            let mut access_descs = Vec::new();
            for aia in &self.authority_info_access {
                let (access_method, location) = match aia {
                    AuthorityInfoAccess::Ocsp(uri) => {
                        (ObjectIdentifier::new("1.3.6.1.5.5.7.48.1").unwrap(), uri)
                    }
                    AuthorityInfoAccess::CaIssuers(uri) => {
                        (ObjectIdentifier::new("1.3.6.1.5.5.7.48.2").unwrap(), uri)
                    }
                };

                let general_name = GeneralName::UniformResourceIdentifier(
                    Ia5StringRef::new(location)
                        .map_err(|e| Error::Encoding(format!("Invalid AIA URI: {}", e)))?
                        .into(),
                );

                let desc = AccessDescription {
                    access_method,
                    access_location: general_name,
                };
                access_descs.push(desc);
            }

            let aia = AuthorityInfoAccessSyntax(access_descs);
            let ext = Extension {
                extn_id: rfc5280::ID_PE_AUTHORITY_INFO_ACCESS,
                critical: false,
                extn_value: OctetString::new(
                    aia.to_der()
                        .map_err(|e| Error::Encoding(format!("Failed to encode AIA: {}", e)))?,
                )?,
            };
            extensions.push(ext);
        }

        // RFC 5280 §4.2.1.4 - Certificate Policies
        if !self.certificate_policies.is_empty() {
            use const_oid::ObjectIdentifier;
            use x509_cert::ext::pkix::CertificatePolicies;
            use x509_cert::ext::pkix::certpolicy::PolicyInformation;

            let mut policies = Vec::new();
            for policy in &self.certificate_policies {
                let oid = ObjectIdentifier::new(&policy.oid)
                    .map_err(|e| Error::Encoding(format!("Invalid policy OID: {}", e)))?;

                // TODO: Add policy qualifiers (CPS URI, user notice)
                let policy_info = PolicyInformation {
                    policy_identifier: oid,
                    policy_qualifiers: None,
                };
                policies.push(policy_info);
            }

            let cert_policies = CertificatePolicies(policies);
            let ext =
                Extension {
                    extn_id: rfc5280::ID_CE_CERTIFICATE_POLICIES,
                    critical: false,
                    extn_value: OctetString::new(cert_policies.to_der().map_err(|e| {
                        Error::Encoding(format!("Failed to encode policies: {}", e))
                    })?)?,
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
    fn test_certificate_builder_from_profile() {
        let profile = CertificateProfile::tls_server(365);
        let builder = CertificateBuilder::from_profile(&profile);

        assert!(builder.not_before.is_some());
        assert!(builder.not_after.is_some());
        assert!(!builder.basic_constraints_ca);
        assert!(
            builder
                .extended_key_usage
                .contains(&ExtendedKeyUsage::ServerAuth)
        );
    }

    #[test]
    fn test_certificate_builder_required_fields() {
        let builder = CertificateBuilder::new();
        let result = builder.build_tbs();
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_builder_validity() {
        let now = Utc::now();
        let past = now - Duration::try_days(1).unwrap();

        let builder = CertificateBuilder::new()
            .serial_number(SerialNumber::from_bytes(vec![1, 2, 3]).unwrap())
            .subject(DistinguishedName::new())
            .issuer(DistinguishedName::new())
            .validity(now, past) // Invalid: not_after before not_before
            .public_key(vec![1, 2, 3]);

        let result = builder.build_tbs();
        assert!(result.is_err());
    }
}
