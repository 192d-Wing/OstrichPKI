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
}

impl TbsCertificate {
    /// Encode to DER format for signing
    ///
    /// RFC 5280 §4.1.1.2 - signatureAlgorithm
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // TODO: Implement DER encoding using x509-cert crate
        // For now, return empty vec as stub
        Ok(Vec::new())
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
