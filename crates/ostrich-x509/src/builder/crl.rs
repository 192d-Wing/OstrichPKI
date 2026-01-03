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
        }
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

            // Build revoked cert entry
            // Note: extensions for revocation reason will be added separately
            let revoked = RevokedCert {
                serial_number: serial,
                revocation_date: revocation_time,
                crl_entry_extensions: None, // TODO: Add revocation reason extension
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
    fn get_signature_algorithm(&self) -> Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        // TODO: Determine algorithm from CA key type
        // For now, default to RSA-PSS with SHA-256
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;

        Ok(x509_cert::spki::AlgorithmIdentifierOwned {
            oid: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: None,
        })
    }

    /// Build CRL extensions
    ///
    /// RFC 5280 §5.2 - CRL extensions
    fn build_extensions(&self) -> Result<Option<x509_cert::ext::Extensions>> {
        // TODO: Implement CRL extensions:
        // - CRL Number (required)
        // - Authority Key Identifier
        // - Issuing Distribution Point

        // For now, return None (empty extensions)
        // CRL Number should be added here when implementing extensions
        Ok(None)
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
}
