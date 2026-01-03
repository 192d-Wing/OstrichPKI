//! CRL generation and management
//!
//! RFC 5280 §5 - Certificate revocation lists

use crate::{Result, builder::CrlBuilder, parser::RevocationReason};
use chrono::{DateTime, Utc};
use ostrich_common::types::DistinguishedName;

/// CRL generator
///
/// RFC 5280 §5 - CRL issuance
pub struct CrlGenerator {
    /// Issuer DN
    issuer: DistinguishedName,
    /// CRL validity period in hours
    validity_hours: u32,
    /// Authority key identifier
    authority_key_id: Option<Vec<u8>>,
}

impl CrlGenerator {
    /// Create a new CRL generator
    pub fn new(issuer: DistinguishedName, validity_hours: u32) -> Self {
        Self {
            issuer,
            validity_hours,
            authority_key_id: None,
        }
    }

    /// Set authority key identifier
    pub fn with_authority_key_id(mut self, key_id: Vec<u8>) -> Self {
        self.authority_key_id = Some(key_id);
        self
    }

    /// Generate a new CRL
    ///
    /// RFC 5280 §5.1.2.1 - CRL number is monotonically increasing
    pub fn generate(
        &self,
        crl_number: u64,
        revoked_certificates: Vec<RevokedCertificateInfo>,
    ) -> Result<CrlBuilder> {
        let mut builder = CrlBuilder::new()
            .issuer(self.issuer.clone())
            .this_update(Utc::now())
            .next_update_hours(self.validity_hours)
            .crl_number(crl_number);

        if let Some(ref key_id) = self.authority_key_id {
            builder = builder.authority_key_id(key_id.clone());
        }

        for revoked in revoked_certificates {
            builder = builder.add_revoked(
                revoked.serial_number,
                revoked.revocation_time,
                revoked.reason,
            );
        }

        Ok(builder)
    }
}

/// Information about a revoked certificate
#[derive(Debug, Clone)]
pub struct RevokedCertificateInfo {
    /// Serial number
    pub serial_number: Vec<u8>,
    /// Revocation time
    pub revocation_time: DateTime<Utc>,
    /// Revocation reason
    pub reason: Option<RevocationReason>,
}

impl RevokedCertificateInfo {
    /// Create new revoked certificate info
    pub fn new(
        serial_number: Vec<u8>,
        revocation_time: DateTime<Utc>,
        reason: Option<RevocationReason>,
    ) -> Self {
        Self {
            serial_number,
            revocation_time,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_generator() {
        let generator = CrlGenerator::new(DistinguishedName::new(), 24);

        let revoked = vec![RevokedCertificateInfo::new(
            vec![1, 2, 3],
            Utc::now(),
            Some(RevocationReason::KeyCompromise),
        )];

        let builder = generator.generate(1, revoked).unwrap();
        let tbs_crl = builder.build_tbs().unwrap();

        assert_eq!(tbs_crl.crl_number, Some(1));
        assert_eq!(tbs_crl.revoked_certificates.len(), 1);
    }
}
