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
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // TODO: Implement DER encoding
        Ok(Vec::new())
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
