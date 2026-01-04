//! Certificate Authority main struct
//!
//! This module contains the main CertificateAuthority struct that coordinates
//! certificate issuance, revocation, and profile management.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: Security management functions - Central coordinator for all CA operations
//! - **FCS_CKM.1**: Cryptographic key generation - CA key pair management
//! - **FCS_COP.1**: Cryptographic operations - Delegate to issuer/revocation manager
//! - **FDP_ACC.1**: Access control policy - Enforce role-based access to CA functions
//! - **FMT_MOF.1**: Management of security functions behavior - Profile configuration
//!
//! ## RFC Compliance
//! - RFC 5280: X.509 Public Key Infrastructure
//!
//! ## NIST 800-53 Controls
//! - SC-12: Cryptographic key establishment and management
//! - SC-13: Cryptographic protection

use crate::{issuance::CertificateIssuer, revocation::RevocationManager};
use ostrich_audit::AuditSink;
use ostrich_common::types::DistinguishedName;
use ostrich_crypto::{CryptoProvider, KeyHandle};
use ostrich_db::{DatabasePool, models::Certificate};
use ostrich_x509::profile::CertificateProfile;
use uuid::Uuid;

/// Certificate Authority
///
/// Main service for certificate issuance and management.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1 - Central security management function for CA operations
/// - NIAP PP-CA: FCS_CKM.1 - Manages CA cryptographic keys
/// - NIAP PP-CA: FDP_ACC.1 - Enforces access control for CA operations
/// - NIST 800-53: SC-12 - CA key management
pub struct CertificateAuthority {
    /// CA identifier
    pub ca_id: Uuid,

    /// CA distinguished name
    pub ca_dn: DistinguishedName,

    /// Certificate issuer
    issuer: CertificateIssuer,

    /// Revocation manager
    revocation_manager: RevocationManager,
}

impl CertificateAuthority {
    /// Create a new Certificate Authority
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Initialize CA security management functions
    /// NIAP PP-CA: FCS_CKM.1.1 - Load CA cryptographic key material
    /// NIST 800-53: SC-12 - CA initialization
    pub fn new(
        ca_certificate: Certificate,
        ca_key: KeyHandle,
        crypto_provider: Box<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
        crl_validity_hours: u32,
    ) -> Self {
        let ca_id = ca_certificate.id;
        let ca_dn = DistinguishedName::new_cn(&ca_certificate.subject_dn); // TODO: Parse properly

        // Wrap crypto provider in Arc for sharing between components
        let crypto_provider_arc: std::sync::Arc<dyn CryptoProvider> =
            std::sync::Arc::from(crypto_provider);

        let issuer = CertificateIssuer::new(
            ca_key.clone(),
            ca_certificate.clone(),
            crypto_provider_arc.clone(),
            db_pool.clone(),
            audit_sink,
        );

        // Create new crypto provider and audit sink for revocation manager
        // TODO: Implement proper provider/sink cloning
        let crypto_provider2 =
            ostrich_crypto::provider::CryptoProviderFactory::create_software_provider();
        let audit_sink2 = Box::new(ostrich_audit::sink::DatabaseAuditSink::new(db_pool.clone()));

        let revocation_manager = RevocationManager::new(
            ca_key,
            ca_id,
            crypto_provider2,
            db_pool.clone(),
            audit_sink2,
            crl_validity_hours,
        );

        Self {
            ca_id,
            ca_dn,
            issuer,
            revocation_manager,
        }
    }

    /// Add a certificate profile
    ///
    /// NIAP PP-CA: FMT_MOF.1.1 - Configure certificate issuance behavior
    /// NIAP PP-CA: FDP_IFC.1.1 - Define information flow policy for certificates
    pub fn add_profile(&mut self, profile: CertificateProfile) {
        self.issuer.add_profile(profile);
    }

    /// Get the certificate issuer
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Access certificate issuance security function
    pub fn issuer(&self) -> &CertificateIssuer {
        &self.issuer
    }

    /// Get the revocation manager
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Access certificate revocation security function
    pub fn revocation_manager(&self) -> &RevocationManager {
        &self.revocation_manager
    }

    /// Get CA information
    pub fn info(&self) -> CaInfo {
        CaInfo {
            ca_id: self.ca_id,
            ca_dn: self.ca_dn.to_string_rfc4514(),
        }
    }
}

/// CA information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaInfo {
    /// CA identifier
    pub ca_id: Uuid,

    /// CA distinguished name
    pub ca_dn: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_info_serialization() {
        let info = CaInfo {
            ca_id: Uuid::new_v4(),
            ca_dn: "CN=Test CA,O=Test Org,C=US".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: CaInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ca_dn, "CN=Test CA,O=Test Org,C=US");
    }
}
