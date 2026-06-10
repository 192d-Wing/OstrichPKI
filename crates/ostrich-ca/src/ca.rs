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
use ostrich_common::types::DistinguishedName;
use ostrich_crypto::{CryptoProvider, HsmKeyValidator, KeyHandle};
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
    /// NIAP PP-CA: FCS_STG_EXT.1 - Validates CA signing key is stored in HSM
    /// NIST 800-53: SC-12 - CA initialization
    pub fn new(
        ca_certificate: Certificate,
        ca_key: KeyHandle,
        crypto_provider: Box<dyn CryptoProvider>,
        db_pool: DatabasePool,
        crl_validity_hours: u32,
    ) -> Result<Self, ostrich_crypto::Error> {
        // FCS_STG_EXT.1: Validate CA signing key is stored in HSM
        HsmKeyValidator::validate_ca_signing_key(&ca_key)?;

        let ca_id = ca_certificate.id;
        // RFC 5280 §7.1 - parse the structured subject DN from the CA
        // certificate so issued certificates' issuer fields chain correctly.
        // (Wrapping the rendered string in new_cn produced "CN=CN=..." and
        // broke OpenSSL chain verification.)
        let ca_dn = ostrich_x509::parser::parse_subject_dn(&ca_certificate.der_encoded)
            .map_err(|e| {
                ostrich_crypto::Error::InvalidInput(format!(
                    "Failed to parse CA certificate subject DN: {}",
                    e
                ))
            })?;

        // Wrap crypto provider in Arc for sharing between components
        let crypto_provider_arc: std::sync::Arc<dyn CryptoProvider> =
            std::sync::Arc::from(crypto_provider);

        // AU-10 (Non-repudiation): sign every audit record's event_hash with the
        // CA key. The hash chain alone is not tamper-evident against an attacker
        // with database write access (SHA-256 is public, so they can rewrite the
        // whole chain); signing closes that gap because they cannot forge the
        // signature. The CA key is used because it is already loaded, stable, and
        // its public key is published in the CA certificate, so any relying party
        // can run verify_signed_chain against the CA cert's SPKI. `signing_key_id`
        // records the key label on each row to support future key separation /
        // rotation. See migrations/00007_audit_signature.sql.
        let issuer_sink = Box::new(ostrich_audit::sink::DatabaseAuditSink::with_signing_key(
            db_pool.clone(),
            crypto_provider_arc.clone(),
            ca_key.clone(),
            ca_key.algorithm,
            ca_key.label.clone(),
        ));
        let revocation_sink = Box::new(ostrich_audit::sink::DatabaseAuditSink::with_signing_key(
            db_pool.clone(),
            crypto_provider_arc.clone(),
            ca_key.clone(),
            ca_key.algorithm,
            ca_key.label.clone(),
        ));

        let issuer = CertificateIssuer::new(
            ca_key.clone(),
            ca_certificate.clone(),
            crypto_provider_arc.clone(),
            db_pool.clone(),
            issuer_sink,
        );

        // The revocation manager shares the same crypto provider as the
        // issuer: the CA key lives in that provider (HSM for production), and
        // a separate software provider cannot sign with it. An earlier version
        // constructed a second software provider here, which broke CRL signing
        // for HSM-backed CAs.
        let revocation_manager = RevocationManager::new(
            ca_key,
            ca_id,
            crypto_provider_arc.clone(),
            db_pool.clone(),
            revocation_sink,
            crl_validity_hours,
        );

        Ok(Self {
            ca_id,
            ca_dn,
            issuer,
            revocation_manager,
        })
    }

    /// Add a certificate profile
    ///
    /// NIAP PP-CA: FMT_MOF.1.1 - Configure certificate issuance behavior
    /// NIAP PP-CA: FDP_IFC.1.1 - Define information flow policy for certificates
    pub fn add_profile(&mut self, profile: CertificateProfile) {
        self.issuer.add_profile(profile);
    }

    /// Override the issuer's approval configuration.
    ///
    /// NIAP PP-CA: FDP_CER_EXT.3 - approval-required is the default; turning
    /// it off is an explicit deployment decision (e.g. automated ACME
    /// issuance where challenge validation is the approval).
    pub fn set_approval_config(&mut self, config: crate::approval::ApprovalConfig) {
        self.issuer.set_approval_config(config);
    }

    /// Wire the approval engine + repository into the issuer so that
    /// approval-gated issuance (FDP_CER_EXT.3) can validate approvals.
    pub fn set_approval(
        &mut self,
        engine: std::sync::Arc<crate::approval::ApprovalEngine>,
        repo: std::sync::Arc<ostrich_db::repository::ApprovalRepository>,
        config: crate::approval::ApprovalConfig,
    ) {
        self.issuer.set_approval(engine, repo, config);
    }

    /// Set the public CRL distribution URL embedded into issued certificates.
    ///
    /// RFC 5280 §4.2.1.13 - issued leaves gain a CRL Distribution Points
    /// extension pointing relying parties at the public CRL GET endpoint.
    /// NIAP PP-CA: FMT_SMF.1 - CRL distribution configuration.
    pub fn set_crl_distribution_url(&mut self, url: impl Into<String>) {
        self.issuer.set_crl_distribution_url(url);
    }

    /// Set the OCSP responder URL embedded into issued certificates (AIA).
    ///
    /// RFC 5280 §4.2.2.1 / RFC 6960 - issued leaves gain an Authority
    /// Information Access extension with an id-ad-ocsp accessDescription so
    /// relying parties can discover the OCSP responder.
    /// NIAP PP-CA: FMT_SMF.1 - certificate status discovery configuration.
    pub fn set_ocsp_responder_url(&mut self, url: impl Into<String>) {
        self.issuer.set_ocsp_responder_url(url);
    }

    /// Set the CA Issuers URL embedded into issued certificates (AIA).
    ///
    /// RFC 5280 §4.2.2.1 - id-ad-caIssuers accessDescription pointing relying
    /// parties at the issuing CA certificate for chain building.
    pub fn set_ca_issuers_url(&mut self, url: impl Into<String>) {
        self.issuer.set_ca_issuers_url(url);
    }

    /// Enable/disable the proof-of-possession requirement for end-entity
    /// issuance (enabled by default). NIST 800-53 SI-10 / SC-8(1); RFC 2986.
    pub fn set_require_proof_of_possession(&mut self, require: bool) {
        self.issuer.set_require_proof_of_possession(require);
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
