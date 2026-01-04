//! Certificate issuance functionality
//!
//! RFC 5280 §4.1 - Certificate issuance
//! NIST 800-53: SC-12 - Cryptographic key establishment and management

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use ostrich_db::{
    DatabasePool,
    models::Certificate,
    repository::{CertificateRepository, Repository},
};
use ostrich_x509::{CertificateBuilder, extensions::SubjectAltName, profile::CertificateProfile};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Certificate issuance request
///
/// RFC 5280 §4.1 - Certificate fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// Profile to use for issuance
    pub profile_name: String,

    /// Subject distinguished name
    pub subject: DistinguishedName,

    /// Subject alternative names (optional)
    pub subject_alt_names: Vec<SubjectAltName>,

    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,

    /// Requestor (for audit)
    pub requestor: String,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Issued certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    /// Certificate ID
    pub certificate_id: Uuid,

    /// Serial number
    pub serial_number: Vec<u8>,

    /// DER-encoded certificate
    pub der_encoded: Vec<u8>,

    /// PEM-encoded certificate
    pub pem_encoded: String,

    /// Validity period
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// Certificate issuer
///
/// NIST 800-53: SC-12 - Cryptographic key generation and management
pub struct CertificateIssuer {
    /// CA key handle
    ca_key: KeyHandle,

    /// CA certificate
    ca_certificate: Certificate,

    /// Crypto provider
    crypto_provider: Box<dyn CryptoProvider>,

    /// Database pool
    db_pool: DatabasePool,

    /// Audit sink
    audit_sink: Box<dyn AuditSink>,

    /// Available profiles
    profiles: std::collections::HashMap<String, CertificateProfile>,
}

impl CertificateIssuer {
    /// Create a new certificate issuer
    pub fn new(
        ca_key: KeyHandle,
        ca_certificate: Certificate,
        crypto_provider: Box<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
    ) -> Self {
        Self {
            ca_key,
            ca_certificate,
            crypto_provider,
            db_pool,
            audit_sink,
            profiles: std::collections::HashMap::new(),
        }
    }

    /// Add a certificate profile
    pub fn add_profile(&mut self, profile: CertificateProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Issue a certificate
    ///
    /// RFC 5280 §4.1 - Certificate generation
    /// NIST 800-53: SC-12 - Cryptographic key generation
    pub async fn issue(&self, request: IssuanceRequest) -> Result<IssuedCertificate> {
        // NIST 800-53: AU-2 - Audit certificate issuance
        let mut audit_event = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            &request.requestor,
            request.subject.to_string_rfc4514(),
            "issue",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "profile": request.profile_name,
            "subject": request.subject.to_string_rfc4514(),
        }))
        .build();

        // Get profile
        let profile = self
            .profiles
            .get(&request.profile_name)
            .ok_or_else(|| Error::ProfileNotFound(request.profile_name.clone()))?;

        // Validate profile
        profile.validate()?;

        // Validate request
        if profile.subject_alt_name_required && request.subject_alt_names.is_empty() {
            audit_event.outcome = EventOutcome::Failure;
            self.audit_sink
                .record(&mut audit_event)
                .await
                .map_err(Error::Audit)?;

            return Err(Error::InvalidRequest(
                "Subject alternative names are required for this profile".to_string(),
            ));
        }

        // Generate serial number
        let serial_number = self.generate_serial_number()?;

        // Build certificate
        let mut builder = CertificateBuilder::from_profile(profile)
            .serial_number(serial_number.clone())
            .subject(request.subject.clone())
            .issuer(
                DistinguishedName::new_cn(&self.ca_certificate.subject_dn), // TODO: Parse from certificate
            )
            .public_key(request.public_key.clone());

        // Add subject alternative names
        for san in request.subject_alt_names {
            builder = builder.add_subject_alt_name(san);
        }

        // Build TBS certificate
        let tbs_cert = builder.build_tbs()?;

        // Encode TBS certificate to DER for signing
        let tbs_der = tbs_cert.to_der()?;

        // Sign the TBS certificate with CA key
        // TODO: Determine signature algorithm from CA key type
        // For now, use RSA-PSS with SHA-256
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, Algorithm::RsaPssSha256, &tbs_der)
            .await?;

        // Construct final signed certificate
        let der_encoded = self.build_signed_certificate(&tbs_der, &signature)?;

        // Convert DER to PEM
        let pem_encoded = self.der_to_pem(&der_encoded)?;

        // Store certificate in database
        let cert_id = Uuid::new_v4();
        let certificate = Certificate {
            id: cert_id,
            ca_id: self.ca_certificate.id,
            serial_number: serial_number.as_bytes().to_vec(),
            subject_dn: request.subject.to_string_rfc4514(),
            issuer_dn: self.ca_certificate.subject_dn.clone(),
            not_before: tbs_cert.not_before,
            not_after: tbs_cert.not_after,
            der_encoded: der_encoded.clone(),
            pem_encoded: pem_encoded.clone(),
            revoked: false,
            revocation_time: None,
            revocation_reason: None,
            issuer_service: Some("CA".to_string()),
            requestor: Some(request.requestor.clone()),
            profile_name: Some(request.profile_name.clone()),
            metadata: request.metadata.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        cert_repo.create(&certificate).await?;

        // Record successful issuance
        self.audit_sink
            .record(&mut audit_event)
            .await
            .map_err(Error::Audit)?;

        tracing::info!(
            "Certificate issued: {} for {}",
            cert_id,
            request.subject.to_string_rfc4514()
        );

        Ok(IssuedCertificate {
            certificate_id: cert_id,
            serial_number: serial_number.as_bytes().to_vec(),
            der_encoded,
            pem_encoded,
            not_before: tbs_cert.not_before,
            not_after: tbs_cert.not_after,
        })
    }

    /// Build a signed X.509 certificate from TBS and signature
    ///
    /// RFC 5280 §4.1 - Certificate structure
    fn build_signed_certificate(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        use der::{Decode, Encode, asn1::BitString};
        use x509_cert::{Certificate as X509Certificate, TbsCertificate};

        // Parse TBS certificate from DER
        let tbs = TbsCertificate::from_der(tbs_der)
            .map_err(|e| Error::Issuance(format!("Failed to parse TBS certificate: {}", e)))?;

        // Get signature algorithm (same as in TBS)
        let signature_algorithm = tbs.signature.clone();

        // Convert signature bytes to BitString
        let signature_value = BitString::from_bytes(signature)
            .map_err(|e| Error::Issuance(format!("Failed to create signature BitString: {}", e)))?;

        // Build complete certificate
        let certificate = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm,
            signature: signature_value,
        };

        // Encode to DER
        certificate
            .to_der()
            .map_err(|e| Error::Issuance(format!("Failed to encode certificate: {}", e)))
    }

    /// Convert DER-encoded certificate to PEM format
    ///
    /// RFC 7468 - PEM encoding
    fn der_to_pem(&self, der: &[u8]) -> Result<String> {
        use pem_rfc7468::{LineEnding, encode_string};

        const CERTIFICATE_LABEL: &str = "CERTIFICATE";

        encode_string(CERTIFICATE_LABEL, LineEnding::LF, der)
            .map_err(|e| Error::Issuance(format!("Failed to encode PEM: {}", e)))
    }

    /// Generate a cryptographically random serial number
    ///
    /// RFC 5280 §4.1.2.2 - Serial number must be positive and unique
    fn generate_serial_number(&self) -> Result<SerialNumber> {
        use ostrich_common::util::random::secure_random_bytes;

        // Generate 20 random bytes (160 bits) - RFC 5280 maximum
        let mut bytes = secure_random_bytes(20);

        // Ensure positive (clear high bit)
        bytes[0] &= 0x7F;

        SerialNumber::from_bytes(bytes).map_err(Error::Common)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuance_request_serialization() {
        let request = IssuanceRequest {
            profile_name: "tls_server".to_string(),
            subject: DistinguishedName::new_cn("example.com"),
            subject_alt_names: vec![SubjectAltName::dns("example.com")],
            public_key: vec![1, 2, 3],
            requestor: "admin@example.com".to_string(),
            metadata: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IssuanceRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.profile_name, "tls_server");
        assert_eq!(deserialized.requestor, "admin@example.com");
    }
}
