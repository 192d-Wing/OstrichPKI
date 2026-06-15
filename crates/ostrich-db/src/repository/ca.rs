//! CA key and certificate repository
//!
//! Read/bootstrap operations over the `ca_keys` and `ca_certificates` tables.
//! Used by the CA server at startup to load its signing key reference and
//! certificate, and by `ostrich-init` style tooling to register a new CA.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: CM-2 (Baseline Configuration) - CA identity is data, not code
//! - NIAP PP-CA: FCS_STG_EXT.1 - key rows record provider storage type
//! - NIAP PP-CA: FMT_SMF.1 - CA bootstrap is a security management function

use crate::models::ca::{CaCertificate, CaKey};
use crate::{DatabasePool, Result};
use uuid::Uuid;

/// Repository for CA keys and CA certificates
pub struct CaRepository {
    pool: DatabasePool,
}

impl CaRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Find a CA certificate by ID
    pub async fn find_ca_certificate(&self, id: Uuid) -> Result<Option<CaCertificate>> {
        let cert =
            sqlx::query_as::<_, CaCertificate>("SELECT * FROM ca_certificates WHERE id = $1")
                .bind(id)
                .fetch_optional(self.pool.pool())
                .await?;
        Ok(cert)
    }

    /// Find the default CA certificate.
    ///
    /// Returns the most recently created, currently valid CA certificate.
    /// Single-CA deployments can rely on this; multi-CA deployments should
    /// pin an explicit certificate ID instead (CM-6 - explicit configuration
    /// beats implicit selection).
    pub async fn find_default_ca_certificate(&self) -> Result<Option<CaCertificate>> {
        let cert = sqlx::query_as::<_, CaCertificate>(
            r#"
            SELECT * FROM ca_certificates
            WHERE not_before <= NOW() AND not_after > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(self.pool.pool())
        .await?;
        Ok(cert)
    }

    /// Find a CA key by ID
    pub async fn find_ca_key(&self, id: Uuid) -> Result<Option<CaKey>> {
        let key = sqlx::query_as::<_, CaKey>("SELECT * FROM ca_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;
        Ok(key)
    }

    /// Find a CA key by its unique label
    pub async fn find_ca_key_by_label(&self, label: &str) -> Result<Option<CaKey>> {
        let key = sqlx::query_as::<_, CaKey>("SELECT * FROM ca_keys WHERE label = $1")
            .bind(label)
            .fetch_optional(self.pool.pool())
            .await?;
        Ok(key)
    }

    /// Register a CA key reference.
    ///
    /// NIAP PP-CA: FCS_STG_EXT.1 - records where the key material lives;
    /// the material itself never passes through this layer.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_ca_key(
        &self,
        label: &str,
        key_type: &str,
        algorithm: &str,
        provider_type: &str,
        provider_slot_id: Option<i64>,
        key_id: &[u8],
        extractable: bool,
    ) -> Result<CaKey> {
        let key = sqlx::query_as::<_, CaKey>(
            r#"
            INSERT INTO ca_keys (
                label, key_type, algorithm, provider_type,
                provider_slot_id, key_id, extractable
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(label)
        .bind(key_type)
        .bind(algorithm)
        .bind(provider_type)
        .bind(provider_slot_id)
        .bind(key_id)
        .bind(extractable)
        .fetch_one(self.pool.pool())
        .await?;
        Ok(key)
    }

    /// Register a CA certificate.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_ca_certificate(
        &self,
        ca_key_id: Uuid,
        serial_number: &[u8],
        subject_dn: &str,
        issuer_dn: &str,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        der_encoded: &[u8],
        pem_encoded: &str,
        is_root: bool,
        parent_ca_id: Option<Uuid>,
        path_len_constraint: Option<i32>,
    ) -> Result<CaCertificate> {
        let cert = sqlx::query_as::<_, CaCertificate>(
            r#"
            INSERT INTO ca_certificates (
                ca_key_id, serial_number, subject_dn, issuer_dn,
                not_before, not_after, der_encoded, pem_encoded,
                is_root, parent_ca_id, path_len_constraint
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(ca_key_id)
        .bind(serial_number)
        .bind(subject_dn)
        .bind(issuer_dn)
        .bind(not_before)
        .bind(not_after)
        .bind(der_encoded)
        .bind(pem_encoded)
        .bind(is_root)
        .bind(parent_ca_id)
        .bind(path_len_constraint)
        .fetch_one(self.pool.pool())
        .await?;
        Ok(cert)
    }
}
