//! Certificate repository for storing and retrieving certificates
//!
//! NIST 800-53: SC-12 - Cryptographic key establishment and management
//! RFC 5280: X.509 certificate storage

use crate::{DatabasePool, Error, Result, models::Certificate};
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

/// Repository for certificate operations
pub struct CertificateRepository {
    pool: DatabasePool,
}

impl CertificateRepository {
    /// Create a new certificate repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Find certificate by serial number
    ///
    /// RFC 5280 §4.1.2.2 - Serial number is unique per CA
    pub async fn find_by_serial(&self, serial_number: &[u8]) -> Result<Option<Certificate>> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            WHERE serial_number = $1
            "#,
        )
        .bind(serial_number)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(cert)
    }

    /// Find certificates by subject DN
    pub async fn find_by_subject(&self, subject_dn: &str) -> Result<Vec<Certificate>> {
        let certs = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            WHERE subject_dn = $1
            ORDER BY not_before DESC
            "#,
        )
        .bind(subject_dn)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(certs)
    }

    /// Find certificates issued by a specific CA
    pub async fn find_by_ca(&self, ca_id: &Uuid) -> Result<Vec<Certificate>> {
        let certs = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            WHERE ca_id = $1
            ORDER BY not_before DESC
            "#,
        )
        .bind(ca_id)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(certs)
    }

    /// Find all revoked certificates (for CRL generation)
    ///
    /// RFC 5280 §5 - Certificate revocation lists
    pub async fn find_revoked(&self, ca_id: &Uuid) -> Result<Vec<Certificate>> {
        let certs = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            WHERE ca_id = $1 AND revoked = true
            ORDER BY revocation_time DESC
            "#,
        )
        .bind(ca_id)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(certs)
    }

    /// Revoke a certificate
    ///
    /// RFC 5280 §5.3 - CRL entry extensions
    /// NIST 800-53: AU-2 - Auditable event (certificate revocation)
    pub async fn revoke(&self, id: &Uuid, reason: i32) -> Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE certificates
            SET revoked = true,
                revocation_time = NOW(),
                revocation_reason = $2,
                updated_at = NOW()
            WHERE id = $1 AND revoked = false
            "#,
        )
        .bind(id)
        .bind(reason)
        .execute(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound(
                "Certificate not found or already revoked".to_string(),
            ));
        }

        tracing::info!("Certificate {} revoked with reason {}", id, reason);
        Ok(())
    }

    /// Check if a certificate is valid (not expired and not revoked)
    ///
    /// RFC 5280 §4.1.2.5 - Validity
    /// RFC 6960 §2.2 - OCSP response
    pub async fn is_valid(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM certificates
            WHERE id = $1
              AND revoked = false
              AND not_before <= NOW()
              AND not_after > NOW()
            "#,
        )
        .bind(id)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        let count: i64 = result.get("count");
        Ok(count > 0)
    }
}

#[async_trait]
impl super::Repository<Certificate> for CertificateRepository {
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Certificate>> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(cert)
    }

    async fn create(&self, cert: &Certificate) -> Result<Certificate> {
        let created = sqlx::query_as::<_, Certificate>(
            r#"
            INSERT INTO certificates (
                id, ca_id, serial_number, subject_dn, issuer_dn,
                not_before, not_after, der_encoded, pem_encoded,
                revoked, revocation_time, revocation_reason,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id, ca_id, serial_number, subject_dn, issuer_dn,
                      not_before, not_after, der_encoded, pem_encoded,
                      revoked, revocation_time, revocation_reason,
                      created_at, updated_at
            "#,
        )
        .bind(cert.id)
        .bind(cert.ca_id)
        .bind(&cert.serial_number)
        .bind(&cert.subject_dn)
        .bind(&cert.issuer_dn)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&cert.der_encoded)
        .bind(&cert.pem_encoded)
        .bind(cert.revoked)
        .bind(cert.revocation_time)
        .bind(cert.revocation_reason)
        .bind(cert.created_at)
        .bind(cert.updated_at)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.is_unique_violation()
            {
                return Error::Duplicate(
                    "Certificate with this serial number already exists".to_string(),
                );
            }
            Error::Query(e.to_string())
        })?;

        Ok(created)
    }

    async fn update(&self, cert: &Certificate) -> Result<Certificate> {
        let updated = sqlx::query_as::<_, Certificate>(
            r#"
            UPDATE certificates
            SET ca_id = $2,
                serial_number = $3,
                subject_dn = $4,
                issuer_dn = $5,
                not_before = $6,
                not_after = $7,
                der_encoded = $8,
                pem_encoded = $9,
                revoked = $10,
                revocation_time = $11,
                revocation_reason = $12,
                updated_at = $13
            WHERE id = $1
            RETURNING id, ca_id, serial_number, subject_dn, issuer_dn,
                      not_before, not_after, der_encoded, pem_encoded,
                      revoked, revocation_time, revocation_reason,
                      created_at, updated_at
            "#,
        )
        .bind(cert.id)
        .bind(cert.ca_id)
        .bind(&cert.serial_number)
        .bind(&cert.subject_dn)
        .bind(&cert.issuer_dn)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&cert.der_encoded)
        .bind(&cert.pem_encoded)
        .bind(cert.revoked)
        .bind(cert.revocation_time)
        .bind(cert.revocation_reason)
        .bind(cert.updated_at)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?
        .ok_or_else(|| Error::NotFound("Certificate not found".to_string()))?;

        Ok(updated)
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM certificates WHERE id = $1")
            .bind(id)
            .execute(self.pool.pool())
            .await
            .map_err(|e| Error::Query(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound("Certificate not found".to_string()));
        }

        Ok(())
    }

    async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<Certificate>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let certs = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT id, ca_id, serial_number, subject_dn, issuer_dn,
                   not_before, not_after, der_encoded, pem_encoded,
                   revoked, revocation_time, revocation_reason,
                   created_at, updated_at
            FROM certificates
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(certs)
    }

    async fn count(&self) -> Result<i64> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM certificates")
            .fetch_one(self.pool.pool())
            .await
            .map_err(|e| Error::Query(e.to_string()))?;

        Ok(result.get("count"))
    }
}
