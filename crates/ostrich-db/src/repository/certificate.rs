//! Certificate repository for storing and retrieving certificates
//!
//! NIST 800-53: SC-12 - Cryptographic key establishment and management
//! RFC 5280: X.509 certificate storage

use crate::{DatabasePool, Error, Result, models::Certificate};
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

/// Inventory-wide certificate counts grouped by derived status.
///
/// Mirrors `cert_status_str` precedence (revoked wins, then expired, then
/// pending, else active) so the figures match the list view's per-row status.
#[derive(Debug, Clone, Copy, Default)]
pub struct CertificateStatusCounts {
    pub total: i64,
    pub active: i64,
    pub revoked: i64,
    pub expired: i64,
    pub pending: i64,
}

/// Repository for certificate operations
pub struct CertificateRepository {
    pool: DatabasePool,
}

impl CertificateRepository {
    /// Create a new certificate repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Find certificate by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Certificate>> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT *
            FROM certificates
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(cert)
    }

    /// Find certificate by serial number
    ///
    /// RFC 5280 §4.1.2.2 - Serial number is unique per CA
    pub async fn find_by_serial(&self, serial_number: &[u8]) -> Result<Option<Certificate>> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT *
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
            SELECT *
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
            SELECT *
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
            SELECT *
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

    /// Count certificates grouped by derived status in a single aggregate query.
    ///
    /// Inventory-wide (independent of any list filter/pagination), so the UI can
    /// show true totals while the table shows a filtered subset.
    pub async fn count_by_status(&self) -> Result<CertificateStatusCounts> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (
                    WHERE NOT revoked AND not_after >= NOW() AND not_before <= NOW()
                ) AS active,
                COUNT(*) FILTER (WHERE revoked) AS revoked,
                COUNT(*) FILTER (WHERE NOT revoked AND not_after < NOW()) AS expired,
                COUNT(*) FILTER (
                    WHERE NOT revoked AND not_after >= NOW() AND not_before > NOW()
                ) AS pending
            FROM certificates
            "#,
        )
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(CertificateStatusCounts {
            total: row.get("total"),
            active: row.get("active"),
            revoked: row.get("revoked"),
            expired: row.get("expired"),
            pending: row.get("pending"),
        })
    }

    /// List certificates with optional status filter + substring search, with
    /// filtering, counting, and pagination performed entirely in SQL.
    ///
    /// This replaces an in-memory scan-and-filter (which capped at a few
    /// thousand rows and loaded the full DER/PEM of every scanned row): the
    /// database now does the work and only the requested page is returned.
    ///
    /// - `status`: `all` | `active` | `revoked` | `expired` | `pending`,
    ///   mirroring `cert_status_str` precedence (revoked → expired → pending →
    ///   active). Any other value matches nothing.
    /// - `search`: case-insensitive **literal** substring (no LIKE wildcards)
    ///   matched against the subject DN and the hex-encoded serial number.
    ///
    /// Returns `(page rows, total matching count)`.
    pub async fn list_filtered(
        &self,
        status: &str,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Certificate>, i64)> {
        // No user input is interpolated here — only bind placeholders — so the
        // shared predicate is safe to splice into both queries.
        const PREDICATE: &str = r#"
            (
                $1 = 'all'
                OR ($1 = 'revoked' AND revoked)
                OR ($1 = 'expired' AND NOT revoked AND not_after < NOW())
                OR ($1 = 'pending' AND NOT revoked AND not_after >= NOW() AND not_before > NOW())
                OR ($1 = 'active'  AND NOT revoked AND not_after >= NOW() AND not_before <= NOW())
            )
            AND (
                $2::text IS NULL
                OR POSITION(LOWER($2) IN LOWER(subject_dn)) > 0
                OR POSITION(LOWER($2) IN encode(serial_number, 'hex')) > 0
            )
        "#;

        // SI-10: PREDICATE is a fixed fragment with $N placeholders; status/search
        // are bound, not interpolated. AssertSqlSafe (sqlx 0.9) marks it audited.
        let rows = sqlx::query_as::<_, Certificate>(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM certificates WHERE {PREDICATE} ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        )))
        .bind(status)
        .bind(search)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM certificates WHERE {PREDICATE}"
        )))
        .bind(status)
        .bind(search)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok((rows, total))
    }
}

#[async_trait]
impl super::Repository<Certificate> for CertificateRepository {
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Certificate>> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT *
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
        // NIST 800-53: AU-3(1) - issuer_service/requestor/profile_name/metadata
        // carry issuance attribution and MUST be persisted (an earlier version
        // of this INSERT silently dropped them, and its explicit RETURNING
        // list broke row mapping after migration 00002 added the columns).
        let created = sqlx::query_as::<_, Certificate>(
            r#"
            INSERT INTO certificates (
                id, ca_id, serial_number, subject_dn, issuer_dn,
                not_before, not_after, der_encoded, pem_encoded,
                revoked, revocation_time, revocation_reason,
                issuer_service, requestor, profile_name, metadata,
                request_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18, $19)
            RETURNING *
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
        .bind(&cert.issuer_service)
        .bind(&cert.requestor)
        .bind(&cert.profile_name)
        .bind(&cert.metadata)
        .bind(cert.request_id)
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
            SELECT *
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
