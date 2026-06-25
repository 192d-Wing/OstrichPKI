//! FQDN history repository.
//!
//! Aggregates certificate history per fully-qualified domain name using the
//! `certificate_sans` index (populated at issuance by the certificate
//! repository), and stores the per-FQDN renewal-notification contact.
//!
//! # Compliance Mapping
//! - NIST 800-53: AC-3 (Access enforcement — gated by Permission::ViewCertificate
//!   at the REST layer), AU-3 (notification updates carry updated_by/updated_at)
//! - NIAP PP-CA: FMT_MTD.1 (Management of TSF data — renewal contact)
//! - RFC 5280 §4.2.1.6: SubjectAltName is the identity being aggregated

use crate::{DatabasePool, Error, Result, models::Certificate};
use chrono::{DateTime, Utc};

/// One row of the distinct-FQDN listing.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FqdnSummary {
    pub fqdn: String,
    pub certificate_count: i64,
    pub first_seen: DateTime<Utc>,
    pub last_issued: DateTime<Utc>,
}

/// Operator-set renewal-notification contact for an FQDN.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FqdnNotification {
    pub fqdn: String,
    pub email: String,
    pub updated_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Repository for per-FQDN certificate history and renewal contacts.
pub struct FqdnRepository {
    pool: DatabasePool,
}

impl FqdnRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// List distinct FQDNs (with cert count + first/last issuance), filtered by
    /// an optional case-insensitive substring, paginated. Returns
    /// `(page rows, total distinct count)`.
    pub async fn list_fqdns(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<FqdnSummary>, i64)> {
        let rows = sqlx::query_as::<_, FqdnSummary>(
            r#"
            SELECT s.name AS fqdn,
                   COUNT(DISTINCT s.certificate_id) AS certificate_count,
                   MIN(c.created_at) AS first_seen,
                   MAX(c.created_at) AS last_issued
            FROM certificate_sans s
            JOIN certificates c ON c.id = s.certificate_id
            WHERE ($1::text IS NULL OR POSITION(LOWER($1) IN s.name) > 0)
            GROUP BY s.name
            ORDER BY s.name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(search)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(DISTINCT s.name)
            FROM certificate_sans s
            WHERE ($1::text IS NULL OR POSITION(LOWER($1) IN s.name) > 0)
            "#,
        )
        .bind(search)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok((rows, total))
    }

    /// All certificates that cover `fqdn` (matched via the SAN/CN index),
    /// newest first. `fqdn` is matched case-insensitively (the index stores
    /// lowercased names, so the caller should lowercase too).
    pub async fn certs_for_fqdn(&self, fqdn: &str) -> Result<Vec<Certificate>> {
        let certs = sqlx::query_as::<_, Certificate>(
            r#"
            SELECT c.*
            FROM certificates c
            JOIN certificate_sans s ON s.certificate_id = c.id
            WHERE s.name = $1
            ORDER BY c.created_at DESC
            "#,
        )
        .bind(fqdn)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(certs)
    }

    /// Fetch the renewal-notification contact for an FQDN, if set.
    pub async fn get_notification(&self, fqdn: &str) -> Result<Option<FqdnNotification>> {
        let row = sqlx::query_as::<_, FqdnNotification>(
            r#"
            SELECT fqdn, email, updated_by, updated_at
            FROM fqdn_notification
            WHERE fqdn = $1
            "#,
        )
        .bind(fqdn)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(row)
    }

    /// Upsert the renewal-notification contact for an FQDN. `updated_by` records
    /// the actor for AU-3 attribution.
    pub async fn set_notification(
        &self,
        fqdn: &str,
        email: &str,
        updated_by: Option<&str>,
    ) -> Result<FqdnNotification> {
        let row = sqlx::query_as::<_, FqdnNotification>(
            r#"
            INSERT INTO fqdn_notification (fqdn, email, updated_by, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (fqdn) DO UPDATE
                SET email = EXCLUDED.email,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = NOW()
            RETURNING fqdn, email, updated_by, updated_at
            "#,
        )
        .bind(fqdn)
        .bind(email)
        .bind(updated_by)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(row)
    }
}
