//! CRL repository for persisting and serving Certificate Revocation Lists
//!
//! Persists every generated CRL and exposes the latest one so it can be served
//! at a public distribution point (RFC 5280 §5). CRL numbers are derived from
//! the database (`MAX(crl_number)+1`) so they remain monotonic and restart
//! stable, satisfying RFC 5280 §5.2.3.
//!
//! # Compliance Mapping
//!
//! ## RFC Compliance
//! - RFC 5280 §5 - Certificate Revocation Lists (public status data)
//! - RFC 5280 §5.2.3 - CRL number monotonicity
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_SMF.1 - CRL management (generation/publication) artifacts
//! - FDP_ACC.1 - Repository access control for CRL records
//!
//! ## NIST 800-53 Controls
//! - SC-17: PKI certificate status (CRL)
//! - AU-2: Auditable event support (CRL generation persisted)

use crate::{DatabasePool, Error, Result, models::Crl};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository for CRL operations
pub struct CrlRepository {
    pool: DatabasePool,
}

impl CrlRepository {
    /// Create a new CRL repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Persist a generated CRL.
    ///
    /// RFC 5280 §5.1 - stores the signed CertificateList (DER + PEM) along with
    /// its number and validity window. The UNIQUE(ca_id, crl_number) constraint
    /// enforces RFC 5280 §5.2.3 monotonicity at the database layer.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_crl(
        &self,
        ca_id: Uuid,
        crl_number: i64,
        this_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
        der_encoded: Vec<u8>,
        pem_encoded: String,
        is_delta: bool,
        base_crl_number: Option<i64>,
    ) -> Result<Crl> {
        let crl = sqlx::query_as::<_, Crl>(
            r#"
            INSERT INTO crls (
                ca_id, crl_number, this_update, next_update, der_encoded, pem_encoded,
                is_delta, base_crl_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(ca_id)
        .bind(crl_number)
        .bind(this_update)
        .bind(next_update)
        .bind(der_encoded)
        .bind(pem_encoded)
        .bind(is_delta)
        .bind(base_crl_number)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(format!("Failed to persist CRL: {}", e)))?;

        Ok(crl)
    }

    /// Find the latest (highest-numbered) FULL CRL for a CA.
    ///
    /// RFC 5280 §5 - the most recent full CRL is served at the distribution point
    /// and is the base for delta CRLs.
    pub async fn find_latest_crl(&self, ca_id: Uuid) -> Result<Option<Crl>> {
        self.find_latest(ca_id, false).await
    }

    /// Find the latest (highest-numbered) DELTA CRL for a CA (RFC 5280 §5.2.4).
    pub async fn find_latest_delta_crl(&self, ca_id: Uuid) -> Result<Option<Crl>> {
        self.find_latest(ca_id, true).await
    }

    async fn find_latest(&self, ca_id: Uuid, is_delta: bool) -> Result<Option<Crl>> {
        let crl = sqlx::query_as::<_, Crl>(
            r#"
            SELECT *
            FROM crls
            WHERE ca_id = $1 AND is_delta = $2
            ORDER BY crl_number DESC
            LIMIT 1
            "#,
        )
        .bind(ca_id)
        .bind(is_delta)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(format!("Failed to load latest CRL: {}", e)))?;

        Ok(crl)
    }

    /// Compute the next CRL number for a CA.
    ///
    /// RFC 5280 §5.2.3 - CRL numbers MUST be monotonically increasing. Deriving
    /// the value from `MAX(crl_number)+1` keeps it stable across process
    /// restarts, unlike an in-memory counter (which would reset to 0 and collide
    /// with the UNIQUE(ca_id, crl_number) constraint).
    pub async fn next_crl_number(&self, ca_id: Uuid) -> Result<i64> {
        let next: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(MAX(crl_number), 0) + 1
            FROM crls
            WHERE ca_id = $1
            "#,
        )
        .bind(ca_id)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(format!("Failed to compute next CRL number: {}", e)))?;

        Ok(next)
    }
}
