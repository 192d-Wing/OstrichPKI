//! EST repository implementation
//!
//! RFC 7030: Enrollment over Secure Transport

use crate::{
    DatabasePool, Result,
    models::{EstClient, EstEnrollment},
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A row of the EST enrollment-token inventory (operator review). The token
/// itself is never returned — only its lifecycle metadata. A status is derived
/// by the caller: live (unused, unexpired), expired, used (consumed by an
/// enrollment), or revoked (consumed early with no certificate).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EstEnrollmentTokenRow {
    pub id: Uuid,
    pub identity: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by_cert: Option<Uuid>,
}

/// EST Repository
///
/// Manages EST enrollments and authorized clients
#[derive(Clone)]
pub struct EstRepository {
    pool: DatabasePool,
}

impl EstRepository {
    /// Create a new EST repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    // =======================
    // Enrollment Operations
    // =======================

    /// Create a new enrollment
    pub async fn create_enrollment(
        &self,
        client_identifier: &str,
        enrollment_type: &str,
        csr_der: Vec<u8>,
        status: &str,
    ) -> Result<EstEnrollment> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let enrollment = sqlx::query_as::<_, EstEnrollment>(
            r#"
            INSERT INTO est_enrollments (
                id, client_identifier, enrollment_type, csr_der,
                status, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(client_identifier)
        .bind(enrollment_type)
        .bind(csr_der)
        .bind(status)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(enrollment)
    }

    /// Find enrollment by ID
    pub async fn find_enrollment(&self, id: Uuid) -> Result<Option<EstEnrollment>> {
        let enrollment =
            sqlx::query_as::<_, EstEnrollment>("SELECT * FROM est_enrollments WHERE id = $1")
                .bind(id)
                .fetch_optional(self.pool.pool())
                .await?;

        Ok(enrollment)
    }

    /// List enrollments by client
    pub async fn list_enrollments_by_client(
        &self,
        client_identifier: &str,
    ) -> Result<Vec<EstEnrollment>> {
        let enrollments = sqlx::query_as::<_, EstEnrollment>(
            "SELECT * FROM est_enrollments WHERE client_identifier = $1 ORDER BY created_at DESC",
        )
        .bind(client_identifier)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(enrollments)
    }

    /// Update enrollment status
    pub async fn update_enrollment_status(&self, id: Uuid, status: &str) -> Result<EstEnrollment> {
        let now = Utc::now();

        let enrollment = sqlx::query_as::<_, EstEnrollment>(
            r#"
            UPDATE est_enrollments
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
        )
        .bind(status)
        .bind(now)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(enrollment)
    }

    /// Update enrollment with certificate and profile
    ///
    /// RFC 7030 §4.2 - Update enrollment after certificate issuance
    pub async fn update_enrollment_certificate(
        &self,
        id: Uuid,
        certificate_id: Uuid,
        profile_name: &str,
    ) -> Result<EstEnrollment> {
        let now = Utc::now();

        let enrollment = sqlx::query_as::<_, EstEnrollment>(
            r#"
            UPDATE est_enrollments
            SET certificate_id = $1, profile_name = $2, updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
        )
        .bind(certificate_id)
        .bind(profile_name)
        .bind(now)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(enrollment)
    }

    /// Atomically record the issued certificate AND mark the enrollment "issued".
    ///
    /// RFC 7030 §4.2 - post-issuance bookkeeping. A single UPDATE avoids the
    /// inconsistent intermediate state (certificate_id set but status not
    /// "issued") that two separate statements could leave on a partial failure
    /// (L2). NIST 800-53: SI-17 (consistent state).
    pub async fn mark_enrollment_issued(
        &self,
        id: Uuid,
        certificate_id: Uuid,
        profile_name: &str,
    ) -> Result<EstEnrollment> {
        let now = Utc::now();

        let enrollment = sqlx::query_as::<_, EstEnrollment>(
            r#"
            UPDATE est_enrollments
            SET certificate_id = $1, profile_name = $2, status = 'issued', updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
        )
        .bind(certificate_id)
        .bind(profile_name)
        .bind(now)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(enrollment)
    }

    // ===========================
    // Per-account Allowed Identities (allow-list policy)
    // ===========================

    /// List the identities (CN / SAN values) an account is permitted to enroll
    /// for under the "account allow-list" identity policy.
    ///
    /// NIST 800-53: AC-3 / AC-6 - access enforcement / least privilege.
    pub async fn list_allowed_identities(&self, account_username: &str) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT allowed_identity
            FROM est_account_identities
            WHERE account_username = $1
            "#,
        )
        .bind(account_username)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(rows)
    }

    /// Grant an account permission to enroll for `identity` (CN or SAN value).
    /// Idempotent: re-adding an existing entry is a no-op.
    pub async fn add_allowed_identity(&self, account_username: &str, identity: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO est_account_identities (account_username, allowed_identity)
            VALUES ($1, $2)
            ON CONFLICT (account_username, allowed_identity) DO NOTHING
            "#,
        )
        .bind(account_username)
        .bind(identity)
        .execute(self.pool.pool())
        .await?;

        Ok(())
    }

    /// Revoke an account's permission to enroll for `identity`.
    ///
    /// Returns `true` if a row was actually deleted, `false` if no matching
    /// (account, identity) grant existed — so callers can distinguish a real
    /// revocation from a no-op and avoid auditing a revocation that did not
    /// happen. NIST 800-53: AU-3 (accurate audit outcome).
    pub async fn remove_allowed_identity(
        &self,
        account_username: &str,
        identity: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM est_account_identities
            WHERE account_username = $1 AND allowed_identity = $2
            "#,
        )
        .bind(account_username)
        .bind(identity)
        .execute(self.pool.pool())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ==============================
    // EST Enrollment Token Operations
    // ==============================

    /// Store a freshly minted single-use enrollment token (only its SHA-256 hash
    /// is persisted; the plaintext is returned to the operator once).
    ///
    /// NIST 800-53: IA-5 (authenticator management); NIAP PP-CA: FMT_MTD.1
    pub async fn create_enrollment_token(
        &self,
        id: Uuid,
        token_hash: &[u8],
        identity: &str,
        profile: Option<&str>,
        created_by: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO est_enrollment_tokens
                (id, token_hash, identity, profile, created_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(id)
        .bind(token_hash)
        .bind(identity)
        .bind(profile)
        .bind(created_by)
        .bind(expires_at)
        .execute(self.pool.pool())
        .await?;

        Ok(())
    }

    /// Look up a live (unused, unexpired) enrollment token by its hash, returning
    /// `(token_id, bound_identity, expires_at)`. Returns `None` if the token is
    /// unknown, already used, or expired.
    pub async fn find_live_enrollment_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<(Uuid, String, DateTime<Utc>)>> {
        let row: Option<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT id, identity, expires_at
            FROM est_enrollment_tokens
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(row)
    }

    /// Atomically mark a token consumed (single-use), keyed by its row id (the
    /// id is carried on the authenticated principal, so no token re-hashing is
    /// needed). Returns `true` only if this call transitioned an unused token to
    /// used, so concurrent enrollments race safely — at most one wins.
    /// NIST 800-53: AU-3 (accurate outcome).
    pub async fn consume_enrollment_token(
        &self,
        id: Uuid,
        used_by_cert: Option<Uuid>,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE est_enrollment_tokens
            SET used_at = now(), used_by_cert = $2
            WHERE id = $1 AND used_at IS NULL
            "#,
        )
        .bind(id)
        .bind(used_by_cert)
        .execute(self.pool.pool())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List recently minted enrollment tokens (most recent first), for operator
    /// review. Never returns the token itself (only its hash is stored); callers
    /// derive a status from `used_at`/`used_by_cert`/`expires_at`.
    pub async fn list_enrollment_tokens(&self, limit: i64) -> Result<Vec<EstEnrollmentTokenRow>> {
        let rows = sqlx::query_as::<_, EstEnrollmentTokenRow>(
            r#"
            SELECT id, identity, created_by, created_at, expires_at, used_at, used_by_cert
            FROM est_enrollment_tokens
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(rows)
    }

    /// Revoke a live enrollment token before it is used, by marking it consumed
    /// with no associated certificate (so it derives as "revoked", distinct from
    /// "used"). Returns `true` only if a live token was actually revoked.
    /// NIST 800-53: IA-5 (authenticator revocation), AU-3 (accurate outcome).
    pub async fn revoke_enrollment_token(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE est_enrollment_tokens
            SET used_at = now()
            WHERE id = $1 AND used_at IS NULL
            "#,
        )
        .bind(id)
        .execute(self.pool.pool())
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ===========================
    // Authorized Client Operations
    // ===========================

    /// Create an authorized client
    pub async fn create_authorized_client(
        &self,
        client_identifier: &str,
        client_certificate_der: Vec<u8>,
        authorized_profiles: Vec<Uuid>,
        active: bool,
    ) -> Result<EstClient> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let client = sqlx::query_as::<_, EstClient>(
            r#"
            INSERT INTO est_clients (
                id, client_identifier, client_certificate_der,
                authorized_profiles, active, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(client_identifier)
        .bind(client_certificate_der)
        .bind(&authorized_profiles)
        .bind(active)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(client)
    }

    /// Find authorized client
    pub async fn find_authorized_client(
        &self,
        client_identifier: &str,
    ) -> Result<Option<EstClient>> {
        let client = sqlx::query_as::<_, EstClient>(
            "SELECT * FROM est_clients WHERE client_identifier = $1",
        )
        .bind(client_identifier)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(client)
    }

    /// List all authorized clients
    pub async fn list_authorized_clients(&self, active_only: bool) -> Result<Vec<EstClient>> {
        let query = if active_only {
            "SELECT * FROM est_clients WHERE active = true ORDER BY client_identifier"
        } else {
            "SELECT * FROM est_clients ORDER BY client_identifier"
        };

        let clients = sqlx::query_as::<_, EstClient>(query)
            .fetch_all(self.pool.pool())
            .await?;

        Ok(clients)
    }

    /// Update authorized client status
    pub async fn update_client_status(
        &self,
        client_identifier: &str,
        active: bool,
    ) -> Result<EstClient> {
        let now = Utc::now();

        let client = sqlx::query_as::<_, EstClient>(
            r#"
            UPDATE est_clients
            SET active = $1, updated_at = $2
            WHERE client_identifier = $3
            RETURNING *
            "#,
        )
        .bind(active)
        .bind(now)
        .bind(client_identifier)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(client)
    }
}
