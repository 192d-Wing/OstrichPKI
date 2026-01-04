//! EST repository implementation
//!
//! RFC 7030: Enrollment over Secure Transport

use crate::{
    DatabasePool, Result,
    models::{EstClient, EstEnrollment},
};
use chrono::Utc;
use uuid::Uuid;

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
    pub async fn update_enrollment_status(
        &self,
        id: Uuid,
        status: &str,
    ) -> Result<EstEnrollment> {
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
