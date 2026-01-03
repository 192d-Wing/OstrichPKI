//! KRA repository implementation
//!
//! Key Recovery Authority repository

use crate::{
    DatabasePool, Result,
    models::{EscrowedKey, RecoveryAgent, RecoveryRequest, RecoveryShare},
};
use chrono::Utc;
use uuid::Uuid;

/// KRA Repository
///
/// Manages escrowed keys, recovery agents, requests, and shares
#[derive(Clone)]
pub struct KraRepository {
    pool: DatabasePool,
}

impl KraRepository {
    /// Create a new KRA repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    // ========================
    // Escrowed Key Operations
    // ========================

    /// Create an escrowed key
    pub async fn create_escrowed_key(
        &self,
        certificate_id: Uuid,
        wrapped_key: Vec<u8>,
        wrapping_key_id: Uuid,
        key_type: &str,
        algorithm: &str,
    ) -> Result<EscrowedKey> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let key = sqlx::query_as::<_, EscrowedKey>(
            r#"
            INSERT INTO escrowed_keys (
                id, certificate_id, wrapped_key, wrapping_key_id,
                key_type, algorithm, escrow_time, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(certificate_id)
        .bind(wrapped_key)
        .bind(wrapping_key_id)
        .bind(key_type)
        .bind(algorithm)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(key)
    }

    /// Find escrowed key by ID
    pub async fn find_escrowed_key(&self, id: Uuid) -> Result<Option<EscrowedKey>> {
        let key = sqlx::query_as::<_, EscrowedKey>("SELECT * FROM escrowed_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(key)
    }

    /// Find escrowed key by certificate ID
    pub async fn find_escrowed_key_by_cert(
        &self,
        certificate_id: Uuid,
    ) -> Result<Option<EscrowedKey>> {
        let key = sqlx::query_as::<_, EscrowedKey>(
            "SELECT * FROM escrowed_keys WHERE certificate_id = $1",
        )
        .bind(certificate_id)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(key)
    }

    // ===========================
    // Recovery Agent Operations
    // ===========================

    /// Create a recovery agent
    pub async fn create_recovery_agent(
        &self,
        name: &str,
        email: &str,
        public_key_der: Vec<u8>,
        active: bool,
    ) -> Result<RecoveryAgent> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let agent = sqlx::query_as::<_, RecoveryAgent>(
            r#"
            INSERT INTO recovery_agents (
                id, name, email, public_key_der, active,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(email)
        .bind(public_key_der)
        .bind(active)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(agent)
    }

    /// Find recovery agent by ID
    pub async fn find_recovery_agent(&self, id: Uuid) -> Result<Option<RecoveryAgent>> {
        let agent =
            sqlx::query_as::<_, RecoveryAgent>("SELECT * FROM recovery_agents WHERE id = $1")
                .bind(id)
                .fetch_optional(self.pool.pool())
                .await?;

        Ok(agent)
    }

    /// List active recovery agents
    pub async fn list_active_recovery_agents(&self) -> Result<Vec<RecoveryAgent>> {
        let agents = sqlx::query_as::<_, RecoveryAgent>(
            "SELECT * FROM recovery_agents WHERE active = true ORDER BY name",
        )
        .fetch_all(self.pool.pool())
        .await?;

        Ok(agents)
    }

    /// Update recovery agent status
    pub async fn update_agent_status(&self, id: Uuid, active: bool) -> Result<RecoveryAgent> {
        let now = Utc::now();

        let agent = sqlx::query_as::<_, RecoveryAgent>(
            r#"
            UPDATE recovery_agents
            SET active = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
        )
        .bind(active)
        .bind(now)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(agent)
    }

    // ============================
    // Recovery Request Operations
    // ============================

    /// Create a recovery request
    pub async fn create_recovery_request(
        &self,
        escrowed_key_id: Uuid,
        requestor: &str,
        justification: &str,
        required_shares: i32,
        total_agents: i32,
    ) -> Result<RecoveryRequest> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let request = sqlx::query_as::<_, RecoveryRequest>(
            r#"
            INSERT INTO recovery_requests (
                id, escrowed_key_id, requestor, justification,
                status, required_shares, total_agents, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(escrowed_key_id)
        .bind(requestor)
        .bind(justification)
        .bind("pending")
        .bind(required_shares)
        .bind(total_agents)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(request)
    }

    /// Find recovery request by ID
    pub async fn find_recovery_request(&self, id: Uuid) -> Result<Option<RecoveryRequest>> {
        let request =
            sqlx::query_as::<_, RecoveryRequest>("SELECT * FROM recovery_requests WHERE id = $1")
                .bind(id)
                .fetch_optional(self.pool.pool())
                .await?;

        Ok(request)
    }

    /// List recovery requests by status
    pub async fn list_recovery_requests_by_status(
        &self,
        status: &str,
    ) -> Result<Vec<RecoveryRequest>> {
        let requests = sqlx::query_as::<_, RecoveryRequest>(
            "SELECT * FROM recovery_requests WHERE status = $1 ORDER BY created_at DESC",
        )
        .bind(status)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(requests)
    }

    /// Update recovery request status
    pub async fn update_recovery_request_status(
        &self,
        id: Uuid,
        status: &str,
    ) -> Result<RecoveryRequest> {
        let now = Utc::now();

        let request = sqlx::query_as::<_, RecoveryRequest>(
            r#"
            UPDATE recovery_requests
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

        Ok(request)
    }

    // ==========================
    // Recovery Share Operations
    // ==========================

    /// Create a recovery share
    pub async fn create_recovery_share(
        &self,
        recovery_request_id: Uuid,
        agent_id: Uuid,
        encrypted_share: Vec<u8>,
    ) -> Result<RecoveryShare> {
        let id = Uuid::new_v4();

        let share = sqlx::query_as::<_, RecoveryShare>(
            r#"
            INSERT INTO recovery_shares (
                id, recovery_request_id, agent_id, encrypted_share
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(recovery_request_id)
        .bind(agent_id)
        .bind(encrypted_share)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(share)
    }

    /// Submit a recovery share
    pub async fn submit_recovery_share(&self, id: Uuid) -> Result<RecoveryShare> {
        let now = Utc::now();

        let share = sqlx::query_as::<_, RecoveryShare>(
            r#"
            UPDATE recovery_shares
            SET submitted_at = $1
            WHERE id = $2
            RETURNING *
            "#,
        )
        .bind(now)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(share)
    }

    /// List shares for a recovery request
    pub async fn list_recovery_shares(
        &self,
        recovery_request_id: Uuid,
    ) -> Result<Vec<RecoveryShare>> {
        let shares = sqlx::query_as::<_, RecoveryShare>(
            "SELECT * FROM recovery_shares WHERE recovery_request_id = $1",
        )
        .bind(recovery_request_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(shares)
    }

    /// Count submitted shares for a recovery request
    pub async fn count_submitted_shares(&self, recovery_request_id: Uuid) -> Result<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM recovery_shares WHERE recovery_request_id = $1 AND submitted_at IS NOT NULL"
        )
        .bind(recovery_request_id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(count.0)
    }
}
