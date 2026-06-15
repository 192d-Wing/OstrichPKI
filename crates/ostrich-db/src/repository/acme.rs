//! ACME repository implementation
//!
//! RFC 8555: Automatic Certificate Management Environment

use crate::{
    DatabasePool, Result,
    models::{AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeNonce, AcmeOrder},
};
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// ACME Repository
///
/// Manages ACME accounts, orders, authorizations, challenges, and nonces
#[derive(Clone)]
pub struct AcmeRepository {
    pool: DatabasePool,
}

impl AcmeRepository {
    /// Create a new ACME repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    // ===================
    // Account Operations
    // ===================

    /// Create a new ACME account
    pub async fn create_account(
        &self,
        account_id: &str,
        jwk_thumbprint: &str,
        public_key_jwk: JsonValue,
        contact: Vec<String>,
        status: &str,
        tos_agreed: bool,
    ) -> Result<AcmeAccount> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let account = sqlx::query_as::<_, AcmeAccount>(
            r#"
            INSERT INTO acme_accounts (
                id, account_id, jwk_thumbprint, public_key_jwk, contact,
                status, terms_of_service_agreed, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(account_id)
        .bind(jwk_thumbprint)
        .bind(public_key_jwk)
        .bind(&contact)
        .bind(status)
        .bind(tos_agreed)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(account)
    }

    /// Find account by JWK thumbprint
    pub async fn find_account_by_jwk(&self, jwk_thumbprint: &str) -> Result<Option<AcmeAccount>> {
        let account = sqlx::query_as::<_, AcmeAccount>(
            "SELECT * FROM acme_accounts WHERE jwk_thumbprint = $1",
        )
        .bind(jwk_thumbprint)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(account)
    }

    /// Find account by account ID
    pub async fn find_account_by_id(&self, account_id: &str) -> Result<Option<AcmeAccount>> {
        let account =
            sqlx::query_as::<_, AcmeAccount>("SELECT * FROM acme_accounts WHERE account_id = $1")
                .bind(account_id)
                .fetch_optional(self.pool.pool())
                .await?;

        Ok(account)
    }

    /// Find account by primary key (used when walking FK chains:
    /// challenge -> authorization -> order -> account)
    pub async fn find_account_by_uuid(&self, id: Uuid) -> Result<Option<AcmeAccount>> {
        let account = sqlx::query_as::<_, AcmeAccount>("SELECT * FROM acme_accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;
        Ok(account)
    }

    /// Find order by primary key
    pub async fn find_order_by_uuid(&self, id: Uuid) -> Result<Option<AcmeOrder>> {
        let order = sqlx::query_as::<_, AcmeOrder>("SELECT * FROM acme_orders WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;
        Ok(order)
    }

    /// Find authorization by primary key
    pub async fn find_authorization_by_uuid(&self, id: Uuid) -> Result<Option<AcmeAuthorization>> {
        let authz = sqlx::query_as::<_, AcmeAuthorization>(
            "SELECT * FROM acme_authorizations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool.pool())
        .await?;
        Ok(authz)
    }

    /// Update account contact and status
    pub async fn update_account(
        &self,
        account_id: &str,
        contact: Option<Vec<String>>,
        status: Option<&str>,
    ) -> Result<AcmeAccount> {
        let now = Utc::now();

        let mut query = String::from("UPDATE acme_accounts SET updated_at = $1");
        let mut param_num = 2;

        if contact.is_some() {
            query.push_str(&format!(", contact = ${}", param_num));
            param_num += 1;
        }

        if status.is_some() {
            query.push_str(&format!(", status = ${}", param_num));
            param_num += 1;
        }

        query.push_str(&format!(" WHERE account_id = ${} RETURNING *", param_num));

        let mut q = sqlx::query_as::<_, AcmeAccount>(&query).bind(now);

        if let Some(c) = contact {
            q = q.bind(c);
        }

        if let Some(s) = status {
            q = q.bind(s);
        }

        let account = q.bind(account_id).fetch_one(self.pool.pool()).await?;

        Ok(account)
    }

    // ================
    // Order Operations
    // ================

    /// Create a new ACME order
    #[allow(clippy::too_many_arguments)]
    pub async fn create_order(
        &self,
        order_id: &str,
        account_id: Uuid,
        status: &str,
        identifiers: JsonValue,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
        expires: DateTime<Utc>,
    ) -> Result<AcmeOrder> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let order = sqlx::query_as::<_, AcmeOrder>(
            r#"
            INSERT INTO acme_orders (
                id, order_id, account_id, status, identifiers,
                not_before, not_after, expires, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(order_id)
        .bind(account_id)
        .bind(status)
        .bind(identifiers)
        .bind(not_before)
        .bind(not_after)
        .bind(expires)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(order)
    }

    /// Find order by order ID
    pub async fn find_order_by_id(&self, order_id: &str) -> Result<Option<AcmeOrder>> {
        let order = sqlx::query_as::<_, AcmeOrder>("SELECT * FROM acme_orders WHERE order_id = $1")
            .bind(order_id)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(order)
    }

    /// List orders by account
    pub async fn list_orders_by_account(&self, account_id: Uuid) -> Result<Vec<AcmeOrder>> {
        let orders = sqlx::query_as::<_, AcmeOrder>(
            "SELECT * FROM acme_orders WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(orders)
    }

    /// Update order status
    pub async fn update_order_status(&self, order_id: Uuid, status: &str) -> Result<AcmeOrder> {
        let now = Utc::now();

        let order = sqlx::query_as::<_, AcmeOrder>(
            r#"
            UPDATE acme_orders
            SET status = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
        )
        .bind(status)
        .bind(now)
        .bind(order_id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(order)
    }

    /// Update order with certificate and CSR
    ///
    /// RFC 8555 §7.4 - Finalize order with CSR and resulting certificate
    pub async fn update_order_certificate(
        &self,
        order_id: Uuid,
        certificate_id: Uuid,
        csr_der: &[u8],
    ) -> Result<AcmeOrder> {
        let now = Utc::now();

        let order = sqlx::query_as::<_, AcmeOrder>(
            r#"
            UPDATE acme_orders
            SET certificate_id = $1, csr_der = $2, updated_at = $3
            WHERE id = $4
            RETURNING *
            "#,
        )
        .bind(certificate_id)
        .bind(csr_der)
        .bind(now)
        .bind(order_id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(order)
    }

    // ==========================
    // Authorization Operations
    // ==========================

    /// Create a new ACME authorization
    #[allow(clippy::too_many_arguments)]
    pub async fn create_authorization(
        &self,
        authorization_id: &str,
        order_id: Uuid,
        identifier_type: &str,
        identifier_value: &str,
        status: &str,
        expires: DateTime<Utc>,
        wildcard: bool,
    ) -> Result<AcmeAuthorization> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let authz = sqlx::query_as::<_, AcmeAuthorization>(
            r#"
            INSERT INTO acme_authorizations (
                id, authorization_id, order_id, identifier_type, identifier_value,
                status, expires, wildcard, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(authorization_id)
        .bind(order_id)
        .bind(identifier_type)
        .bind(identifier_value)
        .bind(status)
        .bind(expires)
        .bind(wildcard)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(authz)
    }

    /// Find authorization by ID
    pub async fn find_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AcmeAuthorization>> {
        let authz = sqlx::query_as::<_, AcmeAuthorization>(
            "SELECT * FROM acme_authorizations WHERE authorization_id = $1",
        )
        .bind(authorization_id)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(authz)
    }

    /// List authorizations by order
    pub async fn list_authorizations_by_order(
        &self,
        order_id: Uuid,
    ) -> Result<Vec<AcmeAuthorization>> {
        let authzs = sqlx::query_as::<_, AcmeAuthorization>(
            "SELECT * FROM acme_authorizations WHERE order_id = $1 ORDER BY created_at",
        )
        .bind(order_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(authzs)
    }

    /// Update authorization status
    pub async fn update_authorization_status(
        &self,
        authorization_id: &str,
        status: &str,
    ) -> Result<AcmeAuthorization> {
        let now = Utc::now();

        let authz = sqlx::query_as::<_, AcmeAuthorization>(
            r#"
            UPDATE acme_authorizations
            SET status = $1, updated_at = $2
            WHERE authorization_id = $3
            RETURNING *
            "#,
        )
        .bind(status)
        .bind(now)
        .bind(authorization_id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(authz)
    }

    // =====================
    // Challenge Operations
    // =====================

    /// Create a new ACME challenge
    pub async fn create_challenge(
        &self,
        challenge_id: &str,
        authorization_id: Uuid,
        challenge_type: &str,
        token: &str,
        status: &str,
    ) -> Result<AcmeChallenge> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let challenge = sqlx::query_as::<_, AcmeChallenge>(
            r#"
            INSERT INTO acme_challenges (
                id, challenge_id, authorization_id, challenge_type, token,
                status, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(challenge_id)
        .bind(authorization_id)
        .bind(challenge_type)
        .bind(token)
        .bind(status)
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(challenge)
    }

    /// Find challenge by ID
    pub async fn find_challenge_by_id(&self, challenge_id: &str) -> Result<Option<AcmeChallenge>> {
        let challenge = sqlx::query_as::<_, AcmeChallenge>(
            "SELECT * FROM acme_challenges WHERE challenge_id = $1",
        )
        .bind(challenge_id)
        .fetch_optional(self.pool.pool())
        .await?;

        Ok(challenge)
    }

    /// List challenges by authorization
    pub async fn list_challenges_by_authorization(
        &self,
        authorization_id: Uuid,
    ) -> Result<Vec<AcmeChallenge>> {
        let challenges = sqlx::query_as::<_, AcmeChallenge>(
            "SELECT * FROM acme_challenges WHERE authorization_id = $1 ORDER BY created_at",
        )
        .bind(authorization_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(challenges)
    }

    /// Update challenge status
    pub async fn update_challenge_status(
        &self,
        challenge_id: &str,
        status: &str,
        validated_at: Option<DateTime<Utc>>,
        error_detail: Option<JsonValue>,
    ) -> Result<AcmeChallenge> {
        let now = Utc::now();

        let challenge = sqlx::query_as::<_, AcmeChallenge>(
            r#"
            UPDATE acme_challenges
            SET status = $1, validated_at = $2, error_detail = $3, updated_at = $4
            WHERE challenge_id = $5
            RETURNING *
            "#,
        )
        .bind(status)
        .bind(validated_at)
        .bind(error_detail)
        .bind(now)
        .bind(challenge_id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(challenge)
    }

    // =================
    // Nonce Operations
    // =================

    /// Create a new nonce
    pub async fn create_nonce(&self, nonce: &str, expires_at: DateTime<Utc>) -> Result<AcmeNonce> {
        let now = Utc::now();

        let nonce_record = sqlx::query_as::<_, AcmeNonce>(
            r#"
            INSERT INTO acme_nonces (nonce, created_at, expires_at)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(nonce)
        .bind(now)
        .bind(expires_at)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(nonce_record)
    }

    /// Consume a nonce (verify it exists and delete it)
    pub async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM acme_nonces WHERE nonce = $1 AND expires_at > NOW()")
            .bind(nonce)
            .execute(self.pool.pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Clean up expired nonces
    pub async fn cleanup_expired_nonces(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM acme_nonces WHERE expires_at <= NOW()")
            .execute(self.pool.pool())
            .await?;

        Ok(result.rows_affected())
    }
}
