//! SCMS repository implementation
//!
//! Smartcard Management System repository

use crate::{
    DatabasePool, Result,
    models::{Token, TokenEvent, TokenKey, TokenModel},
};
use chrono::Utc;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// SCMS Repository
///
/// Manages token models, tokens, keys, and events
#[derive(Clone)]
pub struct ScmsRepository {
    pool: DatabasePool,
}

impl ScmsRepository {
    /// Create a new SCMS repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    // ====================
    // Token Model Operations
    // ====================

    /// Create a new token model
    ///
    /// Phase 1c: now persists `firmware_version`, `key_capacity`,
    /// `cert_capacity`, `pkcs11_support` (migration 00005).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_token_model(
        &self,
        manufacturer: &str,
        model: &str,
        atr: Option<&str>,
        supported_key_types: Vec<String>,
        max_pin_length: i32,
        min_pin_length: i32,
        supports_puk: bool,
        firmware_version: Option<&str>,
        key_capacity: Option<i32>,
        cert_capacity: Option<i32>,
        pkcs11_support: bool,
    ) -> Result<TokenModel> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let token_model = sqlx::query_as::<_, TokenModel>(
            r#"
            INSERT INTO token_models (
                id, manufacturer, model, atr, supported_key_types,
                max_pin_length, min_pin_length, supports_puk,
                firmware_version, key_capacity, cert_capacity, pkcs11_support,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(manufacturer)
        .bind(model)
        .bind(atr)
        .bind(&supported_key_types)
        .bind(max_pin_length)
        .bind(min_pin_length)
        .bind(supports_puk)
        .bind(firmware_version)
        .bind(key_capacity)
        .bind(cert_capacity)
        .bind(pkcs11_support)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(token_model)
    }

    /// List all token models
    pub async fn list_token_models(&self) -> Result<Vec<TokenModel>> {
        let models = sqlx::query_as::<_, TokenModel>(
            "SELECT * FROM token_models ORDER BY manufacturer, model",
        )
        .fetch_all(self.pool.pool())
        .await?;

        Ok(models)
    }

    /// Find token model by ID
    pub async fn find_token_model(&self, id: Uuid) -> Result<Option<TokenModel>> {
        let model = sqlx::query_as::<_, TokenModel>("SELECT * FROM token_models WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(model)
    }

    // ================
    // Token Operations
    // ================

    /// Create a new token
    ///
    /// Phase 1c: now accepts an optional display label persisted via
    /// migration 00005. The SO-PIN counter and the lifecycle timestamps
    /// (`initialized_at`, `expires_at`) start at the column defaults and are
    /// populated by `update_token_lifecycle` once the operator initializes /
    /// expires the token.
    pub async fn create_token(
        &self,
        serial_number: &str,
        token_model_id: Uuid,
        status: &str,
        label: Option<&str>,
    ) -> Result<Token> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let token = sqlx::query_as::<_, Token>(
            r#"
            INSERT INTO tokens (
                id, serial_number, token_model_id, status, label,
                pin_attempts_remaining, puk_attempts_remaining,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(serial_number)
        .bind(token_model_id)
        .bind(status)
        .bind(label)
        .bind(3) // Default PIN attempts
        .bind(10) // Default PUK attempts
        .bind(now)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(token)
    }

    /// Update lifecycle timestamps on a token.
    ///
    /// Used by SCMS handlers to record `initialized_at` and `expires_at`
    /// transitions atomically with the status change. Either field set to
    /// `Some(None)` is a sentinel meaning "leave alone"; pass `Some(Some(ts))`
    /// to write a value.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FPT_STM.1 - reliable timestamps for management functions
    /// - NIAP PP-CA: FMT_SMF.1 - lifecycle state transitions
    pub async fn update_token_lifecycle(
        &self,
        id: Uuid,
        initialized_at: Option<Option<chrono::DateTime<Utc>>>,
        expires_at: Option<Option<chrono::DateTime<Utc>>>,
    ) -> Result<Token> {
        let now = Utc::now();
        let mut query = String::from("UPDATE tokens SET updated_at = $1");
        let mut param_num = 2;

        if initialized_at.is_some() {
            query.push_str(&format!(", initialized_at = ${}", param_num));
            param_num += 1;
        }

        if expires_at.is_some() {
            query.push_str(&format!(", expires_at = ${}", param_num));
            param_num += 1;
        }

        query.push_str(&format!(" WHERE id = ${} RETURNING *", param_num));

        let mut q = sqlx::query_as::<_, Token>(sqlx::AssertSqlSafe(query.as_str())).bind(now);
        if let Some(value) = initialized_at {
            q = q.bind(value);
        }
        if let Some(value) = expires_at {
            q = q.bind(value);
        }

        Ok(q.bind(id).fetch_one(self.pool.pool()).await?)
    }

    /// Update the SO-PIN retry counter independently of the User PIN counter.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FIA_AFL.1 - SO-PIN failure counter is distinct from
    ///   the User PIN counter; tracked per FMT_SMR.1 role separation.
    pub async fn update_token_so_pin_attempts(
        &self,
        id: Uuid,
        so_pin_attempts: i32,
    ) -> Result<Token> {
        let now = Utc::now();
        let token = sqlx::query_as::<_, Token>(
            r#"
            UPDATE tokens
            SET updated_at = $1, so_pin_attempts_remaining = $2
            WHERE id = $3
            RETURNING *
            "#,
        )
        .bind(now)
        .bind(so_pin_attempts)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(token)
    }

    /// Update the operator-facing label on a token.
    pub async fn update_token_label(&self, id: Uuid, label: Option<&str>) -> Result<Token> {
        let now = Utc::now();
        let token = sqlx::query_as::<_, Token>(
            r#"
            UPDATE tokens
            SET updated_at = $1, label = $2
            WHERE id = $3
            RETURNING *
            "#,
        )
        .bind(now)
        .bind(label)
        .bind(id)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(token)
    }

    /// Find token by ID
    pub async fn find_token(&self, id: Uuid) -> Result<Option<Token>> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(token)
    }

    /// Find token by serial number
    pub async fn find_token_by_serial(&self, serial: &str) -> Result<Option<Token>> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE serial_number = $1")
            .bind(serial)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(token)
    }

    /// List tokens with optional filters
    pub async fn list_tokens(
        &self,
        status: Option<&str>,
        assigned_to: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Token>> {
        let mut query = String::from("SELECT * FROM tokens WHERE 1=1");
        let mut param_count = 0;

        if status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }

        if assigned_to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assigned_to = ${}", param_count));
        }

        query.push_str(" ORDER BY created_at DESC");

        if limit.is_some() {
            param_count += 1;
            query.push_str(&format!(" LIMIT ${}", param_count));
        }

        if offset.is_some() {
            param_count += 1;
            query.push_str(&format!(" OFFSET ${}", param_count));
        }

        let mut q = sqlx::query_as::<_, Token>(sqlx::AssertSqlSafe(query.as_str()));

        if let Some(s) = status {
            q = q.bind(s);
        }

        if let Some(a) = assigned_to {
            q = q.bind(a);
        }

        if let Some(l) = limit {
            q = q.bind(l);
        }

        if let Some(o) = offset {
            q = q.bind(o);
        }

        let tokens = q.fetch_all(self.pool.pool()).await?;

        Ok(tokens)
    }

    /// Update token status and metadata
    pub async fn update_token(
        &self,
        id: Uuid,
        status: Option<&str>,
        assigned_to: Option<&str>,
        pin_attempts: Option<i32>,
        puk_attempts: Option<i32>,
    ) -> Result<Token> {
        let now = Utc::now();

        let mut query = String::from("UPDATE tokens SET updated_at = $1");
        let mut param_num = 2;

        if status.is_some() {
            query.push_str(&format!(", status = ${}", param_num));
            param_num += 1;
        }

        if assigned_to.is_some() {
            query.push_str(&format!(", assigned_to = ${}", param_num));
            param_num += 1;
        }

        if pin_attempts.is_some() {
            query.push_str(&format!(", pin_attempts_remaining = ${}", param_num));
            param_num += 1;
        }

        if puk_attempts.is_some() {
            query.push_str(&format!(", puk_attempts_remaining = ${}", param_num));
            param_num += 1;
        }

        query.push_str(&format!(" WHERE id = ${} RETURNING *", param_num));

        let mut q = sqlx::query_as::<_, Token>(sqlx::AssertSqlSafe(query.as_str())).bind(now);

        if let Some(s) = status {
            q = q.bind(s);
        }

        if let Some(a) = assigned_to {
            q = q.bind(a);
        }

        if let Some(p) = pin_attempts {
            q = q.bind(p);
        }

        if let Some(pk) = puk_attempts {
            q = q.bind(pk);
        }

        let token = q.bind(id).fetch_one(self.pool.pool()).await?;

        Ok(token)
    }

    /// Delete a token
    pub async fn delete_token(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE id = $1")
            .bind(id)
            .execute(self.pool.pool())
            .await?;

        Ok(())
    }

    // ==================
    // Token Key Operations
    // ==================

    /// Create a new token key
    ///
    /// Phase 1c: persists `key_size` and `usage` flags via migration 00005.
    /// `usage` strings should be one of the X.509 KeyUsage flag names
    /// (RFC 5280 §4.2.1.3): `digital_signature`, `non_repudiation`,
    /// `key_encipherment`, `data_encipherment`, `key_agreement`,
    /// `key_cert_sign`, `crl_sign`, `encipher_only`, `decipher_only`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_token_key(
        &self,
        token_id: Uuid,
        label: &str,
        key_type: &str,
        algorithm: &str,
        key_size: Option<i32>,
        usage: Vec<String>,
        certificate_id: Option<Uuid>,
    ) -> Result<TokenKey> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let key = sqlx::query_as::<_, TokenKey>(
            r#"
            INSERT INTO token_keys (
                id, token_id, label, key_type, algorithm,
                key_size, usage, certificate_id, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(token_id)
        .bind(label)
        .bind(key_type)
        .bind(algorithm)
        .bind(key_size)
        .bind(&usage)
        .bind(certificate_id)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(key)
    }

    /// List keys on a token
    pub async fn list_token_keys(&self, token_id: Uuid) -> Result<Vec<TokenKey>> {
        let keys = sqlx::query_as::<_, TokenKey>(
            "SELECT * FROM token_keys WHERE token_id = $1 ORDER BY created_at",
        )
        .bind(token_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(keys)
    }

    /// Find a token key
    pub async fn find_token_key(&self, id: Uuid) -> Result<Option<TokenKey>> {
        let key = sqlx::query_as::<_, TokenKey>("SELECT * FROM token_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;

        Ok(key)
    }

    /// Delete a token key
    pub async fn delete_token_key(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM token_keys WHERE id = $1")
            .bind(id)
            .execute(self.pool.pool())
            .await?;

        Ok(())
    }

    // ====================
    // Token Event Operations
    // ====================

    /// Record a token event
    pub async fn record_token_event(
        &self,
        token_id: Uuid,
        event_type: &str,
        actor: &str,
        details: Option<JsonValue>,
    ) -> Result<TokenEvent> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let event = sqlx::query_as::<_, TokenEvent>(
            r#"
            INSERT INTO token_events (
                id, token_id, event_type, actor, details, timestamp
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(token_id)
        .bind(event_type)
        .bind(actor)
        .bind(details)
        .bind(now)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(event)
    }

    /// List events for a token
    pub async fn list_token_events(&self, token_id: Uuid) -> Result<Vec<TokenEvent>> {
        let events = sqlx::query_as::<_, TokenEvent>(
            "SELECT * FROM token_events WHERE token_id = $1 ORDER BY timestamp DESC",
        )
        .bind(token_id)
        .fetch_all(self.pool.pool())
        .await?;

        Ok(events)
    }
}
