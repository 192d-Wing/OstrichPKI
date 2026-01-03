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
    ) -> Result<TokenModel> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let token_model = sqlx::query_as::<_, TokenModel>(
            r#"
            INSERT INTO token_models (
                id, manufacturer, model, atr, supported_key_types,
                max_pin_length, min_pin_length, supports_puk, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    pub async fn create_token(
        &self,
        serial_number: &str,
        token_model_id: Uuid,
        status: &str,
    ) -> Result<Token> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let token = sqlx::query_as::<_, Token>(
            r#"
            INSERT INTO tokens (
                id, serial_number, token_model_id, status,
                pin_attempts_remaining, puk_attempts_remaining,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(serial_number)
        .bind(token_model_id)
        .bind(status)
        .bind(3) // Default PIN attempts
        .bind(10) // Default PUK attempts
        .bind(now)
        .bind(now)
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

        let mut q = sqlx::query_as::<_, Token>(&query);

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

        let mut q = sqlx::query_as::<_, Token>(&query).bind(now);

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
    pub async fn create_token_key(
        &self,
        token_id: Uuid,
        label: &str,
        key_type: &str,
        algorithm: &str,
        certificate_id: Option<Uuid>,
    ) -> Result<TokenKey> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let key = sqlx::query_as::<_, TokenKey>(
            r#"
            INSERT INTO token_keys (
                id, token_id, label, key_type, algorithm,
                certificate_id, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(token_id)
        .bind(label)
        .bind(key_type)
        .bind(algorithm)
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
