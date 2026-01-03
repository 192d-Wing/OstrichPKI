//! SCMS REST API
//!
//! Smartcard Management System HTTP endpoints

use crate::{
    error::{Error, Result},
    token::{Token, TokenEvent, TokenKey, TokenModel, TokenStatus},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use ostrich_audit::AuditSink;
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// SCMS service state
#[derive(Clone)]
pub struct ScmsState {
    pub db_pool: DatabasePool,
    pub crypto_provider: Arc<dyn CryptoProvider>,
    pub audit_sink: Arc<dyn AuditSink>,
    // TODO: Add PKCS#11 provider (Phase 10)
}

impl ScmsState {
    /// Create new SCMS service state
    pub fn new(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            db_pool,
            crypto_provider,
            audit_sink,
        }
    }
}

/// Create SCMS REST API router
pub fn create_router(state: ScmsState) -> Router {
    Router::new()
        // Token management
        .route("/scms/tokens", get(list_tokens).post(create_token))
        .route(
            "/scms/tokens/:id",
            get(get_token).put(update_token).delete(revoke_token),
        )
        .route("/scms/tokens/:id/initialize", post(initialize_token))
        .route("/scms/tokens/:id/personalize", post(personalize_token))
        .route("/scms/tokens/:id/suspend", post(suspend_token))
        .route("/scms/tokens/:id/resume", post(resume_token))
        .route("/scms/tokens/:id/unblock", post(unblock_token))
        .route("/scms/tokens/:id/verify-pin", post(verify_pin))
        .route("/scms/tokens/:id/change-pin", post(change_pin))
        // Key management
        .route("/scms/tokens/:id/keys", get(list_token_keys))
        .route("/scms/tokens/:id/keys/generate", post(generate_key))
        .route("/scms/tokens/:token_id/keys/:key_id", delete(delete_key))
        // Token models
        .route("/scms/models", get(list_models).post(create_model))
        // Events/audit
        .route("/scms/tokens/:id/events", get(get_token_events))
        .with_state(state)
}

/// List tokens request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTokensQuery {
    /// Filter by status
    pub status: Option<TokenStatus>,
    /// Filter by assigned user
    pub assigned_to: Option<String>,
    /// Page number
    pub page: Option<u32>,
    /// Page size
    pub limit: Option<u32>,
}

/// Create token request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenRequest {
    /// Serial number
    pub serial_number: String,
    /// Model ID
    pub model_id: Uuid,
    /// Token label
    pub label: String,
}

/// Personalize token request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalizeTokenRequest {
    /// User to assign to
    pub assigned_to: String,
    /// Initial PIN (hashed)
    pub pin_hash: String,
}

/// Verify PIN request
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyPinRequest {
    /// PIN to verify
    pub pin: String,
}

/// Change PIN request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePinRequest {
    /// Current PIN
    pub current_pin: String,
    /// New PIN
    pub new_pin: String,
}

/// Generate key request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyRequest {
    /// Key label
    pub label: String,
    /// Key type (RSA, ECDSA, EdDSA)
    pub key_type: String,
    /// Key size
    pub key_size: u32,
    /// Key usage
    pub usage: Vec<String>,
}

/// List tokens
async fn list_tokens(State(state): State<ScmsState>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // TODO: Add query parameters for filtering (status, assigned_to) and pagination
    let db_tokens = repo
        .list_tokens(None, None, Some(100), Some(0))
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list tokens: {}", e)))?;

    let tokens: Vec<Token> = db_tokens.into_iter().map(map_db_token_to_service).collect();

    Ok(Json(tokens).into_response())
}

/// Create new token
async fn create_token(
    State(state): State<ScmsState>,
    Json(request): Json<CreateTokenRequest>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Verify model exists
    repo.find_token_model(request.model_id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to verify model: {}", e)))?
        .ok_or_else(|| Error::TokenModelNotFound(request.model_id.to_string()))?;

    // Check if serial number already exists
    if repo
        .find_token_by_serial(&request.serial_number)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to check serial: {}", e)))?
        .is_some()
    {
        return Err(Error::SerialNumberExists(request.serial_number));
    }

    // Create token in database
    let db_token = repo
        .create_token(&request.serial_number, request.model_id, "uninitialized")
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create token: {}", e)))?;

    // TODO: Audit log (Phase 11)

    let mut token = map_db_token_to_service(db_token);
    token.label = request.label; // Set label from request (not in DB yet)

    Ok((StatusCode::CREATED, Json(token)).into_response())
}

/// Get token by ID
async fn get_token(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    let token = map_db_token_to_service(db_token);

    Ok(Json(token).into_response())
}

/// Update token
async fn update_token(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<serde_json::Value>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Update fields
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Revoke token
async fn revoke_token(State(_state): State<ScmsState>, Path(_id): Path<Uuid>) -> Result<Response> {
    // TODO: Load from database
    // TODO: Revoke all certificates on token
    // TODO: Mark token as revoked
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Initialize token
async fn initialize_token(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Initialize via PKCS#11
    // TODO: Update status
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Personalize token
async fn personalize_token(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
    Json(request): Json<PersonalizeTokenRequest>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Set PIN via PKCS#11
    // TODO: Generate keys
    // TODO: Issue certificates
    // TODO: Update status
    // TODO: Audit log

    let mut token = Token::new("SN12345".to_string(), Uuid::new_v4(), "Token".to_string());
    token.personalize(request.assigned_to);

    Ok(Json(token).into_response())
}

/// Suspend token
async fn suspend_token(State(_state): State<ScmsState>, Path(_id): Path<Uuid>) -> Result<Response> {
    // TODO: Load from database
    // TODO: Update status
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Resume token
async fn resume_token(State(_state): State<ScmsState>, Path(_id): Path<Uuid>) -> Result<Response> {
    // TODO: Load from database
    // TODO: Update status
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Unblock token (SO-PIN recovery)
async fn unblock_token(State(_state): State<ScmsState>, Path(_id): Path<Uuid>) -> Result<Response> {
    // TODO: Load from database
    // TODO: Verify SO-PIN
    // TODO: Reset PIN retry counter
    // TODO: Update status
    // TODO: Audit log

    Err(Error::TokenNotFound(_id.to_string()))
}

/// Verify PIN
async fn verify_pin(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
    Json(request): Json<VerifyPinRequest>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Verify PIN via PKCS#11
    // TODO: Update retry counter
    // TODO: Audit log

    if request.pin.is_empty() {
        return Err(Error::InvalidRequest("PIN cannot be empty".to_string()));
    }

    Ok((StatusCode::OK, Json(serde_json::json!({"verified": false}))).into_response())
}

/// Change PIN
async fn change_pin(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
    Json(request): Json<ChangePinRequest>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Verify current PIN
    // TODO: Set new PIN via PKCS#11
    // TODO: Audit log

    if request.current_pin.is_empty() || request.new_pin.is_empty() {
        return Err(Error::InvalidRequest("PINs cannot be empty".to_string()));
    }

    Ok(StatusCode::OK.into_response())
}

/// List keys on token
async fn list_token_keys(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Query PKCS#11 for keys

    let keys: Vec<TokenKey> = vec![]; // Placeholder

    Ok(Json(keys).into_response())
}

/// Generate key pair on token
async fn generate_key(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Response> {
    // TODO: Load token from database
    // TODO: Generate key via PKCS#11
    // TODO: Store key metadata
    // TODO: Audit log

    if request.label.is_empty() {
        return Err(Error::InvalidRequest(
            "Key label cannot be empty".to_string(),
        ));
    }

    Ok(StatusCode::CREATED.into_response())
}

/// Delete key from token
async fn delete_key(
    State(_state): State<ScmsState>,
    Path((_token_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Response> {
    // TODO: Load from database
    // TODO: Delete key via PKCS#11
    // TODO: Audit log

    Err(Error::KeyNotFound(key_id.to_string()))
}

/// List token models
async fn list_models(State(_state): State<ScmsState>) -> Result<Response> {
    // TODO: Query from database

    let models: Vec<TokenModel> = vec![]; // Placeholder

    Ok(Json(models).into_response())
}

/// Create token model
async fn create_model(
    State(_state): State<ScmsState>,
    Json(_request): Json<serde_json::Value>,
) -> Result<Response> {
    // TODO: Create model in database

    Ok(StatusCode::CREATED.into_response())
}

/// Get token events
async fn get_token_events(
    State(_state): State<ScmsState>,
    Path(_id): Path<Uuid>,
) -> Result<Response> {
    // TODO: Query events from database

    let events: Vec<TokenEvent> = vec![]; // Placeholder

    Ok(Json(events).into_response())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Map database Token to service Token
///
/// Note: This mapping handles schema mismatches between database and service models.
/// Missing fields in the database are set to reasonable defaults.
fn map_db_token_to_service(db: ostrich_db::models::Token) -> Token {
    Token {
        id: db.id,
        serial_number: db.serial_number,
        model_id: db.token_model_id, // DB uses token_model_id
        label: String::new(),        // TODO: Add label field to database schema
        status: parse_token_status(&db.status),
        assigned_to: db.assigned_to,
        pin_retry_count: db.pin_attempts_remaining as u8, // DB uses i32, service uses u8
        max_pin_retries: 3,                               // TODO: Get from token model
        so_pin_retry_count: 3,                            // TODO: Add to database schema
        max_so_pin_retries: 3,                            // TODO: Get from token model
        manufactured_at: db.created_at,                   // Use created_at as manufactured_at
        initialized_at: None,                             // TODO: Add to database schema
        personalized_at: db.assigned_at,                  // Use assigned_at as personalized_at
        expires_at: None,                                 // TODO: Add to database schema
        revoked_at: db.retired_at,                        // Use retired_at as revoked_at
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

/// Parse token status from database string
fn parse_token_status(status: &str) -> TokenStatus {
    match status {
        "uninitialized" => TokenStatus::Uninitialized,
        "initialized" => TokenStatus::Initialized,
        "active" => TokenStatus::Active,
        "suspended" => TokenStatus::Suspended,
        "blocked" => TokenStatus::Blocked,
        "expired" => TokenStatus::Expired,
        "revoked" => TokenStatus::Revoked,
        _ => TokenStatus::Uninitialized,
    }
}

/// Convert service TokenStatus to database string
#[allow(dead_code)] // TODO: Use in lifecycle handlers
fn token_status_to_string(status: TokenStatus) -> &'static str {
    match status {
        TokenStatus::Uninitialized => "uninitialized",
        TokenStatus::Initialized => "initialized",
        TokenStatus::Active => "active",
        TokenStatus::Suspended => "suspended",
        TokenStatus::Blocked => "blocked",
        TokenStatus::Expired => "expired",
        TokenStatus::Revoked => "revoked",
    }
}

/// Map database TokenModel to service TokenModel
#[allow(dead_code)] // TODO: Use in list_models handler
fn map_db_token_model_to_service(db: ostrich_db::models::TokenModel) -> TokenModel {
    TokenModel {
        id: db.id,
        manufacturer: db.manufacturer,
        model_name: db.model,
        firmware_version: String::from("1.0.0"), // TODO: Add to database schema
        supported_algorithms: db.supported_key_types,
        key_capacity: 10,     // TODO: Add to database schema
        cert_capacity: 10,    // TODO: Add to database schema
        pkcs11_support: true, // TODO: Add to database schema
        created_at: db.created_at,
    }
}

/// Map database TokenKey to service TokenKey
#[allow(dead_code)] // TODO: Use in key handlers
fn map_db_token_key_to_service(db: ostrich_db::models::TokenKey) -> TokenKey {
    TokenKey {
        id: db.id,
        token_id: db.token_id,
        label: db.label,
        key_type: db.key_type.clone(),
        key_size: 2048, // TODO: Add to database schema or parse from algorithm
        algorithm: db.algorithm,
        usage: vec![], // TODO: Add to database schema
        certificate_id: db.certificate_id,
        created_at: db.created_at,
    }
}

/// Map database TokenEvent to service TokenEvent
#[allow(dead_code)] // TODO: Use in event handlers
fn map_db_token_event_to_service(db: ostrich_db::models::TokenEvent) -> TokenEvent {
    TokenEvent {
        id: db.id,
        token_id: db.token_id,
        event_type: db.event_type,
        actor: db.actor,
        details: db.details,
        occurred_at: db.timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_token() {
        let state = ScmsState::new();
        let request = CreateTokenRequest {
            serial_number: "SN12345".to_string(),
            model_id: Uuid::new_v4(),
            label: "Test Token".to_string(),
        };

        let result = create_token(State(state), Json(request)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_pin_empty() {
        let state = ScmsState::new();
        let request = VerifyPinRequest { pin: String::new() };

        let result = verify_pin(State(state), Path(Uuid::new_v4()), Json(request)).await;
        assert!(result.is_err());
    }
}
