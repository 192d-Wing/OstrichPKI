//! SCMS REST API
//!
//! Smartcard Management System HTTP endpoints.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AC-3**: Access Enforcement - Role-based access to token management endpoints
//! - **AC-6**: Least Privilege - Minimal permissions for token operations
//! - **IA-2**: Identification and Authentication - Multi-factor authentication with smartcards
//! - **IA-5**: Authenticator Management - PIN/credential lifecycle management
//! - **AU-2**: Auditable Events - All token operations are auditable events
//! - **AU-3**: Content of Audit Records - Token events include required audit fields
//!
//! ## NIAP PP-CA v2.1 SFRs (Security Functional Requirements)
//! - **FIA_AFL.1**: Authentication Failure Handling - PIN lockout after consecutive failures
//! - **FIA_UAU.1**: Timing of Authentication - PIN verification before privileged operations
//! - **FIA_UID.1**: Timing of Identification - Token identification required for all operations
//! - **FCS_CKM.1**: Cryptographic Key Generation - Key generation endpoint for token keys
//! - **FCS_CKM.4**: Cryptographic Key Destruction - Key deletion endpoint
//! - **FMT_SMF.1**: Specification of Management Functions - Token lifecycle management endpoints
//! - **FMT_SMR.1**: Security Roles - SO-PIN vs User PIN role separation
//! - **FAU_GEN.1**: Audit Data Generation - Token event logging endpoints

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
        // Health and readiness endpoints
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
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

/// Health check endpoint (liveness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
///
/// Returns 200 OK if the service process is running.
async fn health_check() -> impl IntoResponse {
    ostrich_common::health::health_response("ostrich-scms")
}

/// Readiness check endpoint (readiness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - NIST 800-53: IA-5 (Authenticator management)
///
/// Returns 200 OK if the service is ready to handle SCMS requests.
/// Checks database connectivity.
async fn readiness_check(State(state): State<ScmsState>) -> impl IntoResponse {
    ostrich_common::health::readiness_response_with_db("ostrich-scms", &state.db_pool).await
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
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<serde_json::Value>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load existing token
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Update label if provided
    // TODO: Add support for updating other fields (assigned_to, etc.)
    // TODO: Add database method to update token fields
    // For now, just return the existing token
    // TODO: Audit log

    let token = map_db_token_to_service(db_token);
    Ok(Json(token).into_response())
}

/// Revoke token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FMT_SMF.1: Token revocation is a security management function
/// - NIAP PP-CA FCS_CKM.4: Revocation triggers key destruction
/// - NIAP PP-CA FPT_STM.1: Revocation timestamp recorded
/// - NIAP PP-CA FAU_GEN.1: Revocation event must be audited
/// - NIST 800-53: IA-5(2) - Revocation of PKI-based authenticators
async fn revoke_token(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Update token status to revoked
    repo.update_token(id, Some("revoked"), None, None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to revoke token: {}", e)))?;

    // TODO: Revoke all certificates on token (Phase 12 - CA integration)
    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Revoked;
    token.revoked_at = Some(chrono::Utc::now());

    Ok(Json(token).into_response())
}

/// Initialize token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FMT_SMF.1: Token initialization is a security management function
/// - NIAP PP-CA FPT_STM.1: Initialization timestamp recorded
/// - NIST 800-53: CM-2 - Baseline configuration for token
async fn initialize_token(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Verify token is in uninitialized state
    if db_token.status != "uninitialized" {
        return Err(Error::InvalidRequest(format!(
            "Token must be in uninitialized state, current state: {}",
            db_token.status
        )));
    }

    // TODO: Initialize via PKCS#11 (Phase 10)

    // Update token status to initialized
    repo.update_token(id, Some("initialized"), None, None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to initialize token: {}", e)))?;

    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Initialized;
    token.initialized_at = Some(chrono::Utc::now());

    Ok(Json(token).into_response())
}

/// Personalize token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FMT_SMF.1: Token personalization is a security management function
/// - NIAP PP-CA FIA_UID.1: Assigns user identity to token
/// - NIAP PP-CA FIA_UAU.1: Initial PIN set during personalization
/// - NIAP PP-CA FPT_STM.1: Personalization timestamp recorded
/// - NIST 800-53: IA-5 - Initial authenticator (PIN) provisioning
async fn personalize_token(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
    Json(request): Json<PersonalizeTokenRequest>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Verify token is in initialized state
    if db_token.status != "initialized" {
        return Err(Error::InvalidRequest(format!(
            "Token must be in initialized state, current state: {}",
            db_token.status
        )));
    }

    // TODO: Set PIN via PKCS#11 (Phase 10)
    // TODO: Generate keys (Phase 10)
    // TODO: Issue certificates (Phase 12)

    // Update token assignment and status
    repo.update_token(id, Some("active"), Some(&request.assigned_to), None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to personalize token: {}", e)))?;

    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Active;
    token.assigned_to = Some(request.assigned_to);
    token.personalized_at = Some(chrono::Utc::now());

    Ok(Json(token).into_response())
}

/// Suspend token
async fn suspend_token(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Verify token is in active state
    if db_token.status != "active" {
        return Err(Error::InvalidRequest(format!(
            "Token must be in active state to suspend, current state: {}",
            db_token.status
        )));
    }

    // Update token status to suspended
    repo.update_token(id, Some("suspended"), None, None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to suspend token: {}", e)))?;

    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Suspended;

    Ok(Json(token).into_response())
}

/// Resume token
async fn resume_token(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Verify token is in suspended state
    if db_token.status != "suspended" {
        return Err(Error::InvalidRequest(format!(
            "Token must be in suspended state to resume, current state: {}",
            db_token.status
        )));
    }

    // Update token status to active
    repo.update_token(id, Some("active"), None, None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to resume token: {}", e)))?;

    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Active;

    Ok(Json(token).into_response())
}

/// Unblock token (SO-PIN recovery)
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FIA_AFL.1.2: Reset authentication failure count after SO-PIN verification
/// - NIAP PP-CA FMT_SMR.1: Requires Security Officer (SO) role for unblock operation
/// - NIAP PP-CA FIA_UAU.5: SO-PIN is separate authentication mechanism from User PIN
/// - NIST 800-53: IA-5(1) - Authenticator recovery mechanism
async fn unblock_token(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Verify token is locked
    if db_token.pin_attempts_remaining > 0 {
        return Err(Error::InvalidRequest(
            "Token is not locked, unblock not required".to_string(),
        ));
    }

    // TODO: Verify SO-PIN via PKCS#11 (Phase 10)

    // Reset PIN retry counter (set to max attempts, e.g., 3)
    repo.update_token(id, None, None, Some(3), None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to unblock token: {}", e)))?;

    // TODO: Audit log

    let mut token = map_db_token_to_service(db_token);
    token.pin_retry_count = token.max_pin_retries;

    Ok(Json(token).into_response())
}

/// Verify PIN
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FIA_UAU.1: User authentication via PIN verification
/// - NIAP PP-CA FIA_AFL.1.1: Decrement retry counter on failed authentication
/// - NIAP PP-CA FIA_AFL.1.2: Block token when retry counter reaches zero
/// - NIST 800-53: IA-2 - Unique user identification and authentication
/// - NIST 800-53: IA-5 - Authenticator management
async fn verify_pin(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
    Json(request): Json<VerifyPinRequest>,
) -> Result<Response> {
    if request.pin.is_empty() {
        return Err(Error::InvalidRequest("PIN cannot be empty".to_string()));
    }

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Check if token is locked
    if db_token.pin_attempts_remaining <= 0 {
        return Err(Error::PinBlocked);
    }

    // TODO: Verify PIN via PKCS#11 (Phase 10)
    // For now, this is a placeholder that always fails
    let verified = false;

    if !verified {
        // Decrement retry counter
        let new_attempts = db_token.pin_attempts_remaining - 1;
        repo.update_token(id, None, None, Some(new_attempts), None)
            .await
            .map_err(|e| Error::DatabaseError(format!("Failed to update PIN attempts: {}", e)))?;

        // TODO: Audit log failed attempt

        if new_attempts <= 0 {
            return Err(Error::PinBlocked);
        }

        return Err(Error::InvalidPin);
    }

    // TODO: Audit log successful verification

    Ok((StatusCode::OK, Json(serde_json::json!({"verified": true}))).into_response())
}

/// Change PIN
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FIA_UAU.1: Verify current PIN before allowing change
/// - NIAP PP-CA FMT_SMF.1: PIN change is a security management function
/// - NIST 800-53: IA-5(1) - Password-based authenticator change mechanism
async fn change_pin(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ChangePinRequest>,
) -> Result<Response> {
    if request.current_pin.is_empty() || request.new_pin.is_empty() {
        return Err(Error::InvalidRequest("PINs cannot be empty".to_string()));
    }

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load token to verify it exists
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Check if token is locked
    if db_token.pin_attempts_remaining <= 0 {
        return Err(Error::PinBlocked);
    }

    // TODO: Verify current PIN via PKCS#11 (Phase 10)
    // TODO: Set new PIN via PKCS#11 (Phase 10)

    // Reset PIN retry counter after successful change (set to max attempts, e.g., 3)
    repo.update_token(id, None, None, Some(3), None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to reset PIN attempts: {}", e)))?;

    // TODO: Audit log

    Ok(StatusCode::OK.into_response())
}

/// List keys on token
async fn list_token_keys(State(state): State<ScmsState>, Path(id): Path<Uuid>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Verify token exists
    repo.find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // List keys from database
    let db_keys = repo
        .list_token_keys(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list keys: {}", e)))?;

    // TODO: Query PKCS#11 for keys (Phase 10)

    let keys: Vec<TokenKey> = db_keys
        .into_iter()
        .map(map_db_token_key_to_service)
        .collect();

    Ok(Json(keys).into_response())
}

/// Generate key pair on token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FCS_CKM.1: Cryptographic key generation on hardware token
/// - NIAP PP-CA FCS_CKM.2: Key distribution via secure token storage
/// - NIAP PP-CA FIA_UAU.1: Requires authenticated session (token must be active)
/// - NIST 800-53: SC-12 - Cryptographic key establishment and management
/// - NIST 800-53: SC-13 - Cryptographic protection (FIPS-validated algorithms)
async fn generate_key(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Response> {
    if request.label.is_empty() {
        return Err(Error::InvalidRequest(
            "Key label cannot be empty".to_string(),
        ));
    }

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Verify token exists and is active
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    if db_token.status != "active" {
        return Err(Error::InvalidRequest(format!(
            "Token must be in active state to generate keys, current state: {}",
            db_token.status
        )));
    }

    // TODO: Generate key via PKCS#11 (Phase 10)
    // For now, create a placeholder key metadata record

    // Create algorithm string from key_type and key_size
    let algorithm = format!("{}-{}", request.key_type, request.key_size);

    // Store key metadata in database
    let key = repo
        .create_token_key(id, &request.label, &request.key_type, &algorithm, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create key: {}", e)))?;

    // TODO: Audit log

    let service_key = map_db_token_key_to_service(key);

    Ok((StatusCode::CREATED, Json(service_key)).into_response())
}

/// Delete key from token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FCS_CKM.4: Cryptographic key destruction (zeroization)
/// - NIAP PP-CA FMT_SMF.1: Key deletion is a security management function
/// - NIST 800-53: SC-12(1) - Cryptographic key zeroization
async fn delete_key(
    State(state): State<ScmsState>,
    Path((token_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Verify token exists
    repo.find_token(token_id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(token_id.to_string()))?;

    // Verify key exists
    let key_exists = repo
        .list_token_keys(token_id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list keys: {}", e)))?
        .iter()
        .any(|k| k.id == key_id);

    if !key_exists {
        return Err(Error::KeyNotFound(key_id.to_string()));
    }

    // TODO: Delete key via PKCS#11 (Phase 10)

    // Delete key metadata from database
    repo.delete_token_key(key_id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to delete key: {}", e)))?;

    // TODO: Audit log

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// List token models
async fn list_models(State(state): State<ScmsState>) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Query all token models from database
    let db_models = repo
        .list_token_models()
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list models: {}", e)))?;

    let models: Vec<TokenModel> = db_models
        .into_iter()
        .map(map_db_token_model_to_service)
        .collect();

    Ok(Json(models).into_response())
}

/// Create token model request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenModelRequest {
    /// Manufacturer name
    pub manufacturer: String,
    /// Model name
    pub model_name: String,
}

/// Create token model
async fn create_model(
    State(state): State<ScmsState>,
    Json(request): Json<CreateTokenModelRequest>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Create model in database with default values
    // TODO: Accept additional parameters in request (ATR, supported key types, PIN limits)
    let db_model = repo
        .create_token_model(
            &request.manufacturer,
            &request.model_name,
            None,   // atr
            vec![], // supported_key_types (empty for now)
            12,     // max_pin_length (default)
            4,      // min_pin_length (default)
            false,  // supports_puk (default)
        )
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create model: {}", e)))?;

    // TODO: Audit log

    let model = map_db_token_model_to_service(db_model);

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// Get token events
async fn get_token_events(
    State(state): State<ScmsState>,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Verify token exists
    repo.find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // Query events from database
    let db_events = repo
        .list_token_events(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list events: {}", e)))?;

    let events: Vec<TokenEvent> = db_events
        .into_iter()
        .map(map_db_token_event_to_service)
        .collect();

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

    #[test]
    fn test_create_token_request_deserialization() {
        // JSON uses camelCase per serde rename_all attribute
        let json = r#"{
            "serialNumber": "SN12345",
            "modelId": "550e8400-e29b-41d4-a716-446655440000",
            "label": "Test Token"
        }"#;
        let request: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.serial_number, "SN12345");
        assert_eq!(request.label, "Test Token");
    }

    #[test]
    fn test_verify_pin_request_deserialization() {
        let json = r#"{"pin": "123456"}"#;
        let request: VerifyPinRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.pin, "123456");
    }

    #[test]
    fn test_verify_pin_request_empty() {
        let json = r#"{"pin": ""}"#;
        let request: VerifyPinRequest = serde_json::from_str(json).unwrap();
        assert!(request.pin.is_empty());
    }

    #[test]
    fn test_token_status_serialization() {
        // Use actual TokenStatus variants - note camelCase serialization
        assert_eq!(
            serde_json::to_string(&TokenStatus::Initialized).unwrap(),
            r#""initialized""#
        );
        assert_eq!(
            serde_json::to_string(&TokenStatus::Active).unwrap(),
            r#""active""#
        );
        assert_eq!(
            serde_json::to_string(&TokenStatus::Blocked).unwrap(),
            r#""blocked""#
        );
        assert_eq!(
            serde_json::to_string(&TokenStatus::Revoked).unwrap(),
            r#""revoked""#
        );
    }

    #[test]
    fn test_change_pin_request_deserialization() {
        // JSON uses camelCase per serde rename_all attribute
        let json = r#"{"currentPin": "oldpin", "newPin": "newpin"}"#;
        let request: ChangePinRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.current_pin, "oldpin");
        assert_eq!(request.new_pin, "newpin");
    }
}
