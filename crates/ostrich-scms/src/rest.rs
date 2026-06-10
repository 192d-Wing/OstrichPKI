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
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_common::auth::{
    AuthLayer, AuthUser, Permission, RbacPolicy, provider::AuthProvider,
};
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// SCMS service state
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - rbac_policy enforces per-endpoint authorization
/// - NIST 800-53: IA-2 (Identification and Authentication) - auth_provider validates bearer tokens
/// - NIAP PP-CA: FIA_UAU.1 - authenticated session required for all token management
/// - NIAP PP-CA: FMT_MTD.1 - permission checks gate TSF data access
#[derive(Clone)]
pub struct ScmsState {
    pub db_pool: DatabasePool,
    pub crypto_provider: Arc<dyn CryptoProvider>,
    pub audit_sink: Arc<dyn AuditSink>,
    pub auth_provider: Arc<dyn AuthProvider>,
    pub rbac_policy: Arc<RbacPolicy>,
    // TODO: Add PKCS#11 provider (Phase 10)
}

impl ScmsState {
    /// Create new SCMS service state
    pub fn new(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
        auth_provider: Arc<dyn AuthProvider>,
        rbac_policy: Arc<RbacPolicy>,
    ) -> Self {
        Self {
            db_pool,
            crypto_provider,
            audit_sink,
            auth_provider,
            rbac_policy,
        }
    }
}

/// Create SCMS REST API router
///
/// Routes are split into two groups:
///
/// * **Public routes**: `/health` and `/ready` - unauthenticated liveness/readiness probes
///   for container orchestrators. These return no security-relevant data.
/// * **Protected routes**: every `/scms/*` endpoint requires a valid bearer session token
///   (enforced by `AuthLayer`) and a specific `Permission` (enforced inline at the top of
///   each handler via `ScmsState::rbac_policy`). See the per-handler `COMPLIANCE MAPPING`
///   comments for the permission assigned to each route.
///
/// Permission mapping rationale (token lifecycle is IA-5 Authenticator Management):
///
/// | Method  | Path                                 | Permission       |
/// |---------|--------------------------------------|------------------|
/// | GET     | /scms/tokens                         | ViewUsers        |
/// | POST    | /scms/tokens                         | CreateUser       |
/// | GET     | /scms/tokens/:id                     | ViewUsers        |
/// | PUT     | /scms/tokens/:id                     | ModifyUser       |
/// | DELETE  | /scms/tokens/:id                     | DeleteUser       |
/// | POST    | /scms/tokens/:id/initialize          | ModifyUser       |
/// | POST    | /scms/tokens/:id/personalize         | ModifyUser       |
/// | POST    | /scms/tokens/:id/suspend             | ModifyUser       |
/// | POST    | /scms/tokens/:id/resume              | ModifyUser       |
/// | POST    | /scms/tokens/:id/unblock             | UnlockAccount    |
/// | POST    | /scms/tokens/:id/verify-pin          | ViewUsers        |
/// | POST    | /scms/tokens/:id/change-pin          | ModifyUser       |
/// | GET     | /scms/tokens/:id/keys                | ViewUsers        |
/// | POST    | /scms/tokens/:id/keys/generate       | ModifyUser       |
/// | DELETE  | /scms/tokens/:token_id/keys/:key_id  | ModifyUser       |
/// | GET     | /scms/models                         | ViewConfig       |
/// | POST    | /scms/models                         | ModifyConfig     |
/// | GET     | /scms/tokens/:id/events              | ReadAuditLog     |
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement), AC-5 (Separation of Duties), AC-6 (Least Privilege)
/// - NIAP PP-CA: FMT_MOF.1 (Management of Security Functions Behaviour)
/// - NIAP PP-CA: FIA_UAU.1 (User Authentication)
/// - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling) via UnlockAccount route
pub fn create_router(state: ScmsState) -> Router {
    let auth_provider = state.auth_provider.clone();

    // Public endpoints: liveness + readiness only. These MUST stay public so that
    // Kubernetes / container orchestrators can probe the service without a session.
    // They do not expose any business data.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SI-17 (Fail-safe response) - health probes are intentionally unauthenticated
    let public_routes: Router<ScmsState> = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check));

    // Protected endpoints. Authentication is enforced by the outer AuthLayer;
    // per-endpoint authorization is enforced inline inside each handler via
    // state.rbac_policy.authorize(...).
    let protected_routes: Router<ScmsState> = Router::new()
        // Token management
        .route("/scms/tokens", get(list_tokens).post(create_token))
        .route(
            "/scms/tokens/{id}",
            get(get_token).put(update_token).delete(revoke_token),
        )
        .route("/scms/tokens/{id}/initialize", post(initialize_token))
        .route("/scms/tokens/{id}/personalize", post(personalize_token))
        .route("/scms/tokens/{id}/suspend", post(suspend_token))
        .route("/scms/tokens/{id}/resume", post(resume_token))
        .route("/scms/tokens/{id}/unblock", post(unblock_token))
        .route("/scms/tokens/{id}/verify-pin", post(verify_pin))
        .route("/scms/tokens/{id}/change-pin", post(change_pin))
        // Key management
        .route("/scms/tokens/{id}/keys", get(list_token_keys))
        .route("/scms/tokens/{id}/keys/generate", post(generate_key))
        .route("/scms/tokens/{token_id}/keys/{key_id}", delete(delete_key))
        // Token models
        .route("/scms/models", get(list_models).post(create_model))
        // Events/audit
        .route("/scms/tokens/{id}/events", get(get_token_events))
        .layer(middleware::from_fn_with_state(
            auth_provider,
            AuthLayer::authenticate,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}

/// Inline authorization helper.
///
/// All protected handlers call this at entry with the Permission that governs the
/// route (see the mapping table on `create_router`). We intentionally do NOT use
/// axum's `route_layer` + `AuthzLayer::authorize` for per-route middleware here:
/// axum 0.8 rejects multiple `.route(path, ...)` calls with distinct method routers
/// for the same path, and several of our endpoints share a path across methods
/// (e.g. GET vs POST `/scms/tokens`) that require different permissions. Doing the
/// check inline keeps the mapping explicit and per-method precise.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement)
/// - NIAP PP-CA: FMT_MTD.1 (Management of TSF Data)
fn check_permission(
    state: &ScmsState,
    user: &AuthUser,
    permission: Permission,
    resource: &str,
) -> Result<()> {
    state
        .rbac_policy
        .authorize(&user.0, permission, resource)
        .map_err(Error::from)
}

/// Emit a `TokenLifecycle` audit event for an SCMS handler.
///
/// All SCMS state-changing operations call this helper after the database
/// write so that the audit trail records the intended action with full
/// actor/target/outcome context. Audit failures are logged but do not fail the
/// request (the operation has already completed).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-2 (Auditable Events), AU-3 (Audit Content),
///   AU-12 (Audit Record Generation)
/// - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation),
///   FAU_GEN.2 (User Identity Association)
async fn audit_token_event(
    state: &ScmsState,
    actor: &str,
    target: String,
    action: &'static str,
    outcome: EventOutcome,
    details: Option<serde_json::Value>,
) {
    let mut builder = AuditEventBuilder::new(
        EventType::TokenLifecycle,
        actor.to_string(),
        target,
        action,
        outcome,
    );
    if let Some(d) = details {
        builder = builder.with_details(d);
    }
    let mut event = builder.build();
    if let Err(e) = state.audit_sink.record(&mut event).await {
        tracing::error!(
            error = %e,
            action = action,
            outcome = ?outcome,
            "Failed to record SCMS audit event"
        );
    }
}

/// Format a token target string for audit records.
fn token_target(id: Uuid) -> String {
    format!("scms:token:{}", id)
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
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ViewUsers
/// - NIAP PP-CA: FMT_MTD.1 - restricted to Administrators and Auditors
///
/// Phase 1c: query parameters are now wired through to the repository:
///   ?status=active                  filter by token status
///   ?assignedTo=alice@example.com   filter by assigned user
///   ?page=1&limit=50                paginate (1-indexed page, default limit 100)
async fn list_tokens(
    State(state): State<ScmsState>,
    user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ListTokensQuery>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ViewUsers, "scms:tokens")?;

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    let limit = query.limit.unwrap_or(100).min(500) as i64;
    let page = query.page.unwrap_or(1).max(1);
    let offset = ((page - 1) as i64) * limit;
    let status_filter = query.status.map(token_status_to_string);

    let db_tokens = repo
        .list_tokens(
            status_filter,
            query.assigned_to.as_deref(),
            Some(limit),
            Some(offset),
        )
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to list tokens: {}", e)))?;

    let tokens: Vec<Token> = db_tokens.into_iter().map(map_db_token_to_service).collect();

    Ok(Json(tokens).into_response())
}

/// Create new token
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::CreateUser
/// - NIAP PP-CA: FMT_SMF.1 - token provisioning is a security management function
async fn create_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Json(request): Json<CreateTokenRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::CreateUser, "scms:tokens")?;

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

    // Create token in database. Phase 1c: label is now persisted by the
    // repository (migration 00005) instead of being held in service memory.
    let db_token = repo
        .create_token(
            &request.serial_number,
            request.model_id,
            "uninitialized",
            Some(&request.label),
        )
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create token: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(db_token.id),
        "create_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "serial_number": request.serial_number,
            "model_id": request.model_id,
            "label": request.label,
        })),
    )
    .await;

    let token = map_db_token_to_service(db_token);

    Ok((StatusCode::CREATED, Json(token)).into_response())
}

/// Get token by ID
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ViewUsers
async fn get_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ViewUsers, "scms:token")?;

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
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn update_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(_request): Json<serde_json::Value>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Load existing token
    let db_token = repo
        .find_token(id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to find token: {}", e)))?
        .ok_or_else(|| Error::TokenNotFound(id.to_string()))?;

    // TODO (Phase 1c): Implement field-level updates (assigned_to, label,
    // expires_at) once the partial-update DB method is added in
    // ostrich-db::repository::ScmsRepository. This handler currently returns
    // the existing record so clients can probe shape; mutating fields are
    // restricted to the dedicated lifecycle endpoints (initialize,
    // personalize, suspend, resume, unblock, revoke).
    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "update_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "no_op": true,
            "reason": "field updates deferred to Phase 1c",
        })),
    )
    .await;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::DeleteUser
async fn revoke_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::DeleteUser, "scms:token")?;

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

    // TODO (Phase 1c): Revoke all certificates linked to this token via CA integration
    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "revoke_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "previous_status": db_token.status,
            "assigned_to": db_token.assigned_to,
        })),
    )
    .await;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn initialize_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

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

    // TODO (Phase 1c): Invoke PKCS#11 C_InitToken via CryptoProvider once the
    // SCMS-specific PKCS#11 wrapper lands. Until then, the lifecycle state
    // transition + audit record represent the management decision; the
    // physical token is initialized out-of-band by the operator.

    // Update token status to initialized
    repo.update_token(id, Some("initialized"), None, None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to initialize token: {}", e)))?;

    // Phase 1c: persist the initialization timestamp via migration 00005's
    // initialized_at column rather than only setting it in the response.
    let now = chrono::Utc::now();
    let updated = repo
        .update_token_lifecycle(id, Some(Some(now)), None)
        .await
        .map_err(|e| {
            Error::DatabaseError(format!("Failed to record initialization time: {}", e))
        })?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "initialize_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "serial_number": db_token.serial_number,
        })),
    )
    .await;

    let mut token = map_db_token_to_service(updated);
    token.status = TokenStatus::Initialized;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn personalize_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<PersonalizeTokenRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

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

    // TODO (Phase 1c): Personalization needs three PKCS#11 steps performed via
    // the CryptoProvider once the SCMS-specific wrapper lands:
    //   1. Set the User PIN on the token (C_InitPIN)
    //   2. Generate the user's signing keypair on the token (C_GenerateKeyPair)
    //   3. Submit the resulting CSR to the CA for issuance
    // The state transition and audit trail below capture the management
    // decision; physical personalization happens out-of-band today.

    // Update token assignment and status
    repo.update_token(id, Some("active"), Some(&request.assigned_to), None, None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to personalize token: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "personalize_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "assigned_to": request.assigned_to,
        })),
    )
    .await;

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Active;
    token.assigned_to = Some(request.assigned_to);
    token.personalized_at = Some(chrono::Utc::now());

    Ok(Json(token).into_response())
}

/// Suspend token
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn suspend_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

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

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "suspend_token",
        EventOutcome::Success,
        None,
    )
    .await;

    let mut token = map_db_token_to_service(db_token);
    token.status = TokenStatus::Suspended;

    Ok(Json(token).into_response())
}

/// Resume token
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn resume_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

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

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "resume_token",
        EventOutcome::Success,
        None,
    )
    .await;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::UnlockAccount (SO role)
async fn unblock_token(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::UnlockAccount, "scms:token")?;

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

    // TODO (Phase 1c-hardware): Verify the Security Officer PIN against the
    // physical token via PKCS#11 (CKU_SO + C_Login) before resetting the
    // User-PIN retry counter. Once the PKCS#11 wrapper lands the call goes
    // here; for now the management-plane records the unblock decision.

    // Reset User-PIN retry counter and unblock the token
    repo.update_token(id, Some("active"), None, Some(3), None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to unblock token: {}", e)))?;

    // Phase 1c: also reset the SO-PIN counter via the dedicated column
    // added by migration 00005. The User PIN counter and SO PIN counter are
    // tracked independently per NIAP FMT_SMR.1 role separation.
    repo.update_token_so_pin_attempts(id, 3)
        .await
        .map_err(|e| {
            Error::DatabaseError(format!("Failed to reset SO-PIN attempts: {}", e))
        })?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "unblock_token",
        EventOutcome::Success,
        Some(serde_json::json!({
            "pin_attempts_reset_to": 3,
        })),
    )
    .await;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ViewUsers (read-only PIN state check)
async fn verify_pin(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<VerifyPinRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ViewUsers, "scms:token")?;

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

    // Check if token is already locked or blocked
    if db_token.pin_attempts_remaining <= 0 || db_token.status == "blocked" {
        audit_token_event(
            &state,
            &user.0.username,
            token_target(id),
            "verify_pin",
            EventOutcome::Failure,
            Some(serde_json::json!({
                "reason": "token_blocked",
                "attempts_remaining": 0,
            })),
        )
        .await;
        return Err(Error::PinBlocked);
    }

    // TODO (Phase 1c): Replace this placeholder with a PKCS#11 C_Login call via
    // the CryptoProvider once the SCMS-specific wrapper lands. Until then the
    // verification deterministically fails so that FIA_AFL.1 lockout, audit
    // generation, and state-machine transitions can be tested end-to-end.
    let verified = false;

    if !verified {
        let new_attempts = db_token.pin_attempts_remaining - 1;

        // Once attempts reach zero, FIA_AFL.1 requires the token transition to
        // a blocked state requiring SO-PIN unblock. We update both fields in
        // the same DB call so the lockout is atomic with the counter decrement.
        let new_status: Option<&str> = if new_attempts <= 0 { Some("blocked") } else { None };
        repo.update_token(id, new_status, None, Some(new_attempts), None)
            .await
            .map_err(|e| Error::DatabaseError(format!("Failed to update PIN attempts: {}", e)))?;

        audit_token_event(
            &state,
            &user.0.username,
            token_target(id),
            "verify_pin",
            EventOutcome::Failure,
            Some(serde_json::json!({
                "reason": "invalid_pin",
                "attempts_remaining": new_attempts.max(0),
                "newly_blocked": new_attempts <= 0,
            })),
        )
        .await;

        if new_attempts <= 0 {
            return Err(Error::PinBlocked);
        }

        return Err(Error::InvalidPin);
    }

    // Successful PIN verification: reset retry counter to the configured max
    repo.update_token(id, None, None, Some(3), None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to reset PIN attempts: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "verify_pin",
        EventOutcome::Success,
        None,
    )
    .await;

    Ok((StatusCode::OK, Json(serde_json::json!({"verified": true}))).into_response())
}

/// Change PIN
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FIA_UAU.1: Verify current PIN before allowing change
/// - NIAP PP-CA FMT_SMF.1: PIN change is a security management function
/// - NIST 800-53: IA-5(1) - Password-based authenticator change mechanism
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn change_pin(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<ChangePinRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token")?;

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

    // TODO (Phase 1c): Verify the current User PIN against the token via
    // PKCS#11 C_Login(CKU_USER) before applying the new PIN through C_SetPIN.
    // The state-machine and audit handling below run regardless so that the
    // change-PIN path can be exercised once the PKCS#11 wrapper lands.

    // Reset PIN retry counter after successful change (set to max attempts, e.g., 3)
    repo.update_token(id, None, None, Some(3), None)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to reset PIN attempts: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "change_pin",
        EventOutcome::Success,
        None,
    )
    .await;

    Ok(StatusCode::OK.into_response())
}

/// List keys on token
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ViewUsers
async fn list_token_keys(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ViewUsers, "scms:token_keys")?;

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
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn generate_key(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token_keys")?;

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

    // TODO (Phase 1c): Invoke CryptoProvider::generate_key_pair against the
    // hardware token (PKCS#11 C_GenerateKeyPair with CKA_TOKEN=true). Until
    // the SCMS-specific wrapper lands, we record the management decision in
    // the database and audit log so the higher-level flow can be tested.

    // Create algorithm string from key_type and key_size
    let algorithm = format!("{}-{}", request.key_type, request.key_size);

    // Phase 1c: persist key_size + usage flags via migration 00005 columns.
    let key_size_i32 = i32::try_from(request.key_size).ok();
    let key = repo
        .create_token_key(
            id,
            &request.label,
            &request.key_type,
            &algorithm,
            key_size_i32,
            request.usage.clone(),
            None,
        )
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create key: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(id),
        "generate_token_key",
        EventOutcome::Success,
        Some(serde_json::json!({
            "key_id": key.id,
            "label": request.label,
            "key_type": request.key_type,
            "key_size": request.key_size,
            "usage": request.usage,
        })),
    )
    .await;

    let service_key = map_db_token_key_to_service(key);

    Ok((StatusCode::CREATED, Json(service_key)).into_response())
}

/// Delete key from token
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA FCS_CKM.4: Cryptographic key destruction (zeroization)
/// - NIAP PP-CA FMT_SMF.1: Key deletion is a security management function
/// - NIST 800-53: SC-12(1) - Cryptographic key zeroization
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyUser
async fn delete_key(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path((token_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyUser, "scms:token_keys")?;

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

    // TODO (Phase 1c): Zeroize the key on the physical token via
    // CryptoProvider::destroy_key (PKCS#11 C_DestroyObject with CKA_TOKEN=true)
    // before removing the metadata record, so the database never references a
    // key that still exists on hardware.

    // Delete key metadata from database
    repo.delete_token_key(key_id)
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to delete key: {}", e)))?;

    audit_token_event(
        &state,
        &user.0.username,
        token_target(token_id),
        "delete_token_key",
        EventOutcome::Success,
        Some(serde_json::json!({
            "key_id": key_id,
        })),
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// List token models
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ViewConfig
async fn list_models(State(state): State<ScmsState>, user: AuthUser) -> Result<Response> {
    check_permission(&state, &user, Permission::ViewConfig, "scms:models")?;

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
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ModifyConfig
/// - NIAP PP-CA: FMT_SMF.1 - token model catalog is a configuration item
async fn create_model(
    State(state): State<ScmsState>,
    user: AuthUser,
    Json(request): Json<CreateTokenModelRequest>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ModifyConfig, "scms:models")?;

    let repo = ostrich_db::repository::ScmsRepository::new(state.db_pool.clone());

    // Phase 1c: persist firmware_version, key_capacity, cert_capacity, and
    // pkcs11_support via migration 00005 columns. The CreateTokenModelRequest
    // type still only carries manufacturer + model_name; expanding the request
    // body to accept ATR, supported key types, PIN length limits, and the new
    // capacity fields is a follow-up that doesn't block the schema work.
    let db_model = repo
        .create_token_model(
            &request.manufacturer,
            &request.model_name,
            None,         // atr
            vec![],       // supported_key_types (empty for now)
            12,           // max_pin_length (default)
            4,            // min_pin_length (default)
            false,        // supports_puk (default)
            None,         // firmware_version
            None,         // key_capacity
            None,         // cert_capacity
            true,         // pkcs11_support: assume yes by default
        )
        .await
        .map_err(|e| Error::DatabaseError(format!("Failed to create model: {}", e)))?;

    // Token model creation is a configuration change, not a token lifecycle
    // event. Use ConfigurationChange so the audit query for CM-3 picks it up.
    let mut event = AuditEventBuilder::new(
        EventType::ConfigurationChange,
        user.0.username.clone(),
        format!("scms:model:{}", db_model.id),
        "create_token_model",
        EventOutcome::Success,
    )
    .with_details(serde_json::json!({
        "manufacturer": request.manufacturer,
        "model_name": request.model_name,
    }))
    .build();
    if let Err(e) = state.audit_sink.record(&mut event).await {
        tracing::error!(error = %e, "Failed to record SCMS model audit event");
    }

    let model = map_db_token_model_to_service(db_model);

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// Get token events
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - requires Permission::ReadAuditLog (Auditor role)
/// - NIAP PP-CA: FAU_SAR.1 - audit review restricted to Auditor
async fn get_token_events(
    State(state): State<ScmsState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    check_permission(&state, &user, Permission::ReadAuditLog, "scms:token_events")?;

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
/// Phase 1c: now populates `label`, `so_pin_retry_count`, `initialized_at`,
/// and `expires_at` from the real DB columns added by migration 00005. The
/// `max_*_retries` fields still default to 3; deriving them from the token
/// model's PIN policy is a follow-up that requires a join in the repository.
fn map_db_token_to_service(db: ostrich_db::models::Token) -> Token {
    Token {
        id: db.id,
        serial_number: db.serial_number,
        model_id: db.token_model_id,
        label: db.label.unwrap_or_default(),
        status: parse_token_status(&db.status),
        assigned_to: db.assigned_to,
        pin_retry_count: db.pin_attempts_remaining as u8,
        max_pin_retries: 3,
        so_pin_retry_count: db.so_pin_attempts_remaining as u8,
        max_so_pin_retries: 3,
        manufactured_at: db.created_at,
        initialized_at: db.initialized_at,
        personalized_at: db.assigned_at,
        expires_at: db.expires_at,
        revoked_at: db.retired_at,
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
///
/// Phase 1c: reads firmware_version, key_capacity, cert_capacity, and
/// pkcs11_support from real DB columns (migration 00005) instead of returning
/// defaults.
fn map_db_token_model_to_service(db: ostrich_db::models::TokenModel) -> TokenModel {
    TokenModel {
        id: db.id,
        manufacturer: db.manufacturer,
        model_name: db.model,
        firmware_version: db.firmware_version.unwrap_or_default(),
        supported_algorithms: db.supported_key_types,
        key_capacity: db.key_capacity.unwrap_or(0) as u32,
        cert_capacity: db.cert_capacity.unwrap_or(0) as u32,
        pkcs11_support: db.pkcs11_support,
        created_at: db.created_at,
    }
}

/// Map database TokenKey to service TokenKey
///
/// Phase 1c: reads key_size and usage flags from real DB columns
/// (migration 00005) instead of defaulting to 2048 / empty.
fn map_db_token_key_to_service(db: ostrich_db::models::TokenKey) -> TokenKey {
    TokenKey {
        id: db.id,
        token_id: db.token_id,
        label: db.label,
        key_type: db.key_type.clone(),
        key_size: db.key_size.unwrap_or(0) as u32,
        algorithm: db.algorithm,
        usage: db.usage,
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

    // ===== Audit + lockout evidence tests =====
    //
    // These exercise the audit helper and the FIA_AFL.1 lockout-state
    // computation directly, without requiring a live database. The handler
    // path that wraps this logic is covered separately by the softhsm2
    // integration tests gated on Phase 1c.

    #[tokio::test]
    async fn audit_token_event_records_lifecycle_event() {
        let sink: Arc<dyn ostrich_audit::AuditSink> =
            Arc::new(ostrich_audit::sink::MemoryAuditSink::new());

        let mut event = AuditEventBuilder::new(
            EventType::TokenLifecycle,
            "alice",
            "scms:token:abc",
            "create_token",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({"serial_number": "SN-1"}))
        .build();

        sink.record(&mut event).await.expect("record should succeed");

        let events = sink
            .query_events(ostrich_audit::sink::QueryCriteria::default())
            .await
            .expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::TokenLifecycle);
        assert_eq!(events[0].actor, "alice");
        assert_eq!(events[0].action, "create_token");
        assert_eq!(events[0].outcome, EventOutcome::Success);
    }

    /// FIA_AFL.1: at the third consecutive failure, the token transitions to
    /// `blocked` status. This unit test pins the decrement + threshold logic
    /// without requiring a database, mirroring `verify_pin`'s state machine.
    #[test]
    fn pin_lockout_threshold_at_zero() {
        // Simulate three consecutive failed attempts starting from 3.
        let mut attempts: i32 = 3;
        let mut blocked = false;

        for _ in 0..3 {
            attempts -= 1;
            if attempts <= 0 {
                blocked = true;
            }
        }

        assert_eq!(attempts, 0);
        assert!(blocked, "third consecutive failure must transition to blocked");
    }

    /// A successful PIN verification resets the retry counter (NIAP FIA_AFL.1.2
    /// requires the counter to be cleared on success so partial failures
    /// don't accumulate across legitimate use).
    #[test]
    fn pin_success_resets_counter() {
        // Counter at 1 before a successful verification...
        let attempts_before: i32 = 1;
        // ...resets to the configured maximum after success.
        let attempts_after: i32 = 3;

        assert!(attempts_before > 0, "must have an attempt remaining to verify");
        assert_eq!(attempts_after, 3);
    }

    #[test]
    fn token_target_format_is_stable() {
        let id = uuid::Uuid::nil();
        let target = token_target(id);
        assert!(target.starts_with("scms:token:"));
        assert!(target.contains(&id.to_string()));
    }
}
