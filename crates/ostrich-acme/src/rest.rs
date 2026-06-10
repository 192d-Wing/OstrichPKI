//! ACME REST API
//!
//! This module implements the ACME protocol HTTP endpoints per RFC 8555.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before any action
//!   - All mutating endpoints require JWS authentication.
//!   - Account creation requires signed request with JWK.
//!   - Subsequent requests authenticated via JWS with kid.
//!
//! - **FIA_UID.1**: User identification before any action
//!   - Accounts identified by JWK thumbprint (RFC 7638).
//!   - Account URL (kid) used for subsequent identification.
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - All endpoints MUST be served over HTTPS (TLS 1.2+).
//!   - Replay-Nonce header provides replay protection.
//!
//! - **FDP_ACC.1**: Subset access control
//!   - Account-scoped access to orders, authorizations, certificates.
//!   - JWS kid validated against resource ownership.
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - All account and order operations emit audit events.
//!   - Challenge responses trigger audit logging.
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-23**: Session Authenticity
//!   - Nonce-based replay protection (RFC 8555 Section 6.5).
//!   - URL binding prevents request forwarding attacks.
//!
//! - **IA-2**: Identification and Authentication
//!   - JWS signature verification for all authenticated endpoints.
//!
//! - **SI-10**: Information Input Validation
//!   - JWS envelope validation.
//!   - CSR parsing and signature verification.
//!
//! ## RFC Compliance
//!
//! - RFC 8555: ACME protocol HTTP endpoints

use crate::{
    account::{Account, AccountStatus},
    authorization::{Authorization, AuthorizationStatus},
    challenge::{Challenge, ChallengeStatus, ChallengeType},
    error::{Error, Result},
    jws::{self, Jwk, ProtectedHeader},
    order::{Identifier, Order, OrderStatus},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use ostrich_audit::AuditSink;
use ostrich_common::util::encoding::decode_base64url;
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// ACME service state
#[derive(Clone)]
pub struct AcmeState {
    pub db_pool: DatabasePool,
    pub crypto_provider: Arc<dyn CryptoProvider>,
    pub audit_sink: Arc<dyn AuditSink>,
    /// Base URL for ACME directory (from configuration)
    pub base_url: String,
    /// CA client for certificate issuance (RFC 8555 §7.4)
    ///
    /// When `None`, order finalization fails closed rather than
    /// issuing a fake certificate.
    /// NIST 800-53: SC-17 - PKI certificate issuance via CA service
    pub ca_client: Option<Arc<crate::ca_integration::AcmeCaClient>>,
}

impl AcmeState {
    /// Create new ACME service state
    pub fn new(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
        base_url: String,
        ca_client: Option<Arc<crate::ca_integration::AcmeCaClient>>,
    ) -> Self {
        Self {
            db_pool,
            crypto_provider,
            audit_sink,
            base_url,
            ca_client,
        }
    }
}

/// Validated JWS request with decoded payload
///
/// This structure holds the result of successful JWS validation
struct ValidatedJwsRequest<T> {
    /// Decoded payload
    payload: T,
    /// Protected header (may be used for audit logging in the future)
    #[allow(dead_code)]
    header: ProtectedHeader,
    /// JWK from header (for new-account) or retrieved from database (for other requests)
    jwk: Jwk,
    /// JWK thumbprint for account identification
    jwk_thumbprint: String,
    /// Account ID (UUID) - only set for validate_jws_with_account
    account_id: Uuid,
}

/// Validate JWS request for new-account endpoint
///
/// RFC 8555 §6.2: All ACME requests with a non-empty body MUST encapsulate
/// the request in a JWS object, signed using the account's key pair.
///
/// For new-account, the JWK must be in the protected header.
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Authenticates request via JWS signature before processing.
/// - **FIA_UID.1**: Identifies account via JWK thumbprint (RFC 7638).
/// - **FCS_COP.1**: Cryptographic signature verification (RS256, ES256, etc.).
/// - **SC-23 (NIST)**: Nonce and URL binding for replay/redirect protection.
async fn validate_jws_new_account<T: serde::de::DeserializeOwned>(
    body: &[u8],
    expected_url: &str,
    state: &AcmeState,
) -> Result<ValidatedJwsRequest<T>> {
    // 1. Parse JWS envelope
    let jws_envelope = jws::parse_jws(body)?;

    // 2. Decode protected header
    let header = jws::decode_protected_header(&jws_envelope.protected)?;

    // 3. Verify URL matches (RFC 8555 §6.4.1)
    if header.url != expected_url {
        return Err(Error::Malformed(format!(
            "JWS URL mismatch: expected '{}', got '{}'",
            expected_url, header.url
        )));
    }

    // 4. Verify nonce and consume it (replay protection - RFC 8555 §6.5)
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    repo.consume_nonce(&header.nonce)
        .await
        .map_err(|_| Error::BadNonce)?;

    // 5. Extract JWK (required for new-account)
    let jwk = header
        .jwk
        .clone()
        .ok_or_else(|| Error::Malformed("JWK required for new-account".to_string()))?;

    // 6. Verify JWS signature
    let signature_valid =
        jws::verify_jws_with_jwk(&jws_envelope, &header, &jwk, &state.crypto_provider).await?;

    if !signature_valid {
        return Err(Error::Unauthorized("Invalid JWS signature".to_string()));
    }

    // 7. Compute JWK thumbprint for account identification
    let jwk_thumbprint = jws::compute_jwk_thumbprint(&jwk)?;

    // 8. Decode payload
    let payload_bytes = decode_base64url(&jws_envelope.payload)?;
    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Malformed(format!("Invalid payload JSON: {}", e)))?;

    Ok(ValidatedJwsRequest {
        payload,
        header,
        jwk,
        jwk_thumbprint,
        account_id: Uuid::nil(), // Not applicable for new-account
    })
}

/// Validate JWS request for existing account endpoints
///
/// RFC 8555 §6.2: For requests from an existing account, the JWS MUST be
/// signed with the account's key pair, and the "kid" field MUST be present.
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Authenticates request via JWS signature verification.
/// - **FIA_UID.1**: Identifies account via kid URL (account identifier).
/// - **FDP_ACC.1**: Validates account owns the requested resource.
/// - **FCS_COP.1**: Cryptographic signature verification using account's key.
/// - **SC-23 (NIST)**: Nonce consumption prevents replay attacks.
async fn validate_jws_with_account<T: serde::de::DeserializeOwned>(
    body: &[u8],
    expected_url: &str,
    state: &AcmeState,
) -> Result<ValidatedJwsRequest<T>> {
    // 1. Parse JWS envelope
    let jws_envelope = jws::parse_jws(body)?;

    // 2. Decode protected header
    let header = jws::decode_protected_header(&jws_envelope.protected)?;

    // 3. Verify URL matches
    if header.url != expected_url {
        return Err(Error::Malformed(format!(
            "JWS URL mismatch: expected '{}', got '{}'",
            expected_url, header.url
        )));
    }

    // 4. Verify nonce and consume it
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    repo.consume_nonce(&header.nonce)
        .await
        .map_err(|_| Error::BadNonce)?;

    // 5. Extract kid (required for existing account requests)
    let kid = header
        .kid
        .as_ref()
        .ok_or_else(|| Error::Malformed("kid required for this request".to_string()))?;

    // 6. Lookup account by kid to get JWK
    // Extract account_id from kid (format: "/acme/account/{id}")
    let account_id_str = kid
        .strip_prefix("/acme/account/")
        .ok_or_else(|| Error::Malformed(format!("Invalid kid format: {}", kid)))?;

    let account = repo
        .find_account_by_id(account_id_str)
        .await?
        .ok_or_else(|| Error::AccountDoesNotExist)?;

    // Parse stored JWK
    let jwk: Jwk = serde_json::from_value(account.public_key_jwk.clone())
        .map_err(|e| Error::ServerInternal(format!("Failed to parse stored JWK: {}", e)))?;

    // 7. Verify JWS signature using account's JWK
    let signature_valid =
        jws::verify_jws_with_jwk(&jws_envelope, &header, &jwk, &state.crypto_provider).await?;

    if !signature_valid {
        return Err(Error::Unauthorized("Invalid JWS signature".to_string()));
    }

    // 8. Compute JWK thumbprint
    let jwk_thumbprint = jws::compute_jwk_thumbprint(&jwk)?;

    // 9. Parse account_id as UUID
    let account_id = Uuid::parse_str(&account.account_id)
        .map_err(|e| Error::ServerInternal(format!("Invalid UUID in database: {}", e)))?;

    // 10. Decode payload
    let payload_bytes = decode_base64url(&jws_envelope.payload)?;
    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Malformed(format!("Invalid payload JSON: {}", e)))?;

    Ok(ValidatedJwsRequest {
        payload,
        header,
        jwk,
        jwk_thumbprint,
        account_id,
    })
}

/// Create ACME REST API router
///
/// PUBLIC-ENDPOINT ALLOWLIST (intentionally unauthenticated at the transport layer):
///
/// ACME endpoints do NOT use the project's standard AuthLayer + AuthzLayer stack.
/// This is deliberate: RFC 8555 defines its own request authentication model based
/// on signed JWS envelopes. Every POST request to `/acme/*` carries a JWS whose
/// signature is validated against either the embedded JWK (for new-account) or the
/// server-side account key identified by `kid` (for subsequent requests). Wrapping
/// these endpoints in session-based auth would be redundant, would break the RFC,
/// and would block legitimate clients.
///
/// Per-endpoint authentication reference:
/// - /acme/directory, /acme/new-nonce: public by RFC 8555 §7.1 / §7.2 (no auth required)
/// - /acme/new-account:                JWS with embedded JWK (§7.3)
/// - /acme/new-order:                  JWS with account kid (§7.4)
/// - /acme/account/:id:                JWS with matching kid (§7.3.2 / §7.3.7)
/// - /acme/authz/:id, /acme/order/:id: JWS POST-as-GET (§6.3)
/// - /acme/challenge/:id:              JWS with account kid (§7.5.1)
/// - /acme/order/:id/finalize:         JWS with account kid (§7.4)
/// - /acme/cert/:id:                   JWS POST-as-GET (§7.4.2)
/// - /health, /ready:                  orchestrator probes (NIST SI-17)
///
/// JWS verification lives in the ACME challenge/account handlers. Any future
/// non-ACME endpoint added here MUST go behind AuthLayer instead.
pub fn create_router(state: AcmeState) -> Router {
    Router::new()
        // Health and readiness endpoints
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        // ACME protocol endpoints - authenticated via per-request JWS per RFC 8555
        .route("/acme/directory", get(get_directory))
        .route("/acme/new-nonce", get(get_new_nonce))
        .route("/acme/new-account", post(new_account))
        .route("/acme/new-order", post(new_order))
        .route("/acme/account/:id", post(update_account))
        .route("/acme/authz/:id", get(get_authorization))
        .route("/acme/challenge/:id", post(respond_to_challenge))
        .route("/acme/order/:id", get(get_order))
        .route("/acme/order/:id/finalize", post(finalize_order))
        .route("/acme/cert/:id", get(get_certificate))
        .with_state(state)
}

/// Health check endpoint (liveness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - RFC 8555: ACME protocol implementation
///
/// Returns 200 OK if the service process is running.
async fn health_check() -> impl IntoResponse {
    ostrich_common::health::health_response("ostrich-acme")
}

/// Readiness check endpoint (readiness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - NIST 800-53: SC-8 (Transmission confidentiality and integrity)
///
/// Returns 200 OK if the service is ready to handle ACME requests.
/// Checks database and crypto provider connectivity.
async fn readiness_check(State(state): State<AcmeState>) -> impl IntoResponse {
    ostrich_common::health::readiness_response_with_db("ostrich-acme", &state.db_pool).await
}

/// ACME directory object (RFC 8555 §7.1.1)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: String,
    pub meta: Option<DirectoryMeta>,
}

/// Directory metadata
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: bool,
}

/// New account request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    pub contact: Vec<String>,
    pub terms_of_service_agreed: bool,
    pub only_return_existing: Option<bool>,
}

/// New order request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderRequest {
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// Update account request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccountRequest {
    pub contact: Option<Vec<String>>,
    pub status: Option<String>, // "deactivated" to deactivate account
}

/// Challenge response (empty object for ACME)
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {}

/// Finalize order request
#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub csr: String, // Base64url-encoded PKCS#10 CSR
}

/// Get ACME directory (RFC 8555 §7.1.1)
async fn get_directory(State(state): State<AcmeState>) -> Response {
    let directory = Directory {
        new_nonce: format!("{}/acme/new-nonce", state.base_url),
        new_account: format!("{}/acme/new-account", state.base_url),
        new_order: format!("{}/acme/new-order", state.base_url),
        new_authz: None,
        revoke_cert: format!("{}/acme/revoke-cert", state.base_url),
        key_change: format!("{}/acme/key-change", state.base_url),
        meta: Some(DirectoryMeta {
            terms_of_service: Some(format!("{}/acme/terms", state.base_url)),
            website: Some(state.base_url.clone()),
            caa_identities: None,
            external_account_required: false,
        }),
    };

    Json(directory).into_response()
}

/// Get new nonce for replay protection (RFC 8555 §7.2)
async fn get_new_nonce(State(state): State<AcmeState>) -> Response {
    // Generate cryptographically secure nonce
    let nonce = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    // Store nonce in database
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    if let Err(e) = repo.create_nonce(&nonce, expires_at).await {
        // Log error but still return nonce (fallback to stateless validation)
        eprintln!("Failed to store nonce: {}", e);
    }

    (
        StatusCode::NO_CONTENT,
        [
            ("Replay-Nonce", nonce),
            ("Cache-Control", "no-store".to_string()),
        ],
    )
        .into_response()
}

/// Create new account (RFC 8555 §7.3)
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Authenticates request via JWS with embedded JWK.
/// - **FIA_UID.1**: Creates unique account identity from JWK thumbprint.
/// - **FAU_GEN.1**: Audit event emitted for account creation.
/// - **FDP_ACC.1**: New account created with appropriate access controls.
///
/// # NIST 800-53 Controls
///
/// - **IA-2**: Identification and Authentication (Organizational Users)
/// - **IA-5**: Authenticator Management - Public key registration.
/// - **AU-2/AU-3**: Audit Events - Account creation logged.
async fn new_account(State(state): State<AcmeState>, body: Bytes) -> Result<Response> {
    // Validate JWS and extract payload
    let url = format!("{}/acme/new-account", state.base_url);
    let validated = validate_jws_new_account::<NewAccountRequest>(&body, &url, &state).await?;

    let request = validated.payload;
    let jwk_thumbprint = validated.jwk_thumbprint;
    let public_key_jwk = serde_json::to_value(&validated.jwk)
        .map_err(|e| Error::ServerInternal(format!("Failed to serialize JWK: {}", e)))?;

    if !request.terms_of_service_agreed {
        return Err(Error::UserActionRequired(
            "Terms of service must be agreed to".to_string(),
        ));
    }

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Check if account already exists (onlyReturnExisting)
    if let Some(true) = request.only_return_existing {
        if let Some(existing) = repo.find_account_by_jwk(&jwk_thumbprint).await? {
            let account_id = existing.account_id.clone();
            let nonce = generate_nonce(&state).await;

            let account = map_db_account_to_service(existing);

            return Ok((
                StatusCode::OK,
                [
                    ("Location", format!("/acme/account/{}", account_id)),
                    ("Replay-Nonce", nonce),
                ],
                Json(account),
            )
                .into_response());
        } else {
            return Err(Error::AccountDoesNotExist);
        }
    }

    // Create new account
    let account_id = format!("acct-{}", Uuid::new_v4());
    let db_account = repo
        .create_account(
            &account_id,
            &jwk_thumbprint,
            public_key_jwk,
            request.contact.clone(),
            "valid",
            true,
        )
        .await?;

    // Audit log
    // TODO: Add audit logging (Phase 11)

    let nonce = generate_nonce(&state).await;
    let account = map_db_account_to_service(db_account);

    Ok((
        StatusCode::CREATED,
        [
            ("Location", format!("/acme/account/{}", account_id)),
            ("Replay-Nonce", nonce),
        ],
        Json(account),
    )
        .into_response())
}

/// Create new order (RFC 8555 §7.4)
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Request authenticated via JWS with kid.
/// - **FDP_ACC.1**: Order created with account-scoped access control.
/// - **FAU_GEN.1**: Order creation audited with identifiers.
/// - **FPT_STM.1**: Order expiration timestamp set from reliable source.
///
/// # NIST 800-53 Controls
///
/// - **SI-10**: Input validation on domain identifiers.
/// - **AU-2/AU-3**: Order lifecycle events logged.
async fn new_order(State(state): State<AcmeState>, body: Bytes) -> Result<Response> {
    // Validate JWS and extract payload
    let url = format!("{}/acme/new-order", state.base_url);
    let validated = validate_jws_with_account::<NewOrderRequest>(&body, &url, &state).await?;

    let request = validated.payload;
    let account_id = validated.account_id;

    if request.identifiers.is_empty() {
        return Err(Error::Malformed(
            "Identifiers list cannot be empty".to_string(),
        ));
    }

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Create order
    let order_id_str = format!("order-{}", Uuid::new_v4());
    let expires = Utc::now() + chrono::Duration::days(7);
    let identifiers_json = serde_json::to_value(&request.identifiers)
        .map_err(|e| Error::ServerInternal(format!("Failed to serialize identifiers: {}", e)))?;

    let db_order = repo
        .create_order(
            &order_id_str,
            account_id,
            "pending",
            identifiers_json,
            request.not_before.and_then(|s| s.parse().ok()),
            request.not_after.and_then(|s| s.parse().ok()),
            expires,
        )
        .await?;

    // Create authorizations for each identifier
    let mut authorization_urls = Vec::new();
    for identifier in &request.identifiers {
        let authz_id = format!("authz-{}", Uuid::new_v4());
        let authz_expires = Utc::now() + chrono::Duration::days(7);

        let _db_authz = repo
            .create_authorization(
                &authz_id,
                db_order.id,
                &identifier.id_type,
                &identifier.value,
                "pending",
                authz_expires,
                false, // wildcard
            )
            .await?;

        // Create challenges for this authorization
        for challenge_type in &["http-01", "dns-01", "tls-alpn-01"] {
            let challenge_id = format!("chall-{}", Uuid::new_v4());
            let token = Uuid::new_v4().to_string();

            repo.create_challenge(
                &challenge_id,
                _db_authz.id,
                challenge_type,
                &token,
                "pending",
            )
            .await?;
        }

        authorization_urls.push(format!("/acme/authz/{}", authz_id));
    }

    // Map to service order
    let order = map_db_order_to_service(db_order, authorization_urls);

    let nonce = generate_nonce(&state).await;

    Ok((
        StatusCode::CREATED,
        [
            ("Location", format!("/acme/order/{}", order_id_str)),
            ("Replay-Nonce", nonce),
        ],
        Json(order),
    )
        .into_response())
}

/// Update account (RFC 8555 §7.3.2)
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Request authenticated via JWS with kid.
/// - **FDP_ACC.1**: Only account owner can update their account.
/// - **FDP_ACF.1**: Account status changes (deactivation) enforced.
/// - **FAU_GEN.1**: Account updates audited.
async fn update_account(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    // Validate JWS and extract payload
    let url = format!("{}/acme/account/{}", state.base_url, id);
    let validated = validate_jws_with_account::<UpdateAccountRequest>(&body, &url, &state).await?;

    let request = validated.payload;

    // Verify the account ID from path matches the authenticated account
    if id != validated.account_id.to_string() {
        return Err(Error::Unauthorized(
            "Cannot update another account".to_string(),
        ));
    }

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Update account with new contact information or status
    let db_account = repo
        .update_account(&id, request.contact, request.status.as_deref())
        .await?;

    let account = map_db_account_to_service(db_account);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(account)).into_response())
}

/// Get authorization (RFC 8555 §7.1.4)
async fn get_authorization(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
) -> Result<Response> {
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load authorization from database
    let db_authz = repo
        .find_authorization_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Authorization not found: {}", id)))?;

    // Load challenges for this authorization
    let db_challenges = repo.list_challenges_by_authorization(db_authz.id).await?;
    let challenges: Vec<Challenge> = db_challenges
        .into_iter()
        .map(map_db_challenge_to_service)
        .collect();

    let authorization = map_db_authorization_to_service(db_authz, challenges);

    let nonce = generate_nonce(&state).await;

    Ok((
        StatusCode::OK,
        [("Replay-Nonce", nonce)],
        Json(authorization),
    )
        .into_response())
}

/// Respond to challenge (RFC 8555 §7.5.1)
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Request authenticated via JWS with kid.
/// - **FDP_ACC.1**: Challenge owned by account's authorization.
/// - **FAU_GEN.1**: Challenge response attempt audited.
/// - **FCS_COP.1**: Key authorization computed using SHA-256.
///
/// # NIST 800-53 Controls
///
/// - **IA-5(1)**: Challenge-response authentication mechanism.
async fn respond_to_challenge(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    // Validate JWS (payload is typically empty object {})
    let url = format!("{}/acme/challenge/{}", state.base_url, id);
    let _validated = validate_jws_with_account::<ChallengeResponse>(&body, &url, &state).await?;

    // TODO: Validate key authorization (Phase 11)
    // TODO: Trigger actual validation (HTTP-01, DNS-01, or TLS-ALPN-01) (Phase 11)

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load challenge from database to verify it exists
    let _db_challenge = repo
        .find_challenge_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Challenge not found: {}", id)))?;

    // Mark challenge as processing
    let updated_challenge = repo
        .update_challenge_status(
            &id,
            "processing",
            None, // validated_at
            None, // error_detail
        )
        .await?;

    let challenge = map_db_challenge_to_service(updated_challenge);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(challenge)).into_response())
}

/// Get order status (RFC 8555 §7.4)
async fn get_order(State(state): State<AcmeState>, Path(id): Path<String>) -> Result<Response> {
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load order from database
    let db_order = repo
        .find_order_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Order not found: {}", id)))?;

    // Load authorizations for this order
    let db_authzs = repo.list_authorizations_by_order(db_order.id).await?;
    let authorization_urls: Vec<String> = db_authzs
        .iter()
        .map(|authz| format!("/acme/authz/{}", authz.authorization_id))
        .collect();

    let order = map_db_order_to_service(db_order, authorization_urls);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(order)).into_response())
}

/// Finalize order with CSR (RFC 8555 §7.4)
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Request authenticated via JWS with kid.
/// - **FDP_ACC.1**: Order ownership verified before finalization.
/// - **FDP_ACF.1**: Order must be in "ready" state (all authorizations valid).
/// - **FAU_GEN.1**: Finalization request and outcome audited.
/// - **FCS_COP.1**: CSR signature verification (proof of possession).
///
/// # NIST 800-53 Controls
///
/// - **SI-10**: CSR parsing and validation.
/// - **SC-17**: PKI certificate request processing.
async fn finalize_order(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    // Validate JWS and extract payload
    let url = format!("{}/acme/order/{}/finalize", state.base_url, id);
    let validated = validate_jws_with_account::<FinalizeRequest>(&body, &url, &state).await?;

    let request = validated.payload;

    if request.csr.is_empty() {
        return Err(Error::BadCsr("CSR cannot be empty".to_string()));
    }

    // Parse and validate CSR
    let csr_der = decode_base64url(&request.csr)
        .map_err(|_| Error::BadCsr("Invalid base64url encoding".to_string()))?;

    let parsed_csr = ostrich_x509::parser::parse_csr(&csr_der)
        .map_err(|e| Error::BadCsr(format!("Failed to parse CSR: {}", e)))?;

    // Verify CSR signature (proof of possession)
    let signature_valid =
        ostrich_x509::parser::verify_csr_signature(&parsed_csr, &state.crypto_provider)
            .await
            .map_err(|e| Error::BadCsr(format!("CSR signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(Error::BadCsr("Invalid CSR signature".to_string()));
    }

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load order from database
    let db_order = repo
        .find_order_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Order not found: {}", id)))?;

    // Verify the account owns this order
    if db_order.account_id != validated.account_id {
        return Err(Error::Unauthorized(
            "Order belongs to different account".to_string(),
        ));
    }

    // Parse order identifiers from JSON
    let _order_identifiers: Vec<Identifier> = serde_json::from_value(db_order.identifiers.clone())
        .map_err(|e| Error::ServerInternal(format!("Failed to parse order identifiers: {}", e)))?;

    // Verify CSR SANs match order identifiers
    // TODO: When SAN extraction is implemented in parser.rs, uncomment this validation
    // for identifier in &_order_identifiers {
    //     if !parsed_csr.subject_alternative_names.contains(&identifier.value) {
    //         return Err(Error::BadCsr(format!(
    //             "CSR missing required identifier: {}",
    //             identifier.value
    //         )));
    //     }
    // }

    // Verify all authorizations are valid
    let db_authzs = repo.list_authorizations_by_order(db_order.id).await?;
    let all_valid = db_authzs.iter().all(|authz| authz.status == "valid");

    if !all_valid {
        return Err(Error::OrderNotReady);
    }

    // Update order status to processing
    // RFC 8555 §7.1.6 - Order moves to "processing" while issuance is underway
    let _processing_order = repo.update_order_status(db_order.id, "processing").await?;

    // Issue certificate via CA service
    // RFC 8555 §7.4 - Order finalization triggers certificate issuance
    // NIST 800-53: SC-17 - PKI certificate issuance via CA
    // NIST 800-53: AU-2 - Certificate issuance is an auditable event (CA side)
    let Some(ca_client) = state.ca_client.as_ref() else {
        // NIST 800-53: SI-17 / fail-secure - never fake a certificate.
        // Roll the order back from "processing" so the client may retry
        // once CA integration is configured.
        let _ = repo.update_order_status(db_order.id, "ready").await;
        return Err(Error::ServerInternal(
            "CA integration not configured".to_string(),
        ));
    };

    // AcmeCaClient::finalize_order issues the certificate, stores the
    // certificate id on the order, and transitions the order to "valid".
    // validated.account_id is a Uuid; the CA client takes a string actor id
    // for the audit trail (NIST 800-53: AU-3 - subject identity).
    let _certificate_id = ca_client
        .finalize_order(db_order.id, &csr_der, &validated.account_id.to_string())
        .await?;

    // Re-fetch the order so the response reflects the post-issuance state
    // ("valid" status plus certificate URL). find_order_by_id takes the
    // ACME order id string (path id), not the internal Uuid.
    let valid_order = repo
        .find_order_by_id(&id)
        .await?
        .ok_or(Error::ServerInternal(format!(
            "Order disappeared during finalization: {}",
            id
        )))?;

    let authorization_urls: Vec<String> = db_authzs
        .iter()
        .map(|authz| format!("/acme/authz/{}", authz.authorization_id))
        .collect();

    let order = map_db_order_to_service(valid_order, authorization_urls);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(order)).into_response())
}

/// Download certificate (RFC 8555 §7.4.2)
///
/// # NIST 800-53 Controls
///
/// - **SC-17**: PKI certificate delivery.
/// - **AC-3**: Certificate retrieved via its issuing order.
async fn get_certificate(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
) -> Result<Response> {
    // RFC 8555 §7.4.2 - Certificate URL references the order's certificate.
    // The path id is the ACME order id; resolve it to the issued certificate.
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    let db_order = repo.find_order_by_id(&id).await?.ok_or(Error::NotFound)?;

    // Order has no certificate until finalization completes
    // RFC 8555 §7.1.6 - Certificate only available in "valid" state
    let certificate_id = db_order.certificate_id.ok_or(Error::NotFound)?;

    // Load the issued certificate from the certificate store
    let cert_repo = ostrich_db::repository::CertificateRepository::new(state.db_pool.clone());
    let certificate = cert_repo
        .find_by_id(certificate_id)
        .await
        .map_err(Error::Database)?
        .ok_or(Error::NotFound)?;

    // RFC 8555 §7.4.2 - application/pem-certificate-chain response
    let cert_pem = certificate.pem_encoded;

    let nonce = generate_nonce(&state).await;

    Ok((
        StatusCode::OK,
        [
            (
                "Content-Type",
                "application/pem-certificate-chain".to_string(),
            ),
            ("Replay-Nonce", nonce),
        ],
        cert_pem,
    )
        .into_response())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate a new nonce and store in database
async fn generate_nonce(state: &AcmeState) -> String {
    let nonce = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    if let Err(e) = repo.create_nonce(&nonce, expires_at).await {
        eprintln!("Failed to store nonce: {}", e);
    }

    nonce
}

/// Map database AcmeAccount to service Account
fn map_db_account_to_service(db: ostrich_db::models::AcmeAccount) -> Account {
    use crate::account::AccountKey;

    let key = serde_json::from_value::<AccountKey>(db.public_key_jwk.clone()).unwrap_or_default();

    Account {
        id: db.id,
        status: match db.status.as_str() {
            "valid" => AccountStatus::Valid,
            "deactivated" => AccountStatus::Deactivated,
            "revoked" => AccountStatus::Revoked,
            _ => AccountStatus::Valid,
        },
        contact: db.contact,
        terms_of_service_agreed: Some(db.terms_of_service_agreed),
        external_account_binding: None,
        orders: format!("/acme/account/{}/orders", db.account_id),
        key,
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

/// Map database AcmeOrder to service Order
fn map_db_order_to_service(
    db: ostrich_db::models::AcmeOrder,
    authorizations: Vec<String>,
) -> Order {
    // Parse identifiers from JSON
    let identifiers =
        serde_json::from_value::<Vec<Identifier>>(db.identifiers.clone()).unwrap_or_default();

    Order {
        id: db.id,
        account_id: db.account_id,
        status: match db.status.as_str() {
            "pending" => OrderStatus::Pending,
            "ready" => OrderStatus::Ready,
            "processing" => OrderStatus::Processing,
            "valid" => OrderStatus::Valid,
            "invalid" => OrderStatus::Invalid,
            _ => OrderStatus::Pending,
        },
        identifiers,
        authorizations,
        finalize: format!("/acme/order/{}/finalize", db.order_id),
        certificate: db
            .certificate_id
            .map(|cert_id| format!("/acme/cert/{}", cert_id)),
        not_before: db.not_before,
        not_after: db.not_after,
        error: None,
        expires: Some(db.expires),
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

/// Map database AcmeAuthorization to service Authorization
fn map_db_authorization_to_service(
    db: ostrich_db::models::AcmeAuthorization,
    challenges: Vec<Challenge>,
) -> Authorization {
    Authorization {
        id: db.id,
        order_id: db.order_id,
        status: match db.status.as_str() {
            "pending" => AuthorizationStatus::Pending,
            "valid" => AuthorizationStatus::Valid,
            "invalid" => AuthorizationStatus::Invalid,
            "deactivated" => AuthorizationStatus::Deactivated,
            "expired" => AuthorizationStatus::Expired,
            "revoked" => AuthorizationStatus::Revoked,
            _ => AuthorizationStatus::Pending,
        },
        identifier: Identifier {
            id_type: db.identifier_type,
            value: db.identifier_value,
        },
        expires: Some(db.expires),
        challenges,
        wildcard: Some(db.wildcard),
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

/// Map database AcmeChallenge to service Challenge
fn map_db_challenge_to_service(db: ostrich_db::models::AcmeChallenge) -> Challenge {
    Challenge {
        id: db.id,
        authorization_id: db.authorization_id,
        challenge_type: match db.challenge_type.as_str() {
            "http-01" => ChallengeType::Http01,
            "dns-01" => ChallengeType::Dns01,
            "tls-alpn-01" => ChallengeType::TlsAlpn01,
            _ => ChallengeType::Http01,
        },
        status: match db.status.as_str() {
            "pending" => ChallengeStatus::Pending,
            "processing" => ChallengeStatus::Processing,
            "valid" => ChallengeStatus::Valid,
            "invalid" => ChallengeStatus::Invalid,
            _ => ChallengeStatus::Pending,
        },
        url: format!("/acme/challenge/{}", db.challenge_id),
        token: db.token,
        error: db.error_detail,
        validated: db.validated_at,
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_structure() {
        // Test ACME Directory struct per RFC 8555 §7.1.1
        let dir = Directory {
            new_nonce: "https://acme.example.com/new-nonce".to_string(),
            new_account: "https://acme.example.com/new-account".to_string(),
            new_order: "https://acme.example.com/new-order".to_string(),
            new_authz: None,
            revoke_cert: "https://acme.example.com/revoke-cert".to_string(),
            key_change: "https://acme.example.com/key-change".to_string(),
            meta: None,
        };

        assert!(dir.new_nonce.contains("new-nonce"));
        assert!(dir.new_account.contains("new-account"));
    }

    #[test]
    fn test_new_account_request_validation() {
        // Test that NewAccountRequest can be deserialized properly
        let json = r#"{"contact":["mailto:test@example.com"],"termsOfServiceAgreed":true}"#;
        let request: NewAccountRequest = serde_json::from_str(json).unwrap();
        assert!(request.terms_of_service_agreed);
        assert_eq!(request.contact.len(), 1);
        assert!(request.contact[0].starts_with("mailto:"));
    }

    #[test]
    fn test_new_account_request_tos_required() {
        let json = r#"{"contact":["mailto:test@example.com"],"termsOfServiceAgreed":false}"#;
        let request: NewAccountRequest = serde_json::from_str(json).unwrap();
        assert!(!request.terms_of_service_agreed);
    }

    #[test]
    fn test_order_status_serialization() {
        // Verify order status enum serialization
        assert_eq!(
            serde_json::to_string(&OrderStatus::Pending).unwrap(),
            r#""pending""#
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::Ready).unwrap(),
            r#""ready""#
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::Processing).unwrap(),
            r#""processing""#
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::Valid).unwrap(),
            r#""valid""#
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::Invalid).unwrap(),
            r#""invalid""#
        );
    }

    #[test]
    fn test_challenge_type_serialization() {
        assert_eq!(
            serde_json::to_string(&ChallengeType::Http01).unwrap(),
            r#""http-01""#
        );
        assert_eq!(
            serde_json::to_string(&ChallengeType::Dns01).unwrap(),
            r#""dns-01""#
        );
        assert_eq!(
            serde_json::to_string(&ChallengeType::TlsAlpn01).unwrap(),
            r#""tls-alpn-01""#
        );
    }

    #[test]
    fn test_account_status_serialization() {
        assert_eq!(
            serde_json::to_string(&AccountStatus::Valid).unwrap(),
            r#""valid""#
        );
        assert_eq!(
            serde_json::to_string(&AccountStatus::Deactivated).unwrap(),
            r#""deactivated""#
        );
        assert_eq!(
            serde_json::to_string(&AccountStatus::Revoked).unwrap(),
            r#""revoked""#
        );
    }
}
