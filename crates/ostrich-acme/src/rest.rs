//! ACME REST API
//!
//! RFC 8555: ACME protocol HTTP endpoints

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
}

impl AcmeState {
    /// Create new ACME service state
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

/// Validated JWS request with decoded payload
///
/// This structure holds the result of successful JWS validation
struct ValidatedJwsRequest<T> {
    /// Decoded payload
    payload: T,
    /// Protected header
    header: ProtectedHeader,
    /// JWK from header (for new-account) or retrieved from database (for other requests)
    jwk: Jwk,
    /// JWK thumbprint for account identification
    jwk_thumbprint: String,
}

/// Validate JWS request for new-account endpoint
///
/// RFC 8555 §6.2: All ACME requests with a non-empty body MUST encapsulate
/// the request in a JWS object, signed using the account's key pair.
///
/// For new-account, the JWK must be in the protected header.
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
    })
}

/// Validate JWS request for existing account endpoints
///
/// RFC 8555 §6.2: For requests from an existing account, the JWS MUST be
/// signed with the account's key pair, and the "kid" field MUST be present.
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
    let account_id = kid
        .strip_prefix("/acme/account/")
        .ok_or_else(|| Error::Malformed(format!("Invalid kid format: {}", kid)))?;

    let account = repo
        .find_account_by_id(account_id)
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

    // 9. Decode payload
    let payload_bytes = decode_base64url(&jws_envelope.payload)?;
    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Malformed(format!("Invalid payload JSON: {}", e)))?;

    Ok(ValidatedJwsRequest {
        payload,
        header,
        jwk,
        jwk_thumbprint,
    })
}

/// Create ACME REST API router
pub fn create_router(state: AcmeState) -> Router {
    Router::new()
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

/// Finalize order request
#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub csr: String, // Base64url-encoded PKCS#10 CSR
}

/// Get ACME directory (RFC 8555 §7.1.1)
async fn get_directory() -> Response {
    let directory = Directory {
        new_nonce: "/acme/new-nonce".to_string(),
        new_account: "/acme/new-account".to_string(),
        new_order: "/acme/new-order".to_string(),
        new_authz: None,
        revoke_cert: "/acme/revoke-cert".to_string(),
        key_change: "/acme/key-change".to_string(),
        meta: Some(DirectoryMeta {
            terms_of_service: Some("https://example.com/acme/terms".to_string()),
            website: Some("https://example.com".to_string()),
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
/// NIST 800-53: IA-2 - Identification and Authentication
async fn new_account(State(state): State<AcmeState>, body: Bytes) -> Result<Response> {
    // Validate JWS and extract payload
    let validated = validate_jws_new_account::<NewAccountRequest>(
        &body,
        "https://example.com/acme/new-account", // TODO: Get actual URL from request
        &state,
    )
    .await?;

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
async fn new_order(
    State(state): State<AcmeState>,
    Json(request): Json<NewOrderRequest>,
) -> Result<Response> {
    // TODO: Validate JWS signature (Phase 11)
    // TODO: Verify account exists (Phase 11)
    // For now, use placeholder account ID
    let account_id = Uuid::new_v4();

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
async fn update_account(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
) -> Result<Response> {
    // TODO: Validate JWS signature (Phase 11)
    // TODO: Extract updated contact info from request body (Phase 11)
    // For now, just load and return existing account

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load account from database
    let db_account = repo
        .find_account_by_id(&id)
        .await?
        .ok_or(Error::AccountDoesNotExist)?;

    // TODO: Update contact information when request parsing is implemented
    // let updated_account = repo.update_account(&id, Some(new_contact), None).await?;

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
async fn respond_to_challenge(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
) -> Result<Response> {
    // TODO: Validate JWS signature (Phase 11)
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
async fn finalize_order(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    Json(request): Json<FinalizeRequest>,
) -> Result<Response> {
    // TODO: Validate JWS signature (Phase 11)
    // TODO: Parse and validate CSR (Phase 11)
    // TODO: Verify SANs match order identifiers (Phase 11)
    // TODO: Issue certificate via CA service (Phase 12)

    if request.csr.is_empty() {
        return Err(Error::BadCsr("CSR cannot be empty".to_string()));
    }

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load order from database
    let db_order = repo
        .find_order_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Order not found: {}", id)))?;

    // Verify all authorizations are valid
    let db_authzs = repo.list_authorizations_by_order(db_order.id).await?;
    let all_valid = db_authzs.iter().all(|authz| authz.status == "valid");

    if !all_valid {
        return Err(Error::OrderNotReady);
    }

    // Update order status to processing, then to valid
    let _processing_order = repo.update_order_status(&id, "processing", None).await?;

    // TODO: Actually issue certificate via CA (Phase 12)
    // For now, simulate certificate issuance
    let cert_id = Uuid::new_v4();
    let valid_order = repo
        .update_order_status(&id, "valid", Some(cert_id))
        .await?;

    let authorization_urls: Vec<String> = db_authzs
        .iter()
        .map(|authz| format!("/acme/authz/{}", authz.authorization_id))
        .collect();

    let order = map_db_order_to_service(valid_order, authorization_urls);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(order)).into_response())
}

/// Download certificate (RFC 8555 §7.4.2)
async fn get_certificate(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
) -> Result<Response> {
    // TODO: Load certificate from database (Phase 12 - CA integration)
    // TODO: Return actual PEM-encoded certificate chain (Phase 12)

    // For now, return placeholder certificate
    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n\
         MIICertificatePlaceholder{}\n\
         -----END CERTIFICATE-----\n",
        id
    );

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

    #[tokio::test]
    async fn test_get_directory() {
        let response = get_directory().await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_new_nonce() {
        let response = get_new_nonce().await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_new_account_requires_tos() {
        let state = AcmeState::new();
        let request = NewAccountRequest {
            contact: vec!["mailto:test@example.com".to_string()],
            terms_of_service_agreed: false,
            only_return_existing: None,
        };

        let result = new_account(State(state), Json(request)).await;
        assert!(result.is_err());
    }
}
