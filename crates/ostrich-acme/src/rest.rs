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
    /// HTTP-01 fetch port (RFC 8555 §8.3 mandates 80; overridable for dev/E2E)
    pub http01_port: u16,
    /// Permit private-IP/localhost identifiers (disables the SI-10 SSRF
    /// guard). Dev/E2E ONLY.
    pub allow_private_ip_domains: bool,
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
            http01_port: 80,
            allow_private_ip_domains: false,
        }
    }

    /// Override challenge-validation options for dev/E2E environments.
    ///
    /// SECURITY: `allow_private_ip_domains` disables SSRF protection and a
    /// non-80 port deviates from RFC 8555 §8.3. Production keeps the defaults.
    pub fn with_challenge_options(
        mut self,
        http01_port: u16,
        allow_private_ip_domains: bool,
    ) -> Self {
        self.http01_port = http01_port;
        self.allow_private_ip_domains = allow_private_ip_domains;
        self
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

    // 4. Verify nonce and consume it (replay protection - RFC 8555 §6.5).
    // consume_nonce returns false when the nonce is unknown, expired, or already
    // used (a replay); that case MUST be rejected, not just DB errors.
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    let nonce_ok = repo
        .consume_nonce(&header.nonce)
        .await
        .map_err(|_| Error::BadNonce)?;
    if !nonce_ok {
        return Err(Error::BadNonce);
    }

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

/// A kid-authenticated JWS request validated down to (but excluding) its
/// payload. Shared by payload-carrying requests and POST-as-GET (RFC 8555 §6.3).
struct VerifiedJwsAccount {
    header: ProtectedHeader,
    jwk: Jwk,
    jwk_thumbprint: String,
    /// Account primary key (UUID) for ownership checks.
    account_id: Uuid,
    /// The JWS payload, still base64url-encoded (empty for POST-as-GET).
    payload_b64: String,
}

/// Validate a kid-authenticated JWS request: envelope, URL, nonce (consumed for
/// replay protection), account lookup by kid, and signature — everything except
/// the payload. RFC 8555 §6.2 (requests from an existing account).
///
/// COMPLIANCE: NIAP FIA_UAU.1 (JWS signature auth), FIA_UID.1 (account via kid),
/// FDP_ACC.1 (account owns the resource), FCS_COP.1 (signature verification);
/// NIST SC-23 (nonce consumption prevents replay).
async fn verify_jws_account(
    body: &[u8],
    expected_url: &str,
    state: &AcmeState,
) -> Result<VerifiedJwsAccount> {
    let jws_envelope = jws::parse_jws(body)?;
    let header = jws::decode_protected_header(&jws_envelope.protected)?;

    if header.url != expected_url {
        return Err(Error::Malformed(format!(
            "JWS URL mismatch: expected '{}', got '{}'",
            expected_url, header.url
        )));
    }

    // Replay protection (RFC 8555 §6.5): a false result means the nonce was
    // unknown/expired/already used.
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    let nonce_ok = repo
        .consume_nonce(&header.nonce)
        .await
        .map_err(|_| Error::BadNonce)?;
    if !nonce_ok {
        return Err(Error::BadNonce);
    }

    let kid = header
        .kid
        .as_ref()
        .ok_or_else(|| Error::Malformed("kid required for this request".to_string()))?;

    // RFC 8555 §6.2: `kid` is the (absolute) account URL. Accept either the full
    // URL (e.g. "https://host/acme/account/acct-<uuid>") or a relative path by
    // taking the final path segment as the account id — account ids contain no
    // '/'. (Required now that the server emits absolute URLs per §7.1.)
    let account_id_str = kid
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Malformed(format!("Invalid kid: {}", kid)))?;

    let account = repo
        .find_account_by_id(account_id_str)
        .await?
        .ok_or(Error::AccountDoesNotExist)?;

    let jwk: Jwk = serde_json::from_value(account.public_key_jwk.clone())
        .map_err(|e| Error::ServerInternal(format!("Failed to parse stored JWK: {}", e)))?;

    let signature_valid =
        jws::verify_jws_with_jwk(&jws_envelope, &header, &jwk, &state.crypto_provider).await?;
    if !signature_valid {
        return Err(Error::Unauthorized("Invalid JWS signature".to_string()));
    }

    let jwk_thumbprint = jws::compute_jwk_thumbprint(&jwk)?;

    Ok(VerifiedJwsAccount {
        header,
        jwk,
        jwk_thumbprint,
        account_id: account.id,
        payload_b64: jws_envelope.payload,
    })
}

async fn validate_jws_with_account<T: serde::de::DeserializeOwned>(
    body: &[u8],
    expected_url: &str,
    state: &AcmeState,
) -> Result<ValidatedJwsRequest<T>> {
    let v = verify_jws_account(body, expected_url, state).await?;

    let payload_bytes = decode_base64url(&v.payload_b64)?;
    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Malformed(format!("Invalid payload JSON: {}", e)))?;

    Ok(ValidatedJwsRequest {
        payload,
        header: v.header,
        jwk: v.jwk,
        jwk_thumbprint: v.jwk_thumbprint,
        account_id: v.account_id,
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
        .route("/acme/account/{id}", post(update_account))
        // RFC 8555 §6.3: orders, authorizations, and certificates are fetched
        // via POST-as-GET (signed JWS, empty payload). GET is kept for
        // convenience/debugging; strict clients (lego, certbot) use POST.
        .route(
            "/acme/authz/{id}",
            get(get_authorization).post(post_as_get_authorization),
        )
        .route("/acme/challenge/{id}", post(respond_to_challenge))
        .route("/acme/order/{id}", get(get_order).post(post_as_get_order))
        .route("/acme/order/{id}/finalize", post(finalize_order))
        .route(
            "/acme/cert/{id}",
            get(get_certificate).post(post_as_get_certificate),
        )
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

/// New account request (RFC 8555 §7.3).
///
/// Every member is optional: `contact` and `termsOfServiceAgreed` are OPTIONAL
/// per §7.3, and a key-lookup request (`onlyReturnExisting`, §7.3.1) legitimately
/// sends neither — e.g. lego's "resolve account by key" probe. Requiring them
/// rejected real clients with a malformed-request error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    #[serde(default)]
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

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // RFC 8555 §7.3.1: a key-lookup (onlyReturnExisting) returns the existing
    // account or `accountDoesNotExist`. It is NOT account creation, so it does
    // not require terms agreement — handle it before the terms-of-service gate.
    if let Some(true) = request.only_return_existing {
        if let Some(existing) = repo.find_account_by_jwk(&jwk_thumbprint).await? {
            let account_id = existing.account_id.clone();
            let nonce = generate_nonce(&state).await;

            let account = map_db_account_to_service(existing, &state.base_url);

            return Ok((
                StatusCode::OK,
                [
                    (
                        "Location",
                        format!("{}/acme/account/{}", state.base_url, account_id),
                    ),
                    ("Replay-Nonce", nonce),
                ],
                Json(account),
            )
                .into_response());
        } else {
            return Err(Error::AccountDoesNotExist);
        }
    }

    // RFC 8555 §7.3: creating a new account requires agreement to the terms.
    if !request.terms_of_service_agreed {
        return Err(Error::UserActionRequired(
            "Terms of service must be agreed to".to_string(),
        ));
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
    let account = map_db_account_to_service(db_account, &state.base_url);

    Ok((
        StatusCode::CREATED,
        [
            (
                "Location",
                format!("{}/acme/account/{}", state.base_url, account_id),
            ),
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

        authorization_urls.push(format!("{}/acme/authz/{}", state.base_url, authz_id));
    }

    // Map to service order
    let order = map_db_order_to_service(db_order, authorization_urls, &state.base_url);

    let nonce = generate_nonce(&state).await;

    Ok((
        StatusCode::CREATED,
        [
            (
                "Location",
                format!("{}/acme/order/{}", state.base_url, order_id_str),
            ),
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

    let account = map_db_account_to_service(db_account, &state.base_url);

    let nonce = generate_nonce(&state).await;

    Ok((StatusCode::OK, [("Replay-Nonce", nonce)], Json(account)).into_response())
}

// ---------------------------------------------------------------------------
// POST-as-GET handlers (RFC 8555 §6.3): authenticate the signed JWS (empty
// payload) via the account kid, then return the same body as the GET route.
// ---------------------------------------------------------------------------

async fn post_as_get_authorization(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    let url = format!("{}/acme/authz/{}", state.base_url, id);
    verify_jws_account(&body, &url, &state).await?;
    get_authorization(State(state), Path(id)).await
}

async fn post_as_get_order(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    let url = format!("{}/acme/order/{}", state.base_url, id);
    verify_jws_account(&body, &url, &state).await?;
    get_order(State(state), Path(id)).await
}

async fn post_as_get_certificate(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response> {
    let url = format!("{}/acme/cert/{}", state.base_url, id);
    verify_jws_account(&body, &url, &state).await?;
    get_certificate(State(state), Path(id)).await
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
        .map(|c| map_db_challenge_to_service(c, &state.base_url))
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

    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());

    // Load challenge from database to verify it exists
    let db_challenge = repo
        .find_challenge_by_id(&id)
        .await?
        .ok_or(Error::Malformed(format!("Challenge not found: {}", id)))?;

    // Mark challenge as processing; validation runs asynchronously and the
    // client polls for the result (RFC 8555 §7.5.1).
    let updated_challenge = repo
        .update_challenge_status(
            &id,
            "processing",
            None, // validated_at
            None, // error_detail
        )
        .await?;

    // RFC 8555 §7.5.1: the challenge response MUST carry a Link header with
    // rel="up" pointing to the authorization. Clients (lego, certbot) use it to
    // locate the authorization to poll after responding; without it the client
    // has no poll target and aborts. Resolve the authorization's public id from
    // the challenge's FK before the challenge value is moved into validation.
    let up_link = repo
        .find_authorization_by_uuid(db_challenge.authorization_id)
        .await?
        .map(|a| {
            format!(
                "<{}/acme/authz/{}>;rel=\"up\"",
                state.base_url, a.authorization_id
            )
        });

    // RFC 8555 §8.3/§8.4 - perform the actual domain-control validation.
    // NIAP PP-CA: FIA_UAU.1 - proof of identifier control before issuance.
    tokio::spawn(run_challenge_validation(state.clone(), db_challenge));

    let challenge = map_db_challenge_to_service(updated_challenge, &state.base_url);

    let nonce = generate_nonce(&state).await;

    let mut response = (StatusCode::OK, Json(challenge)).into_response();
    let headers = response.headers_mut();
    if let Ok(v) = axum::http::HeaderValue::from_str(&nonce) {
        headers.insert("Replay-Nonce", v);
    }
    if let Some(v) = up_link.and_then(|link| axum::http::HeaderValue::from_str(&link).ok()) {
        headers.insert(axum::http::header::LINK, v);
    }
    Ok(response)
}

/// Asynchronous challenge validation (RFC 8555 §7.5.1).
///
/// Walks the FK chain (challenge -> authorization -> order -> account),
/// runs the type-appropriate validator, then updates the RFC 8555 state
/// machines: challenge -> valid/invalid, authorization -> valid/invalid,
/// and order -> ready once every authorization is valid (§7.1.6).
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - identifier control proven before issuance
/// - NIST 800-53: IA-5(1) - challenge-response authentication
/// - NIST 800-53: AU-2 - validation outcome audited
async fn run_challenge_validation(state: AcmeState, challenge: ostrich_db::models::AcmeChallenge) {
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    let challenge_id = challenge.challenge_id.clone();

    let outcome = validate_challenge_inner(&state, &repo, &challenge).await;

    match outcome {
        Ok(()) => {
            tracing::info!(challenge_id = %challenge_id, "Challenge validation succeeded");
        }
        Err(e) => {
            tracing::warn!(challenge_id = %challenge_id, error = %e, "Challenge validation failed");
            let detail = serde_json::json!({
                "type": "urn:ietf:params:acme:error:unauthorized",
                "detail": e.to_string(),
            });
            let _ = repo
                .update_challenge_status(&challenge_id, "invalid", None, Some(detail))
                .await;
            // RFC 8555 §7.1.6: failed challenge invalidates the authorization
            if let Ok(Some(authz)) = repo
                .find_authorization_by_uuid(challenge.authorization_id)
                .await
            {
                let _ = repo
                    .update_authorization_status(&authz.authorization_id, "invalid")
                    .await;
            }
        }
    }

    // AU-2: audit the validation outcome
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::Authentication,
        "acme-validator",
        format!("acme:challenge:{}", challenge_id),
        "validate_challenge",
        if matches!(outcome_recorded(&repo, &challenge_id).await, Some(true)) {
            ostrich_audit::EventOutcome::Success
        } else {
            ostrich_audit::EventOutcome::Failure
        },
    )
    .build();
    let _ = state.audit_sink.record(&mut event).await;
}

/// Whether the challenge ended up valid (for the audit record).
async fn outcome_recorded(
    repo: &ostrich_db::repository::AcmeRepository,
    challenge_id: &str,
) -> Option<bool> {
    repo.find_challenge_by_id(challenge_id)
        .await
        .ok()
        .flatten()
        .map(|c| c.status == "valid")
}

/// The fallible part of challenge validation.
async fn validate_challenge_inner(
    state: &AcmeState,
    repo: &ostrich_db::repository::AcmeRepository,
    challenge: &ostrich_db::models::AcmeChallenge,
) -> Result<()> {
    // Walk challenge -> authorization -> order -> account
    let authz = repo
        .find_authorization_by_uuid(challenge.authorization_id)
        .await?
        .ok_or_else(|| Error::ServerInternal("Authorization not found".to_string()))?;
    let order = repo
        .find_order_by_uuid(authz.order_id)
        .await?
        .ok_or_else(|| Error::ServerInternal("Order not found".to_string()))?;
    let account = repo
        .find_account_by_uuid(order.account_id)
        .await?
        .ok_or_else(|| Error::ServerInternal("Account not found".to_string()))?;

    let domain = &authz.identifier_value;
    let token = &challenge.token;
    let thumbprint = &account.jwk_thumbprint;

    // Run the type-appropriate validator (RFC 8555 §8)
    let valid = match challenge.challenge_type.as_str() {
        "http-01" => {
            let mut validator =
                crate::validation::Http01Validator::new().with_http_port(state.http01_port);
            if state.allow_private_ip_domains {
                validator = validator.insecure_allow_private_domains();
            }
            validator.validate(domain, token, thumbprint).await?
        }
        "dns-01" => {
            crate::validation::Dns01Validator::new()
                .validate(domain, token, thumbprint)
                .await?
        }
        "tls-alpn-01" => {
            crate::validation::TlsAlpn01Validator::new()
                .validate(domain, token, thumbprint)
                .await?
        }
        other => {
            return Err(Error::Malformed(format!(
                "Unsupported challenge type: {}",
                other
            )));
        }
    };

    if !valid {
        return Err(Error::ChallengeValidation(
            "Challenge response did not match key authorization".to_string(),
        ));
    }

    // Challenge -> valid (RFC 8555 §7.1.6)
    repo.update_challenge_status(
        &challenge.challenge_id,
        "valid",
        Some(chrono::Utc::now()),
        None,
    )
    .await?;

    // Authorization -> valid
    repo.update_authorization_status(&authz.authorization_id, "valid")
        .await?;

    // Order -> ready once ALL authorizations are valid (RFC 8555 §7.1.6)
    let authzs = repo.list_authorizations_by_order(order.id).await?;
    if authzs.iter().all(|a| a.status == "valid") {
        repo.update_order_status(order.id, "ready").await?;
    }

    Ok(())
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
        .map(|authz| format!("{}/acme/authz/{}", state.base_url, authz.authorization_id))
        .collect();

    let order = map_db_order_to_service(db_order, authorization_urls, &state.base_url);

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
///
/// RFC 8555 §7.4 - the CSR MUST request EXACTLY the identifiers authorized in the
/// order. Set equality in both directions: every authorized identifier must
/// appear in the CSR, and the CSR must request nothing the order did not
/// authorize. Without this, a client that validated one identifier could obtain
/// a certificate for arbitrary others (authorization bypass).
fn validate_csr_identifiers(order_identifiers: &[Identifier], csr_sans: &[String]) -> Result<()> {
    let normalize = |ty: &str, val: &str| -> (String, String) {
        let ty = ty.to_ascii_lowercase();
        // DNS names are case-insensitive (RFC 4343); IPs compared verbatim.
        let val = if ty == "dns" {
            val.to_ascii_lowercase()
        } else {
            val.to_string()
        };
        (ty, val)
    };

    let authorized: std::collections::BTreeSet<(String, String)> = order_identifiers
        .iter()
        .map(|id| normalize(&id.id_type, &id.value))
        .collect();

    let mut requested = std::collections::BTreeSet::new();
    for san in csr_sans {
        let entry = if let Some(dns) = san.strip_prefix("DNS:") {
            normalize("dns", dns)
        } else if let Some(ip) = san.strip_prefix("IP:") {
            normalize("ip", ip)
        } else {
            // email/URI/otherName are not authorizable ACME identifiers; their
            // presence means the CSR requests something the order cannot grant.
            return Err(Error::Unauthorized(format!(
                "CSR contains a Subject Alternative Name that is not an authorized \
                 ACME identifier: {}",
                san
            )));
        };
        requested.insert(entry);
    }

    if authorized != requested {
        return Err(Error::Unauthorized(format!(
            "CSR identifiers do not match the order's authorized identifiers \
             (RFC 8555 §7.4): authorized {:?}, requested {:?}",
            authorized, requested
        )));
    }
    Ok(())
}

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

    // RFC 8555 §7.4 - the CSR MUST request EXACTLY the set of identifiers that
    // were authorized in the order. Without this binding, a client that proved
    // control of one identifier could submit a CSR for arbitrary OTHER
    // identifiers and obtain a certificate for them (a complete domain-control /
    // authorization bypass). The check is set equality in BOTH directions:
    // every authorized identifier must appear in the CSR, and the CSR must not
    // request any identifier the order did not authorize.
    //
    // COMPLIANCE: RFC 8555 §7.4; NIST 800-53 SI-10 / AC-3; NIAP PP-CA FIA_UAU.1.
    let order_identifiers: Vec<Identifier> = serde_json::from_value(db_order.identifiers.clone())
        .map_err(|e| {
        Error::ServerInternal(format!("Failed to parse order identifiers: {}", e))
    })?;

    validate_csr_identifiers(&order_identifiers, &parsed_csr.subject_alternative_names)?;

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
        .map(|authz| format!("{}/acme/authz/{}", state.base_url, authz.authorization_id))
        .collect();

    let order = map_db_order_to_service(valid_order, authorization_urls, &state.base_url);

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
fn map_db_account_to_service(db: ostrich_db::models::AcmeAccount, base_url: &str) -> Account {
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
        orders: format!("{}/acme/account/{}/orders", base_url, db.account_id),
        key,
        created_at: db.created_at,
        updated_at: db.updated_at,
    }
}

/// Map database AcmeOrder to service Order
fn map_db_order_to_service(
    db: ostrich_db::models::AcmeOrder,
    authorizations: Vec<String>,
    base_url: &str,
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
        finalize: format!("{}/acme/order/{}/finalize", base_url, db.order_id),
        // The /acme/cert/{id} handler resolves {id} as the ACME order id
        // (RFC 8555 §7.4.2 download), so the URL must carry the order id -
        // an earlier version emitted the internal certificate UUID here,
        // which 404'd.
        certificate: db
            .certificate_id
            .map(|_| format!("{}/acme/cert/{}", base_url, db.order_id)),
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
fn map_db_challenge_to_service(db: ostrich_db::models::AcmeChallenge, base_url: &str) -> Challenge {
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
        url: format!("{}/acme/challenge/{}", base_url, db.challenge_id),
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

    /// RFC 8555 §7.4 - the finalize CSR identifiers must exactly match the
    /// order's authorized identifiers (the authorization-bypass guard).
    #[test]
    fn test_validate_csr_identifiers() {
        let dns = |v: &str| Identifier {
            id_type: "dns".to_string(),
            value: v.to_string(),
        };
        let order = vec![dns("Example.com"), dns("www.example.com")];

        // Exact match, case-insensitive on DNS names -> accepted.
        assert!(
            validate_csr_identifiers(
                &order,
                &["DNS:example.com".into(), "DNS:WWW.Example.com".into()],
            )
            .is_ok()
        );

        // Missing an authorized identifier -> rejected.
        assert!(validate_csr_identifiers(&order, &["DNS:example.com".into()]).is_err());

        // Extra, UNAUTHORIZED identifier -> rejected (the bypass we are closing).
        assert!(
            validate_csr_identifiers(
                &order,
                &[
                    "DNS:example.com".into(),
                    "DNS:www.example.com".into(),
                    "DNS:victim.com".into(),
                ],
            )
            .is_err()
        );

        // A non-DNS/IP SAN (email/URI/...) -> rejected.
        assert!(
            validate_csr_identifiers(
                &order,
                &[
                    "DNS:example.com".into(),
                    "DNS:www.example.com".into(),
                    "email:attacker@evil.test".into(),
                ],
            )
            .is_err()
        );

        // IP identifiers match verbatim.
        let ip_order = vec![Identifier {
            id_type: "ip".to_string(),
            value: "192.0.2.1".to_string(),
        }];
        assert!(validate_csr_identifiers(&ip_order, &["IP:192.0.2.1".into()]).is_ok());
        assert!(validate_csr_identifiers(&ip_order, &["IP:192.0.2.2".into()]).is_err());
    }

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
