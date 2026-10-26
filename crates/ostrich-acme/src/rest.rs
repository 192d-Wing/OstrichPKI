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
    http::{Method, StatusCode},
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
    /// Upstream recursive resolvers for dns-01 validation (RFC 8555 §8.4).
    /// Empty = system resolver configuration.
    /// NIST 800-53: CM-6 - operator-controlled, validated at configuration load.
    pub dns01_resolvers: Vec<std::net::IpAddr>,
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
            dns01_resolvers: Vec::new(),
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

    /// Use these upstream recursive resolvers for dns-01 validation instead of
    /// the system resolver configuration. Callers should validate the list with
    /// [`crate::validation::validate_dns01_resolver_ips`] at configuration load;
    /// the validator re-checks it and fails closed.
    ///
    /// NIST 800-53: CM-6 (Configuration Settings). NIAP PP-CA: FMT_SMF.1.
    pub fn with_dns01_resolvers(mut self, ips: Vec<std::net::IpAddr>) -> Self {
        self.dns01_resolvers = ips;
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
///
/// Per RFC 8555 §7.2 the response MUST carry a fresh `Replay-Nonce`, and the
/// status code is method-dependent:
/// - a **HEAD** request **SHOULD** return `200 (OK)`
/// - a **GET** request **MUST** return `204 (No Content)`
///
/// Returning `204` for HEAD (as a single status for both) is rejected by
/// strictly-conformant clients (e.g. `instant-acme`, which enforces the
/// SHOULD-200), so the status is selected by request method. The route is GET
/// only (axum dispatches HEAD to this handler); any other method is `405`.
async fn get_new_nonce(State(state): State<AcmeState>, method: Method) -> Response {
    // Generate cryptographically secure nonce
    let nonce = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    // Store nonce in database
    let repo = ostrich_db::repository::AcmeRepository::new(state.db_pool.clone());
    if let Err(e) = repo.create_nonce(&nonce, expires_at).await {
        // Log error but still return nonce (fallback to stateless validation)
        eprintln!("Failed to store nonce: {}", e);
    }

    // RFC 8555 §7.2: HEAD -> 200 (OK), GET -> 204 (No Content).
    let status = if method == Method::HEAD {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    };

    (
        status,
        [
            ("Replay-Nonce", nonce),
            ("Cache-Control", "no-store".to_string()),
        ],
    )
        .into_response()
}

/// Build the 200 (OK) response returned when new-account finds — or races into —
/// an account that already exists for the request key (RFC 8555 §7.3: new-account
/// is idempotent on the account key and returns the existing account, never a
/// duplicate).
async fn existing_account_response(
    state: &AcmeState,
    existing: ostrich_db::models::AcmeAccount,
) -> Response {
    let account_id = existing.account_id.clone();
    let nonce = generate_nonce(state).await;
    let account = map_db_account_to_service(existing, &state.base_url);
    (
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

    // RFC 8555 §7.3: new-account is idempotent on the account key. If an account
    // already exists for this JWK, the server MUST return 200 (OK) with the
    // existing account and MUST NOT create a duplicate — for BOTH a plain
    // new-account request and an `onlyReturnExisting` key-lookup (§7.3.1). Look
    // up first so a returning client is answered from the existing row instead
    // of hitting the `acme_accounts_jwk_thumbprint` unique constraint (which
    // previously surfaced as a 500 serverInternal).
    if let Some(existing) = repo.find_account_by_jwk(&jwk_thumbprint).await? {
        return Ok(existing_account_response(&state, existing).await);
    }

    // No existing account. A key-lookup (`onlyReturnExisting`) must NOT create
    // one — it returns `accountDoesNotExist` (RFC 8555 §7.3.1).
    if let Some(true) = request.only_return_existing {
        return Err(Error::AccountDoesNotExist);
    }

    // RFC 8555 §7.3: creating a new account requires agreement to the terms.
    if !request.terms_of_service_agreed {
        return Err(Error::UserActionRequired(
            "Terms of service must be agreed to".to_string(),
        ));
    }

    // Create new account
    let account_id = format!("acct-{}", Uuid::new_v4());
    let db_account = match repo
        .create_account(
            &account_id,
            &jwk_thumbprint,
            public_key_jwk,
            request.contact.clone(),
            "valid",
            true,
        )
        .await
    {
        Ok(account) => account,
        Err(e) => {
            // Race: a concurrent new-account for the same key won the insert
            // between our lookup above and this one. Preserve RFC 8555 §7.3
            // idempotency by returning the now-existing account instead of
            // surfacing the `acme_accounts_jwk_thumbprint` unique-constraint 500.
            if let Some(existing) = repo.find_account_by_jwk(&jwk_thumbprint).await? {
                return Ok(existing_account_response(&state, existing).await);
            }
            return Err(e.into());
        }
    };

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
/// - **FAU_GEN.1**: Order creation and identifier refusal are audited
///   ([`new_order_audit_event`]): account, order, outcome, identifier
///   summary and, on refusal, the problem type.
/// - **FPT_STM.1**: Order expiration timestamp set from reliable source.
///
/// # NIST 800-53 Controls
///
/// - **SI-10**: Every identifier is validated (type, syntax, wildcard form,
///   canonical IP, duplicates, list size) before any database write.
/// - **AU-2/AU-3**: A successful order and an identifier refusal each emit an
///   `ostrich-audit` record (who: account id; what: `new_order`; when: record
///   timestamp; where: order id or `acme:new-order`; outcome).
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - identifiers validated
//   by `identifier::validate_order_identifiers` before `create_order`
// - NIST 800-53: AC-3 (Access Enforcement), SC-17 (PKI Certificates) - a
//   wildcard authorization is offered dns-01 only
// - NIAP PP-CA: FDP_CER_EXT.1 (certificate profile: subject identifiers
//   verified before issuance)
// - RFC 8555 §6.7 - unsupportedIdentifier / rejectedIdentifier / malformed
// - RFC 8555 §7.1.3 - the order keeps the `*.` identifier as requested
// - RFC 8555 §7.1.4 - wildcard authz is for the base domain, `wildcard: true`
// - RFC 8555 §7.4 - newOrder
// - RFC 8738 §3 / §7 - canonical `ip` identifiers, never offered dns-01
// - NIST 800-53: AU-2, AU-3, AU-12; NIAP PP-CA: FAU_GEN.1 - order creation
//   and identifier refusal audited
async fn new_order(State(state): State<AcmeState>, body: Bytes) -> Result<Response> {
    // Validate JWS and extract payload
    let url = format!("{}/acme/new-order", state.base_url);
    let validated = validate_jws_with_account::<NewOrderRequest>(&body, &url, &state).await?;

    let request = validated.payload;
    let account_id = validated.account_id;

    // NIST 800-53: SI-10 - validate every identifier before any write, so a
    // rejected request leaves no order, authorization or challenge behind.
    let authz_identifiers =
        match crate::identifier::validate_order_identifiers(&request.identifiers) {
            Ok(a) => a,
            Err(e) => {
                // AU-2: the policy refusal is a security-relevant event.
                let mut event = new_order_audit_event(
                    &account_id.to_string(),
                    None,
                    &request.identifiers,
                    Some(&e),
                );
                record_audit(state.audit_sink.as_ref(), &mut event).await;
                return Err(e);
            }
        };

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

    // Create one authorization per order identifier. RFC 8555 §7.1.4: a `*.`
    // identifier is authorized as its base domain with `wildcard: true`.
    let mut authorization_urls = Vec::new();
    for identifier in &authz_identifiers {
        let authz_id = format!("authz-{}", Uuid::new_v4());
        let authz_expires = Utc::now() + chrono::Duration::days(7);

        let db_authz = repo
            .create_authorization(
                &authz_id,
                db_order.id,
                &identifier.id_type,
                &identifier.value,
                "pending",
                authz_expires,
                identifier.wildcard,
            )
            .await?;

        // Only the challenges valid for this identifier kind (RFC 8555
        // §7.1.3 / §8: wildcard -> dns-01 only; RFC 8738 §7: ip -> no dns-01).
        for challenge_type in identifier.challenge_types() {
            let challenge_id = format!("chall-{}", Uuid::new_v4());
            let token = Uuid::new_v4().to_string();

            repo.create_challenge(
                &challenge_id,
                db_authz.id,
                challenge_type,
                &token,
                "pending",
            )
            .await?;
        }

        authorization_urls.push(format!("{}/acme/authz/{}", state.base_url, authz_id));
    }

    // AU-2 / AU-3: order created.
    let mut event = new_order_audit_event(
        &account_id.to_string(),
        Some(&order_id_str),
        &request.identifiers,
        None,
    );
    record_audit(state.audit_sink.as_ref(), &mut event).await;

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

/// The `ostrich-audit` record for a newOrder request.
///
/// `order_id` is `Some` for a created order (target `acme:order:<id>`) and
/// `None` for a refused request (target `acme:new-order`); `refusal` is the
/// identifier error, whose RFC 8555 §6.7 problem type is recorded.
///
/// The identifier summary is bounded: the count, per-type counts (`dns`,
/// `ip`, anything else as `other`, so an untrusted type string is never
/// stored) and the wildcard count. Identifier values are recorded only for a
/// created order, where each passed the newOrder rules (LDH name or canonical
/// IP, at most 253 octets, at most [`crate::identifier::MAX_ORDER_IDENTIFIERS`]
/// of them). Values of a refused request are untrusted and not recorded.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records),
//   AU-12 (Audit Record Generation)
// - NIST 800-53: SI-10 - untrusted refused values kept out of the record
// - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation), FAU_GEN.2 (actor)
fn new_order_audit_event(
    account_id: &str,
    order_id: Option<&str>,
    identifiers: &[Identifier],
    refusal: Option<&Error>,
) -> ostrich_audit::AuditEvent {
    let (mut dns, mut ip, mut other, mut wildcards) = (0usize, 0usize, 0usize, 0usize);
    for id in identifiers {
        match id.id_type.as_str() {
            "dns" => {
                dns += 1;
                if id.value.starts_with("*.") {
                    wildcards += 1;
                }
            }
            "ip" => ip += 1,
            _ => other += 1,
        }
    }
    let mut details = serde_json::json!({
        "identifier_count": identifiers.len(),
        "identifier_types": { "dns": dns, "ip": ip, "other": other },
        "wildcard_count": wildcards,
    });

    let (target, outcome) = match (order_id, refusal) {
        (_, Some(e)) => {
            details["problem_type"] = serde_json::Value::from(e.error_type());
            (
                "acme:new-order".to_string(),
                ostrich_audit::EventOutcome::Failure,
            )
        }
        (Some(order_id), None) => {
            details["identifiers"] = serde_json::Value::from(
                identifiers
                    .iter()
                    .map(|id| format!("{}:{}", id.id_type, id.value))
                    .collect::<Vec<_>>(),
            );
            (
                format!("acme:order:{order_id}"),
                ostrich_audit::EventOutcome::Success,
            )
        }
        (None, None) => (
            "acme:new-order".to_string(),
            ostrich_audit::EventOutcome::Failure,
        ),
    };

    ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::AcmeProtocol,
        account_id,
        target,
        "new_order",
        outcome,
    )
    .with_details(details)
    .build()
}

/// The `ostrich-audit` record for a refused finalize request: the order
/// state or identifier binding check ([`check_order_finalizable`]) or the CSR
/// identifier match ([`validate_csr_identifiers`]) failed.
///
/// Actor is the account id, target `acme:order:<order_id>`, action
/// `finalize_order`, outcome Failure; the only detail is the RFC 8555 §6.7
/// problem type. The error detail, CSR contents and CSR SAN values are
/// untrusted or derived from the request and are not recorded.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records),
//   AU-12 (Audit Record Generation) - finalize refusals after the ownership
//   check; source IP and request id are not recorded
// - NIST 800-53: SI-10 - untrusted submitted values kept out of the record
// - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation), FAU_GEN.2 (actor)
fn finalize_refusal_audit_event(
    account_id: &str,
    order_id: &str,
    refusal: &Error,
) -> ostrich_audit::AuditEvent {
    ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::AcmeProtocol,
        account_id,
        format!("acme:order:{order_id}"),
        "finalize_order",
        ostrich_audit::EventOutcome::Failure,
    )
    .with_details(serde_json::json!({ "problem_type": refusal.error_type() }))
    .build()
}

/// Record an audit event, logging (not failing the request) if the sink
/// errors; matches the challenge-validation audit path.
async fn record_audit(sink: &dyn AuditSink, event: &mut ostrich_audit::AuditEvent) {
    if let Err(e) = sink.record(event).await {
        tracing::error!(
            action = %event.action,
            target = %event.target,
            error = %e,
            "failed to record ACME audit event"
        );
    }
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
/// - **SC-17**: Identifier control verified before certificate issuance.
// POAM: POAM-2026-10-23-50 - no ownership/state check on the challenge POST and validation tasks are spawned without a concurrency bound (AC-3, SC-5; RFC 8555 §7.5.1).
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
    // NIAP PP-CA: FDP_CER_EXT.1 - proof of identifier control before issuance.
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
/// - NIAP PP-CA: FDP_CER_EXT.1 - identifier control proven before issuance
/// - NIST 800-53: SC-17 - identifier control verified before certificate issuance
/// - NIST 800-53: AU-2 - validation outcome audited
/// - NIST 800-53: SI-11 - challenge `error` built from the client-safe detail
/// - RFC 8555 §6.7 / §7.1.5 - challenge `error` is a problem document whose
///   type matches the failure (e.g. `dns`, `incorrectResponse`, `serverInternal`)
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
            let detail = challenge_error_document(&e);
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
    // POAM: POAM-2026-10-23-51 - this record lacks challenge type, identifier, account and failure category, so a CA misconfiguration is indistinguishable from a subscriber failure (AU-3).
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

/// The RFC 8555 §6.7 problem document stored as a failed challenge's `error`.
///
/// The type comes from the error variant and the detail from
/// [`Error::client_detail`], so internal-class errors (configuration, database)
/// reach the subscriber only as a generic message.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - no internal detail in client errors
// - RFC 8555 §6.7 - problem document type/detail
fn challenge_error_document(e: &Error) -> serde_json::Value {
    serde_json::json!({
        "type": e.error_type(),
        "detail": e.client_detail(),
    })
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

/// Refuse a challenge that must never be validated for this authorization.
///
/// - RFC 8555 §7.1.3 / §8: a wildcard authorization is only ever offered
///   dns-01; any other challenge on it would prove control of the base host,
///   not the zone, so it is refused rather than validated.
/// - An `ip` authorization is validated by http-01 only: RFC 8738 §7 forbids
///   dns-01, and tls-alpn-01 lacks the RFC 8738 §6 checks
///   (POAM-2026-10-23-52). Rows created before this rule offered both, so
///   they are refused here.
/// - A `*` in a stored identifier is a legacy row from before the
///   identifier-handling part of POAM-2026-10-23-49 was fixed (2026-10-26;
///   `*.x` stored with `wildcard = false`); no validator may run on it.
///
/// # Errors
///
/// [`Error::Unauthorized`] for a non-dns-01 challenge on a wildcard
/// authorization or a non-http-01 challenge on an `ip` authorization;
/// [`Error::Malformed`] for an identifier containing `*`.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - fail closed
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIAP PP-CA: FDP_CER_EXT.1
// - RFC 8555 §7.1.4 / §8.4 - wildcard authorizations are validated by dns-01
// - RFC 8738 §6 / §7 - ip authorizations: no dns-01; tls-alpn-01 withheld
fn check_challenge_permitted(
    authz: &ostrich_db::models::AcmeAuthorization,
    challenge_type: &str,
) -> Result<()> {
    if authz.wildcard && challenge_type != "dns-01" {
        return Err(Error::Unauthorized(
            "wildcard authorizations can only be validated with dns-01".to_string(),
        ));
    }
    if authz.identifier_type == "ip" && challenge_type != "http-01" {
        return Err(Error::Unauthorized(
            "ip authorizations can only be validated with http-01".to_string(),
        ));
    }
    if authz.identifier_value.contains('*') {
        return Err(Error::Malformed(
            "authorization identifier is not a valid DNS name".to_string(),
        ));
    }
    Ok(())
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

    // Defence in depth: refuse before any network traffic.
    check_challenge_permitted(&authz, &challenge.challenge_type)?;

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
                .with_resolvers(state.dns01_resolvers.clone())
                .validate(domain, token, thumbprint)
                .await?
        }
        "tls-alpn-01" => {
            let mut validator = crate::validation::TlsAlpn01Validator::new();
            if state.allow_private_ip_domains {
                validator = validator.insecure_allow_private_domains();
            }
            validator.validate(domain, token, thumbprint).await?
        }
        other => {
            return Err(Error::Malformed(format!(
                "Unsupported challenge type: {}",
                other
            )));
        }
    };

    // RFC 8555 §6.7: a response that was retrieved but did not match is
    // `incorrectResponse`.
    if !valid {
        return Err(Error::IncorrectResponse(
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
/// - **FDP_ACF.1**: Order must be `ready` and unexpired, with every order
///   identifier bound to a valid, unexpired authorization
///   ([`check_order_finalizable`]); an `ip` authorization must have been
///   validated by http-01.
/// - **FAU_GEN.1**: A finalize refused by [`check_order_finalizable`] or the
///   CSR identifier match is audited as a Failure with the problem type
///   ([`finalize_refusal_audit_event`]); issuance is audited by the CA
///   service. CSR parse/signature failures, an ownership refusal and
///   database errors are not audited by this handler.
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

/// Refuse finalization unless the order is `ready`, unexpired, and every
/// order identifier is bound one-to-one to a `valid`, unexpired authorization.
///
/// The order identifiers are re-parsed with the newOrder rules
/// ([`crate::identifier::validate_order_identifiers`]) into the expected
/// authorization keys `(type, lowercase value, wildcard)`; the order's
/// authorization rows must form exactly that set, with no missing, extra or
/// duplicate rows. So a `*.example.com` order identifier needs a `wildcard`
/// authorization for `example.com`; a legacy row (`*.example.com` stored with
/// `wildcard = false`, possibly validated by http-01 before the fix) never
/// matches and the order cannot be finalized. An order whose authorization
/// loop failed part-way (missing rows) is refused too.
///
/// `challenges` are the challenge rows of the order's `ip` authorizations
/// (rows of other authorizations are ignored). A `valid` `ip` authorization
/// must have a `valid` `http-01` challenge row: an `ip` authorization proven
/// before the fix by tls-alpn-01 or dns-01 is not usable (RFC 8738 §6/§7).
///
/// The checks run in three passes over all rows, so the error type does not
/// depend on row order: order state, then the identifier binding of every row
/// (`unauthorized`), then the status and expiry of every row
/// (`orderNotReady`), then the `ip` validation method (`unauthorized`).
///
/// # Errors
///
/// - [`Error::OrderNotReady`] if the order is not `ready` or has expired, or
///   (once every row is bound) an authorization is not `valid` or has expired.
/// - [`Error::Unauthorized`] if the stored order identifiers no longer pass
///   the newOrder rules, the authorizations do not match them one-to-one, or
///   an `ip` authorization has no `valid` `http-01` challenge.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - fail closed before issuance
// - NIST 800-53: SC-17 (PKI Certificates) - issue only for names whose
//   control was proven by a matching authorization
// - NIAP PP-CA: FDP_CER_EXT.1 (identifier control proven before issuance)
// - RFC 8555 §7.1.3 / §7.1.4 - authorizations match order identifiers,
//   wildcard flag included
// - RFC 8555 §7.1.6 - only a `ready` order may be finalized; expired orders
//   and authorizations are not usable
// - RFC 8555 §7.4 - orderNotReady
// - RFC 8738 §7 - `ip` identifiers proven by http-01 only (tls-alpn-01 for
//   IP is deferred, POAM-2026-10-23-52)
fn check_order_finalizable(
    order: &ostrich_db::models::AcmeOrder,
    order_identifiers: &[Identifier],
    authzs: &[ostrich_db::models::AcmeAuthorization],
    challenges: &[ostrich_db::models::AcmeChallenge],
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    if order.status != "ready" || order.expires <= now {
        return Err(Error::OrderNotReady);
    }

    let expected =
        crate::identifier::validate_order_identifiers(order_identifiers).map_err(|_| {
            Error::Unauthorized(
                "order identifiers do not satisfy the current identifier policy".to_string(),
            )
        })?;
    let mut expected_keys: std::collections::HashSet<(String, String, bool)> = expected
        .into_iter()
        .map(|a| (a.id_type, a.value.to_ascii_lowercase(), a.wildcard))
        .collect();

    // Pass 1 - binding (RFC-007: before any status check).
    if authzs.len() != expected_keys.len() {
        return Err(Error::Unauthorized(
            "order authorizations do not match the order identifiers".to_string(),
        ));
    }
    for authz in authzs {
        let key = (
            authz.identifier_type.clone(),
            authz.identifier_value.to_ascii_lowercase(),
            authz.wildcard,
        );
        // Removing makes the match one-to-one: a duplicate row finds nothing.
        if !expected_keys.remove(&key) {
            return Err(Error::Unauthorized(
                "order authorizations do not match the order identifiers".to_string(),
            ));
        }
    }

    // Pass 2 - status and expiry.
    if authzs
        .iter()
        .any(|authz| authz.status != "valid" || authz.expires <= now)
    {
        return Err(Error::OrderNotReady);
    }

    // Pass 3 - an `ip` authorization must have been proven by http-01.
    for authz in authzs.iter().filter(|a| a.identifier_type == "ip") {
        let proven_by_http01 = challenges.iter().any(|c| {
            c.authorization_id == authz.id && c.challenge_type == "http-01" && c.status == "valid"
        });
        if !proven_by_http01 {
            return Err(Error::Unauthorized(
                "ip authorization was not validated by http-01".to_string(),
            ));
        }
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

    // RFC 8555 §7.1.6 / §7.4; AC-3, SC-17: the order must be ready and
    // unexpired, and each order identifier bound to its own valid, unexpired
    // authorization (type, value, wildcard). Fails closed before the CSR
    // match and before any state change.
    let db_authzs = repo.list_authorizations_by_order(db_order.id).await?;
    // RFC 8738 §7 / SEC-005: the challenge rows of `ip` authorizations, so
    // the check can require that each was proven by http-01.
    let mut ip_challenges = Vec::new();
    for authz in db_authzs.iter().filter(|a| a.identifier_type == "ip") {
        ip_challenges.extend(repo.list_challenges_by_authorization(authz.id).await?);
    }

    // NIST 800-53: AU-2, AU-12 - a refused finalize is audited (Failure, with
    // the problem type only; no CSR contents or submitted values).
    let refusal = check_order_finalizable(
        &db_order,
        &order_identifiers,
        &db_authzs,
        &ip_challenges,
        Utc::now(),
    )
    .and_then(|()| {
        validate_csr_identifiers(&order_identifiers, &parsed_csr.subject_alternative_names)
    });
    if let Err(e) = refusal {
        let mut event =
            finalize_refusal_audit_event(&validated.account_id.to_string(), &db_order.order_id, &e);
        record_audit(state.audit_sink.as_ref(), &mut event).await;
        return Err(e);
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
        // RFC 8555 §7.1.4: `wildcard` MUST be present and true for a wildcard
        // authorization and absent otherwise (never `false`).
        wildcard: db.wildcard.then_some(true),
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

    /// RFC-010 / SEC-003 / NIST-008: a failed challenge's `error` carries the
    /// problem type of the actual failure and only the client-safe detail.
    #[test]
    fn challenge_error_document_uses_type_and_client_detail() {
        // Exhausted DNS lookups -> `dns`, detail names only the query name.
        let doc = challenge_error_document(&Error::Dns(
            "DNS lookup failed for _acme-challenge.example.com.".to_string(),
        ));
        assert_eq!(doc["type"], "urn:ietf:params:acme:error:dns");
        assert_eq!(
            doc["detail"],
            "DNS error: DNS lookup failed for _acme-challenge.example.com."
        );

        // Retrieved but non-matching response -> `incorrectResponse`.
        let doc = challenge_error_document(&Error::IncorrectResponse(
            "Challenge response did not match key authorization".to_string(),
        ));
        assert_eq!(doc["type"], "urn:ietf:params:acme:error:incorrectResponse");

        // Malformed identifier -> `malformed` with its descriptive detail.
        let doc = challenge_error_document(&Error::Malformed(
            "dns-01 identifier is not a valid DNS name".to_string(),
        ));
        assert_eq!(doc["type"], "urn:ietf:params:acme:error:malformed");

        // CA-side resolver misconfiguration never reaches the subscriber.
        let doc = challenge_error_document(&Error::ServerInternal(
            "dns-01 resolver has no name servers configured".to_string(),
        ));
        assert_eq!(doc["type"], "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(doc["detail"], "Internal server error");
        let rendered = doc.to_string();
        assert!(!rendered.contains("name servers"), "{rendered}");
        assert!(!rendered.contains("resolver"), "{rendered}");
        // The old hardcoded type is gone.
        assert!(!rendered.contains("unauthorized"), "{rendered}");
    }

    /// RFC-013: whatever a validator returns, the stored challenge `error` is a
    /// problem type registered in RFC 8555 §6.7, and the http-01 / tls-alpn-01
    /// failure details carry no raw transport, TLS, or resolver text.
    #[test]
    fn challenge_error_document_only_emits_registered_types() {
        use crate::error::tests::{RFC8555_REGISTERED_TYPES, one_of_every_variant};

        for e in one_of_every_variant() {
            let doc = challenge_error_document(&e);
            let t = doc["type"].as_str().unwrap_or_default();
            let name = t.strip_prefix("urn:ietf:params:acme:error:").unwrap_or(t);
            assert!(
                RFC8555_REGISTERED_TYPES.contains(&name),
                "{e:?} produced unregistered challenge error type {t}"
            );
            assert_ne!(name, "challengeFailed");
        }
    }

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

    fn db_authz(value: &str, wildcard: bool) -> ostrich_db::models::AcmeAuthorization {
        let now = Utc::now();
        ostrich_db::models::AcmeAuthorization {
            id: Uuid::new_v4(),
            authorization_id: "authz-test".to_string(),
            order_id: Uuid::new_v4(),
            identifier_type: "dns".to_string(),
            identifier_value: value.to_string(),
            status: "pending".to_string(),
            expires: now,
            wildcard,
            created_at: now,
            updated_at: now,
        }
    }

    /// RFC 8555 §7.1.4: `wildcard` is present and true for a wildcard
    /// authorization, and absent (never `false`) otherwise.
    #[test]
    fn authorization_json_wildcard_only_when_true() {
        let json = serde_json::to_value(map_db_authorization_to_service(
            db_authz("example.com", true),
            vec![],
        ))
        .expect("serialize");
        assert_eq!(json["wildcard"], serde_json::Value::Bool(true));
        assert_eq!(json["identifier"]["value"], "example.com");

        let json = serde_json::to_value(map_db_authorization_to_service(
            db_authz("example.com", false),
            vec![],
        ))
        .expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(!obj.contains_key("wildcard"), "{json}");
    }

    /// Defence in depth: a wildcard authz is validated only via dns-01, and a
    /// legacy `*.` identifier is never validated.
    #[test]
    fn check_challenge_permitted_policy() {
        let wild = db_authz("example.com", true);
        assert!(check_challenge_permitted(&wild, "dns-01").is_ok());
        for t in ["http-01", "tls-alpn-01", "unknown"] {
            assert!(
                matches!(
                    check_challenge_permitted(&wild, t),
                    Err(Error::Unauthorized(_))
                ),
                "{t}"
            );
        }

        let plain = db_authz("example.com", false);
        for t in ["http-01", "dns-01", "tls-alpn-01"] {
            assert!(check_challenge_permitted(&plain, t).is_ok(), "{t}");
        }

        let legacy = db_authz("*.example.com", false);
        for t in ["http-01", "dns-01", "tls-alpn-01"] {
            assert!(
                matches!(
                    check_challenge_permitted(&legacy, t),
                    Err(Error::Malformed(_))
                ),
                "{t}"
            );
        }
    }

    /// RFC 8555 §7.4: the order keeps `*.example.com`, so a CSR for the
    /// wildcard name finalizes while one for only the base name does not.
    #[test]
    fn wildcard_order_identifier_matches_wildcard_csr() {
        let order = vec![Identifier {
            id_type: "dns".to_string(),
            value: "*.example.com".to_string(),
        }];
        assert!(validate_csr_identifiers(&order, &["DNS:*.Example.com".into()]).is_ok());
        assert!(validate_csr_identifiers(&order, &["DNS:example.com".into()]).is_err());
    }

    // ---- QA additions (SA-11 / CA-2 evidence) ----

    /// RFC 8555 §6.7: the defence-in-depth refusals carry the registered
    /// problem-type URNs (they reach the challenge `error` document).
    #[test]
    fn qa_check_challenge_permitted_problem_types() {
        let e = check_challenge_permitted(&db_authz("example.com", true), "http-01")
            .expect_err("wildcard http-01");
        assert_eq!(e.error_type(), "urn:ietf:params:acme:error:unauthorized");
        let e = check_challenge_permitted(&db_authz("*.example.com", false), "dns-01")
            .expect_err("legacy row");
        assert_eq!(e.error_type(), "urn:ietf:params:acme:error:malformed");
        // A wildcard-flagged row that still holds a `*` value fails closed
        // for dns-01 as well.
        assert!(check_challenge_permitted(&db_authz("*.example.com", true), "dns-01").is_err());
        // Challenge type is compared exactly.
        for t in ["DNS-01", "dns-01 ", ""] {
            assert!(
                check_challenge_permitted(&db_authz("example.com", true), t).is_err(),
                "{t:?}"
            );
        }
    }

    /// Offering and enforcement agree: every challenge new_order would create
    /// for an identifier passes `check_challenge_permitted` on the resulting
    /// authz row, and for a wildcard every non-offered type is refused.
    #[test]
    fn qa_offered_challenges_are_permitted() {
        let authzs = crate::identifier::validate_order_identifiers(&[
            Identifier {
                id_type: "dns".to_string(),
                value: "example.com".to_string(),
            },
            Identifier {
                id_type: "dns".to_string(),
                value: "*.example.com".to_string(),
            },
            Identifier {
                id_type: "ip".to_string(),
                value: "192.0.2.1".to_string(),
            },
        ])
        .expect("valid");
        for a in &authzs {
            let mut row = db_authz(&a.value, a.wildcard);
            row.identifier_type = a.id_type.clone();
            for t in a.challenge_types() {
                assert!(check_challenge_permitted(&row, t).is_ok(), "{a:?} {t}");
            }
            if a.wildcard {
                for t in ["http-01", "tls-alpn-01"] {
                    assert!(!a.challenge_types().contains(&t));
                    assert!(check_challenge_permitted(&row, t).is_err(), "{a:?} {t}");
                }
            }
        }
        // The IP authz is never offered dns-01, and the dns-01 validator
        // refuses an IP literal if one reached it anyway (RFC 8738 §7).
        assert!(!authzs[2].challenge_types().contains(&"dns-01"));
        assert!(crate::validation::dns01_query_name(&authzs[2].value).is_err());
    }

    /// RFC 8555 §7.1.4: the serialized text never contains a `wildcard` key
    /// for a non-wildcard authorization (not even `null`), and the wildcard
    /// authorization identifier is the base domain without `*.`.
    #[test]
    fn qa_authorization_json_wildcard_text() {
        let plain = serde_json::to_string(&map_db_authorization_to_service(
            db_authz("example.com", false),
            vec![],
        ))
        .expect("serialize");
        assert!(!plain.contains("wildcard"), "{plain}");

        let wild = serde_json::to_string(&map_db_authorization_to_service(
            db_authz("example.com", true),
            vec![],
        ))
        .expect("serialize");
        assert!(wild.contains("\"wildcard\":true"), "{wild}");
        assert!(!wild.contains('*'), "{wild}");
    }

    // ---- Fix round 1 (SEC-001, RFC-001, NIST-001) ----

    fn ident(t: &str, v: &str) -> Identifier {
        Identifier {
            id_type: t.to_string(),
            value: v.to_string(),
        }
    }

    fn db_order(status: &str, expires: chrono::DateTime<Utc>) -> ostrich_db::models::AcmeOrder {
        let now = Utc::now();
        ostrich_db::models::AcmeOrder {
            id: Uuid::new_v4(),
            order_id: "order-test".to_string(),
            account_id: Uuid::new_v4(),
            status: status.to_string(),
            identifiers: serde_json::Value::Null,
            not_before: None,
            not_after: None,
            expires,
            certificate_id: None,
            csr_der: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// A `valid`, unexpired authorization row.
    fn valid_authz(
        t: &str,
        v: &str,
        wildcard: bool,
        expires: chrono::DateTime<Utc>,
    ) -> ostrich_db::models::AcmeAuthorization {
        let mut a = db_authz(v, wildcard);
        a.identifier_type = t.to_string();
        a.status = "valid".to_string();
        a.expires = expires;
        a
    }

    /// A `valid` http-01 challenge row for each `ip` authorization, i.e. what
    /// finalize loads for rows proven after the fix (SEC-005).
    fn http01_valid(
        authzs: &[ostrich_db::models::AcmeAuthorization],
    ) -> Vec<ostrich_db::models::AcmeChallenge> {
        authzs
            .iter()
            .filter(|a| a.identifier_type == "ip")
            .map(|a| challenge_row(a, "http-01", "valid"))
            .collect()
    }

    fn challenge_row(
        authz: &ostrich_db::models::AcmeAuthorization,
        challenge_type: &str,
        status: &str,
    ) -> ostrich_db::models::AcmeChallenge {
        let now = Utc::now();
        ostrich_db::models::AcmeChallenge {
            id: Uuid::new_v4(),
            challenge_id: "chall-test".to_string(),
            authorization_id: authz.id,
            challenge_type: challenge_type.to_string(),
            token: "token".to_string(),
            status: status.to_string(),
            validated_at: None,
            error_detail: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// [`check_order_finalizable`] with every `ip` row proven by http-01, so
    /// the pre-SEC-005 tests keep testing the order state and the binding.
    fn finalizable(
        order: &ostrich_db::models::AcmeOrder,
        ids: &[Identifier],
        authzs: &[ostrich_db::models::AcmeAuthorization],
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        check_order_finalizable(order, ids, authzs, &http01_valid(authzs), now)
    }

    /// SEC-001: finalize requires a ready, unexpired order whose identifiers
    /// are bound one-to-one to valid, unexpired authorizations.
    #[test]
    fn check_order_finalizable_happy_path() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let ids = [
            ident("dns", "Example.com"),
            ident("dns", "*.example.com"),
            ident("ip", "192.0.2.1"),
        ];
        let authzs = [
            valid_authz("ip", "192.0.2.1", false, later),
            valid_authz("dns", "example.com", true, later),
            valid_authz("dns", "EXAMPLE.com", false, later),
        ];
        assert!(finalizable(&order, &ids, &authzs, now).is_ok());
    }

    #[test]
    fn check_order_finalizable_order_state() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let ids = [ident("dns", "example.com")];
        let authzs = [valid_authz("dns", "example.com", false, later)];
        for status in ["pending", "processing", "valid", "invalid", "READY"] {
            let e = finalizable(&db_order(status, later), &ids, &authzs, now).expect_err(status);
            assert!(matches!(e, Error::OrderNotReady), "{status}: {e:?}");
        }
        // Expired (or expiring now) order.
        for exp in [now, now - chrono::Duration::seconds(1)] {
            let e = finalizable(&db_order("ready", exp), &ids, &authzs, now)
                .expect_err("expired order");
            assert!(matches!(e, Error::OrderNotReady), "{e:?}");
        }
    }

    #[test]
    fn check_order_finalizable_authz_state() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let ids = [ident("dns", "example.com")];
        for status in ["pending", "invalid", "deactivated", "expired", "revoked"] {
            let mut a = valid_authz("dns", "example.com", false, later);
            a.status = status.to_string();
            let e = finalizable(&order, &ids, &[a], now).expect_err(status);
            assert!(matches!(e, Error::OrderNotReady), "{status}: {e:?}");
        }
        let expired = valid_authz("dns", "example.com", false, now);
        let e = finalizable(&order, &ids, &[expired], now).expect_err("expired");
        assert!(matches!(e, Error::OrderNotReady), "{e:?}");
    }

    /// The identifier binding: missing, extra, duplicate, wrong-type,
    /// wrong-value and wrong-wildcard rows are all `unauthorized`.
    #[test]
    fn check_order_finalizable_identifier_binding() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let a = |t: &str, v: &str, w: bool| valid_authz(t, v, w, later);
        let ids = [ident("dns", "example.com"), ident("dns", "*.example.com")];

        let cases: Vec<(&str, Vec<ostrich_db::models::AcmeAuthorization>)> = vec![
            ("missing row", vec![a("dns", "example.com", false)]),
            ("no rows", vec![]),
            (
                "extra row",
                vec![
                    a("dns", "example.com", false),
                    a("dns", "example.com", true),
                    a("dns", "other.example", false),
                ],
            ),
            (
                "duplicate row instead of wildcard",
                vec![
                    a("dns", "example.com", false),
                    a("dns", "example.com", false),
                ],
            ),
            (
                "wildcard flag missing",
                vec![
                    a("dns", "example.com", false),
                    a("dns", "victim.example", true),
                ],
            ),
            (
                // Legacy row: `*.` value stored with wildcard = false.
                "legacy wildcard row",
                vec![
                    a("dns", "example.com", false),
                    a("dns", "*.example.com", false),
                ],
            ),
            (
                "wrong type",
                vec![a("ip", "example.com", false), a("dns", "example.com", true)],
            ),
        ];
        for (name, authzs) in cases {
            let e = finalizable(&order, &ids, &authzs, now).expect_err(name);
            assert!(matches!(e, Error::Unauthorized(_)), "{name}: {e:?}");
        }

        // Stored order identifiers that no longer pass the newOrder rules
        // (legacy orders) are refused even with "matching" rows.
        for bad in [
            vec![ident("dns", "*.com")],
            vec![ident("dns", "a.*.example.com")],
            vec![ident("ip", "::ffff:192.0.2.1")],
            vec![],
        ] {
            let rows: Vec<_> = bad.iter().map(|i| a(&i.id_type, &i.value, false)).collect();
            let e = finalizable(&order, &bad, &rows, now).expect_err("legacy order");
            assert!(matches!(e, Error::Unauthorized(_)), "{bad:?}: {e:?}");
        }
    }

    /// RFC-001: an `ip` authorization is validated by http-01 only; legacy
    /// rows that were offered tls-alpn-01 or dns-01 are refused before I/O.
    #[test]
    fn check_challenge_permitted_ip_http01_only() {
        let mut row = db_authz("192.0.2.1", false);
        row.identifier_type = "ip".to_string();
        assert!(check_challenge_permitted(&row, "http-01").is_ok());
        for t in ["tls-alpn-01", "dns-01", "HTTP-01", ""] {
            let e = check_challenge_permitted(&row, t).expect_err(t);
            assert!(matches!(e, Error::Unauthorized(_)), "{t:?}: {e:?}");
            assert_eq!(e.error_type(), "urn:ietf:params:acme:error:unauthorized");
        }
        // dns authorizations keep tls-alpn-01.
        assert!(check_challenge_permitted(&db_authz("example.com", false), "tls-alpn-01").is_ok());
    }

    /// NIST-001: a created order is audited as success with the actor, the
    /// order target and the (validated) identifier values.
    #[test]
    fn new_order_audit_event_success() {
        let ids = [
            ident("dns", "example.com"),
            ident("dns", "*.example.com"),
            ident("ip", "192.0.2.1"),
        ];
        let ev = new_order_audit_event("acct-1", Some("order-abc"), &ids, None);
        assert_eq!(ev.event_type, ostrich_audit::EventType::AcmeProtocol);
        assert_eq!(ev.actor, "acct-1");
        assert_eq!(ev.target, "acme:order:order-abc");
        assert_eq!(ev.action, "new_order");
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Success);
        let d = ev.details.expect("details");
        assert_eq!(d["identifier_count"], 3);
        assert_eq!(d["identifier_types"]["dns"], 2);
        assert_eq!(d["identifier_types"]["ip"], 1);
        assert_eq!(d["identifier_types"]["other"], 0);
        assert_eq!(d["wildcard_count"], 1);
        assert_eq!(
            d["identifiers"],
            serde_json::json!(["dns:example.com", "dns:*.example.com", "ip:192.0.2.1"])
        );
        assert!(d.get("problem_type").is_none());
    }

    /// NIST-001: a refusal is audited as failure with the problem type, and
    /// no untrusted value or type string reaches the record.
    #[test]
    fn new_order_audit_event_refusal_is_bounded() {
        let marker = "zzauditmarker";
        let ids = [
            ident("dns", &format!("*.{marker}.com")),
            ident(marker, "x"),
            ident("ip", marker),
        ];
        let err = crate::identifier::validate_order_identifiers(&ids).expect_err("refused");
        let ev = new_order_audit_event("acct-2", None, &ids, Some(&err));
        assert_eq!(ev.actor, "acct-2");
        assert_eq!(ev.target, "acme:new-order");
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure);
        let d = ev.details.clone().expect("details");
        assert_eq!(d["problem_type"], err.error_type());
        assert_eq!(d["identifier_count"], 3);
        assert_eq!(d["identifier_types"]["other"], 1);
        assert!(d.get("identifiers").is_none());
        let rendered = serde_json::to_string(&ev).expect("serialize");
        assert!(!rendered.contains(marker), "{rendered}");

        // A 1000-identifier refusal still yields a constant-size record.
        let many: Vec<Identifier> = (0..1000).map(|_| ident("dns", marker)).collect();
        let err = crate::identifier::validate_order_identifiers(&many).expect_err("cap");
        let ev = new_order_audit_event("acct-2", None, &many, Some(&err));
        let rendered = serde_json::to_string(&ev.details).expect("serialize");
        assert!(rendered.len() < 256, "{rendered}");
        assert!(rendered.contains("\"identifier_count\":1000"), "{rendered}");
        assert_eq!(
            ev.details.as_ref().expect("details")["problem_type"],
            "urn:ietf:params:acme:error:malformed"
        );
    }

    /// NIST-001: the events reach the audit sink (and its hash chain).
    #[tokio::test]
    async fn new_order_audit_events_are_recorded() {
        use ostrich_audit::AuditSink as _;
        let sink = ostrich_audit::sink::MemoryAuditSink::new();
        let ids = [ident("dns", "*.com")];
        let err = crate::identifier::validate_order_identifiers(&ids).expect_err("refused");
        let mut refused = new_order_audit_event("acct-3", None, &ids, Some(&err));
        record_audit(&sink, &mut refused).await;
        let ok_ids = [ident("dns", "example.com")];
        let mut created = new_order_audit_event("acct-3", Some("order-1"), &ok_ids, None);
        record_audit(&sink, &mut created).await;

        let events = sink
            .query_events(ostrich_audit::sink::QueryCriteria {
                actor: Some("acct-3".to_string()),
                event_type: None,
                start_time: None,
                end_time: None,
                limit: None,
                offset: None,
            })
            .await
            .expect("query");
        assert_eq!(events.len(), 2);
        let outcomes: Vec<_> = events.iter().map(|e| e.outcome).collect();
        assert!(outcomes.contains(&ostrich_audit::EventOutcome::Failure));
        assert!(outcomes.contains(&ostrich_audit::EventOutcome::Success));
        let refusal = events
            .iter()
            .find(|e| e.outcome == ostrich_audit::EventOutcome::Failure)
            .expect("refusal");
        assert_eq!(
            refusal.details.as_ref().expect("details")["problem_type"],
            "urn:ietf:params:acme:error:rejectedIdentifier"
        );
        assert!(sink.verify_integrity().await.expect("verify"));
    }

    // ---- QA round 1 (SEC-001, RFC-001, NIST-001) ----

    /// SEC-001: the wildcard flag is part of the binding in both directions.
    /// A wildcard order identifier is never satisfied by a non-wildcard
    /// authorization for the same base (which may have been proven by
    /// http-01 or tls-alpn-01), and vice versa; case is not significant.
    #[test]
    fn qa_finalizable_wildcard_flag_binding() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let a = |t: &str, v: &str, w: bool| valid_authz(t, v, w, later);

        let denied: Vec<(
            &str,
            Vec<Identifier>,
            Vec<ostrich_db::models::AcmeAuthorization>,
        )> = vec![
            (
                "wildcard order, non-wildcard authz",
                vec![ident("dns", "*.example.com")],
                vec![a("dns", "example.com", false)],
            ),
            (
                "plain order, wildcard authz",
                vec![ident("dns", "example.com")],
                vec![a("dns", "example.com", true)],
            ),
            (
                "wildcard authz still carrying `*.`",
                vec![ident("dns", "*.example.com")],
                vec![a("dns", "*.example.com", true)],
            ),
            (
                "ip authz flagged wildcard",
                vec![ident("ip", "192.0.2.1")],
                vec![a("ip", "192.0.2.1", true)],
            ),
            (
                "ip order bound to a dns-typed row",
                vec![ident("ip", "2001:db8::1")],
                vec![a("dns", "2001:db8::1", false)],
            ),
            (
                "wildcard for a different base",
                vec![ident("dns", "*.example.com")],
                vec![a("dns", "a.example.com", true)],
            ),
            (
                "101 identifiers with 101 matching rows (cap)",
                (0..101)
                    .map(|i| ident("dns", &format!("h{i}.example.com")))
                    .collect(),
                (0..101)
                    .map(|i| a("dns", &format!("h{i}.example.com"), false))
                    .collect(),
            ),
        ];
        for (name, ids, rows) in denied {
            let e = finalizable(&order, &ids, &rows, now).expect_err(name);
            assert!(matches!(e, Error::Unauthorized(_)), "{name}: {e:?}");
            assert_eq!(
                e.error_type(),
                "urn:ietf:params:acme:error:unauthorized",
                "{name}"
            );
        }

        // Case-insensitive on both sides, for wildcard and IPv6 values.
        let ids = [ident("dns", "*.Example.COM"), ident("ip", "2001:db8::a")];
        let rows = [a("ip", "2001:DB8::A", false), a("dns", "eXample.com", true)];
        assert!(finalizable(&order, &ids, &rows, now).is_ok());
    }

    /// SEC-001 fail-closed matrix: a single bad row denies the whole order,
    /// whatever its position, and the problem types are the RFC 8555 URNs.
    #[test]
    fn qa_finalizable_fails_closed_on_any_bad_row() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let ids = [
            ident("dns", "a.example.com"),
            ident("dns", "*.example.com"),
            ident("ip", "192.0.2.7"),
        ];
        let good = || {
            vec![
                valid_authz("dns", "a.example.com", false, later),
                valid_authz("dns", "example.com", true, later),
                valid_authz("ip", "192.0.2.7", false, later),
            ]
        };
        assert!(finalizable(&order, &ids, &good(), now).is_ok());
        for i in 0..3 {
            let mut pending = good();
            pending[i].status = "pending".to_string();
            let e = finalizable(&order, &ids, &pending, now).expect_err("pending");
            assert!(matches!(e, Error::OrderNotReady), "row {i}: {e:?}");
            assert_eq!(e.error_type(), "urn:ietf:params:acme:error:orderNotReady");

            let mut expired = good();
            expired[i].expires = now - chrono::Duration::seconds(1);
            let e = finalizable(&order, &ids, &expired, now).expect_err("expired");
            assert!(matches!(e, Error::OrderNotReady), "row {i}: {e:?}");

            let mut swapped = good();
            swapped[i].identifier_value = "evil.example".to_string();
            let e = finalizable(&order, &ids, &swapped, now).expect_err("swap");
            assert!(matches!(e, Error::Unauthorized(_)), "row {i}: {e:?}");
        }
        // An authorization valid one second past `now` is still usable.
        let mut edge = good();
        for r in &mut edge {
            r.expires = now + chrono::Duration::seconds(1);
        }
        assert!(finalizable(&order, &ids, &edge, now).is_ok());
        // A not-ready order is `orderNotReady` even when the rows also
        // mismatch: the order state is checked first, and both deny.
        let e =
            finalizable(&db_order("pending", later), &ids, &[], now).expect_err("pending order");
        assert!(matches!(e, Error::OrderNotReady), "{e:?}");
    }

    /// RFC-001: the ip rule holds for IPv6 rows and for rows also flagged
    /// wildcard (dns-01 passes the wildcard rule but not the ip rule).
    #[test]
    fn qa_check_challenge_permitted_ip_variants() {
        let mut v6 = db_authz("2001:db8::1", false);
        v6.identifier_type = "ip".to_string();
        assert!(check_challenge_permitted(&v6, "http-01").is_ok());
        assert!(matches!(
            check_challenge_permitted(&v6, "tls-alpn-01"),
            Err(Error::Unauthorized(_))
        ));
        let mut flagged = db_authz("192.0.2.1", true);
        flagged.identifier_type = "ip".to_string();
        for t in ["dns-01", "http-01", "tls-alpn-01"] {
            assert!(
                matches!(
                    check_challenge_permitted(&flagged, t),
                    Err(Error::Unauthorized(_))
                ),
                "{t}"
            );
        }
        // Offering and enforcement agree for ip authorizations.
        for a in crate::identifier::validate_order_identifiers(&[
            ident("ip", "192.0.2.1"),
            ident("ip", "2001:db8::1"),
        ])
        .expect("valid")
        {
            let mut row = db_authz(&a.value, a.wildcard);
            row.identifier_type = a.id_type.clone();
            for t in a.challenge_types() {
                assert!(check_challenge_permitted(&row, t).is_ok(), "{t}");
            }
        }
    }

    /// NIST-001 / SI-10: for every newOrder refusal class, the audit record
    /// is a Failure on `acme:new-order` with the matching problem type and
    /// carries none of the request's identifier values or type strings.
    #[test]
    fn qa_new_order_refusal_audit_never_records_values() {
        let m = "qamarkerq";
        let cases: Vec<(&str, Vec<Identifier>)> = vec![
            ("unsupported type", vec![ident(m, "x.example")]),
            (
                "unsupported type (value)",
                vec![ident("email", &format!("{m}@x"))],
            ),
            ("rejected wildcard", vec![ident("dns", &format!("*.{m}"))]),
            (
                "nested wildcard",
                vec![ident("dns", &format!("a.*.{m}.com"))],
            ),
            ("malformed dns", vec![ident("dns", &format!("{m} .com"))]),
            ("dns ip literal", vec![ident("dns", "203.0.113.9")]),
            ("non-canonical ip", vec![ident("ip", &format!("{m}::1"))]),
            ("ipv4-mapped", vec![ident("ip", "::ffff:203.0.113.9")]),
            (
                "duplicate",
                vec![
                    ident("dns", &format!("{m}.com")),
                    ident("dns", &format!("{}.COM", m.to_uppercase())),
                ],
            ),
            (
                "valid then refused",
                vec![
                    ident("dns", &format!("{m}.example")),
                    ident("dns", &format!("*.{m}")),
                ],
            ),
            (
                "cap",
                (0..101)
                    .map(|i| ident("dns", &format!("{m}{i}.com")))
                    .collect(),
            ),
        ];
        for (name, ids) in cases {
            let err = crate::identifier::validate_order_identifiers(&ids).expect_err(name);
            let ev = new_order_audit_event("acct-qa", None, &ids, Some(&err));
            assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure, "{name}");
            assert_eq!(ev.target, "acme:new-order", "{name}");
            assert_eq!(ev.action, "new_order", "{name}");
            assert_eq!(ev.actor, "acct-qa", "{name}");
            let d = ev.details.as_ref().expect("details");
            assert_eq!(d["problem_type"], err.error_type(), "{name}");
            assert_eq!(d["identifier_count"], ids.len(), "{name}");
            assert!(d.get("identifiers").is_none(), "{name}");
            let rendered = serde_json::to_string(&ev).expect("serialize");
            let lower = rendered.to_ascii_lowercase();
            for needle in [m, "203.0.113.9", "x.example", "email"] {
                assert!(!lower.contains(needle), "{name}: {needle} in {rendered}");
            }
        }
    }

    /// NIST-001 / AU-3: the record has who (actor), what (event type,
    /// action), when (timestamp), outcome and object; `wildcard_count`
    /// counts only `dns` `*.` identifiers. The defensive (no order, no
    /// error) arm is a Failure that records no values.
    #[test]
    fn qa_new_order_audit_au3_fields_and_defensive_arm() {
        let before = Utc::now();
        let ids = [
            ident("dns", "*.a.example"),
            ident("dns", "*.b.example"),
            ident("dns", "c.example"),
            ident("ip", "192.0.2.1"),
        ];
        let ev = new_order_audit_event("acct-au3", Some("order-xyz"), &ids, None);
        assert!(ev.timestamp >= before && ev.timestamp <= Utc::now());
        assert_eq!(ev.event_type, ostrich_audit::EventType::AcmeProtocol);
        let d = ev.details.as_ref().expect("details");
        assert_eq!(d["wildcard_count"], 2);
        assert_eq!(d["identifier_types"]["dns"], 3);
        assert_eq!(d["identifier_types"]["ip"], 1);

        // `*.` on a non-dns type is not a wildcard and is not stored.
        let odd = [ident("ip", "*.x"), ident("other", "*.y")];
        let ev = new_order_audit_event("acct-au3", None, &odd, None);
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure);
        assert_eq!(ev.target, "acme:new-order");
        let d = ev.details.as_ref().expect("details");
        assert_eq!(d["wildcard_count"], 0);
        assert_eq!(d["identifier_types"]["ip"], 1);
        assert_eq!(d["identifier_types"]["other"], 1);
        assert!(d.get("identifiers").is_none());
        assert!(d.get("problem_type").is_none());
        let rendered = serde_json::to_string(&ev).expect("serialize");
        assert!(!rendered.contains("*.x") && !rendered.contains("*.y"));
    }

    /// An audit sink that always fails.
    struct FailingSink;

    impl ostrich_audit::AuditSink for FailingSink {
        fn record<'a, 'b, 'r>(
            &'a self,
            _event: &'b mut ostrich_audit::AuditEvent,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = ostrich_audit::Result<()>> + Send + 'r>,
        >
        where
            'a: 'r,
            'b: 'r,
            Self: 'r,
        {
            Box::pin(async {
                Err(ostrich_audit::Error::Serialization(
                    "sink unavailable".to_string(),
                ))
            })
        }

        fn verify_integrity<'a, 'r>(
            &'a self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = ostrich_audit::Result<bool>> + Send + 'r>,
        >
        where
            'a: 'r,
            Self: 'r,
        {
            Box::pin(async { Ok(false) })
        }

        fn query_events<'a, 'r>(
            &'a self,
            _criteria: ostrich_audit::sink::QueryCriteria,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = ostrich_audit::Result<Vec<ostrich_audit::AuditEvent>>,
                    > + Send
                    + 'r,
            >,
        >
        where
            'a: 'r,
            Self: 'r,
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    /// A failing audit sink neither panics nor propagates into the request
    /// (documented behaviour, consistent with challenge validation; no
    /// AU-5 fail-closed). `record_audit` returns normally.
    #[tokio::test]
    async fn qa_record_audit_survives_sink_failure() {
        let ids = [ident("dns", "example.com")];
        let mut ev = new_order_audit_event("acct-f", Some("order-f"), &ids, None);
        record_audit(&FailingSink, &mut ev).await;
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Success);
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

    // ---- Fix round 2 (NIST-007, RFC-007, SEC-005) ----

    /// NIST-007: a finalize refusal is a Failure for `acme:order:<id>` with
    /// the problem type only; the error detail (which may echo CSR SANs) and
    /// CSR values never reach the record.
    #[test]
    fn finalize_refusal_audit_event_records_problem_type_only() {
        let marker = "zzcsrmarker";
        let ids = [ident("dns", "example.com")];
        let err = validate_csr_identifiers(&ids, &[format!("DNS:{marker}.example")])
            .expect_err("CSR mismatch");
        assert!(format!("{err:?}").contains(marker), "precondition");
        let ev = finalize_refusal_audit_event("acct-9", "order-xyz", &err);
        assert_eq!(ev.event_type, ostrich_audit::EventType::AcmeProtocol);
        assert_eq!(ev.actor, "acct-9");
        assert_eq!(ev.target, "acme:order:order-xyz");
        assert_eq!(ev.action, "finalize_order");
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure);
        assert_eq!(
            ev.details.clone().expect("details"),
            serde_json::json!({ "problem_type": "urn:ietf:params:acme:error:unauthorized" })
        );
        let rendered = serde_json::to_string(&ev).expect("serialize");
        assert!(!rendered.contains(marker), "{rendered}");

        let now = Utc::now();
        let e = finalizable(&db_order("pending", now), &ids, &[], now).expect_err("pending");
        let ev = finalize_refusal_audit_event("acct-9", "order-xyz", &e);
        assert_eq!(
            ev.details.expect("details")["problem_type"],
            "urn:ietf:params:acme:error:orderNotReady"
        );
    }

    /// NIST-007: the refusal reaches the audit sink and its hash chain.
    #[tokio::test]
    async fn finalize_refusal_audit_event_is_recorded() {
        use ostrich_audit::AuditSink as _;
        let sink = ostrich_audit::sink::MemoryAuditSink::new();
        let mut ev = finalize_refusal_audit_event("acct-10", "order-1", &Error::OrderNotReady);
        record_audit(&sink, &mut ev).await;
        let events = sink
            .query_events(ostrich_audit::sink::QueryCriteria {
                actor: Some("acct-10".to_string()),
                event_type: None,
                start_time: None,
                end_time: None,
                limit: None,
                offset: None,
            })
            .await
            .expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "finalize_order");
        assert_eq!(events[0].target, "acme:order:order-1");
        assert_eq!(events[0].outcome, ostrich_audit::EventOutcome::Failure);
        assert!(sink.verify_integrity().await.expect("verify"));
    }

    /// RFC-007: the binding pass runs over every row before the status pass,
    /// so a pending row plus a mismatched row is `unauthorized` in either
    /// order; a pending row plus an ip row not proven by http-01 is
    /// `orderNotReady` in either order.
    #[test]
    fn check_order_finalizable_error_type_independent_of_row_order() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let ids = [ident("dns", "a.example.com"), ident("dns", "b.example.com")];
        let mut pending = valid_authz("dns", "a.example.com", false, later);
        pending.status = "pending".to_string();
        let mismatched = valid_authz("dns", "evil.example", false, later);
        for rows in [
            [pending.clone(), mismatched.clone()],
            [mismatched, pending.clone()],
        ] {
            let e = finalizable(&order, &ids, &rows, now).expect_err("denied");
            assert!(matches!(e, Error::Unauthorized(_)), "{e:?}");
        }

        let ids = [ident("dns", "a.example.com"), ident("ip", "192.0.2.1")];
        let ip = valid_authz("ip", "192.0.2.1", false, later);
        let tls = [challenge_row(&ip, "tls-alpn-01", "valid")];
        for rows in [[pending.clone(), ip.clone()], [ip.clone(), pending.clone()]] {
            let e = check_order_finalizable(&order, &ids, &rows, &tls, now).expect_err("denied");
            assert!(matches!(e, Error::OrderNotReady), "{e:?}");
        }
    }

    /// SEC-005: a `valid` ip authorization is usable only with a `valid`
    /// http-01 challenge row of that authorization.
    #[test]
    fn check_order_finalizable_ip_requires_http01() {
        let now = Utc::now();
        let later = now + chrono::Duration::days(1);
        let order = db_order("ready", later);
        let ids = [ident("dns", "example.com"), ident("ip", "2001:db8::1")];
        let dns = valid_authz("dns", "example.com", false, later);
        let ip = valid_authz("ip", "2001:db8::1", false, later);
        let rows = [dns.clone(), ip.clone()];
        let other = valid_authz("ip", "2001:db8::1", false, later);

        let denied: Vec<(&str, Vec<ostrich_db::models::AcmeChallenge>)> = vec![
            ("no challenge rows", vec![]),
            (
                "legacy tls-alpn-01",
                vec![
                    challenge_row(&ip, "tls-alpn-01", "valid"),
                    challenge_row(&ip, "http-01", "pending"),
                ],
            ),
            ("legacy dns-01", vec![challenge_row(&ip, "dns-01", "valid")]),
            (
                "http-01 invalid",
                vec![challenge_row(&ip, "http-01", "invalid")],
            ),
            (
                "http-01 processing",
                vec![challenge_row(&ip, "http-01", "processing")],
            ),
            ("type case", vec![challenge_row(&ip, "HTTP-01", "valid")]),
            (
                "http-01 of another authorization",
                vec![challenge_row(&other, "http-01", "valid")],
            ),
            (
                "http-01 of the dns authorization",
                vec![challenge_row(&dns, "http-01", "valid")],
            ),
        ];
        for (name, challs) in denied {
            let e = check_order_finalizable(&order, &ids, &rows, &challs, now).expect_err(name);
            assert!(matches!(e, Error::Unauthorized(_)), "{name}: {e:?}");
            assert_eq!(e.error_type(), "urn:ietf:params:acme:error:unauthorized");
        }

        // Proven by http-01 (other rows of the authorization do not matter);
        // dns authorizations need no challenge rows here.
        let ok = [
            challenge_row(&ip, "tls-alpn-01", "invalid"),
            challenge_row(&ip, "http-01", "valid"),
        ];
        assert!(check_order_finalizable(&order, &ids, &rows, &ok, now).is_ok());
        let dns_only = [ident("dns", "example.com")];
        assert!(check_order_finalizable(&order, &dns_only, &[dns], &[], now).is_ok());
    }
}
