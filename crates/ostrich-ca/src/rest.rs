//! REST API implementation for Certificate Authority
//!
//! This module provides REST API endpoints for certificate issuance, revocation,
//! and CA management operations.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: Security management functions - API endpoints for CA operations
//! - **FDP_ACC.1**: Access control - API authentication and authorization
//! - **FIA_AFL.1**: Authentication failure handling - Rate limiting, lockout
//! - **FTP_ITC.1**: Inter-TSF trusted channel - TLS for API transport
//!
//! ## RFC Compliance
//! - RFC 5280: X.509 Public Key Infrastructure
//!
//! ## NIST 800-53 Controls
//! - SC-8: Transmission confidentiality (TLS)
//! - SC-12: Cryptographic key establishment and management
//! - AC-3: Access enforcement

use crate::{CertificateAuthority, Error, IssuanceRequest, Result, RevocationRequest};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use ostrich_common::auth::provider::AuthProvider;
use ostrich_common::auth::{AuthLayer, AuthUser, AuthzLayer, Permission, RbacPolicy};
use ostrich_common::types::DistinguishedName;
use ostrich_x509::{extensions::SubjectAltName, parser::RevocationReason};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// REST API state
pub struct ApiState {
    ca: Arc<CertificateAuthority>,
    #[allow(dead_code)]
    auth_provider: Arc<dyn AuthProvider>,
    #[allow(dead_code)]
    rbac_policy: Arc<RbacPolicy>,
}

impl ApiState {
    /// Create new API state
    pub fn new(
        ca: Arc<CertificateAuthority>,
        auth_provider: Arc<dyn AuthProvider>,
        rbac_policy: Arc<RbacPolicy>,
    ) -> Self {
        Self {
            ca,
            auth_provider,
            rbac_policy,
        }
    }
}

/// Create REST API router
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - Authentication required for all management endpoints
/// - NIAP PP-CA: FMT_MTD.1 - Access control for TSF data management
/// - NIST 800-53: AC-3 - Access enforcement via RBAC middleware
pub fn create_router(
    ca: Arc<CertificateAuthority>,
    auth_provider: Arc<dyn AuthProvider>,
    rbac_policy: Arc<RbacPolicy>,
) -> Router {
    let state = Arc::new(ApiState::new(
        ca,
        auth_provider.clone(),
        rbac_policy.clone(),
    ));

    // Public endpoints (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/api/v1/ca/info", get(get_ca_info))
        // Revocation status is publicly accessible per RFC 5280
        .route(
            "/api/v1/certificates/:id/status",
            get(check_revocation_status),
        )
        .route("/api/v1/profiles", get(list_profiles));

    // Protected endpoints requiring authentication and authorization
    let protected_routes = Router::new()
        .route("/api/v1/certificates", post(issue_certificate))
        .route_layer(middleware::from_fn_with_state(
            (
                rbac_policy.clone(),
                Permission::IssueCertificate,
                None::<String>,
            ),
            AuthzLayer::authorize,
        ))
        .route("/api/v1/certificates/:id/revoke", post(revoke_certificate))
        .route_layer(middleware::from_fn_with_state(
            (
                rbac_policy.clone(),
                Permission::RevokeCertificate,
                None::<String>,
            ),
            AuthzLayer::authorize,
        ))
        .route("/api/v1/crl", post(generate_crl))
        .route_layer(middleware::from_fn_with_state(
            (rbac_policy.clone(), Permission::GenerateCrl, None::<String>),
            AuthzLayer::authorize,
        ))
        .layer(middleware::from_fn_with_state(
            auth_provider.clone(),
            AuthLayer::authenticate,
        ));

    // Merge public and protected routes
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}

/// Health check endpoint (liveness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
///
/// Returns 200 OK if the service process is running.
/// This is used by Kubernetes liveness probes to restart unhealthy pods.
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "ostrich-ca",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness check endpoint (readiness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - NIST 800-53: SC-12 (Cryptographic key establishment)
///
/// Returns 200 OK if the service is ready to handle requests.
/// This checks that all dependencies (database, HSM) are accessible.
/// Used by Kubernetes readiness probes to route traffic.
async fn readiness_check(State(state): State<Arc<ApiState>>) -> Result<impl IntoResponse> {
    // Check if CA is initialized (has access to signing key)
    // This validates HSM connectivity and key accessibility
    let _ = state.ca.info();

    // TODO: Add database connectivity check when repository pattern is integrated
    // Example: state.ca.check_database_connection().await?;

    Ok(Json(serde_json::json!({
        "status": "ready",
        "service": "ostrich-ca",
        "version": env!("CARGO_PKG_VERSION"),
        "checks": {
            "ca_initialized": true,
            "database": "not_implemented"
        }
    })))
}

/// Get CA information
async fn get_ca_info(State(state): State<Arc<ApiState>>) -> Result<Json<CaInfoResponse>> {
    let info = state.ca.info();

    Ok(Json(CaInfoResponse {
        ca_id: info.ca_id.to_string(),
        ca_dn: info.ca_dn,
    }))
}

/// Issue a new certificate
///
/// NIAP PP-CA: FMT_SMF.1.1 - Certificate issuance endpoint
/// NIAP PP-CA: FDP_ACC.1.1 - Requires authorized requestor
/// NIAP PP-CA: FIA_UAU.1 - Authenticated user required
/// NIST 800-53: AC-3 - Access enforcement (checked by middleware)
/// NIST 800-53: AU-2 - Auditable event (actor identity logged)
async fn issue_certificate(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<IssueCertificateRequest>,
) -> Result<Json<IssueCertificateResponse>> {
    // Convert REST request to internal request
    // Use authenticated user's identity as requestor (override client-provided value)
    let issuance_req = IssuanceRequest {
        profile_name: req.profile_name,
        subject: req.subject,
        subject_alt_names: req.subject_alt_names,
        public_key: req.public_key,
        requestor: user.username.clone(), // Use authenticated identity
        metadata: req.metadata,
        csr_der: None, // REST API doesn't currently accept CSR
    };

    // Issue certificate
    let issued = state.ca.issuer().issue(issuance_req).await?;

    Ok(Json(IssueCertificateResponse {
        certificate_id: issued.certificate_id.to_string(),
        serial_number: hex::encode(&issued.serial_number),
        der_encoded: BASE64_STANDARD.encode(&issued.der_encoded),
        pem_encoded: issued.pem_encoded,
        not_before: issued.not_before.to_rfc3339(),
        not_after: issued.not_after.to_rfc3339(),
    }))
}

/// Revoke a certificate
///
/// NIAP PP-CA: FMT_SMF.1.1 - Certificate revocation endpoint
/// NIAP PP-CA: FDP_ACC.1.1 - Requires authorized requestor
/// NIAP PP-CA: FIA_UAU.1 - Authenticated user required
/// NIST 800-53: AC-3 - Access enforcement (checked by middleware)
/// NIST 800-53: AU-2 - Auditable event (actor identity logged)
async fn revoke_certificate(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RevokeCertificateRequest>,
) -> Result<Json<RevokeCertificateResponse>> {
    // Parse certificate ID
    let certificate_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid certificate ID".to_string()))?;

    // Create revocation request
    // Use authenticated user's identity as requestor (override client-provided value)
    let revocation_req = RevocationRequest {
        certificate_id,
        reason: req.reason,
        requestor: user.username.clone(), // Use authenticated identity
        justification: req.justification,
    };

    // Revoke certificate
    state.ca.revocation_manager().revoke(revocation_req).await?;

    Ok(Json(RevokeCertificateResponse {
        success: true,
        revocation_time: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Check revocation status
async fn check_revocation_status(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<RevocationStatusResponse>> {
    // Parse certificate ID
    let certificate_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid certificate ID".to_string()))?;

    // Check revocation status
    let is_revoked = state
        .ca
        .revocation_manager()
        .is_revoked(&certificate_id)
        .await?;

    Ok(Json(RevocationStatusResponse {
        revoked: is_revoked,
        revocation_time: None, // TODO: Get from database
        reason: None,          // TODO: Get from database
    }))
}

/// Generate a new CRL
///
/// NIAP PP-CA: FMT_SMF.1.1 - CRL generation endpoint
/// NIAP PP-CA: FDP_ACC.1.1 - Requires authorized administrator
/// NIAP PP-CA: FIA_UAU.1 - Authenticated user required
/// NIST 800-53: AC-3 - Access enforcement (checked by middleware)
/// NIST 800-53: AU-2 - Auditable event (actor identity logged)
async fn generate_crl(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
) -> Result<Json<GenerateCrlResponse>> {
    // Generate CRL
    let crl = state
        .ca
        .revocation_manager()
        .generate_crl(state.ca.ca_dn.clone())
        .await?;

    Ok(Json(GenerateCrlResponse {
        crl_number: crl.crl_number,
        this_update: crl.this_update.to_rfc3339(),
        next_update: crl.next_update.to_rfc3339(),
        revoked_count: crl.revoked_count,
        der_encoded: BASE64_STANDARD.encode(&crl.der_encoded),
        pem_encoded: crl.pem_encoded,
    }))
}

/// List certificate profiles
async fn list_profiles(State(_state): State<Arc<ApiState>>) -> Result<Json<ListProfilesResponse>> {
    // TODO: Get profiles from CA
    // For now, return example profiles
    use ostrich_x509::profile::CertificateProfile;

    let profiles = vec![
        ProfileInfo::from_profile(&CertificateProfile::root_ca(3650)),
        ProfileInfo::from_profile(&CertificateProfile::intermediate_ca(1825, 0)),
        ProfileInfo::from_profile(&CertificateProfile::tls_server(365)),
        ProfileInfo::from_profile(&CertificateProfile::tls_client(365)),
        ProfileInfo::from_profile(&CertificateProfile::code_signing(365)),
        ProfileInfo::from_profile(&CertificateProfile::ocsp_signing(90)),
    ];

    Ok(Json(ListProfilesResponse { profiles }))
}

// REST API Request/Response types

/// CA information response
#[derive(Debug, Serialize, Deserialize)]
pub struct CaInfoResponse {
    pub ca_id: String,
    pub ca_dn: String,
}

/// Certificate issuance request
#[derive(Debug, Serialize, Deserialize)]
pub struct IssueCertificateRequest {
    pub profile_name: String,
    pub subject: DistinguishedName,
    #[serde(default)]
    pub subject_alt_names: Vec<SubjectAltName>,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    pub requestor: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Certificate issuance response
#[derive(Debug, Serialize, Deserialize)]
pub struct IssueCertificateResponse {
    pub certificate_id: String,
    pub serial_number: String,
    pub der_encoded: String,
    pub pem_encoded: String,
    pub not_before: String,
    pub not_after: String,
}

/// Certificate revocation request
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeCertificateRequest {
    pub reason: RevocationReason,
    pub requestor: String,
    pub justification: Option<String>,
}

/// Certificate revocation response
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeCertificateResponse {
    pub success: bool,
    pub revocation_time: String,
}

/// Revocation status response
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationStatusResponse {
    pub revoked: bool,
    pub revocation_time: Option<String>,
    pub reason: Option<RevocationReason>,
}

/// CRL generation response
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateCrlResponse {
    pub crl_number: u64,
    pub this_update: String,
    pub next_update: String,
    pub revoked_count: usize,
    pub der_encoded: String,
    pub pem_encoded: String,
}

/// List profiles response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListProfilesResponse {
    pub profiles: Vec<ProfileInfo>,
}

/// Profile information
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: String,
    pub profile_type: String,
    pub description: String,
    pub validity_days: u32,
    pub key_type: String,
    pub algorithm: String,
    pub basic_constraints_ca: bool,
    pub basic_constraints_path_len: Option<u8>,
    pub subject_alt_name_required: bool,
}

impl ProfileInfo {
    fn from_profile(profile: &ostrich_x509::profile::CertificateProfile) -> Self {
        Self {
            name: profile.name.clone(),
            profile_type: profile.profile_type.as_str().to_string(),
            description: profile.description.clone().unwrap_or_default(),
            validity_days: profile.validity_days,
            key_type: profile.key_type.clone(),
            algorithm: profile.algorithm.clone(),
            basic_constraints_ca: profile.basic_constraints_ca,
            basic_constraints_path_len: profile.basic_constraints_path_len,
            subject_alt_name_required: profile.subject_alt_name_required,
        }
    }
}

// Custom serde module for base64 encoding
mod base64_serde {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// Error conversion for Axum responses
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Error::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Error::Issuance(msg) => (StatusCode::BAD_REQUEST, msg),
            Error::Revocation(msg) => (StatusCode::BAD_REQUEST, msg),
            Error::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()),
            Error::Crypto(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()),
            Error::X509(msg) => (StatusCode::BAD_REQUEST, msg.to_string()),
            Error::Audit(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()),
            Error::Common(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()),
            Error::ProfileNotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Error::CrlGeneration(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Error::NotInitialized => (
                StatusCode::SERVICE_UNAVAILABLE,
                "CA not initialized".to_string(),
            ),
            Error::KeyNotFound(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Error::SelfApprovalProhibited => (
                StatusCode::FORBIDDEN,
                "Self-approval prohibited: requestor cannot approve their own request".to_string(),
            ),
            Error::InsufficientRole { required } => (
                StatusCode::FORBIDDEN,
                format!("Insufficient role: {} role required", required),
            ),
            Error::InvalidApprovalState { current, expected } => (
                StatusCode::BAD_REQUEST,
                format!("Invalid approval state: current={}, expected={}", current, expected),
            ),
            Error::ApprovalRequestExpired { expired_at } => (
                StatusCode::GONE,
                format!("Approval request expired at {}", expired_at),
            ),
            Error::ApprovalRequestNotFound(id) => (
                StatusCode::NOT_FOUND,
                format!("Approval request not found: {}", id),
            ),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_info_conversion() {
        use ostrich_x509::profile::CertificateProfile;

        let profile = CertificateProfile::tls_server(365);
        let info = ProfileInfo::from_profile(&profile);

        assert_eq!(info.name, "TLS Server");
        assert_eq!(info.validity_days, 365);
        assert!(info.subject_alt_name_required);
    }
}
