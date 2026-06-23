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

use crate::{
    CertificateAuthority, Error, IssuanceRequest, Result, RevocationRequest,
    approval::{ApprovalEngine, ApprovalRequest, RequestType},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use ostrich_common::auth::provider::AuthProvider;
use ostrich_common::auth::{AuthLayer, AuthUser, AuthzLayer, Permission, RbacPolicy};
use ostrich_common::types::DistinguishedName;
use ostrich_db::DatabasePool;
use ostrich_db::models::Certificate;
use ostrich_db::repository::{ApprovalRepository, CertificateRepository, CrlRepository};
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
    approval_engine: Arc<ApprovalEngine>,
    approval_repo: Arc<ApprovalRepository>,
    /// Database pool, used to serve the latest persisted CRL at the public
    /// distribution point (RFC 5280 §5).
    db_pool: DatabasePool,
}

impl ApiState {
    /// Create new API state
    pub fn new(
        ca: Arc<CertificateAuthority>,
        auth_provider: Arc<dyn AuthProvider>,
        rbac_policy: Arc<RbacPolicy>,
        approval_engine: Arc<ApprovalEngine>,
        approval_repo: Arc<ApprovalRepository>,
        db_pool: DatabasePool,
    ) -> Self {
        Self {
            ca,
            auth_provider,
            rbac_policy,
            approval_engine,
            approval_repo,
            db_pool,
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
    approval_engine: Arc<ApprovalEngine>,
    approval_repo: Arc<ApprovalRepository>,
    db_pool: DatabasePool,
) -> Router {
    let state = Arc::new(ApiState::new(
        ca,
        auth_provider.clone(),
        rbac_policy.clone(),
        approval_engine,
        approval_repo,
        db_pool,
    ));

    // Public endpoints (no authentication required)
    //
    // Each entry below is an intentional exception to the default-authenticated
    // policy. Any new public route MUST be justified here.
    //
    // - /health, /ready: orchestrator probes; no security-relevant data (NIST SI-17)
    // - /api/v1/ca/info: CA subject DN and key id are needed by any relying party
    //   to build an AIA reference. Equivalent to serving the CA cert chain, which
    //   is public by definition (RFC 5280).
    // - /api/v1/certificates/:id/status: revocation status must be reachable by any
    //   relying party performing certificate validation (RFC 5280 §5, RFC 6960).
    // - GET /api/v1/crl: the signed CRL is public status data by definition
    //   (RFC 5280 §5). Relying parties fetch it (via the CDP extension in issued
    //   certs, RFC 5280 §4.2.1.13) with no authentication. The authenticated
    //   POST /api/v1/crl (generation) stays in protected_routes below.
    //
    // NOTE: /api/v1/profiles was previously public; it leaked the configured profile
    // catalog (key types, key sizes, validity periods) to unauthenticated clients.
    // It is now protected and requires Permission::ViewConfig.
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/api/v1/ca/info", get(get_ca_info))
        .route(
            "/api/v1/certificates/{id}/status",
            get(check_revocation_status),
        )
        // RFC 5280 §5 - public CRL distribution point (no auth)
        .route("/api/v1/crl", get(get_crl))
        .route("/api/v1/crl/delta", get(get_delta_crl));

    // Per-permission authorization middleware factory.
    //
    // IMPORTANT: the permission layer is applied to the *MethodRouter*
    // (`post(handler).route_layer(...)`), never via `Router::route_layer`
    // chained between `.route(...)` calls. `Router::route_layer` wraps every
    // route added so far, so the previous chained style stacked ALL
    // subsequent permission checks onto the earlier routes - no single role
    // held every permission (AC-5 separation of duties), making the entire
    // protected API return 403 for everyone.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3 (Access Enforcement) - exactly one permission per route
    // - NIST 800-53: AC-5 - separation-of-duties matrix remains enforceable
    let authz = |permission: Permission| {
        middleware::from_fn_with_state(
            (rbac_policy.clone(), permission, None::<String>),
            AuthzLayer::authorize,
        )
    };

    // Protected endpoints requiring authentication and authorization
    let protected_routes = Router::new()
        .route(
            "/api/v1/certificates",
            post(issue_certificate).route_layer(authz(Permission::IssueCertificate)),
        )
        // Read access to the issued-certificate inventory. Separate from the
        // POST (issuance) on the same path, with its own permission, mirroring
        // the GET/POST split already used for /api/v1/approvals.
        .route(
            "/api/v1/certificates",
            get(list_certificates).route_layer(authz(Permission::ViewCertificate)),
        )
        // Inventory-wide status counts for the dashboard summary cards. Static
        // segment, registered alongside `/{id}`; the router prefers the literal.
        .route(
            "/api/v1/certificates/stats",
            get(certificate_stats).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/certificates/{id}",
            get(get_certificate).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/certificates/{id}/revoke",
            post(revoke_certificate).route_layer(authz(Permission::RevokeCertificate)),
        )
        .route(
            "/api/v1/crl",
            post(generate_crl).route_layer(authz(Permission::GenerateCrl)),
        )
        .route(
            "/api/v1/crl/delta",
            post(generate_delta_crl).route_layer(authz(Permission::GenerateCrl)),
        )
        // Configuration metadata
        // Permission::ViewConfig - profile catalog is configuration data (NIAP FMT_SMF.1)
        .route(
            "/api/v1/profiles",
            get(list_profiles).route_layer(authz(Permission::ViewConfig)),
        )
        // Approval workflow endpoints
        .route(
            "/api/v1/approvals",
            post(submit_approval_request).route_layer(authz(Permission::SubmitRequest)),
        )
        .route(
            "/api/v1/approvals",
            get(list_approval_requests).route_layer(authz(Permission::ViewRequests)),
        )
        .route(
            "/api/v1/approvals/{id}",
            get(get_approval_request).route_layer(authz(Permission::ViewRequests)),
        )
        .route(
            "/api/v1/approvals/{id}/approve",
            post(approve_request).route_layer(authz(Permission::ApproveRequest)),
        )
        .route(
            "/api/v1/approvals/{id}/reject",
            post(reject_request).route_layer(authz(Permission::ApproveRequest)),
        )
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
/// Convert the prefixed SAN strings produced by `ostrich_x509::parser::parse_csr`
/// (`"DNS:.."`, `"IP:.."`, `"email:.."`, `"URI:.."`) into structured
/// [`SubjectAltName`] values. Unrecognized/unparsable entries are dropped.
fn sans_from_strings(sans: &[String]) -> Vec<SubjectAltName> {
    sans.iter()
        .filter_map(|s| {
            let (kind, value) = s.split_once(':')?;
            match kind.to_ascii_uppercase().as_str() {
                "DNS" => Some(SubjectAltName::dns(value)),
                "EMAIL" => Some(SubjectAltName::email(value)),
                "URI" => Some(SubjectAltName::uri(value)),
                "IP" => value
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(SubjectAltName::ip),
                _ => None,
            }
        })
        .collect()
}

async fn issue_certificate(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<IssueCertificateRequest>,
) -> Result<Json<IssueCertificateResponse>> {
    // Parse the optional approval request id (NIAP PP-CA FDP_CER_EXT.3).
    // When the CA runs with the approval workflow enabled (the secure
    // default), the issuer requires this to reference an already-Approved
    // request; when disabled it is ignored.
    let approval_request_id = match req.approval_request_id.as_deref() {
        Some(id) => Some(
            uuid::Uuid::parse_str(id)
                .map_err(|_| Error::InvalidRequest("Invalid approval_request_id".to_string()))?,
        ),
        None => None,
    };

    // Resolve subject / public key / SANs. When a CSR is supplied, any of
    // these that the caller omitted are derived from it (the "paste a CSR"
    // admin flow); explicit values still take precedence.
    let (subject, public_key, subject_alt_names) = match &req.csr_der {
        Some(csr_der) => {
            let parsed = ostrich_x509::parser::parse_csr(csr_der)
                .map_err(|e| Error::InvalidRequest(format!("Invalid CSR: {e}")))?;
            let subject = match req.subject {
                Some(s) => s,
                None => ostrich_x509::parser::parse_csr_subject_dn(csr_der)
                    .map_err(|e| Error::InvalidRequest(format!("Invalid CSR subject: {e}")))?,
            };
            let public_key = req.public_key.unwrap_or(parsed.public_key);
            let subject_alt_names = if req.subject_alt_names.is_empty() {
                sans_from_strings(&parsed.subject_alternative_names)
            } else {
                req.subject_alt_names
            };
            (subject, public_key, subject_alt_names)
        }
        None => {
            let subject = req.subject.ok_or_else(|| {
                Error::InvalidRequest("subject is required when no CSR is supplied".to_string())
            })?;
            let public_key = req.public_key.ok_or_else(|| {
                Error::InvalidRequest("public_key is required when no CSR is supplied".to_string())
            })?;
            (subject, public_key, req.subject_alt_names)
        }
    };

    // Convert REST request to internal request
    // Use authenticated user's identity as requestor (override client-provided value)
    let issuance_req = IssuanceRequest {
        profile_name: req.profile_name,
        subject,
        subject_alt_names,
        public_key,
        requestor: user.username.clone(), // Use authenticated identity
        metadata: req.metadata,
        csr_der: req.csr_der, // when present, issue() verifies proof-of-possession (RFC 2986)
        approval_request_id,
        request_id: None, // CA generates a request_id for traceability (FDP_CER_EXT.2)
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

/// Derive the relying-party-visible status of a stored certificate.
///
/// RFC 5280 §5: a certificate is "revoked" once it appears on the CRL;
/// otherwise its temporal validity (§4.1.2.5) determines active/expired/pending.
fn cert_status_str(cert: &Certificate, now: chrono::DateTime<chrono::Utc>) -> &'static str {
    if cert.revoked {
        "revoked"
    } else if cert.not_after < now {
        "expired"
    } else if cert.not_before > now {
        "pending"
    } else {
        "active"
    }
}

/// Query parameters for the certificate inventory listing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListCertificatesQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    status: Option<String>,
    search: Option<String>,
}

/// One row in the certificate inventory listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateSummaryDto {
    id: String,
    serial_number: String,
    subject: String,
    issuer: String,
    valid_from: String,
    valid_to: String,
    status: String,
    key_algorithm: Option<String>,
}

/// Paginated response for the certificate inventory listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateListResponseDto {
    certificates: Vec<CertificateSummaryDto>,
    total: u64,
    page: u32,
    page_size: u32,
}

/// Inventory-wide certificate counts by status (dashboard summary cards).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateStatsDto {
    total: u64,
    active: u64,
    revoked: u64,
    expired: u64,
    pending: u64,
}

/// A Subject Alternative Name entry in the certificate detail view.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SanDto {
    name_type: String,
    value: String,
}

/// A parsed X.509 extension entry in the certificate detail view.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionDto {
    oid: String,
    name: String,
    critical: bool,
    value: String,
}

/// Full detail view of a single stored certificate.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateDetailsDto {
    id: String,
    serial_number: String,
    version: u8,
    status: String,
    subject_dn: String,
    issuer_dn: String,
    valid_from: String,
    valid_to: String,
    days_remaining: Option<i64>,
    key_algorithm: String,
    key_size: u32,
    signature_algorithm: String,
    fingerprint_sha256: String,
    fingerprint_sha1: String,
    extensions: Vec<ExtensionDto>,
    subject_alt_names: Vec<SanDto>,
    key_usage: Vec<String>,
    extended_key_usage: Vec<String>,
    authority_key_id: Option<String>,
    subject_key_id: Option<String>,
    crl_distribution_points: Vec<String>,
    ocsp_responder_urls: Vec<String>,
    revocation_time: Option<String>,
    revocation_reason: Option<String>,
    pem: String,
}

/// List issued certificates (paginated).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate via middleware)
/// - NIAP PP-CA: FMT_SMF.1 - Security management: certificate inventory query
/// - NIAP PP-CA: FMT_MTD.1 - Authorized read access to TSF data
async fn list_certificates(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Query(query): Query<ListCertificatesQuery>,
) -> Result<Json<CertificateListResponseDto>> {
    let repo = CertificateRepository::new(state.db_pool.clone());
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).clamp(1, 1000);
    let offset = i64::from(page - 1) * i64::from(page_size);
    let now = chrono::Utc::now();

    // Status defaults to "all"; lowercased so it matches cert_status_str output.
    let status = query
        .status
        .as_deref()
        .map(str::to_lowercase)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "all".to_string());
    // Trimmed literal substring; empty search means "no search".
    let search = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // Map a stored row to its summary DTO (status derived before fields move).
    let to_summary = |c: Certificate| {
        let status = cert_status_str(&c, now).to_string();
        CertificateSummaryDto {
            id: c.id.to_string(),
            serial_number: hex::encode(&c.serial_number),
            subject: c.subject_dn,
            issuer: c.issuer_dn,
            valid_from: c.not_before.to_rfc3339(),
            valid_to: c.not_after.to_rfc3339(),
            status,
            key_algorithm: None,
        }
    };

    // Filter + search + paginate + count entirely in SQL — no in-memory scan,
    // no row cap, and `total` always describes the full matching population.
    let (rows, total) = repo
        .list_filtered(&status, search.as_deref(), i64::from(page_size), offset)
        .await?;
    let certificates: Vec<CertificateSummaryDto> = rows.into_iter().map(to_summary).collect();
    let total = total as u64;

    // NIST 800-53 AU-2/AU-3: record who enumerated the inventory and the outcome.
    tracing::info!(
        actor = %user.username,
        resource = "certificates",
        page,
        page_size,
        returned = certificates.len(),
        total,
        "certificate inventory listed"
    );

    Ok(Json(CertificateListResponseDto {
        certificates,
        total,
        page,
        page_size,
    }))
}

/// Inventory-wide certificate status counts (GET /api/v1/certificates/stats).
///
/// Backs the dashboard summary cards with true totals, independent of the list
/// view's filter and pagination (a single SQL aggregate, not a row scan).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate)
/// - NIST 800-53: AU-2 - Auditable read of TSF data
/// - NIAP PP-CA: FMT_MTD.1 - Authorized read access to TSF data
async fn certificate_stats(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
) -> Result<Json<CertificateStatsDto>> {
    let repo = CertificateRepository::new(state.db_pool.clone());
    let counts = repo.count_by_status().await?;

    tracing::info!(
        actor = %user.username,
        resource = "certificates:stats",
        total = counts.total,
        "certificate inventory stats read"
    );

    Ok(Json(CertificateStatsDto {
        total: counts.total.max(0) as u64,
        active: counts.active.max(0) as u64,
        revoked: counts.revoked.max(0) as u64,
        expired: counts.expired.max(0) as u64,
        pending: counts.pending.max(0) as u64,
    }))
}

/// Get a single certificate by id, with parsed X.509 detail.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate via middleware)
/// - NIAP PP-CA: FMT_SMF.1 - Security management: certificate inspection
async fn get_certificate(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let cert_id = match uuid::Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return Ok((StatusCode::BAD_REQUEST, "invalid certificate id").into_response());
        }
    };

    let repo = CertificateRepository::new(state.db_pool.clone());
    let cert = match repo.find_by_id(cert_id).await? {
        Some(cert) => cert,
        None => return Ok((StatusCode::NOT_FOUND, "certificate not found").into_response()),
    };

    let now = chrono::Utc::now();
    // Rich X.509 detail (key alg/size, fingerprints, EKU, AKI/SKI, extension
    // inventory, …). Best-effort: an unparseable cert yields the DB fields only.
    let desc = ostrich_x509::parser::describe_certificate(&cert.der_encoded).ok();
    let d = desc.as_ref();

    // SANs come back as "DNS:host" / "email:addr" strings; split into type+value.
    let subject_alt_names = d
        .map(|d| {
            d.subject_alt_names
                .iter()
                .map(|san| match san.split_once(':') {
                    Some((kind, value)) => SanDto {
                        name_type: kind.to_string(),
                        value: value.to_string(),
                    },
                    None => SanDto {
                        name_type: "DNS".to_string(),
                        value: san.clone(),
                    },
                })
                .collect()
        })
        .unwrap_or_default();

    let extensions = d
        .map(|d| {
            d.extensions
                .iter()
                .map(|e| ExtensionDto {
                    oid: e.oid.clone(),
                    name: e.name.clone(),
                    critical: e.critical,
                    value: e.value.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let revocation_reason = cert.revocation_reason.map(|r| {
        RevocationReason::from_i32(r)
            .map(|reason| format!("{reason:?}"))
            .unwrap_or_else(|| r.to_string())
    });

    let details = CertificateDetailsDto {
        id: cert.id.to_string(),
        serial_number: hex::encode(&cert.serial_number),
        version: 3, // RFC 5280 §4.1.2.1 - X.509 v3 (all certs this CA issues)
        status: cert_status_str(&cert, now).to_string(),
        subject_dn: cert.subject_dn.clone(),
        issuer_dn: cert.issuer_dn.clone(),
        valid_from: cert.not_before.to_rfc3339(),
        valid_to: cert.not_after.to_rfc3339(),
        // Clamp at 0 so an expired certificate reads "0", never a negative count.
        days_remaining: Some((cert.not_after - now).num_days().max(0)),
        key_algorithm: d.map(|d| d.key_algorithm.clone()).unwrap_or_default(),
        key_size: d.map(|d| d.key_size).unwrap_or(0),
        signature_algorithm: d.map(|d| d.signature_algorithm.clone()).unwrap_or_default(),
        fingerprint_sha256: d.map(|d| d.fingerprint_sha256.clone()).unwrap_or_default(),
        fingerprint_sha1: d.map(|d| d.fingerprint_sha1.clone()).unwrap_or_default(),
        extensions,
        subject_alt_names,
        key_usage: d.map(|d| d.key_usage.clone()).unwrap_or_default(),
        extended_key_usage: d.map(|d| d.extended_key_usage.clone()).unwrap_or_default(),
        authority_key_id: d.and_then(|d| d.authority_key_id.clone()),
        subject_key_id: d.and_then(|d| d.subject_key_id.clone()),
        crl_distribution_points: d
            .map(|d| d.crl_distribution_points.clone())
            .unwrap_or_default(),
        ocsp_responder_urls: d.map(|d| d.ocsp_urls.clone()).unwrap_or_default(),
        revocation_time: cert.revocation_time.map(|t| t.to_rfc3339()),
        revocation_reason,
        pem: cert.pem_encoded.clone(),
    };

    // NIST 800-53 AU-2/AU-3: record who inspected which certificate.
    tracing::info!(
        actor = %user.username,
        resource = %cert.id,
        "certificate detail viewed"
    );

    Ok(Json(details).into_response())
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

/// Serve the latest CRL at the public distribution point.
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §5 - CRLs are public certificate status data; served without auth
/// - RFC 5280 §4.2.1.13 - this is the endpoint referenced by issued certs' CDP
/// - NIAP PP-CA: FMT_SMF.1 - CRL publication/distribution function
/// - NIST 800-53: SC-17 - PKI certificate status distribution
///
/// Returns the DER-encoded CRL with `Content-Type: application/pkix-crl`
/// (RFC 5280). Returns 404 if no CRL has been generated yet.
async fn get_crl(State(state): State<Arc<ApiState>>) -> Result<Response> {
    use axum::http::header::CONTENT_TYPE;

    let crl_repo = CrlRepository::new(state.db_pool.clone());
    let latest = crl_repo
        .find_latest_crl(state.ca.ca_id)
        .await
        .map_err(|e| Error::CrlGeneration(format!("Failed to load CRL: {}", e)))?;

    match latest {
        Some(crl) => Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/pkix-crl")],
            crl.der_encoded,
        )
            .into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            "No CRL has been generated yet".to_string(),
        )
            .into_response()),
    }
}

/// Generate a delta CRL (RFC 5280 §5.2.4) listing entries revoked since the
/// latest full (base) CRL. Requires a base full CRL to exist.
async fn generate_delta_crl(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
) -> Result<Json<GenerateCrlResponse>> {
    let crl = state
        .ca
        .revocation_manager()
        .generate_delta_crl(state.ca.ca_dn.clone())
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

/// Serve the latest delta CRL at its public distribution point (the Freshest
/// CRL location, RFC 5280 §5.2.6). Returns 404 until a delta CRL exists.
async fn get_delta_crl(State(state): State<Arc<ApiState>>) -> Result<Response> {
    use axum::http::header::CONTENT_TYPE;

    let crl_repo = CrlRepository::new(state.db_pool.clone());
    let latest = crl_repo
        .find_latest_delta_crl(state.ca.ca_id)
        .await
        .map_err(|e| Error::CrlGeneration(format!("Failed to load delta CRL: {}", e)))?;

    match latest {
        Some(crl) => Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/pkix-crl")],
            crl.der_encoded,
        )
            .into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            "No delta CRL has been generated yet".to_string(),
        )
            .into_response()),
    }
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

// Approval Workflow Endpoints

/// Submit approval request
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval workflow
/// - NIAP PP-CA: FIA_UAU.1 - Authenticated user required
/// - NIST 800-53: AC-3 - Access enforcement
/// - NIST 800-53: AU-2 - Auditable event
async fn submit_approval_request(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<SubmitApprovalRequest>,
) -> Result<Json<ApprovalRequestResponse>> {
    use ostrich_common::auth::user::AuthMethod;

    // Create authenticated user from auth context
    let auth_user = ostrich_common::auth::user::AuthenticatedUser::new(
        user.id,
        user.username.clone(),
        user.roles.clone(),
        AuthMethod::Password,
    );

    // Create approval request via engine
    let submitted =
        state
            .approval_engine
            .create_request(req.request_type, &auth_user, req.request_details);

    // Persist to database
    use ostrich_db::models::ApprovalRequestRecord;
    let record = ApprovalRequestRecord {
        id: submitted.id,
        request_type: submitted.request_type.to_string(),
        csr_id: submitted.csr_id,
        certificate_id: submitted.certificate_id,
        requestor_id: *submitted.requestor_id.as_uuid(),
        requestor_username: submitted.requestor_username.clone(),
        requestor_roles: submitted
            .requestor_roles
            .iter()
            .map(|r| r.to_string())
            .collect(),
        status: submitted.status.to_string(),
        request_details: submitted.request_details.clone(),
        created_at: submitted.created_at,
        expires_at: submitted.expires_at,
        approved_at: submitted.approved_at,
        completed_at: submitted.completed_at,
        metadata: None,
    };

    state.approval_repo.create_request(&record).await?;

    Ok(Json(ApprovalRequestResponse::from(submitted)))
}

/// List approval requests
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - View approval queue
/// - NIAP PP-CA: FIA_UAU.1 - Authenticated user required
async fn list_approval_requests(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
) -> Result<Json<ListApprovalRequestsResponse>> {
    let requests = if user.roles.iter().any(|r| {
        matches!(
            r,
            ostrich_common::auth::Role::RaStaff | ostrich_common::auth::Role::Aor
        )
    }) {
        // RA Staff and AOR can see all pending requests
        state.approval_repo.list_pending_requests().await?
    } else {
        // Regular users can only see their own requests
        state
            .approval_repo
            .list_requests_by_requestor(user.id.as_uuid())
            .await?
    };

    Ok(Json(ListApprovalRequestsResponse {
        requests: requests
            .into_iter()
            .map(ApprovalRequestInfo::from)
            .collect(),
    }))
}

/// Get approval request by ID
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - View request details
async fn get_approval_request(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApprovalRequestDetailResponse>> {
    let request_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid request ID".to_string()))?;

    let (request, decisions) = state
        .approval_repo
        .get_request_with_decisions(&request_id)
        .await?
        .ok_or_else(|| Error::ApprovalRequestNotFound(request_id))?;

    // Authorization: user can view if they are the requestor or have approval role
    let can_approve = user.roles.iter().any(|r| {
        matches!(
            r,
            ostrich_common::auth::Role::RaStaff | ostrich_common::auth::Role::Aor
        )
    });
    if request.requestor_id != *user.id.as_uuid() && !can_approve {
        return Err(Error::InsufficientRole {
            required: "RaStaff/Aor role or request ownership".to_string(),
        });
    }

    Ok(Json(ApprovalRequestDetailResponse {
        request: ApprovalRequestInfo::from(request),
        decisions: decisions
            .into_iter()
            .map(ApprovalDecisionInfo::from)
            .collect(),
    }))
}

/// Approve request
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - Approve certificate request
/// - NIAP PP-CA: FDP_SEPP.1 - Segregation of duties (requestor ≠ approver)
/// - NIST 800-53: AC-3 - Access enforcement
/// - NIST 800-53: AU-2 - Auditable event
async fn approve_request(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> Result<Json<ApprovalDecisionResponse>> {
    use ostrich_common::auth::user::AuthMethod;

    let request_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid request ID".to_string()))?;

    // Get request from database
    let request_record = state
        .approval_repo
        .get_request(&request_id)
        .await?
        .ok_or_else(|| Error::ApprovalRequestNotFound(request_id))?;

    // Convert to engine type
    let mut request = ApprovalRequest::from_record(request_record);

    // Create authenticated user from auth context
    let approver = ostrich_common::auth::user::AuthenticatedUser::new(
        user.id,
        user.username.clone(),
        user.roles.clone(),
        AuthMethod::Password,
    );

    // Approve via engine (enforces segregation of duties)
    let decision = state.approval_engine.approve_request(
        &mut request,
        &approver,
        req.justification.unwrap_or_else(|| "Approved".to_string()),
    )?;

    // Persist decision
    use ostrich_db::models::ApprovalDecisionRecord;
    let decision_record = ApprovalDecisionRecord {
        id: decision.id,
        request_id: decision.request_id,
        approver_id: *decision.approver_id.as_uuid(),
        approver_username: decision.approver_username.clone(),
        approver_roles: decision
            .approver_roles
            .iter()
            .map(|r| r.to_string())
            .collect(),
        decision: decision.decision.to_string(),
        reason: decision.reason.clone(),
        justification: decision.justification.clone(),
        decided_at: decision.decided_at,
        metadata: None,
    };

    state
        .approval_repo
        .create_decision(&decision_record)
        .await?;

    // Update request status
    state
        .approval_repo
        .update_request_status(
            &request_id,
            &request.status.to_string(),
            request.approved_at,
        )
        .await?;

    Ok(Json(ApprovalDecisionResponse {
        decision: ApprovalDecisionInfo::from(decision_record),
        updated_status: request.status.to_string(),
    }))
}

/// Reject request
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - Reject certificate request
/// - NIAP PP-CA: FDP_SEPP.1 - Segregation of duties (requestor ≠ approver)
async fn reject_request(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> Result<Json<ApprovalDecisionResponse>> {
    use ostrich_common::auth::user::AuthMethod;

    let request_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid request ID".to_string()))?;

    // Get request from database
    let request_record = state
        .approval_repo
        .get_request(&request_id)
        .await?
        .ok_or_else(|| Error::ApprovalRequestNotFound(request_id))?;

    // Convert to engine type
    let mut request = ApprovalRequest::from_record(request_record);

    // Create authenticated user from auth context
    let approver = ostrich_common::auth::user::AuthenticatedUser::new(
        user.id,
        user.username.clone(),
        user.roles.clone(),
        AuthMethod::Password,
    );

    // Reject via engine (enforces segregation of duties)
    let decision = state.approval_engine.reject_request(
        &mut request,
        &approver,
        req.reason.unwrap_or_else(|| "Rejected".to_string()),
        req.justification
            .unwrap_or_else(|| "Request rejected".to_string()),
    )?;

    // Persist decision
    use ostrich_db::models::ApprovalDecisionRecord;
    let decision_record = ApprovalDecisionRecord {
        id: decision.id,
        request_id: decision.request_id,
        approver_id: *decision.approver_id.as_uuid(),
        approver_username: decision.approver_username.clone(),
        approver_roles: decision
            .approver_roles
            .iter()
            .map(|r| r.to_string())
            .collect(),
        decision: decision.decision.to_string(),
        reason: decision.reason.clone(),
        justification: decision.justification.clone(),
        decided_at: decision.decided_at,
        metadata: None,
    };

    state
        .approval_repo
        .create_decision(&decision_record)
        .await?;

    // Update request status
    state
        .approval_repo
        .update_request_status(
            &request_id,
            &request.status.to_string(),
            request.approved_at,
        )
        .await?;

    Ok(Json(ApprovalDecisionResponse {
        decision: ApprovalDecisionInfo::from(decision_record),
        updated_status: request.status.to_string(),
    }))
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
    /// Subject DN. Optional: when omitted and a `csr_der` is supplied, the CA
    /// derives the subject from the CSR (the usual "paste a CSR" admin flow).
    #[serde(default)]
    pub subject: Option<DistinguishedName>,
    /// Subject alternative names. When empty and a `csr_der` is supplied, the
    /// SANs are taken from the CSR's requested extensions.
    #[serde(default)]
    pub subject_alt_names: Vec<SubjectAltName>,
    /// SubjectPublicKeyInfo (DER). Optional: when omitted and a `csr_der` is
    /// supplied, the CA uses the CSR's public key.
    #[serde(default, with = "base64_opt_serde")]
    pub public_key: Option<Vec<u8>>,
    /// Ignored; the authenticated identity is always used as the requestor.
    #[serde(default)]
    pub requestor: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Optional base64 DER PKCS#10 CSR. When present the CA verifies
    /// proof-of-possession (RFC 2986); required for end-entity issuance when the
    /// CA enforces proof-of-possession (the secure default). When `subject` /
    /// `public_key` are omitted they are derived from this CSR.
    #[serde(default, with = "base64_opt_serde")]
    pub csr_der: Option<Vec<u8>>,
    /// Approved request to issue against (NIAP PP-CA FDP_CER_EXT.3).
    /// Required when the CA runs with the approval workflow enabled (the
    /// secure default); the referenced request must already be Approved by a
    /// different user (separation of duties enforced at approval time).
    #[serde(default)]
    pub approval_request_id: Option<String>,
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
///
/// `requestor` is server-derived from the authenticated identity (AC-3): the
/// handler overrides any client-supplied value, so it is optional on the wire
/// and a client need not send it. `justification` also accepts the legacy field
/// name `notes` so older clients keep working.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeCertificateRequest {
    pub reason: RevocationReason,
    #[serde(default)]
    pub requestor: Option<String>,
    #[serde(default, alias = "notes")]
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
    #[serde(default)]
    pub key_usages: Vec<String>,
    #[serde(default)]
    pub extended_key_usages: Vec<String>,
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
            key_usages: profile.key_usage.iter().map(|k| format!("{k:?}")).collect(),
            extended_key_usages: profile
                .extended_key_usage
                .iter()
                .map(|e| format!("{e:?}"))
                .collect(),
        }
    }
}

// Approval Workflow Request/Response types

/// Submit approval request
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitApprovalRequest {
    pub request_type: RequestType,
    pub request_details: serde_json::Value,
}

/// Approval request response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalRequestResponse {
    pub id: String,
    pub request_type: String,
    pub requestor_username: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

impl From<ApprovalRequest> for ApprovalRequestResponse {
    fn from(req: ApprovalRequest) -> Self {
        Self {
            id: req.id.to_string(),
            request_type: req.request_type.to_string(),
            requestor_username: req.requestor_username,
            status: req.status.to_string(),
            created_at: req.created_at.to_rfc3339(),
            expires_at: req.expires_at.to_rfc3339(),
        }
    }
}

/// List approval requests response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListApprovalRequestsResponse {
    pub requests: Vec<ApprovalRequestInfo>,
}

/// Approval request info (summary)
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalRequestInfo {
    pub id: String,
    pub request_type: String,
    pub requestor_username: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

impl From<ostrich_db::models::ApprovalRequestRecord> for ApprovalRequestInfo {
    fn from(record: ostrich_db::models::ApprovalRequestRecord) -> Self {
        Self {
            id: record.id.to_string(),
            request_type: record.request_type,
            requestor_username: record.requestor_username,
            status: record.status,
            created_at: record.created_at.to_rfc3339(),
            expires_at: record.expires_at.to_rfc3339(),
        }
    }
}

/// Approval request detail response (includes decisions)
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalRequestDetailResponse {
    pub request: ApprovalRequestInfo,
    pub decisions: Vec<ApprovalDecisionInfo>,
}

/// Approval decision info
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionInfo {
    pub id: String,
    pub approver_username: String,
    pub decision: String,
    pub reason: Option<String>,
    pub justification: Option<String>,
    pub decided_at: String,
}

impl From<ostrich_db::models::ApprovalDecisionRecord> for ApprovalDecisionInfo {
    fn from(record: ostrich_db::models::ApprovalDecisionRecord) -> Self {
        Self {
            id: record.id.to_string(),
            approver_username: record.approver_username,
            decision: record.decision,
            reason: record.reason,
            justification: record.justification,
            decided_at: record.decided_at.to_rfc3339(),
        }
    }
}

/// Approval decision request
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub reason: Option<String>,
    pub justification: Option<String>,
}

/// Approval decision response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionResponse {
    pub decision: ApprovalDecisionInfo,
    pub updated_status: String,
}

/// base64 (de)serialization for an `Option<Vec<u8>>` field (None when absent/null).
mod base64_opt_serde {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&BASE64_STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => Ok(Some(
                BASE64_STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?,
            )),
            None => Ok(None),
        }
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
                format!(
                    "Invalid approval state: current={}, expected={}",
                    current, expected
                ),
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

    // axum 0.8: GET (public) and POST (protected) live on the same path
    // `/api/v1/crl` but in two separate routers that are `.merge`d. axum merges
    // these into one MethodRouter as long as the methods don't overlap. This
    // test pins that coexistence so a regression (e.g. moving POST to the public
    // group, creating a duplicate method) fails loudly at build/test time rather
    // than panicking at server startup.
    #[test]
    fn test_crl_get_post_same_path_coexist() {
        use axum::routing::{get, post};

        async fn noop() -> &'static str {
            "ok"
        }

        let public: Router<()> = Router::new().route("/api/v1/crl", get(noop));
        let protected: Router<()> = Router::new().route("/api/v1/crl", post(noop));

        // Must not panic: overlapping path, disjoint methods.
        let _merged = Router::new().merge(public).merge(protected);
    }

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
