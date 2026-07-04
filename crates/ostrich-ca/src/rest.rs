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
    routing::{delete, get, post, put},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use ostrich_common::auth::provider::AuthProvider;
use ostrich_common::auth::{
    AuthLayer, AuthUser, AuthzLayer, Permission, RbacPolicy, Role, TrustedProxyAuthLayer,
    TrustedProxyConfig, any_role_has_permission,
};
use ostrich_common::types::DistinguishedName;
use ostrich_db::DatabasePool;
use ostrich_db::models::Certificate;
use ostrich_db::repository::{
    ApprovalRepository, AuditRepository, CertificateRepository, CrlRepository, EstRepository,
    FqdnRepository,
};
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
    /// Rate-limit cache for the audit-chain integrity verification: a recent
    /// result is reused within a short TTL so repeated/scripted calls can't force
    /// an unbounded full-table O(n) rehash (a self-inflicted DoS). SC-5.
    audit_verify_cache: Arc<std::sync::Mutex<Option<(std::time::Instant, AuditVerifyResponseDto)>>>,
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
            audit_verify_cache: Arc::new(std::sync::Mutex::new(None)),
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
    // When set (non-empty allow-list), protected routes accept the NPE portal's
    // mTLS-forwarded identity in addition to bearer tokens (the identity bridge).
    // `None` keeps bearer-only auth.
    trusted_proxy: Option<Arc<TrustedProxyConfig>>,
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
        // Certs-only PKCS#7 (.p7b) download — the leaf plus its issuing CA.
        .route(
            "/api/v1/certificates/{id}/pkcs7",
            get(get_certificate_pkcs7).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/certificates/{id}/revoke",
            post(revoke_certificate).route_layer(authz(Permission::RevokeCertificate)),
        )
        // Per-FQDN certificate history. Reads are gated like the inventory
        // (ViewCertificate); the renewal-contact write is a TSF-data management
        // action (ModifyConfig / FMT_MTD.1). The literal `/notification` segment
        // sits a level below `/{fqdn}`, so there is no static-vs-param conflict.
        .route(
            "/api/v1/fqdns",
            get(list_fqdns).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/fqdns/{fqdn}",
            get(get_fqdn_record).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/fqdns/{fqdn}/est-tokens",
            get(get_fqdn_est_tokens).route_layer(authz(Permission::GenerateEstToken)),
        )
        .route(
            "/api/v1/fqdns/{fqdn}/notification",
            get(get_fqdn_notification).route_layer(authz(Permission::ViewCertificate)),
        )
        .route(
            "/api/v1/fqdns/{fqdn}/notification",
            put(set_fqdn_notification).route_layer(authz(Permission::ModifyConfig)),
        )
        .route(
            "/api/v1/crl",
            post(generate_crl).route_layer(authz(Permission::GenerateCrl)),
        )
        .route(
            "/api/v1/crl/delta",
            post(generate_delta_crl).route_layer(authz(Permission::GenerateCrl)),
        )
        // Audit review + tamper-evidence (FAU_SAR.1 / AU-6, AU-9/AU-10).
        // `/audit/verify` is a static segment registered before any param route.
        .route(
            "/api/v1/audit/verify",
            get(verify_audit_chain).route_layer(authz(Permission::ReadAuditLog)),
        )
        .route(
            "/api/v1/audit",
            get(list_audit_events).route_layer(authz(Permission::ReadAuditLog)),
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
        // Bulk status: status for many applications at once. Registered before the
        // `/{id}` capture; axum matches the static `status` segment first.
        .route(
            "/api/v1/approvals/status",
            get(bulk_approval_status).route_layer(authz(Permission::ViewRequests)),
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
            post(reject_request).route_layer(authz(Permission::RejectRequest)),
        )
        // Bulk enrollment (Administrator "Submit Bulk"): upload a ZIP of CSRs.
        // The explicit body limit bounds the buffered multipart upload (the
        // per-CSR and entry caps bound what is then extracted from it).
        .route(
            "/api/v1/bulk-enroll",
            post(bulk_enroll)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_BULK_UPLOAD_BYTES))
                .route_layer(authz(Permission::BulkEnroll)),
        )
        .route(
            "/api/v1/bulk-enroll",
            get(list_bulk_jobs).route_layer(authz(Permission::ViewRequests)),
        )
        .route(
            "/api/v1/bulk-enroll/{id}",
            get(get_bulk_job).route_layer(authz(Permission::ViewRequests)),
        )
        // CAA user management. Each verb is gated by its own permission; the
        // handlers additionally enforce a self-action block (a CAA cannot modify,
        // disable, or delete their own account).
        .route(
            "/api/v1/users",
            get(list_users).route_layer(authz(Permission::ViewUsers)),
        )
        .route(
            "/api/v1/users",
            post(create_user).route_layer(authz(Permission::CreateUser)),
        )
        .route(
            "/api/v1/users/{id}/roles",
            put(set_user_roles).route_layer(authz(Permission::AssignRoles)),
        )
        .route(
            "/api/v1/users/{id}/status",
            put(set_user_status).route_layer(authz(Permission::ModifyUser)),
        )
        .route(
            "/api/v1/users/{id}",
            delete(delete_user).route_layer(authz(Permission::DeleteUser)),
        )
        // CAA wildcard / namespace policy management.
        .route(
            "/api/v1/namespaces",
            get(list_namespaces).route_layer(authz(Permission::ManageNamespaces)),
        )
        .route(
            "/api/v1/namespaces",
            post(create_namespace).route_layer(authz(Permission::ManageNamespaces)),
        )
        .route(
            "/api/v1/namespaces/{id}",
            delete(delete_namespace).route_layer(authz(Permission::ManageNamespaces)),
        )
        // CAA system configuration.
        .route(
            "/api/v1/config",
            get(list_config).route_layer(authz(Permission::ViewConfig)),
        )
        .route(
            "/api/v1/config/{key}",
            put(set_config).route_layer(authz(Permission::ModifyConfig)),
        );

    // Authentication layer. With a trusted-proxy config, use the composite layer
    // that accepts the NPE portal's mTLS-forwarded identity OR a bearer token;
    // otherwise bearer-only. NIST 800-53: IA-2 / AC-3.
    let protected_routes = match trusted_proxy {
        Some(cfg) => protected_routes.layer(middleware::from_fn_with_state(
            (auth_provider.clone(), cfg),
            TrustedProxyAuthLayer::authenticate,
        )),
        None => protected_routes.layer(middleware::from_fn_with_state(
            auth_provider.clone(),
            AuthLayer::authenticate,
        )),
    };

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
    let der = state.ca.certificate_der();

    // Best-effort enrichment from the CA certificate. If parsing fails we still
    // return the basic identity rather than erroring the public info endpoint.
    let parsed = ostrich_x509::parser::parse_certificate(der).ok();
    let mut resp = CaInfoResponse {
        ca_id: info.ca_id.to_string(),
        ca_dn: info.ca_dn,
        issuer_dn: None,
        serial: None,
        not_before: None,
        not_after: None,
        signature_algorithm: None,
        key_type: None,
        chain_pem: Some(der_to_pem(der)),
    };
    if let Some(c) = parsed {
        let (alg, key_type) = describe_signature_algorithm(&c.signature_algorithm);
        resp.issuer_dn = Some(c.issuer_dn);
        resp.serial = Some(
            c.serial_number
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
        );
        resp.not_before = Some(c.not_before.to_rfc3339());
        resp.not_after = Some(c.not_after.to_rfc3339());
        resp.signature_algorithm = Some(alg);
        resp.key_type = Some(key_type);
    }

    Ok(Json(resp))
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

/// Resolve the SANs to place in a certificate issued from an approved request.
///
/// The requester's explicitly-submitted SANs (prefixed strings stored in
/// `request_details.subject_alt_names`, e.g. `"DNS:host.example"`) take
/// precedence; the CSR's embedded SANs are used only when the form supplied
/// none. This mirrors the precedence in `issue_certificate` (explicit request
/// over CSR), so the approval-issuance path and the direct-issue path agree.
///
/// Without this, a requester who pastes a CN-only CSR — or generates the
/// in-browser CSR before adding a SAN — has their requested SANs silently
/// dropped, and a SAN-required profile (e.g. `tls_server`) then rejects issuance
/// even though the SAN was supplied. The resolved names are still subject to the
/// same profile / namespace validation in `issue()`, and proof-of-possession is
/// still verified over the CSR.
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.2.1.6: Subject Alternative Name
/// - NIST 800-53 SI-10: Information input validation (requested names revalidated)
fn resolve_approval_sans(details: &serde_json::Value, csr_sans: &[String]) -> Vec<SubjectAltName> {
    let requested: Vec<String> = details
        .get("subject_alt_names")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if requested.is_empty() {
        sans_from_strings(csr_sans)
    } else {
        sans_from_strings(&requested)
    }
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
    /// Restrict to active certificates expiring within this many days — the
    /// drill-down behind the dashboard's "Expiring in N Days" card. Matches the
    /// `expiring_soon` count definition exactly. Ignored when absent or <= 0.
    expiring_in_days: Option<i64>,
    /// Column key to sort by (`serial` | `subject` | `issuer` | `expires`);
    /// unrecognized/absent falls back to newest-first (`created_at DESC`).
    sort: Option<String>,
    /// Sort direction for `sort`: `asc` or `desc` (default `desc`).
    order: Option<String>,
}

/// NPE sponsors are self-service requesters: they can view and manage only
/// certificate/token records they created. Approver roles retain global queue
/// and inventory visibility for review duties.
fn is_npe_self_service(user: &ostrich_common::auth::AuthenticatedUser) -> bool {
    user.roles
        .iter()
        .any(|r| matches!(r, Role::PkiSponsor | Role::PkiSponsorAdmin))
        && !any_role_has_permission(&user.roles, Permission::ApproveRequest)
}

fn certificate_requestor_scope(user: &ostrich_common::auth::AuthenticatedUser) -> Option<&str> {
    is_npe_self_service(user).then_some(user.username.as_str())
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
    /// Whole days until expiry, clamped at 0 (so the list and the detail view
    /// report the same figure instead of the client recomputing it).
    days_remaining: Option<i64>,
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

/// Query parameters for the distinct-FQDN listing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListFqdnsQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    search: Option<String>,
}

/// One row in the distinct-FQDN listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FqdnSummaryDto {
    fqdn: String,
    certificate_count: u64,
    first_seen: String,
    last_issued: String,
}

/// Paginated response for the distinct-FQDN listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FqdnListResponseDto {
    fqdns: Vec<FqdnSummaryDto>,
    total: u64,
    page: u32,
    page_size: u32,
}

/// The aggregated history record for a single FQDN.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FqdnRecordDto {
    fqdn: String,
    /// Earliest issuance for this FQDN (RFC 3339), if any certs exist.
    first_seen: Option<String>,
    /// Most recent issuance/renewal for this FQDN (RFC 3339).
    last_issued: Option<String>,
    /// Requestor of the earliest certificate.
    first_requested_by: Option<String>,
    /// Requestor of the most recent certificate.
    last_requested_by: Option<String>,
    certificate_count: u64,
    /// Operator-set renewal-notification contact, if configured.
    notification_email: Option<String>,
    /// True if any certificate for this FQDN was issued via EST — drives the
    /// "EST Tokens" tab in the UI (tokens are fetched from the gated sub-resource).
    uses_est: bool,
    /// Every certificate ever issued for this FQDN, newest first.
    certificates: Vec<CertificateSummaryDto>,
}

/// One EST enrollment token bound to an FQDN (operator review; never the token).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EstTokenDto {
    id: String,
    identity: String,
    created_by: String,
    created_at: String,
    expires_at: String,
    /// Derived: `live` | `used` | `revoked` | `expired`.
    status: String,
    /// Certificate issued when the token was consumed, if any.
    used_by_cert: Option<String>,
}

/// EST tokens for a single FQDN (GET .../est-tokens).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FqdnEstTokensDto {
    tokens: Vec<EstTokenDto>,
}

/// The renewal-notification contact for an FQDN (GET/PUT).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FqdnNotificationDto {
    fqdn: String,
    email: Option<String>,
    updated_by: Option<String>,
    updated_at: Option<String>,
}

/// Request body for setting an FQDN's renewal-notification contact.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetFqdnNotificationBody {
    email: String,
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
    /// Active certificates expiring within the next 90 days (subset of `active`).
    expiring_soon: u64,
}

/// Query parameters for the audit-log listing (all optional filters).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAuditQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    actor: Option<String>,
    event_type: Option<String>,
    outcome: Option<String>,
    /// RFC 3339 timestamps bounding the window (inclusive).
    start: Option<String>,
    end: Option<String>,
    /// Column key to sort by (`timestamp` | `eventType` | `actor` | `target` |
    /// `action` | `outcome`); unrecognized/absent falls back to `timestamp DESC`.
    sort: Option<String>,
    /// Sort direction for `sort`: `asc` or `desc` (default `desc`).
    order: Option<String>,
}

/// One audit record in the review listing (FAU_SAR.1).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventDto {
    id: String,
    timestamp: String,
    event_type: String,
    actor: String,
    target: String,
    action: String,
    outcome: String,
    /// Whether this record carries an AU-10 signature (vs. hash-chain only).
    signed: bool,
    ip_address: Option<String>,
}

/// Paginated audit-log listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditListResponseDto {
    events: Vec<AuditEventDto>,
    total: u64,
    page: u32,
    page_size: u32,
}

/// Result of an audit-trail integrity verification (AU-9/AU-10).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditVerifyResponseDto {
    /// True iff the hash chain recomputes AND every signed record verifies.
    intact: bool,
    total_records: u64,
    signed_records: u64,
    verified_at: String,
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

/// Certs-only PKCS#7 (.p7b) download payload: base64-encoded DER of the leaf
/// certificate plus its issuing CA certificate.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificatePkcs7Dto {
    pkcs7: String,
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
        let days_remaining = Some((c.not_after - now).num_days().max(0));
        CertificateSummaryDto {
            id: c.id.to_string(),
            serial_number: hex::encode(&c.serial_number),
            subject: c.subject_dn,
            issuer: c.issuer_dn,
            valid_from: c.not_before.to_rfc3339(),
            valid_to: c.not_after.to_rfc3339(),
            status,
            key_algorithm: None,
            days_remaining,
        }
    };

    // Filter + search + paginate + count entirely in SQL — no in-memory scan,
    // no row cap, and `total` always describes the full matching population.
    // Direction defaults to descending (preserves the historic newest-first
    // default); only an explicit `order=asc` flips it.
    let descending = !query
        .order
        .as_deref()
        .is_some_and(|o| o.eq_ignore_ascii_case("asc"));
    // Only a positive window is a real filter; <= 0 (or absent) means "no filter".
    let expiring_in_days = query.expiring_in_days.filter(|&d| d > 0);
    let (rows, total) = repo
        .list_filtered(
            &status,
            search.as_deref(),
            certificate_requestor_scope(&user),
            expiring_in_days,
            query.sort.as_deref(),
            descending,
            i64::from(page_size),
            offset,
        )
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
    let counts = repo
        .count_by_status(certificate_requestor_scope(&user))
        .await?;

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
        expiring_soon: counts.expiring_soon.max(0) as u64,
    }))
}

/// List distinct FQDNs with per-name issuance summary (GET /api/v1/fqdns).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate)
/// - NIAP PP-CA: FMT_SMF.1 - Security management: per-FQDN inventory query
async fn list_fqdns(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Query(query): Query<ListFqdnsQuery>,
) -> Result<Json<FqdnListResponseDto>> {
    let repo = FqdnRepository::new(state.db_pool.clone());
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).clamp(1, 1000);
    let offset = i64::from(page - 1) * i64::from(page_size);
    let search = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    let (rows, total) = repo
        .list_fqdns(
            search.as_deref(),
            certificate_requestor_scope(&user),
            i64::from(page_size),
            offset,
        )
        .await?;
    let fqdns = rows
        .into_iter()
        .map(|r| FqdnSummaryDto {
            fqdn: r.fqdn,
            certificate_count: r.certificate_count.max(0) as u64,
            first_seen: r.first_seen.to_rfc3339(),
            last_issued: r.last_issued.to_rfc3339(),
        })
        .collect();

    tracing::info!(actor = %user.username, resource = "fqdns", page, total, "fqdn inventory listed");
    Ok(Json(FqdnListResponseDto {
        fqdns,
        total: total.max(0) as u64,
        page,
        page_size,
    }))
}

/// Aggregated certificate history for one FQDN (GET /api/v1/fqdns/{fqdn}).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate)
/// - NIAP PP-CA: FMT_SMF.1 - Security management: per-FQDN certificate history
/// - RFC 5280 §4.2.1.6 - the SubjectAltName binding being aggregated
async fn get_fqdn_record(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(fqdn): Path<String>,
) -> Result<Json<FqdnRecordDto>> {
    let fqdn = fqdn.trim().to_lowercase();
    let repo = FqdnRepository::new(state.db_pool.clone());
    let now = chrono::Utc::now();

    // Certs are newest-first; the oldest (history start) is last in the vec.
    let scope = certificate_requestor_scope(&user);
    let certs = repo.certs_for_fqdn_scoped(&fqdn, scope).await?;
    // Own-scope (AC-3): a self-service sponsor who owns no certificate for this
    // FQDN must not learn it exists or see its renewal-notification contact.
    // Return 404 before reading any unscoped per-FQDN data. (An approver/admin is
    // unscoped — `scope` is None — and still gets the full global record.)
    if scope.is_some() && certs.is_empty() {
        return Err(Error::NotFound(format!("no record for '{fqdn}'")));
    }
    let newest = certs.first();
    let oldest = certs.last();

    let certificates: Vec<CertificateSummaryDto> = certs
        .iter()
        .map(|c| CertificateSummaryDto {
            id: c.id.to_string(),
            serial_number: hex::encode(&c.serial_number),
            subject: c.subject_dn.clone(),
            issuer: c.issuer_dn.clone(),
            valid_from: c.not_before.to_rfc3339(),
            valid_to: c.not_after.to_rfc3339(),
            status: cert_status_str(c, now).to_string(),
            key_algorithm: None,
            days_remaining: Some((c.not_after - now).num_days().max(0)),
        })
        .collect();

    let notification = repo.get_notification(&fqdn).await?;
    // Detect EST via issuer_service OR the requestor prefix. The prefix is the
    // authoritative signal and is correct on certs issued before issuer_service
    // was populated per-service, so the tab works on historical data too.
    let uses_est = certs.iter().any(|c| {
        c.issuer_service.as_deref() == Some("EST")
            || c.requestor
                .as_deref()
                .is_some_and(|r| r.starts_with("est::"))
    });

    tracing::info!(
        actor = %user.username,
        resource = "fqdn",
        fqdn = %fqdn,
        count = certs.len(),
        "fqdn record viewed"
    );
    Ok(Json(FqdnRecordDto {
        first_seen: oldest.map(|c| c.created_at.to_rfc3339()),
        last_issued: newest.map(|c| c.created_at.to_rfc3339()),
        first_requested_by: oldest.and_then(|c| c.requestor.clone()),
        last_requested_by: newest.and_then(|c| c.requestor.clone()),
        certificate_count: certs.len() as u64,
        notification_email: notification.map(|n| n.email),
        uses_est,
        certificates,
        fqdn,
    }))
}

/// EST enrollment tokens bound to an FQDN (GET /api/v1/fqdns/{fqdn}/est-tokens).
///
/// Tokens are matched by their `identity` (the CN/FQDN a bearer may enroll as).
/// Gated by `GenerateEstToken` — the same permission that mints/lists tokens —
/// so EST-token visibility is not broadened to plain certificate viewers.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::GenerateEstToken)
/// - NIAP PP-CA: FMT_SMF.1 - management of enrollment credentials
async fn get_fqdn_est_tokens(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(fqdn): Path<String>,
) -> Result<Json<FqdnEstTokensDto>> {
    let fqdn = fqdn.trim().to_lowercase();
    let repo = EstRepository::new(state.db_pool.clone());
    let now = chrono::Utc::now();

    let rows = repo
        .list_enrollment_tokens_for_identity(&fqdn, certificate_requestor_scope(&user), 200)
        .await?;
    let tokens = rows
        .into_iter()
        .map(|t| {
            // Status precedence mirrors the EST service: used (consumed with a
            // cert) → revoked (consumed without one) → expired → live.
            let status = match (t.used_at, t.used_by_cert) {
                (Some(_), Some(_)) => "used",
                (Some(_), None) => "revoked",
                (None, _) if t.expires_at <= now => "expired",
                (None, _) => "live",
            };
            EstTokenDto {
                id: t.id.to_string(),
                identity: t.identity,
                created_by: t.created_by,
                created_at: t.created_at.to_rfc3339(),
                expires_at: t.expires_at.to_rfc3339(),
                status: status.to_string(),
                used_by_cert: t.used_by_cert.map(|c| c.to_string()),
            }
        })
        .collect();

    tracing::info!(actor = %user.username, resource = "fqdn:est-tokens", fqdn = %fqdn, "fqdn EST tokens listed");
    Ok(Json(FqdnEstTokensDto { tokens }))
}

/// Read an FQDN's renewal-notification contact (GET .../notification).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate)
async fn get_fqdn_notification(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
    Path(fqdn): Path<String>,
) -> Result<Json<FqdnNotificationDto>> {
    let fqdn = fqdn.trim().to_lowercase();
    let repo = FqdnRepository::new(state.db_pool.clone());
    let dto = match repo.get_notification(&fqdn).await? {
        Some(n) => FqdnNotificationDto {
            fqdn: n.fqdn,
            email: Some(n.email),
            updated_by: n.updated_by,
            updated_at: Some(n.updated_at.to_rfc3339()),
        },
        None => FqdnNotificationDto {
            fqdn,
            email: None,
            updated_by: None,
            updated_at: None,
        },
    };
    Ok(Json(dto))
}

/// Set an FQDN's renewal-notification contact (PUT .../notification).
///
/// Storage + display only; no mail is sent (no mailer exists yet).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ModifyConfig)
/// - NIST 800-53: AU-2 - Auditable event (actor + outcome logged)
/// - NIAP PP-CA: FMT_MTD.1 - Management of TSF data (renewal contact)
// POAM: emit a formal hash-chained AuditEvent (AU-10) for this config change once
// a REST-accessible audit emitter is exposed; today it is a structured AU-2 log.
async fn set_fqdn_notification(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(fqdn): Path<String>,
    Json(body): Json<SetFqdnNotificationBody>,
) -> Result<Json<FqdnNotificationDto>> {
    let fqdn = fqdn.trim().to_lowercase();
    let email = body.email.trim().to_string();
    // SI-10: minimal input validation; the address is stored verbatim, never
    // interpolated into a query (bound parameter).
    if email.is_empty() || !email.contains('@') || email.len() > 254 {
        return Err(Error::InvalidRequest(
            "a valid email address is required".to_string(),
        ));
    }

    let repo = FqdnRepository::new(state.db_pool.clone());
    let n = repo
        .set_notification(&fqdn, &email, Some(&user.username))
        .await?;

    tracing::info!(
        actor = %user.username,
        resource = "fqdn:notification",
        fqdn = %fqdn,
        outcome = "success",
        "renewal-notification contact updated"
    );
    Ok(Json(FqdnNotificationDto {
        fqdn: n.fqdn,
        email: Some(n.email),
        updated_by: n.updated_by,
        updated_at: Some(n.updated_at.to_rfc3339()),
    }))
}

/// Record that the audit trail itself was accessed — reviewing or verifying
/// audit records is a security-relevant access to TSF data that must appear in
/// the tamper-evident chain, not only the ephemeral tracing stream.
///
/// Best-effort: a failure to write the access record must never fail the read
/// the auditor requested. Hash-chained (AU-9) via `DatabaseAuditSink`.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AU-2 (Auditable Events), AU-6 (Audit Review), AU-9 (Protection)
/// - NIAP PP-CA: FAU_GEN.1 (Audit generation for audit-access)
async fn record_audit_access(
    db_pool: &DatabasePool,
    actor: &str,
    action: &str,
    details: serde_json::Value,
) {
    use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
    let sink = ostrich_audit::sink::DatabaseAuditSink::new(db_pool.clone());
    let mut event = AuditEventBuilder::new(
        EventType::Authorization,
        actor.to_string(),
        "audit_log",
        action,
        EventOutcome::Success,
    )
    .with_details(details)
    .build();
    if let Err(e) = sink.record(&mut event).await {
        tracing::warn!(error = %e, actor, action, "failed to record audit-log access event");
    }
}

/// List audit records, paginated and filterable (GET /api/v1/audit).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AU-6 (Audit Review), AC-3 (Permission::ReadAuditLog)
/// - NIAP PP-CA: FAU_SAR.1 (Audit Review)
async fn list_audit_events(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Query(q): Query<ListAuditQuery>,
) -> Result<Json<AuditListResponseDto>> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(50).clamp(1, 1000);
    let offset = i64::from(page - 1) * i64::from(page_size);

    let parse_ts = |s: &str| -> Result<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|_| Error::InvalidRequest(format!("invalid RFC3339 timestamp: {s}")))
    };
    let norm = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let start = match norm(q.start) {
        Some(s) => Some(parse_ts(&s)?),
        None => None,
    };
    let end = match norm(q.end) {
        Some(s) => Some(parse_ts(&s)?),
        None => None,
    };
    let actor = norm(q.actor);
    let event_type = norm(q.event_type);
    let outcome = norm(q.outcome);

    let descending = !q
        .order
        .as_deref()
        .is_some_and(|o| o.eq_ignore_ascii_case("asc"));
    let repo = AuditRepository::new(state.db_pool.clone());
    let (rows, total) = repo
        .list_filtered(
            actor.as_deref(),
            event_type.as_deref(),
            outcome.as_deref(),
            start,
            end,
            q.sort.as_deref(),
            descending,
            i64::from(page_size),
            offset,
        )
        .await?;

    let events = rows
        .into_iter()
        .map(|e| AuditEventDto {
            id: e.id.to_string(),
            timestamp: e.timestamp.to_rfc3339(),
            event_type: e.event_type,
            actor: e.actor,
            target: e.target,
            action: e.action,
            outcome: e.outcome,
            signed: e.signature.is_some(),
            ip_address: e.ip_address,
        })
        .collect();

    tracing::info!(actor = %user.username, resource = "audit", page, total, "audit log listed");
    // AU-6: record who reviewed the audit trail (and with which filters) in the
    // tamper-evident chain, not only the tracing stream.
    record_audit_access(
        &state.db_pool,
        &user.username,
        "audit.review",
        serde_json::json!({ "page": page, "pageSize": page_size, "actor": actor, "eventType": event_type, "outcome": outcome }),
    )
    .await;
    Ok(Json(AuditListResponseDto {
        events,
        total: total.max(0) as u64,
        page,
        page_size,
    }))
}

/// Verify the integrity of the audit trail (GET /api/v1/audit/verify).
///
/// Recomputes the hash chain and checks each signed record against the CA
/// public key; `intact: false` means tampering, reordering, or deletion was
/// detected. The on-demand check auditors run for continuous monitoring.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AU-9 (Protection of audit info), AU-9(3), AU-10 (non-repudiation)
/// - NIST 800-53: SC-5 (DoS protection) - the full-table recompute is rate-limited
/// - NIAP PP-CA: FAU_STG.1.2, FAU_STG.4
async fn verify_audit_chain(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
) -> Result<Json<AuditVerifyResponseDto>> {
    // Reuse a recent verification within the TTL so repeated / scripted calls
    // can't force an unbounded full-table O(n) rehash + signature check (SC-5).
    const TTL: std::time::Duration = std::time::Duration::from_secs(30);
    let cached = {
        let guard = state
            .audit_verify_cache
            .lock()
            .expect("audit-verify cache poisoned");
        guard
            .as_ref()
            .filter(|(at, _)| at.elapsed() < TTL)
            .map(|(_, dto)| dto.clone())
    };
    if let Some(dto) = cached {
        record_audit_access(
            &state.db_pool,
            &user.username,
            "audit.verify",
            serde_json::json!({ "cached": true, "intact": dto.intact }),
        )
        .await;
        return Ok(Json(dto));
    }

    let intact = state.ca.verify_audit_chain().await?;
    let repo = AuditRepository::new(state.db_pool.clone());
    let (total, signed) = repo.signed_counts().await?;
    let dto = AuditVerifyResponseDto {
        intact,
        total_records: total.max(0) as u64,
        signed_records: signed.max(0) as u64,
        verified_at: chrono::Utc::now().to_rfc3339(),
    };
    {
        let mut guard = state
            .audit_verify_cache
            .lock()
            .expect("audit-verify cache poisoned");
        *guard = Some((std::time::Instant::now(), dto.clone()));
    }

    tracing::info!(
        actor = %user.username,
        resource = "audit:verify",
        intact,
        total,
        signed,
        "audit trail integrity verified"
    );
    record_audit_access(
        &state.db_pool,
        &user.username,
        "audit.verify",
        serde_json::json!({ "cached": false, "intact": intact, "total": total, "signed": signed }),
    )
    .await;
    Ok(Json(dto))
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
    if let Some(requestor) = certificate_requestor_scope(&user)
        && cert.requestor.as_deref() != Some(requestor)
    {
        return Err(Error::InsufficientRole {
            required: "certificate ownership or global certificate-view permission".to_string(),
        });
    }

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

/// Download a certificate as a certs-only PKCS#7 (.p7b): the leaf plus its
/// issuing CA certificate, base64-encoded DER. Backs the certificate detail
/// view's "Download PKCS#7" option (PEM/DER/full-chain are derived client-side).
///
/// Chain depth: this bundles the leaf + the issuing CA certificate
/// (`state.ca.certificate_der()`) — the same single cert `get_ca_info` exposes
/// as `chain_pem`, so the PKCS#7 and the client-side "Full chain (PEM)" download
/// are built from one source and stay consistent. When the issuing CA is itself
/// an intermediate, neither carries the upper intermediates/root, because the CA
/// service does not hold its own issuer chain.
// POAM: when the CA gains access to its issuer chain, return the full ordered
// chain here (and from get_ca_info) via a shared chain-resolution helper.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 - Access enforcement (Permission::ViewCertificate); own-scoped
/// - NIST 800-53: AU-2/AU-3 - Records who downloaded which certificate
/// - RFC 5652 §5 / RFC 7030 §4.1.3 - degenerate certs-only PKCS#7 (CMS SignedData)
async fn get_certificate_pkcs7(
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
    // Own-scope: a Sponsor may download only certificates they requested.
    if let Some(requestor) = certificate_requestor_scope(&user)
        && cert.requestor.as_deref() != Some(requestor)
    {
        return Err(Error::InsufficientRole {
            required: "certificate ownership or global certificate-view permission".to_string(),
        });
    }

    // Leaf first, then the issuing CA certificate, so the .p7b carries the chain.
    let bundle = [
        cert.der_encoded.clone(),
        state.ca.certificate_der().to_vec(),
    ];
    let p7 = ostrich_x509::pkcs7::encode_certs_only_pkcs7(&bundle)?;

    tracing::info!(
        actor = %user.username,
        resource = %cert.id,
        "certificate downloaded as PKCS#7"
    );

    Ok(Json(CertificatePkcs7Dto {
        pkcs7: BASE64_STANDARD.encode(&p7),
    })
    .into_response())
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
///
/// Ensure a bridged NPE identity (authenticated via the portal's mTLS identity
/// bridge, not a local `users` account) has a row in `users`, so approval FKs
/// (`approval_requests.requestor_id`, `approval_decisions.approver_id`) resolve.
/// No-op for principals that already have a row — password/admin users carry no
/// `certificate_subject`, so they are skipped and their existing row is left
/// untouched.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-2 (persist the bridged principal's unique identity),
///   AC-3 (referential integrity of approval authorization records)
async fn ensure_principal_provisioned(
    state: &ApiState,
    user: &ostrich_common::auth::user::AuthenticatedUser,
) -> Result<()> {
    let Some(subject) = user.certificate_subject.as_deref() else {
        return Ok(());
    };
    ostrich_db::repository::DbUserRepository::new(state.db_pool.clone())
        .ensure_user(*user.id.as_uuid(), &user.username, subject, &user.roles)
        .await
        .map_err(|e| Error::Internal(format!("Failed to provision requestor identity: {e}")))?;
    Ok(())
}

/// Issue the certificate for a just-approved request from the CSR the requestor
/// submitted, so the request moves Approved → Completed and the requestor can
/// download the certificate. The issued certificate is owned by the ORIGINAL
/// requestor (not the approving RA), so own-scope view/download works for the
/// sponsor. Returns the new certificate id.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.2/.3 - issuance is linked to the approved request
///   (`approval_request_id`); requestor ≠ approver was enforced at approval time
async fn issue_from_approved_request(
    state: &ApiState,
    request: &ApprovalRequest,
) -> Result<uuid::Uuid> {
    let details = &request.request_details;
    let csr_pem = details
        .get("csr_pem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::InvalidRequest("approved request has no csr_pem to issue from".to_string())
        })?;
    let profile = details
        .get("profile")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::InvalidRequest("approved request has no profile to issue against".to_string())
        })?;

    let (_label, csr_der) = pem_rfc7468::decode_vec(csr_pem.as_bytes())
        .map_err(|e| Error::InvalidRequest(format!("invalid CSR PEM: {e}")))?;

    let parsed = ostrich_x509::parser::parse_csr(&csr_der)
        .map_err(|e| Error::InvalidRequest(format!("invalid CSR: {e}")))?;
    let subject = ostrich_x509::parser::parse_csr_subject_dn(&csr_der)
        .map_err(|e| Error::InvalidRequest(format!("invalid CSR subject: {e}")))?;

    // Honor the SANs the requester explicitly submitted on the application form,
    // falling back to the CSR's embedded SANs (see `resolve_approval_sans`).
    let subject_alt_names = resolve_approval_sans(details, &parsed.subject_alternative_names);

    let issuance_req = IssuanceRequest {
        profile_name: profile.to_string(),
        subject,
        subject_alt_names,
        public_key: parsed.public_key,
        requestor: request.requestor_username.clone(),
        metadata: None,
        csr_der: Some(csr_der),
        approval_request_id: Some(request.id),
        request_id: None,
    };
    let issued = state.ca.issuer().issue(issuance_req).await?;
    Ok(issued.certificate_id)
}

async fn submit_approval_request(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<SubmitApprovalRequest>,
) -> Result<Json<ApprovalRequestResponse>> {
    use ostrich_common::auth::user::AuthMethod;

    // A bridged NPE requestor has no local users row; provision it so the
    // approval_requests.requestor_id FK resolves (idempotent).
    ensure_principal_provisioned(&state, &user).await?;

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
    // Anyone who may act on requests (holds ApproveRequest) sees the whole queue;
    // everyone else sees only their own. Gating on the PERMISSION rather than a
    // hardcoded role set means every approver role qualifies — RaStaff, Aor, and
    // the NPE RegistrationAuthority alike (the latter was previously excluded and
    // could not see the queue it was authorized to act on).
    let requests = if any_role_has_permission(&user.roles, Permission::ApproveRequest) {
        state.approval_repo.list_pending_requests().await?
    } else {
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

    // Authorization: a user may view a request if they own it or may act on it
    // (holds ApproveRequest — RaStaff, Aor, or the NPE RegistrationAuthority).
    let can_approve = any_role_has_permission(&user.roles, Permission::ApproveRequest);
    if request.requestor_id != *user.id.as_uuid() && !can_approve {
        return Err(Error::InsufficientRole {
            required: "approval permission or request ownership".to_string(),
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

/// Query for the bulk-status endpoint: a comma-separated list of request ids.
#[derive(Debug, Deserialize)]
struct BulkStatusQuery {
    ids: String,
}

/// Bulk status lookup for many certificate applications at once.
///
/// `GET /api/v1/approvals/status?ids=<uuid>,<uuid>,...` — capped at 100 ids.
/// Own-scope: a requester sees only their own applications; RA Staff / AOR see
/// any of the requested ids. Unknown ids are simply omitted from the result.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_CER_EXT.3 - view request status
/// - NIST 800-53: AC-3 (access enforcement), SI-10 (input validation)
async fn bulk_approval_status(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    axum::extract::Query(q): axum::extract::Query<BulkStatusQuery>,
) -> Result<Json<ListApprovalRequestsResponse>> {
    const MAX_IDS: usize = 100;

    // SI-10: parse + validate every id; reject the whole request on a bad id.
    let ids: Vec<uuid::Uuid> = q
        .ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(uuid::Uuid::parse_str)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidRequest("Invalid request ID in 'ids'".to_string()))?;

    if ids.is_empty() {
        return Ok(Json(ListApprovalRequestsResponse { requests: vec![] }));
    }
    if ids.len() > MAX_IDS {
        return Err(Error::InvalidRequest(format!(
            "Too many ids requested (max {MAX_IDS})"
        )));
    }

    let mut records = state.approval_repo.list_requests_by_ids(&ids).await?;

    // Own-scope enforcement: only approvers (holders of ApproveRequest) may see
    // other requesters' rows — kept in lockstep with list_approval_requests so an
    // RA's bulk-status view matches their single-request and list views.
    let can_view_all = any_role_has_permission(&user.roles, Permission::ApproveRequest);
    if !can_view_all {
        let uid = *user.id.as_uuid();
        records.retain(|r| r.requestor_id == uid);
    }

    Ok(Json(ListApprovalRequestsResponse {
        requests: records.into_iter().map(ApprovalRequestInfo::from).collect(),
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
    Query(q): Query<ApproveQuery>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> Result<Json<ApprovalDecisionResponse>> {
    use ostrich_common::auth::user::AuthMethod;

    let request_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid request ID".to_string()))?;

    // A bridged NPE approver has no local users row; provision it so the
    // approval_decisions.approver_id FK resolves (idempotent).
    ensure_principal_provisioned(&state, &user).await?;

    // AC-3 - approving despite validation advisories is a distinct, higher
    // privilege than ordinary approval: require OverrideValidation on top of the
    // route's ApproveRequest guard. Fail closed (403) if the approver lacks it.
    if q.r#override && !any_role_has_permission(&user.roles, Permission::OverrideValidation) {
        return Err(Error::InsufficientRole {
            required: "OverrideValidation".to_string(),
        });
    }

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

    // AU-2/AU-3 - when validation is overridden, annotate the decision so the
    // override is visible in the human-readable justification AND emit a
    // high-signal audit log line with who/what/when context.
    let justification = {
        let base = req.justification.unwrap_or_else(|| "Approved".to_string());
        if q.r#override {
            format!("{base} [validation overridden]")
        } else {
            base
        }
    };
    if q.r#override {
        // The durable, tamper-evident record of the override is the persisted
        // approval decision below (`metadata.validation_overridden` + annotated
        // justification, in the append-only approval_decisions table). This
        // tracing line is the operational signal.
        // POAM: also emit a formal hash-chained AuditEvent (AU-10) for the
        // override once that audit infrastructure lands (see line ~1043).
        tracing::warn!(
            request_id = %request_id,
            approver = %user.username,
            "approval validation OVERRIDDEN (OverrideValidation)"
        );
    }

    // Approve via engine (enforces segregation of duties)
    let decision = state
        .approval_engine
        .approve_request(&mut request, &approver, justification)?;

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
        metadata: if q.r#override {
            Some(serde_json::json!({ "validation_overridden": true }))
        } else {
            None
        },
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

    // Auto-issue on approval so the requestor can download the certificate
    // (Approved → Completed). Only issuance/renewal requests carry a CSR to
    // issue from; revocation approvals do not. If issuance fails the request
    // stays Approved (the decision is already recorded) and the error surfaces
    // to the approver.
    let mut updated_status = request.status.to_string();
    if request.certificate_id.is_none()
        && matches!(
            request.request_type,
            crate::approval::RequestType::Issuance | crate::approval::RequestType::Renewal
        )
    {
        let certificate_id = issue_from_approved_request(&state, &request).await?;
        state
            .approval_repo
            .mark_request_completed(&request_id, certificate_id)
            .await?;
        updated_status = "completed".to_string();
        tracing::info!(
            request_id = %request_id,
            certificate_id = %certificate_id,
            approver = %user.username,
            "approved request issued and marked completed"
        );
    }

    Ok(Json(ApprovalDecisionResponse {
        decision: ApprovalDecisionInfo::from(decision_record),
        updated_status,
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

    // A bridged NPE approver has no local users row; provision it so the
    // approval_decisions.approver_id FK resolves (idempotent).
    ensure_principal_provisioned(&state, &user).await?;

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

// ===========================================================================
// Bulk enrollment (Administrator "Submit Bulk")
// ===========================================================================

/// Maximum number of CSRs accepted in one bulk upload (spec cap).
const MAX_BULK_CSRS: usize = 100;
/// Per-CSR size ceiling (anti zip-bomb). A PEM CSR is a few KiB; 64 KiB is ample.
const MAX_CSR_BYTES: u64 = 64 * 1024;
/// Total ZIP entry ceiling, independent of how many are CSRs. Bounds the
/// directory scan so a pathological archive (e.g. 100k empty/non-CSR entries
/// alongside a few CSRs) cannot force a huge iteration past the CSR cap.
const MAX_ZIP_ENTRIES: usize = 1000;
/// Whole-upload ceiling for the multipart body (defense in depth on top of the
/// per-CSR and entry caps). 8 MiB is ample for 100 PEM CSRs + ZIP overhead.
const MAX_BULK_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Extract the CSR-bearing entries from an uploaded ZIP, capped and size-bounded.
/// Returns `(source_name, raw_bytes)` for each `.csr/.pem/.req/.der` file.
fn extract_csr_entries(zip_bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .map_err(|e| Error::InvalidRequest(format!("invalid ZIP archive: {e}")))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(Error::InvalidRequest(format!(
            "archive has more than {MAX_ZIP_ENTRIES} entries"
        )));
    }
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| Error::InvalidRequest(format!("unreadable ZIP entry: {e}")))?;
        if !file.is_file() {
            continue;
        }
        let name = file.name().to_string();
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with(".csr")
            || lower.ends_with(".pem")
            || lower.ends_with(".req")
            || lower.ends_with(".der"))
        {
            continue;
        }
        if entries.len() >= MAX_BULK_CSRS {
            return Err(Error::InvalidRequest(format!(
                "archive contains more than {MAX_BULK_CSRS} certificate requests"
            )));
        }
        // SI-10 / anti zip-bomb: bound the read regardless of the entry's claimed
        // size, then reject anything over the ceiling.
        let mut buf = Vec::new();
        file.take(MAX_CSR_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| Error::InvalidRequest(format!("failed reading '{name}': {e}")))?;
        if buf.len() as u64 > MAX_CSR_BYTES {
            return Err(Error::InvalidRequest(format!(
                "entry '{name}' exceeds the {MAX_CSR_BYTES}-byte per-CSR limit"
            )));
        }
        entries.push((name, buf));
    }
    Ok(entries)
}

/// Validate one CSR entry (PEM or DER). Returns `(canonical_pem, subject_cn)` on
/// success, or a human-readable reason on failure (recorded per-item, never fatal
/// to the batch).
fn validate_csr_entry(bytes: &[u8]) -> std::result::Result<(String, Option<String>), String> {
    let der = if bytes.starts_with(b"-----BEGIN") {
        let (label, der) =
            pem_rfc7468::decode_vec(bytes).map_err(|e| format!("invalid PEM: {e}"))?;
        if !label.contains("CERTIFICATE REQUEST") {
            return Err(format!("unexpected PEM label '{label}' (expected a CSR)"));
        }
        der
    } else {
        bytes.to_vec()
    };
    // SI-10: the bytes must parse as a PKCS#10 CSR to be queued.
    ostrich_x509::parser::parse_csr(&der).map_err(|e| format!("invalid CSR: {e}"))?;
    let subject_cn = ostrich_x509::parser::parse_csr_subject_dn(&der)
        .ok()
        .and_then(|dn| dn.common_name);
    let pem = pem_rfc7468::encode_string("CERTIFICATE REQUEST", pem_rfc7468::LineEnding::LF, &der)
        .map_err(|e| format!("could not normalize CSR: {e}"))?;
    Ok((pem, subject_cn))
}

/// Bulk-enroll a ZIP of CSRs under one profile (multipart: `profile` + `archive`).
///
/// Each CSR is validated and, if valid, queued as an Issuance approval request so
/// the RA can review it; the per-CSR outcome is recorded durably and the batch is
/// summarized by a Bulk Identifier. Processing is synchronous (the spec caps a
/// batch at 100 CSRs, which is a handful of inserts).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3/AC-6 (BulkEnroll permission; submitter-owned),
///   AU-2/AU-3 (auditable bulk operation + per-CSR outcome), SI-10 (each CSR
///   validated before it is queued)
/// - NIAP PP-CA: FDP_CER_EXT.2 (CSR -> request linkage), FDP_CER_EXT.3 (workflow)
// POAM: for very large batches, move processing to a durable background worker
// with restart recovery, and notify the submitter by email on completion (no
// email subsystem exists yet; the result is retrievable in-portal meanwhile).
async fn bulk_enroll(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<BulkJobDetailDto>> {
    use ostrich_common::auth::user::{AuthMethod, AuthenticatedUser};
    use ostrich_db::models::{BulkEnrollmentItemRecord, BulkEnrollmentJobRecord};
    use ostrich_db::repository::BulkEnrollmentRepository;

    // Read the multipart fields: a `profile` text field and an `archive` ZIP.
    let mut profile_name: Option<String> = None;
    let mut zip_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| Error::InvalidRequest(format!("invalid multipart body: {e}")))?
    {
        match field.name() {
            Some("profile") => {
                profile_name =
                    Some(field.text().await.map_err(|e| {
                        Error::InvalidRequest(format!("invalid profile field: {e}"))
                    })?);
            }
            Some("archive") | Some("file") => {
                zip_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| Error::InvalidRequest(format!("invalid archive field: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let profile_name = profile_name
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Error::InvalidRequest("missing 'profile' field".to_string()))?;
    let zip_bytes = zip_bytes
        .ok_or_else(|| Error::InvalidRequest("missing 'archive' (ZIP) field".to_string()))?;

    let entries = extract_csr_entries(&zip_bytes)?;
    if entries.is_empty() {
        return Err(Error::InvalidRequest(
            "archive contains no .csr/.pem/.req/.der certificate requests".to_string(),
        ));
    }

    // A bridged NPE submitter has no local users row; provision it so the
    // per-CSR approval_requests.requestor_id FK resolves (idempotent).
    ensure_principal_provisioned(&state, &user).await?;

    let bulk_repo = BulkEnrollmentRepository::new(state.db_pool.as_ref().clone());

    // Create the job row up front (status `processing`) with the known total, so a
    // crash mid-batch leaves a non-terminal job rather than nothing.
    let job_id = uuid::Uuid::new_v4();
    let bulk_identifier = format!("BULK-{}", job_id.simple().to_string()[..12].to_uppercase());
    let now = chrono::Utc::now();
    let job = BulkEnrollmentJobRecord {
        id: job_id,
        bulk_identifier: bulk_identifier.clone(),
        submitter_id: *user.id.as_uuid(),
        submitter_username: user.username.clone(),
        profile_name: profile_name.clone(),
        status: "processing".to_string(),
        total_count: entries.len() as i32,
        succeeded_count: 0,
        failed_count: 0,
        created_at: now,
        completed_at: None,
    };
    bulk_repo.create_job(&job).await?;

    let auth_user = AuthenticatedUser::new(
        user.id,
        user.username.clone(),
        user.roles.clone(),
        AuthMethod::Password,
    );

    let mut succeeded = 0i32;
    let mut failed = 0i32;
    let mut items = Vec::with_capacity(entries.len());
    for (idx, (name, bytes)) in entries.into_iter().enumerate() {
        let mut item = BulkEnrollmentItemRecord {
            id: uuid::Uuid::new_v4(),
            job_id,
            item_index: idx as i32,
            source_name: name.clone(),
            subject_cn: None,
            status: "failed".to_string(),
            request_id: None,
            certificate_id: None,
            error: None,
            created_at: chrono::Utc::now(),
        };

        match validate_csr_entry(&bytes) {
            Err(reason) => {
                item.error = Some(reason);
                failed += 1;
            }
            Ok((csr_pem, subject_cn)) => {
                // Queue an Issuance approval request carrying the CSR + profile,
                // exactly like a single submission (the RA reviews it later).
                let details = serde_json::json!({
                    "profile": profile_name,
                    "csr_pem": csr_pem,
                    "source": name,
                    "bulk_identifier": bulk_identifier,
                });
                let submitted = state.approval_engine.create_request(
                    crate::approval::RequestType::Issuance,
                    &auth_user,
                    details,
                );
                let record = ostrich_db::models::ApprovalRequestRecord {
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
                // On a mid-loop DB failure, drive the job to a terminal `failed`
                // state before returning — otherwise the job row is stranded in
                // `processing` forever with a partial item set and no recovery.
                if let Err(e) = state.approval_repo.create_request(&record).await {
                    let _ = bulk_repo
                        .finalize_job(job_id, "failed", succeeded, failed)
                        .await;
                    return Err(e.into());
                }
                item.subject_cn = subject_cn;
                item.status = "queued".to_string();
                item.request_id = Some(submitted.id);
                succeeded += 1;
            }
        }

        let stored = match bulk_repo.create_item(&item).await {
            Ok(stored) => stored,
            Err(e) => {
                let _ = bulk_repo
                    .finalize_job(job_id, "failed", succeeded, failed)
                    .await;
                return Err(e.into());
            }
        };
        items.push(BulkItemDto::from(stored));
    }

    bulk_repo
        .finalize_job(job_id, "completed", succeeded, failed)
        .await?;

    tracing::info!(
        actor = %user.username,
        bulk_identifier = %bulk_identifier,
        total = items.len(),
        succeeded,
        failed,
        "bulk enrollment completed"
    );

    let final_job = BulkEnrollmentJobRecord {
        status: "completed".to_string(),
        succeeded_count: succeeded,
        failed_count: failed,
        completed_at: Some(chrono::Utc::now()),
        ..job
    };
    Ok(Json(BulkJobDetailDto {
        job: BulkJobSummaryDto::from(final_job),
        items,
    }))
}

/// List the bulk jobs the authenticated user submitted (own-scope).
async fn list_bulk_jobs(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<BulkJobSummaryDto>>> {
    let bulk_repo =
        ostrich_db::repository::BulkEnrollmentRepository::new(state.db_pool.as_ref().clone());
    let jobs = bulk_repo.list_jobs_by_submitter(*user.id.as_uuid()).await?;
    Ok(Json(
        jobs.into_iter().map(BulkJobSummaryDto::from).collect(),
    ))
}

/// Fetch one bulk job + its per-CSR items. Own-scope: the submitter, or any
/// approver (ApproveRequest), may read it.
async fn get_bulk_job(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<BulkJobDetailDto>> {
    let job_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid bulk job ID".to_string()))?;
    let bulk_repo =
        ostrich_db::repository::BulkEnrollmentRepository::new(state.db_pool.as_ref().clone());
    let job = bulk_repo
        .get_job(job_id)
        .await?
        .ok_or_else(|| Error::NotFound(format!("bulk job {job_id} not found")))?;

    if job.submitter_id != *user.id.as_uuid()
        && !any_role_has_permission(&user.roles, Permission::ApproveRequest)
    {
        return Err(Error::InsufficientRole {
            required: "bulk job ownership or approval permission".to_string(),
        });
    }

    let items = bulk_repo.list_items(job_id).await?;
    Ok(Json(BulkJobDetailDto {
        job: BulkJobSummaryDto::from(job),
        items: items.into_iter().map(BulkItemDto::from).collect(),
    }))
}

// ===========================================================================
// CAA user management
// ===========================================================================

/// Roles the CAA may assign through the portal. This is a privilege ceiling
/// (AC-6): the CAA manages NPE portal accounts, so it may grant only the NPE
/// roles — never a legacy CA super-role (e.g. `Administrator`, the legacy
/// `Auditor` with export/search). `NpeAuditor` is the read-only portal auditor.
const ASSIGNABLE_NPE_ROLES: [ostrich_common::auth::Role; 5] = {
    use ostrich_common::auth::Role;
    [
        Role::PkiSponsor,
        Role::PkiSponsorAdmin,
        Role::RegistrationAuthority,
        Role::CaaAdmin,
        Role::NpeAuditor,
    ]
};

/// Parse a list of role-name strings into `Role`s, rejecting any unknown name
/// (SI-10) and any role outside the CAA's assignable ceiling (AC-6). Never
/// silently drops or mis-assigns a role.
fn parse_roles(names: &[String]) -> Result<Vec<ostrich_common::auth::Role>> {
    use std::str::FromStr;
    names
        .iter()
        .map(|n| {
            let role = ostrich_common::auth::Role::from_str(n.trim())
                .map_err(|_| Error::InvalidRequest(format!("unknown role '{n}'")))?;
            if !ASSIGNABLE_NPE_ROLES.contains(&role) {
                return Err(Error::InvalidRequest(format!(
                    "role '{n}' may not be assigned through the portal"
                )));
            }
            Ok(role)
        })
        .collect()
}

/// List all user accounts (CAA "User Management"). Requires ViewUsers.
async fn list_users(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
) -> Result<Json<Vec<UserDto>>> {
    let repo = ostrich_db::repository::DbUserRepository::new(state.db_pool.clone());
    let users = repo
        .list_users()
        .await
        .map_err(|e| Error::Internal(format!("Failed to list users: {e}")))?;
    Ok(Json(users.into_iter().map(UserDto::from).collect()))
}

/// Create a certificate-authenticated user with assigned roles. Requires CreateUser.
async fn create_user(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserDto>> {
    let username = req.username.trim();
    let cert_subject = req.certificate_subject.trim();
    if username.is_empty() || cert_subject.is_empty() {
        return Err(Error::InvalidRequest(
            "username and certificateSubject are required".to_string(),
        ));
    }
    let roles = parse_roles(&req.roles)?;

    let repo = ostrich_db::repository::DbUserRepository::new(state.db_pool.clone());
    if repo
        .user_exists(username)
        .await
        .map_err(|e| Error::Internal(format!("Failed to check user: {e}")))?
    {
        return Err(Error::InvalidRequest(format!(
            "a user named '{username}' already exists"
        )));
    }

    let id = repo
        .create_certificate_user(
            username,
            cert_subject,
            req.display_name.as_deref(),
            req.email.as_deref(),
            &roles,
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create user: {e}")))?;

    tracing::info!(actor = %user.username, new_user = %username, "CAA created user account");

    let created = repo
        .get_user(id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load user: {e}")))?
        .ok_or_else(|| Error::Internal("created user not found".to_string()))?;
    Ok(Json(UserDto::from(created)))
}

/// Load the target user and enforce the CAA self-action block: a CAA may never
/// modify, disable, or delete their own account (AC-5 separation of duties — a
/// privileged admin cannot remove the controls on themselves).
async fn load_target_user_guarded(
    repo: &ostrich_db::repository::DbUserRepository,
    actor: &str,
    id: &str,
) -> Result<(uuid::Uuid, ostrich_common::auth::UserAccount)> {
    let user_id = uuid::Uuid::parse_str(id)
        .map_err(|_| Error::InvalidRequest("Invalid user ID".to_string()))?;
    let target = repo
        .get_user(user_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load user: {e}")))?
        .ok_or_else(|| Error::NotFound(format!("user {user_id} not found")))?;
    // Case-insensitive so a CAA cannot sidestep the block via a case-variant
    // username (defense in depth; usernames are unique but not case-normalized).
    if target.username.eq_ignore_ascii_case(actor) {
        return Err(Error::InsufficientRole {
            required: "a different administrator (cannot act on your own account)".to_string(),
        });
    }
    Ok((user_id, target))
}

/// Replace a user's roles. Requires AssignRoles; self-action blocked.
async fn set_user_roles(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
    Json(req): Json<SetRolesRequest>,
) -> Result<Json<UserDto>> {
    let roles = parse_roles(&req.roles)?;
    let repo = ostrich_db::repository::DbUserRepository::new(state.db_pool.clone());
    let (user_id, _target) = load_target_user_guarded(&repo, &user.username, &id).await?;

    repo.set_user_roles(user_id, &roles)
        .await
        .map_err(|e| Error::Internal(format!("Failed to set roles: {e}")))?;
    tracing::info!(actor = %user.username, target = %user_id, "CAA reassigned user roles");

    let updated = repo
        .get_user(user_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load user: {e}")))?
        .ok_or_else(|| Error::NotFound(format!("user {user_id} not found")))?;
    Ok(Json(UserDto::from(updated)))
}

/// Set a user's account status (e.g. enable/disable). Requires ModifyUser;
/// self-action blocked. Only the table's allowed status values are accepted.
async fn set_user_status(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
    Json(req): Json<SetStatusRequest>,
) -> Result<Json<UserDto>> {
    const ALLOWED: [&str; 5] = [
        "active",
        "locked",
        "suspended",
        "disabled",
        "pending_activation",
    ];
    let status = req.status.trim().to_ascii_lowercase();
    if !ALLOWED.contains(&status.as_str()) {
        return Err(Error::InvalidRequest(format!(
            "invalid status '{status}' (expected one of {ALLOWED:?})"
        )));
    }
    let repo = ostrich_db::repository::DbUserRepository::new(state.db_pool.clone());
    let (user_id, _target) = load_target_user_guarded(&repo, &user.username, &id).await?;

    repo.set_user_status(user_id, &status)
        .await
        .map_err(|e| Error::Internal(format!("Failed to set status: {e}")))?;
    tracing::info!(actor = %user.username, target = %user_id, status = %status, "CAA changed user status");

    let updated = repo
        .get_user(user_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load user: {e}")))?
        .ok_or_else(|| Error::NotFound(format!("user {user_id} not found")))?;
    Ok(Json(UserDto::from(updated)))
}

/// Delete a user account. Requires DeleteUser; self-action blocked.
async fn delete_user(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let repo = ostrich_db::repository::DbUserRepository::new(state.db_pool.clone());
    let (user_id, _target) = load_target_user_guarded(&repo, &user.username, &id).await?;

    repo.delete_user(user_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to delete user: {e}")))?;
    tracing::info!(actor = %user.username, target = %user_id, "CAA deleted user account");
    Ok(StatusCode::NO_CONTENT)
}

// ===========================================================================
// CAA wildcard / namespace policy management
//
// POAM: this milestone delivers the CAA management surface (curate the rule
// list). Enforcing the rules at issuance time — consulting `namespaces` in the
// CSR/subject validation path to permit or deny wildcard/namespace scopes — is
// the follow-up integration (FDP_ACF.1) and is tracked separately.
// ===========================================================================

/// List all namespace / wildcard policy rules. Requires ManageNamespaces.
async fn list_namespaces(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
) -> Result<Json<Vec<NamespaceDto>>> {
    let repo = ostrich_db::repository::NamespaceRepository::new(state.db_pool.as_ref().clone());
    let rules = repo
        .list()
        .await
        .map_err(|e| Error::Internal(format!("Failed to list namespaces: {e}")))?;
    Ok(Json(rules.into_iter().map(NamespaceDto::from).collect()))
}

/// Create a namespace / wildcard policy rule. Requires ManageNamespaces.
///
/// CM-3: the change is attributed to the authenticated CAA and audited.
async fn create_namespace(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<Json<NamespaceDto>> {
    // SI-10: normalize + validate the pattern. A DNS pattern is a set of
    // dot-separated labels, optionally a single leading `*` wildcard label.
    let pattern = req.pattern.trim().to_ascii_lowercase();
    if !is_valid_namespace_pattern(&pattern) {
        return Err(Error::InvalidRequest(format!(
            "invalid namespace pattern '{pattern}'"
        )));
    }

    // SI-10 defense in depth: bound the free-text description (the column is TEXT).
    const MAX_DESCRIPTION: usize = 1024;
    let description = req
        .description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty());
    if let Some(d) = &description
        && d.len() > MAX_DESCRIPTION
    {
        return Err(Error::InvalidRequest(format!(
            "description exceeds {MAX_DESCRIPTION} characters"
        )));
    }

    let rule = ostrich_db::models::NamespaceRecord {
        id: uuid::Uuid::new_v4(),
        pattern,
        allow: req.allow.unwrap_or(true),
        description,
        created_by: user.username.clone(),
        created_at: chrono::Utc::now(),
    };

    let repo = ostrich_db::repository::NamespaceRepository::new(state.db_pool.as_ref().clone());
    let created = repo.create(&rule).await.map_err(|e| {
        // Distinguish a duplicate pattern (client error, clean message) from a
        // genuine infrastructure failure (server error) — and never echo the raw
        // DB error to the client (SI-11). The detail is logged server-side.
        let detail = e.to_string().to_ascii_lowercase();
        if detail.contains("duplicate") || detail.contains("unique") {
            Error::InvalidRequest(format!(
                "a namespace rule for '{}' already exists",
                rule.pattern
            ))
        } else {
            tracing::error!(error = %e, "failed to create namespace rule");
            Error::Internal("failed to create namespace rule".to_string())
        }
    })?;
    tracing::info!(actor = %user.username, pattern = %created.pattern, allow = created.allow, "CAA created namespace rule");
    Ok(Json(NamespaceDto::from(created)))
}

/// Delete a namespace rule. Requires ManageNamespaces.
async fn delete_namespace(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let rule_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| Error::InvalidRequest("Invalid namespace ID".to_string()))?;
    let repo = ostrich_db::repository::NamespaceRepository::new(state.db_pool.as_ref().clone());
    if !repo
        .delete(rule_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to delete namespace: {e}")))?
    {
        return Err(Error::NotFound(format!("namespace {rule_id} not found")));
    }
    tracing::info!(actor = %user.username, namespace = %rule_id, "CAA deleted namespace rule");
    Ok(StatusCode::NO_CONTENT)
}

/// Validate a DNS namespace pattern: 1+ labels, each `[a-z0-9-]` (not starting/
/// ending with `-`), optionally a single leading `*` wildcard label.
fn is_valid_namespace_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.len() > 253 {
        return false;
    }
    let mut labels = pattern.split('.');
    let first = labels.clone().next().unwrap_or("");
    let is_label = |l: &str| -> bool {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    // The first label may be exactly "*"; every other label must be a normal label.
    if first == "*" {
        labels.next(); // consume "*"
        let rest: Vec<&str> = labels.collect();
        !rest.is_empty() && rest.iter().all(|l| is_label(l))
    } else {
        pattern.split('.').all(is_label)
    }
}

// ===========================================================================
// CAA system configuration
//
// POAM: this milestone delivers the managed, audited settings store + the CAA
// management surface. Wiring each setting to runtime behavior (reading
// `default_certificate_validity_days` / `require_approval_for_issuance` /
// `max_bulk_csrs` from this store instead of the current compile-time constants)
// is the follow-up integration, tracked separately.
// ===========================================================================

/// Validate a configuration value against the expected type for its key, so a
/// type-invalid value (e.g. a non-boolean flag, a negative count) is never
/// stored (SI-10). Unknown keys are rejected separately by the caller.
fn validate_config_value(key: &str, value: &str) -> Result<()> {
    let ok = match key {
        "default_certificate_validity_days" | "max_bulk_csrs" => {
            value.parse::<u32>().is_ok_and(|n| n > 0)
        }
        "require_approval_for_issuance" => matches!(value, "true" | "false"),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidRequest(format!(
            "invalid value '{value}' for setting '{key}'"
        )))
    }
}

/// List all system configuration settings. Requires ViewConfig.
async fn list_config(
    State(state): State<Arc<ApiState>>,
    AuthUser(_user): AuthUser,
) -> Result<Json<Vec<ConfigDto>>> {
    let repo = ostrich_db::repository::SystemConfigRepository::new(state.db_pool.as_ref().clone());
    let settings = repo
        .list()
        .await
        .map_err(|e| Error::Internal(format!("Failed to list config: {e}")))?;
    Ok(Json(settings.into_iter().map(ConfigDto::from).collect()))
}

/// Set a configuration value (and optional description). Requires ModifyConfig.
///
/// CM-3: the change is attributed to the authenticated CAA and audited. Only
/// existing (seeded) keys may be set, so the config surface cannot sprawl into
/// arbitrary unconsumed keys.
async fn set_config(
    State(state): State<Arc<ApiState>>,
    AuthUser(user): AuthUser,
    Path(key): Path<String>,
    Json(req): Json<SetConfigRequest>,
) -> Result<Json<ConfigDto>> {
    const MAX_VALUE: usize = 4096;
    let value = req.value.trim().to_string();
    if value.len() > MAX_VALUE {
        return Err(Error::InvalidRequest(format!(
            "value exceeds {MAX_VALUE} characters"
        )));
    }

    let repo = ostrich_db::repository::SystemConfigRepository::new(state.db_pool.as_ref().clone());

    // CM-3 / fail closed: only a known (seeded) setting may be changed; reject an
    // unknown key rather than creating an unconsumed configuration entry.
    if repo
        .get(&key)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load config: {e}")))?
        .is_none()
    {
        return Err(Error::NotFound(format!(
            "unknown configuration key '{key}'"
        )));
    }

    // SI-10: a known key's value must match its expected type.
    validate_config_value(&key, &value)?;

    let updated = repo
        .upsert(&key, &value, req.description.as_deref(), &user.username)
        .await
        .map_err(|e| Error::Internal(format!("Failed to update config: {e}")))?;

    tracing::info!(actor = %user.username, key = %key, "CAA updated system configuration");
    Ok(Json(ConfigDto::from(updated)))
}

// REST API Request/Response types

/// Summary of a bulk enrollment job.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkJobSummaryDto {
    id: String,
    bulk_identifier: String,
    profile_name: String,
    status: String,
    total_count: i32,
    succeeded_count: i32,
    failed_count: i32,
    created_at: String,
    completed_at: Option<String>,
}

impl From<ostrich_db::models::BulkEnrollmentJobRecord> for BulkJobSummaryDto {
    fn from(j: ostrich_db::models::BulkEnrollmentJobRecord) -> Self {
        Self {
            id: j.id.to_string(),
            bulk_identifier: j.bulk_identifier,
            profile_name: j.profile_name,
            status: j.status,
            total_count: j.total_count,
            succeeded_count: j.succeeded_count,
            failed_count: j.failed_count,
            created_at: j.created_at.to_rfc3339(),
            completed_at: j.completed_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// One CSR's outcome within a bulk enrollment job.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkItemDto {
    item_index: i32,
    source_name: String,
    subject_cn: Option<String>,
    status: String,
    request_id: Option<String>,
    error: Option<String>,
}

impl From<ostrich_db::models::BulkEnrollmentItemRecord> for BulkItemDto {
    fn from(i: ostrich_db::models::BulkEnrollmentItemRecord) -> Self {
        Self {
            item_index: i.item_index,
            source_name: i.source_name,
            subject_cn: i.subject_cn,
            status: i.status,
            request_id: i.request_id.map(|r| r.to_string()),
            error: i.error,
        }
    }
}

/// A bulk job plus its per-CSR items.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkJobDetailDto {
    job: BulkJobSummaryDto,
    items: Vec<BulkItemDto>,
}

/// A user account as exposed to the CAA management UI. The password hash is
/// never included (the model marks it `#[serde(skip_serializing)]` anyway, but
/// this DTO simply does not carry it).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDto {
    id: String,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    certificate_subject: Option<String>,
    roles: Vec<String>,
    status: String,
    created_at: String,
    updated_at: String,
    last_login_at: Option<String>,
}

impl From<ostrich_common::auth::UserAccount> for UserDto {
    fn from(u: ostrich_common::auth::UserAccount) -> Self {
        Self {
            id: u.id.as_uuid().to_string(),
            username: u.username,
            display_name: u.display_name,
            email: u.email,
            certificate_subject: u.certificate_subject,
            roles: u.roles.iter().map(|r| r.name().to_string()).collect(),
            status: u.status.to_string(),
            created_at: u.created_at.to_rfc3339(),
            updated_at: u.updated_at.to_rfc3339(),
            last_login_at: u.last_login_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Create-user request (certificate-authenticated NPE account).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    username: String,
    certificate_subject: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// Replace-roles request.
#[derive(Debug, Deserialize)]
struct SetRolesRequest {
    roles: Vec<String>,
}

/// Set-status request.
#[derive(Debug, Deserialize)]
struct SetStatusRequest {
    status: String,
}

/// A namespace / wildcard policy rule as exposed to the CAA UI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NamespaceDto {
    id: String,
    pattern: String,
    allow: bool,
    description: Option<String>,
    created_by: String,
    created_at: String,
}

impl From<ostrich_db::models::NamespaceRecord> for NamespaceDto {
    fn from(n: ostrich_db::models::NamespaceRecord) -> Self {
        Self {
            id: n.id.to_string(),
            pattern: n.pattern,
            allow: n.allow,
            description: n.description,
            created_by: n.created_by,
            created_at: n.created_at.to_rfc3339(),
        }
    }
}

/// Create-namespace request.
#[derive(Debug, Deserialize)]
struct CreateNamespaceRequest {
    pattern: String,
    #[serde(default)]
    allow: Option<bool>,
    #[serde(default)]
    description: Option<String>,
}

/// A system configuration setting as exposed to the CAA UI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigDto {
    key: String,
    value: String,
    description: Option<String>,
    updated_by: String,
    updated_at: String,
}

impl From<ostrich_db::models::SystemConfigRecord> for ConfigDto {
    fn from(c: ostrich_db::models::SystemConfigRecord) -> Self {
        Self {
            key: c.key,
            value: c.value,
            description: c.description,
            updated_by: c.updated_by,
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

/// Set-config request (the key is in the path).
#[derive(Debug, Deserialize)]
struct SetConfigRequest {
    value: String,
    #[serde(default)]
    description: Option<String>,
}

/// CA information response.
///
/// The basic identity (`ca_id`, `ca_dn`) is always present; the remaining
/// fields are best-effort enrichment parsed from the CA certificate (key type,
/// algorithm, validity, serial, PEM chain) and are `None` if parsing fails.
/// Surfacing the key type lets clients distinguish, e.g., an EC CA from an RSA
/// CA when several CA backends are deployed.
#[derive(Debug, Serialize, Deserialize)]
pub struct CaInfoResponse {
    pub ca_id: String,
    pub ca_dn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Human-friendly signature algorithm (e.g. "ECDSA-SHA384", "RSA-SHA256").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    /// Public-key family: "EC", "RSA", "Ed25519", "ML-DSA", or the raw OID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// PEM encoding of the CA certificate (the trust anchor / chain root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
}

/// Map a signature-algorithm OID to a friendly name and the public-key family.
/// Unknown OIDs are returned verbatim with an "unknown" key type so the endpoint
/// degrades gracefully rather than failing.
fn describe_signature_algorithm(oid: &str) -> (String, String) {
    let (alg, key) = match oid {
        "1.2.840.113549.1.1.11" => ("RSA-SHA256", "RSA"),
        "1.2.840.113549.1.1.12" => ("RSA-SHA384", "RSA"),
        "1.2.840.113549.1.1.13" => ("RSA-SHA512", "RSA"),
        "1.2.840.113549.1.1.10" => ("RSA-PSS", "RSA"),
        "1.2.840.10045.4.3.2" => ("ECDSA-SHA256", "EC"),
        "1.2.840.10045.4.3.3" => ("ECDSA-SHA384", "EC"),
        "1.2.840.10045.4.3.4" => ("ECDSA-SHA512", "EC"),
        "1.3.101.112" => ("Ed25519", "Ed25519"),
        // ML-DSA (FIPS 204)
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44", "ML-DSA"),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65", "ML-DSA"),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87", "ML-DSA"),
        other => return (other.to_string(), "unknown".to_string()),
    };
    (alg.to_string(), key.to_string())
}

/// PEM-encode DER bytes as a CERTIFICATE block (64-char lines, RFC 7468).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // chunk is a slice of the ASCII base64 string, always valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
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
    /// Set once the approved request has been issued (Completed): the id of the
    /// issued certificate, so the requestor can view/download it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
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
            certificate_id: record.certificate_id.map(|c| c.to_string()),
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

/// Query parameters for the approve endpoint.
#[derive(Debug, Default, Deserialize)]
struct ApproveQuery {
    /// When true, the approver is consciously approving despite validation
    /// advisories (e.g. validity/namespace/policy warnings). This is a distinct,
    /// higher privilege: it requires `OverrideValidation` on top of the route's
    /// `ApproveRequest` guard, and the override is recorded on the decision.
    #[serde(default)]
    r#override: bool,
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
            Error::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Error::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
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

    /// A known config key's value must match its expected type (SI-10).
    #[test]
    fn config_value_type_validation() {
        assert!(validate_config_value("max_bulk_csrs", "100").is_ok());
        assert!(validate_config_value("max_bulk_csrs", "-5").is_err());
        assert!(validate_config_value("max_bulk_csrs", "0").is_err());
        assert!(validate_config_value("max_bulk_csrs", "abc").is_err());
        assert!(validate_config_value("require_approval_for_issuance", "true").is_ok());
        assert!(validate_config_value("require_approval_for_issuance", "false").is_ok());
        assert!(validate_config_value("require_approval_for_issuance", "maybe").is_err());
        assert!(validate_config_value("default_certificate_validity_days", "397").is_ok());
    }

    /// Approval-issuance SAN resolution: the requester's explicitly-submitted
    /// `subject_alt_names` win over the CSR's; the CSR is the fallback only when
    /// the form supplied none. Regression for a SAN-required profile rejecting an
    /// application whose SAN was entered on the form but absent from the CSR
    /// (CN-only paste, or in-browser CSR generated before the SAN was added).
    #[test]
    fn resolve_approval_sans_prefers_form_over_csr() {
        use serde_json::json;

        // Explicit form SANs take precedence over whatever the CSR carried.
        let details = json!({ "subject_alt_names": ["DNS:deploy.oopl.dev.mil"] });
        assert_eq!(
            resolve_approval_sans(&details, &["DNS:stale.example".to_string()]),
            vec![SubjectAltName::dns("deploy.oopl.dev.mil")],
        );

        // Empty form list → fall back to the CSR's embedded SANs.
        let empty = json!({ "subject_alt_names": [] });
        assert_eq!(
            resolve_approval_sans(&empty, &["DNS:from-csr.example".to_string()]),
            vec![SubjectAltName::dns("from-csr.example")],
        );

        // Missing field entirely → CSR fallback (older payloads / EST paths).
        let absent = json!({ "profile": "tls_server" });
        assert_eq!(
            resolve_approval_sans(&absent, &["email:admin@example.mil".to_string()]),
            vec![SubjectAltName::email("admin@example.mil")],
        );

        // Neither source has a SAN → empty (issue() then enforces profile policy).
        assert!(resolve_approval_sans(&json!({}), &[]).is_empty());
    }

    /// Namespace patterns are validated (SI-10): normal DNS names and a single
    /// leading `*` wildcard are accepted; malformed/abusive patterns rejected.
    #[test]
    fn namespace_pattern_validation() {
        assert!(is_valid_namespace_pattern("example.mil"));
        assert!(is_valid_namespace_pattern("app.example.mil"));
        assert!(is_valid_namespace_pattern("*.example.mil"));
        // Rejections.
        assert!(!is_valid_namespace_pattern(""));
        assert!(!is_valid_namespace_pattern("*")); // wildcard with no suffix
        assert!(!is_valid_namespace_pattern("*.*.mil")); // only one wildcard label
        assert!(!is_valid_namespace_pattern("a..b")); // empty label
        assert!(!is_valid_namespace_pattern("-bad.mil")); // label starts with '-'
        assert!(!is_valid_namespace_pattern("bad_underscore.mil")); // illegal char
        assert!(!is_valid_namespace_pattern("foo.*.mil")); // wildcard not leading
    }

    /// CAA role assignment must reject unknown role names (SI-10) rather than
    /// silently dropping them, and accept the canonical snake_case names.
    #[test]
    fn parse_roles_accepts_known_rejects_unknown() {
        let ok = parse_roles(&[
            "registration_authority".to_string(),
            "caa_admin".to_string(),
        ])
        .expect("known roles parse");
        assert_eq!(ok.len(), 2);
        assert!(parse_roles(&["not_a_role".to_string()]).is_err());
        // Whitespace is tolerated; an empty/garbage entry is not.
        assert!(parse_roles(&["  registration_authority  ".to_string()]).is_ok());
        assert!(parse_roles(&["".to_string()]).is_err());
        // Privilege ceiling (AC-6): a real but non-NPE role is rejected, so a CAA
        // cannot mint a legacy CA super-role through the portal.
        assert!(
            parse_roles(&["ra_staff".to_string()]).is_err(),
            "legacy roles must be outside the CAA's assignable ceiling"
        );
    }

    /// A bulk CSR entry that is not a valid PKCS#10 request is rejected (and, in
    /// the handler, recorded as a per-item failure rather than aborting the
    /// batch). Covers the guard logic in `validate_csr_entry`.
    #[test]
    fn validate_csr_entry_rejects_non_csr() {
        // Arbitrary bytes are not DER CSR.
        assert!(validate_csr_entry(b"this is not a csr").is_err());
        assert!(validate_csr_entry(b"").is_err());
        // A PEM block with the wrong label must be rejected before parsing.
        let cert_pem = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &[0x30, 0x03, 0x02, 0x01, 0x00],
        )
        .unwrap();
        let err = validate_csr_entry(cert_pem.as_bytes()).unwrap_err();
        assert!(err.contains("unexpected PEM label"), "got: {err}");
    }

    /// The raw-identifier field `r#override` must (de)serialize under the key
    /// "override" so `POST .../approve?override=true` is actually honored. serde
    /// strips the `r#` prefix; this guards against that ever silently changing
    /// (which would disable the override path while still appearing to work).
    #[test]
    fn approve_query_override_uses_unprefixed_key() {
        let on: ApproveQuery = serde_json::from_str(r#"{"override": true}"#).unwrap();
        assert!(on.r#override, "?override=true must deserialize to true");
        let absent: ApproveQuery = serde_json::from_str("{}").unwrap();
        assert!(!absent.r#override, "absent override must default to false");
    }

    #[test]
    fn test_describe_signature_algorithm_known() {
        assert_eq!(
            describe_signature_algorithm("1.2.840.10045.4.3.3"),
            ("ECDSA-SHA384".to_string(), "EC".to_string())
        );
        assert_eq!(
            describe_signature_algorithm("1.2.840.113549.1.1.11"),
            ("RSA-SHA256".to_string(), "RSA".to_string())
        );
        assert_eq!(
            describe_signature_algorithm("2.16.840.1.101.3.4.3.18"),
            ("ML-DSA-65".to_string(), "ML-DSA".to_string())
        );
    }

    #[test]
    fn test_describe_signature_algorithm_unknown_degrades() {
        // Unknown OIDs are returned verbatim with an "unknown" key type rather
        // than failing the info endpoint.
        let (alg, key) = describe_signature_algorithm("9.9.9.9");
        assert_eq!(alg, "9.9.9.9");
        assert_eq!(key, "unknown");
    }

    #[test]
    fn test_der_to_pem_roundtrip() {
        let der = b"hello world certificate bytes";
        let pem = der_to_pem(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        // The base64 body must decode back to the original DER.
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(BASE64_STANDARD.decode(body).unwrap(), der);
    }

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
