//! Axum Middleware for Authentication and Authorization
//!
//! Provides HTTP middleware for protecting REST API endpoints with
//! authentication and role-based access control.
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UAU.1: User Authentication - enforce authentication before access
//! - FMT_MTD.1: TSF Data Management - access control for management functions
//! - FMT_SMR.2: Security Management Roles - role-based authorization
//!
//! ## NIST 800-53 Rev 5
//! - AC-3: Access Enforcement - enforce authorized access
//! - IA-2: Identification and Authentication - verify user identity
//! - AU-2: Auditable Events - log authorization decisions
//!
//! # Usage
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use ostrich_common::auth::middleware::{AuthLayer, RequirePermission};
//! use ostrich_common::auth::Permission;
//!
//! let app = Router::new()
//!     .route("/api/certificates", get(list_certificates))
//!     .layer(RequirePermission::new(Permission::ViewCertificate))
//!     .layer(AuthLayer::new(auth_provider, rbac_policy));
//! ```

use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, warn};

use super::{
    permissions::Permission,
    provider::{AuthError, AuthProvider, Credentials},
    rbac::RbacPolicy,
    user::AuthenticatedUser,
};
use crate::tls::PeerCertificate;

/// Authentication layer for Axum
///
/// Extracts authentication token from request and validates it.
/// Injects AuthenticatedUser into request extensions on success.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - Authentication before TSF-mediated actions
/// - NIST 800-53: IA-2 - Identification and authentication
#[allow(dead_code)]
pub struct AuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl AuthLayer {
    /// Create new authentication layer
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }

    /// Middleware function for authentication
    pub async fn authenticate(
        State(provider): State<Arc<dyn AuthProvider>>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // Extract token from Authorization header
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| {
                debug!("Missing or invalid Authorization header");
                AuthResponse::Unauthorized
            })?;

        // Validate session token
        let session_info = provider.validate_session(token).await.map_err(|e| {
            warn!(error = %e, "Session validation failed");
            match e {
                AuthError::SessionExpired => AuthResponse::SessionExpired,
                AuthError::InvalidSession => AuthResponse::Unauthorized,
                _ => AuthResponse::Unauthorized,
            }
        })?;

        // Insert authenticated user into request extensions
        req.extensions_mut().insert(session_info.user);

        // Continue to next middleware/handler
        Ok(next.run(req).await)
    }
}

/// mTLS authentication layer for Axum.
///
/// Authenticates the request by the verified TLS *client certificate* (surfaced
/// by [`crate::tls::serve`] as a [`PeerCertificate`] extension) rather than a
/// bearer token. The certificate's subject is mapped to an account by the
/// configured certificate [`AuthProvider`]; on success the resulting
/// [`AuthenticatedUser`] is injected into the request extensions, so the same
/// `AuthzLayer` permission checks apply. A request without a client certificate
/// is rejected (RFC 7030 §3.3 requires mTLS for EST).
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - certificate-based authentication
/// - NIST 800-53: IA-2 / AC-17 - identification via mTLS client certificate
/// - RFC 7030 §3.3 / RFC 9325 - TLS client authentication
#[allow(dead_code)]
pub struct MtlsAuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl MtlsAuthLayer {
    /// Create a new mTLS authentication layer over a certificate auth provider.
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }

    /// Middleware: authenticate by the verified TLS client certificate.
    pub async fn authenticate(
        State(provider): State<Arc<dyn AuthProvider>>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // The certificate was verified by rustls (WebPkiClientVerifier) during
        // the handshake; here we only map its identity to an account.
        let cert_der = req
            .extensions()
            .get::<PeerCertificate>()
            .and_then(|p| p.0.clone())
            .ok_or_else(|| {
                debug!("mTLS required but no client certificate was presented");
                AuthResponse::Unauthorized
            })?;

        let credentials = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: None,
        };
        let user = provider.authenticate(&credentials).await.map_err(|e| {
            warn!(error = %e, "mTLS client certificate authentication failed");
            match e {
                AuthError::AccountLocked { .. } => AuthResponse::Forbidden,
                _ => AuthResponse::Unauthorized,
            }
        })?;

        req.extensions_mut().insert(user);
        Ok(next.run(req).await)
    }
}

/// Composite layer: verified TLS client certificate, with a **bearer-token**
/// fallback. The bootstrap counterpart to [`super::basic::MtlsOrBasicAuthLayer`]
/// for deployments that bootstrap with a single-use bearer enrollment token
/// rather than HTTP Basic.
///
/// If the handshake presented a client certificate it is used (RFC 7030 §3.3,
/// e.g. re-enrollment by the existing cert); otherwise the request must carry
/// `Authorization: Bearer <token>`, validated via the provider's session path
/// (e.g. an enrollment token or operator session). This lets a single EST port
/// serve certificate-less token bootstrap *and* mTLS re-enrollment, paired with
/// an optional-client-auth TLS listener ([`crate::tls::TlsSettings::with_optional_client_auth`]).
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - certificate or bearer-token authentication
/// - NIST 800-53: IA-2 / AC-17 - mTLS identity, bearer fallback
/// - RFC 7030 §3.3 - TLS client authentication for EST
#[allow(dead_code)]
pub struct MtlsOrBearerAuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl MtlsOrBearerAuthLayer {
    /// Create a new mTLS-or-bearer authentication layer.
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }

    /// Middleware: prefer the TLS client certificate, fall back to a bearer token.
    pub async fn authenticate(
        State(provider): State<Arc<dyn AuthProvider>>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        let cert_der = req
            .extensions()
            .get::<PeerCertificate>()
            .and_then(|p| p.0.clone());

        if let Some(cert_der) = cert_der {
            // Verified TLS client certificate (RFC 7030 §3.3) — map to an account.
            let credentials = Credentials::Certificate {
                cert_chain: vec![cert_der],
                client_ip: None,
            };
            let user = provider.authenticate(&credentials).await.map_err(|e| {
                warn!(error = %e, "mTLS client certificate authentication failed");
                match e {
                    AuthError::AccountLocked { .. } => AuthResponse::Forbidden,
                    _ => AuthResponse::Unauthorized,
                }
            })?;
            req.extensions_mut().insert(user);
        } else {
            // No client certificate: fall back to a bearer token (bootstrap).
            let token = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "))
                .ok_or_else(|| {
                    debug!("No client certificate and no Bearer token presented");
                    AuthResponse::Unauthorized
                })?;
            let session_info = provider.validate_session(token).await.map_err(|e| {
                warn!(error = %e, "Bearer token validation failed");
                match e {
                    AuthError::SessionExpired => AuthResponse::SessionExpired,
                    _ => AuthResponse::Unauthorized,
                }
            })?;
            req.extensions_mut().insert(session_info.user);
        }

        Ok(next.run(req).await)
    }
}

/// Header carrying the proxied user's identity (Common Name / username).
pub const HEADER_NPE_USER: &str = "x-npe-user";
/// Header carrying the proxied user's full RFC 4514 subject DN.
pub const HEADER_NPE_SUBJECT: &str = "x-npe-subject";
/// Header carrying the proxied user's comma-separated role names.
pub const HEADER_NPE_ROLES: &str = "x-npe-roles";
/// Header carrying the originating portal session id (audit correlation).
pub const HEADER_NPE_SESSION: &str = "x-npe-session-id";

/// Configuration for the trusted-proxy authentication path.
///
/// `allowed_subjects` are the RFC 4514 subject DNs of the reverse proxy's client
/// certificate(s) (e.g. the NPE portal's service certificate). The trusted-proxy
/// path is taken ONLY when the verified TLS peer certificate's subject is in this
/// set; an empty set disables the path entirely (fail closed).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 (access enforcement), SC-8/AC-17 (mTLS-gated trust)
/// - NIAP PP-CA: FIA_UAU.1 / FTP_ITC.1
#[derive(Debug, Clone, Default)]
pub struct TrustedProxyConfig {
    /// RFC 4514 subject DNs of trusted proxy client certificates.
    pub allowed_subjects: Vec<String>,
}

impl TrustedProxyConfig {
    /// Build from a list of trusted subject DNs.
    pub fn new(allowed_subjects: Vec<String>) -> Self {
        Self { allowed_subjects }
    }

    /// Whether a verified peer-certificate subject DN is a trusted proxy.
    pub fn is_trusted_subject(&self, subject_dn: &str) -> bool {
        self.allowed_subjects.iter().any(|s| s == subject_dn)
    }

    /// Whether the trusted-proxy path is enabled at all.
    pub fn is_enabled(&self) -> bool {
        !self.allowed_subjects.is_empty()
    }
}

/// Parse the RFC 4514 subject DN from a DER end-entity certificate, matching the
/// rendering used by [`super::mtls`] so configured `allowed_subjects` compare
/// verbatim.
fn peer_cert_subject(cert_der: &[u8]) -> Option<String> {
    use x509_cert::der::Decode;
    x509_cert::Certificate::from_der(cert_der)
        .ok()
        .map(|c| c.tbs_certificate.subject.to_string())
}

/// Build a synthetic [`AuthenticatedUser`] from the trusted-proxy identity
/// headers. Returns `None` if the mandatory user header is missing/empty.
fn build_trusted_proxy_user(headers: &header::HeaderMap) -> Option<AuthenticatedUser> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let username = get(HEADER_NPE_USER).map(str::trim).filter(|s| !s.is_empty())?;
    // The subject DN defaults to the username when not supplied (own-scope id is
    // derived from it, so a stable value is required).
    let subject = get(HEADER_NPE_SUBJECT)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(username);
    let roles: Vec<super::roles::Role> = get(HEADER_NPE_ROLES)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(super::roles::Role::from_name)
        .collect();

    Some(AuthenticatedUser::from_trusted_proxy(subject, username, roles))
}

/// Composite layer: a verified, allow-listed reverse-proxy client certificate
/// authenticates the request using the proxy's asserted `X-Npe-*` identity
/// headers; otherwise the request falls back to bearer-token authentication.
///
/// This lets one CA/EST listener serve both the NPE portal (mTLS + forwarded
/// identity) and the admin console / direct API (bearer token) without a second
/// port. The trust gate is strict: the header identity is honoured ONLY when the
/// TLS handshake presented a certificate whose subject is in
/// [`TrustedProxyConfig::allowed_subjects`]. A trusted proxy that omits the
/// identity headers is rejected (it must not silently fall through to bearer).
///
/// Pair with an optional-client-auth TLS listener
/// ([`crate::tls::TlsSettings::with_optional_client_auth`]) so bearer clients
/// that present no certificate still complete the handshake.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: IA-2 / AC-3 / AC-17 - mTLS-gated proxied identity, bearer fallback
/// - NIAP PP-CA: FIA_UAU.1 / FTP_ITC.1
#[allow(dead_code)]
pub struct TrustedProxyAuthLayer;

impl TrustedProxyAuthLayer {
    /// Middleware: trusted-proxy identity if the peer cert is an allow-listed
    /// proxy, otherwise bearer-token authentication.
    pub async fn authenticate(
        State((provider, config)): State<(Arc<dyn AuthProvider>, Arc<TrustedProxyConfig>)>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // Trusted-proxy path: only when a verified peer certificate is present
        // AND its subject is an allow-listed proxy.
        if config.is_enabled()
            && let Some(cert_der) = req
                .extensions()
                .get::<PeerCertificate>()
                .and_then(|p| p.0.clone())
            && let Some(subject) = peer_cert_subject(&cert_der)
            && config.is_trusted_subject(&subject)
        {
            // The proxy is trusted; its asserted identity headers are required.
            let user = build_trusted_proxy_user(req.headers()).ok_or_else(|| {
                warn!(
                    proxy_subject = %subject,
                    "trusted proxy presented no {HEADER_NPE_USER} identity header"
                );
                AuthResponse::Unauthorized
            })?;
            debug!(
                user = %user.username,
                proxy_subject = %subject,
                "authenticated via trusted-proxy identity bridge"
            );
            req.extensions_mut().insert(user);
            return Ok(next.run(req).await);
        }

        // Bearer fallback (admin console / direct API).
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| {
                debug!("No trusted-proxy identity and no Bearer token presented");
                AuthResponse::Unauthorized
            })?;
        let session_info = provider.validate_session(token).await.map_err(|e| {
            warn!(error = %e, "Session validation failed");
            match e {
                AuthError::SessionExpired => AuthResponse::SessionExpired,
                _ => AuthResponse::Unauthorized,
            }
        })?;
        req.extensions_mut().insert(session_info.user);
        Ok(next.run(req).await)
    }
}

/// Authorization layer for Axum
///
/// Checks if authenticated user has required permission.
/// Must be used after AuthLayer.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_MTD.1 - Access control for TSF data
/// - NIAP PP-CA: FMT_SMR.2 - Role-based authorization
/// - NIST 800-53: AC-3 - Access enforcement
#[allow(dead_code)]
pub struct AuthzLayer {
    policy: Arc<RbacPolicy>,
    permission: Permission,
    resource_type: Option<String>,
}

impl AuthzLayer {
    /// Create new authorization layer
    ///
    /// # Arguments
    /// * `policy` - RBAC policy for authorization checks
    /// * `permission` - Required permission for this endpoint
    /// * `resource_type` - Optional resource type for audit logging
    pub fn new(
        policy: Arc<RbacPolicy>,
        permission: Permission,
        resource_type: Option<String>,
    ) -> Self {
        Self {
            policy,
            permission,
            resource_type,
        }
    }

    /// Middleware function for authorization
    pub async fn authorize(
        State((policy, permission, resource_type)): State<(
            Arc<RbacPolicy>,
            Permission,
            Option<String>,
        )>,
        req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // Extract authenticated user from request extensions
        let user = req
            .extensions()
            .get::<AuthenticatedUser>()
            .ok_or_else(|| {
                warn!("AuthenticatedUser not found in request extensions - AuthLayer missing?");
                AuthResponse::Unauthorized
            })?
            .clone();

        // Check authorization
        let resource = resource_type.as_deref().unwrap_or("resource");
        policy.authorize(&user, permission, resource).map_err(|e| {
            warn!(
                username = %user.username,
                permission = ?permission,
                error = %e,
                "Authorization denied"
            );
            AuthResponse::Forbidden
        })?;

        // Continue to next middleware/handler
        Ok(next.run(req).await)
    }
}

/// Convenience extractor for authenticated user
///
/// Use this in handler functions to access the authenticated user.
///
/// # Example
///
/// ```rust,ignore
/// async fn my_handler(
///     AuthUser(user): AuthUser,
/// ) -> impl IntoResponse {
///     format!("Hello, {}!", user.username)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser(pub AuthenticatedUser);

impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthResponse;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .map(AuthUser)
            .ok_or(AuthResponse::Unauthorized)
    }
}

/// Authentication/Authorization error responses
///
/// Converts authorization errors into HTTP responses.
#[derive(Debug)]
pub enum AuthResponse {
    /// 401 Unauthorized - Missing or invalid credentials
    Unauthorized,
    /// 403 Forbidden - Valid credentials but insufficient permissions
    Forbidden,
    /// 401 Unauthorized - Session expired
    SessionExpired,
    /// 401 Unauthorized with an HTTP Basic challenge.
    ///
    /// Emits `WWW-Authenticate: Basic` (RFC 7235 §4.1) so EST clients
    /// (RFC 7030 §3.2.3) know to retry with `Authorization: Basic`.
    BasicChallenge,
}

impl IntoResponse for AuthResponse {
    fn into_response(self) -> Response {
        // The Basic challenge needs an extra WWW-Authenticate header.
        if let AuthResponse::BasicChallenge = self {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"EST\"")
                .body(Body::from("Unauthorized"))
                .unwrap();
        }

        let (status, message) = match self {
            AuthResponse::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthResponse::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            AuthResponse::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired"),
            AuthResponse::BasicChallenge => unreachable!("handled above"),
        };

        let body = Body::from(message);
        Response::builder().status(status).body(body).unwrap()
    }
}

/// Helper macro to require permission for a route
///
/// # Example
///
/// ```rust,ignore
/// Router::new()
///     .route("/api/certificates", get(issue_cert))
///     .layer(require_permission!(Permission::IssueCertificate, "certificate"))
///     .layer(auth_layer())
/// ```
#[macro_export]
macro_rules! require_permission {
    ($permission:expr) => {
        $crate::auth::middleware::AuthzLayer::new(policy.clone(), $permission, None)
    };
    ($permission:expr, $resource:expr) => {
        $crate::auth::middleware::AuthzLayer::new(
            policy.clone(),
            $permission,
            Some($resource.to_string()),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{roles::Role, user::UserId};

    #[test]
    fn test_auth_response_status_codes() {
        use axum::http::StatusCode;

        let resp = AuthResponse::Unauthorized.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = AuthResponse::Forbidden.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = AuthResponse::SessionExpired.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_trusted_proxy_user_id_is_deterministic_per_subject() {
        let a = AuthenticatedUser::from_trusted_proxy(
            "CN=DOE.JOHN.A.123,O=U.S. Government,C=US",
            "DOE.JOHN.A.123",
            vec![Role::PkiSponsor],
        );
        let b = AuthenticatedUser::from_trusted_proxy(
            "CN=DOE.JOHN.A.123,O=U.S. Government,C=US",
            "DOE.JOHN.A.123",
            vec![Role::PkiSponsor],
        );
        // Same subject -> same id (own-scope stability across requests).
        assert_eq!(a.id, b.id);
        assert_eq!(a.certificate_subject.as_deref(), Some("CN=DOE.JOHN.A.123,O=U.S. Government,C=US"));

        // Different subject -> different id.
        let c = AuthenticatedUser::from_trusted_proxy("CN=OTHER", "OTHER", vec![]);
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn test_trusted_proxy_config_gate() {
        let cfg = TrustedProxyConfig::new(vec!["CN=npe-portal,O=Ostrich".to_string()]);
        assert!(cfg.is_enabled());
        assert!(cfg.is_trusted_subject("CN=npe-portal,O=Ostrich"));
        assert!(!cfg.is_trusted_subject("CN=attacker"));

        // Empty config disables the path (fail closed).
        let off = TrustedProxyConfig::default();
        assert!(!off.is_enabled());
        assert!(!off.is_trusted_subject("CN=npe-portal,O=Ostrich"));
    }

    #[test]
    fn test_build_trusted_proxy_user_from_headers() {
        let mut headers = header::HeaderMap::new();
        headers.insert(HEADER_NPE_USER, "DOE.JOHN.A.123".parse().unwrap());
        headers.insert(HEADER_NPE_SUBJECT, "CN=DOE.JOHN.A.123".parse().unwrap());
        headers.insert(
            HEADER_NPE_ROLES,
            "pki_sponsor,bogus_role,registration_authority".parse().unwrap(),
        );

        let user = build_trusted_proxy_user(&headers).expect("user");
        assert_eq!(user.username, "DOE.JOHN.A.123");
        // Known roles parsed; unknown role names silently dropped.
        assert!(user.has_role(Role::PkiSponsor));
        assert!(user.has_role(Role::RegistrationAuthority));
        assert_eq!(user.roles.len(), 2);

        // Missing the mandatory user header -> None.
        assert!(build_trusted_proxy_user(&header::HeaderMap::new()).is_none());
    }

    #[test]
    fn test_auth_user_from_authenticated_user() {
        let user = AuthenticatedUser::new(
            UserId::new(),
            "testuser".to_string(),
            vec![Role::OperationsStaff],
            crate::auth::user::AuthMethod::Password,
        );

        let auth_user = AuthUser(user.clone());
        assert_eq!(auth_user.0.username, "testuser");
        assert!(auth_user.0.has_role(Role::OperationsStaff));
    }
}
