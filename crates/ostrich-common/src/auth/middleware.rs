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
}

impl IntoResponse for AuthResponse {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthResponse::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthResponse::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            AuthResponse::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired"),
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
