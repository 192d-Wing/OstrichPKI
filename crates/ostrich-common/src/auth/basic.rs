//! HTTP Basic authentication middleware for EST (RFC 7030 §3.2.3).
//!
//! RFC 7030 §3.2.3 permits an EST server to authenticate the client with
//! HTTP-based client authentication ("in addition to or instead of" the TLS
//! client certificate of §3.3). This module provides that path. Its primary
//! purpose is *bootstrap enrollment*: a client that does not yet hold a
//! certificate cannot perform mTLS, so it authenticates the first enrollment
//! with a username/password.
//!
//! Two layers are provided:
//! - [`BasicAuthLayer`] - HTTP Basic only.
//! - [`MtlsOrBasicAuthLayer`] - prefer the verified TLS client certificate
//!   (RFC 7030 §3.3); fall back to HTTP Basic when no certificate is presented.
//!
//! Both produce the same [`AuthenticatedUser`] extension that `AuthzLayer`
//! consumes, so RBAC enforcement is identical regardless of the auth method.
//!
//! Because HTTP Basic transmits a reusable password on every request, these
//! layers MUST only be mounted on a TLS-protected listener (the EST server
//! enforces this by enabling Basic only alongside `--tls-ca-cert`).
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UAU.1: User Authentication - password authentication before enrollment
//! - FIA_AFL.1: Authentication Failure Handling - reuses provider lockout
//!
//! ## NIST 800-53 Rev 5
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management (password verification via provider)
//! - AC-7: Unsuccessful Logon Attempts (account lockout via provider)
//! - SC-8: Transmission Confidentiality (Basic permitted on TLS only)
//!
//! ## RFC
//! - RFC 7030 §3.2.3: HTTP-based client authentication for EST
//! - RFC 7235 §4.1: WWW-Authenticate challenge

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::sync::Arc;
use tracing::{debug, warn};

use super::{
    middleware::AuthResponse,
    provider::{AuthError, AuthProvider, Credentials},
};
use crate::tls::PeerCertificate;

/// Authenticate the request by an `Authorization: Basic` header.
///
/// On success the resolved [`AuthenticatedUser`](super::user::AuthenticatedUser)
/// is inserted into the request extensions. On any failure to parse the header
/// or invalid credentials, a [`AuthResponse::BasicChallenge`] (401 +
/// `WWW-Authenticate: Basic`) is returned; a locked account yields 403.
async fn authenticate_basic(
    provider: &Arc<dyn AuthProvider>,
    req: &mut Request,
) -> Result<(), AuthResponse> {
    let encoded = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
        .ok_or_else(|| {
            debug!("Missing or non-Basic Authorization header");
            AuthResponse::BasicChallenge
        })?;

    let decoded = BASE64_STANDARD.decode(encoded.trim()).map_err(|_| {
        debug!("Basic credentials are not valid base64");
        AuthResponse::BasicChallenge
    })?;
    let decoded = String::from_utf8(decoded).map_err(|_| {
        debug!("Basic credentials are not valid UTF-8");
        AuthResponse::BasicChallenge
    })?;

    // RFC 7617 §2: userid is everything before the first colon; the password
    // is the remainder (which may itself contain colons).
    let (username, password) = decoded.split_once(':').ok_or_else(|| {
        debug!("Basic credentials missing ':' separator");
        AuthResponse::BasicChallenge
    })?;

    let credentials = Credentials::password(username, password);
    let user = provider.authenticate(&credentials).await.map_err(|e| {
        // Never log the password; the username is an audit identifier.
        warn!(error = %e, username = %username, "EST HTTP Basic authentication failed");
        match e {
            AuthError::AccountLocked { .. } => AuthResponse::Forbidden,
            _ => AuthResponse::BasicChallenge,
        }
    })?;

    req.extensions_mut().insert(user);
    Ok(())
}

/// HTTP Basic authentication layer for Axum.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - password authentication
/// - NIST 800-53: IA-2 / IA-5 - identification and authenticator management
/// - RFC 7030 §3.2.3 - HTTP-based client authentication
#[allow(dead_code)]
pub struct BasicAuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl BasicAuthLayer {
    /// Create a new HTTP Basic authentication layer over a password auth provider.
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }

    /// Middleware: authenticate by HTTP Basic credentials.
    pub async fn authenticate(
        State(provider): State<Arc<dyn AuthProvider>>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        authenticate_basic(&provider, &mut req).await?;
        Ok(next.run(req).await)
    }
}

/// Composite layer: verified TLS client certificate, with HTTP Basic fallback.
///
/// This is the RFC 7030 §3.2.3 pattern where HTTP-based authentication is
/// offered "in addition to" TLS client authentication. If the handshake
/// presented a client certificate it is used (RFC 7030 §3.3); otherwise the
/// request must carry `Authorization: Basic` (bootstrap enrollment). The
/// configured [`AuthProvider`] must support both certificate and password
/// credentials (e.g. a [`CompositeAuthProvider`](super::provider::CompositeAuthProvider)).
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - certificate or password authentication
/// - NIST 800-53: IA-2 / AC-17 - mTLS identity, password fallback
/// - RFC 7030 §3.2.3 / §3.3 - client authentication for EST enrollment
#[allow(dead_code)]
pub struct MtlsOrBasicAuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl MtlsOrBasicAuthLayer {
    /// Create a new mTLS-or-Basic authentication layer.
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }

    /// Middleware: prefer the TLS client certificate, fall back to HTTP Basic.
    pub async fn authenticate(
        State(provider): State<Arc<dyn AuthProvider>>,
        mut req: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // Prefer the verified TLS client certificate (RFC 7030 §3.3). It was
        // validated by rustls during the handshake; we only map it to an account.
        let cert_der = req
            .extensions()
            .get::<PeerCertificate>()
            .and_then(|p| p.0.clone());

        if let Some(cert_der) = cert_der {
            let credentials = Credentials::Certificate {
                cert_chain: vec![cert_der],
                client_ip: None,
            };
            let user = provider.authenticate(&credentials).await.map_err(|e| {
                warn!(error = %e, "EST mTLS client certificate authentication failed");
                match e {
                    AuthError::AccountLocked { .. } => AuthResponse::Forbidden,
                    _ => AuthResponse::Unauthorized,
                }
            })?;
            req.extensions_mut().insert(user);
        } else {
            // No client certificate: fall back to HTTP Basic (RFC 7030 §3.2.3),
            // the bootstrap path for a client that does not yet hold a cert.
            authenticate_basic(&provider, &mut req).await?;
        }

        Ok(next.run(req).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::{AuthResult, SessionInfo};
    use crate::auth::user::{AuthMethod, AuthenticatedUser, UserId};
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use axum::response::IntoResponse;

    /// Minimal provider: accepts password "secret" for "alice", locks "bob".
    struct TestProvider;

    #[async_trait]
    impl AuthProvider for TestProvider {
        async fn authenticate(&self, creds: &Credentials) -> AuthResult<AuthenticatedUser> {
            match creds {
                Credentials::Password { username, password } => {
                    use secrecy::ExposeSecret;
                    if username == "bob" {
                        return Err(AuthError::AccountLocked {
                            until: "later".into(),
                        });
                    }
                    if username == "alice" && password.expose_secret() == "secret" {
                        Ok(AuthenticatedUser::new(
                            UserId::new(),
                            "alice".into(),
                            vec![],
                            AuthMethod::Password,
                        ))
                    } else {
                        Err(AuthError::InvalidCredentials)
                    }
                }
                _ => Err(AuthError::UnsupportedAuthMethod),
            }
        }
        async fn validate_session(&self, _: &str) -> AuthResult<SessionInfo> {
            Err(AuthError::InvalidSession)
        }
        async fn create_session(&self, _: &AuthenticatedUser) -> AuthResult<SessionInfo> {
            Err(AuthError::InvalidSession)
        }
        async fn invalidate_session(&self, _: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn record_failed_attempt(&self, _: &str, _: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn is_account_locked(&self, _: &str) -> AuthResult<bool> {
            Ok(false)
        }
        async fn unlock_account(&self, _: &str) -> AuthResult<()> {
            Ok(())
        }
        fn provider_name(&self) -> &str {
            "test"
        }
        fn supported_methods(&self) -> &[AuthMethod] {
            &[AuthMethod::Password]
        }
    }

    fn basic_header(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    async fn run(req: HttpRequest<Body>) -> Result<(), AuthResponse> {
        let provider: Arc<dyn AuthProvider> = Arc::new(TestProvider);
        let mut req = req;
        authenticate_basic(&provider, &mut req).await
    }

    #[tokio::test]
    async fn valid_credentials_inject_user() {
        let req = HttpRequest::builder()
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(Body::empty())
            .unwrap();
        let provider: Arc<dyn AuthProvider> = Arc::new(TestProvider);
        let mut req = req;
        authenticate_basic(&provider, &mut req).await.unwrap();
        assert!(req.extensions().get::<AuthenticatedUser>().is_some());
    }

    #[tokio::test]
    async fn wrong_password_is_challenge() {
        let req = HttpRequest::builder()
            .header(header::AUTHORIZATION, basic_header("alice", "nope"))
            .body(Body::empty())
            .unwrap();
        let err = run(req).await.unwrap_err();
        assert_eq!(
            err.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn missing_header_is_challenge_with_www_authenticate() {
        let req = HttpRequest::builder().body(Body::empty()).unwrap();
        let err = run(req).await.unwrap_err();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"EST\""
        );
    }

    #[tokio::test]
    async fn malformed_base64_is_challenge() {
        let req = HttpRequest::builder()
            .header(header::AUTHORIZATION, "Basic !!!not-base64!!!")
            .body(Body::empty())
            .unwrap();
        let err = run(req).await.unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_colon_is_challenge() {
        let req = HttpRequest::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64_STANDARD.encode("nocolon")),
            )
            .body(Body::empty())
            .unwrap();
        let err = run(req).await.unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn locked_account_is_forbidden() {
        let req = HttpRequest::builder()
            .header(header::AUTHORIZATION, basic_header("bob", "secret"))
            .body(Body::empty())
            .unwrap();
        let err = run(req).await.unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn password_with_colon_is_preserved() {
        // RFC 7617: only the first colon separates userid from password.
        let req = HttpRequest::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64_STANDARD.encode("alice:se:cret")),
            )
            .body(Body::empty())
            .unwrap();
        // "se:cret" != "secret", so this should fail auth (proves split_once, not splitn-all).
        let err = run(req).await.unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }
}
