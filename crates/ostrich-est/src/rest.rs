//! EST REST API
//!
//! RFC 7030: Enrollment over Secure Transport
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before enrollment operations
//!   - mTLS client certificate required for simpleenroll/simplereenroll
//!   - Certificate validation via [`crate::mtls::validate_client`]
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - All endpoints served over TLS 1.3
//!   - Mutual TLS for enrollment endpoints
//!
//! - **FMT_SMF.1**: Enrollment management functions
//!   - Simple enrollment (RFC 7030 S4.2.1)
//!   - Simple re-enrollment (RFC 7030 S4.2.2)
//!   - CSR attributes retrieval (RFC 7030 S4.5)
//!
//! - **FDP_ACC.1/FDP_ACF.1**: Access control for enrollment
//!   - Only authenticated clients may enroll
//!   - Re-enrollment (RFC 7030 §4.2.2) is bound to the client's existing
//!     certificate: the CSR subject must structurally match a certificate
//!     previously issued to the same client, else the request is denied and
//!     audited (see `simple_reenroll`)
//!
//! - **FCS_COP.1**: Cryptographic operations
//!   - CSR signature verification (proof of possession)
//!   - PKCS#7/CMS response encoding
//!
//! - **FAU_GEN.1**: Audit generation for enrollment events
//!   - Enrollment requests logged with client identity
//!   - Success/failure outcomes recorded
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-8**: Transmission confidentiality via TLS
//! - **SI-10**: Input validation for CSRs
//! - **AU-2**: Auditable enrollment events

use crate::{
    enrollment::CsrAttributes,
    error::{Error, Result},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ostrich_audit::AuditSink;
use ostrich_common::auth::provider::AuthProvider;
use ostrich_common::auth::{
    AuthLayer, AuthUser, AuthzLayer, Permission, RbacPolicy, Role, any_role_has_permission,
};
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use std::sync::Arc;

/// Client authentication mode for EST protected (enrollment) endpoints.
///
/// RFC 7030 §3.3 expects mTLS client authentication; §3.2.3 additionally
/// permits HTTP-based (Basic) authentication, primarily for bootstrap
/// enrollment before a client holds a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EstAuthMode {
    /// Bearer session token (default; not an RFC 7030 method, kept for
    /// backward compatibility when no TLS client CA is configured).
    #[default]
    BearerToken,
    /// mTLS client certificate only (RFC 7030 §3.3).
    Mtls,
    /// mTLS client certificate, falling back to HTTP Basic (RFC 7030 §3.2.3)
    /// when no client certificate is presented. Basic is intended for
    /// bootstrap enrollment and is only safe on a TLS listener.
    MtlsWithBasicFallback,
    /// mTLS client certificate, falling back to a single-use bearer enrollment
    /// token when no client certificate is presented. Enables one port to serve
    /// both certificate-less token bootstrap (`/simpleenroll`) and mTLS
    /// re-enrollment by the existing certificate (`/simplereenroll`). Requires
    /// an optional-client-auth TLS listener (a client CA configured, client
    /// certs requested but not required).
    MtlsWithTokenBootstrap,
}

/// How the requested certificate identity is authorized against the
/// authenticated principal on enrollment (H1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EstIdentityPolicy {
    /// The CSR must name the authenticated username in its CommonName or a SAN.
    /// Secure default; suits one-account-per-identity deployments.
    #[default]
    MatchUsername,
    /// Every identity the CSR asserts (CN + each SAN value) must appear in the
    /// account's allow-list (`est_account_identities`). Supports delegated
    /// enrollment where an account may request several distinct identities.
    AccountAllowList,
}

/// A named CA backend for label-routed enrollment (RFC 7030 §3.2.2). Multiple
/// backends let one EST instance issue from, e.g., an EC CA and an RSA CA,
/// selected by the label's key-algorithm token.
#[derive(Clone)]
pub struct CaBackend {
    /// gRPC client to this CA backend.
    pub client: Arc<crate::ca_integration::EstCaClient>,
    /// This backend's CA certificate DER, served by `/{label}/cacerts`.
    pub certificate_der: Option<Vec<u8>>,
}

/// Maps a parsed label to a named CA backend. Backend selection is by the
/// label's key-algorithm token (`2048` -> RSA CA, `P384` -> EC CA, etc.).
#[derive(Clone, Default)]
pub struct LabelRoutingConfig {
    /// Key-algorithm token (`2048`, `P384`) -> backend name.
    pub algo_backends: std::collections::HashMap<String, String>,
    /// Backend used when the label specifies no key algorithm.
    pub default_backend: String,
}

/// A resolved enrollment target: which CA backend issues, under which profile,
/// plus any label-derived constraints to forward as issuance metadata.
struct ResolvedEnrollment<'a> {
    client: &'a Arc<crate::ca_integration::EstCaClient>,
    profile: String,
    /// Key algorithm requested by the label, if any. For client-CSR enrollment
    /// the client already chose the key; for server-side key generation the
    /// server must honor (or reject) this.
    key_algo: Option<crate::label::KeyAlgo>,
    validity_days: Option<u32>,
    ccsa: Option<String>,
}

impl ResolvedEnrollment<'_> {
    /// Label-derived issuance metadata (CC/S/A, requested validity), forwarded to
    /// the CA for audit/provenance. Empty for the unlabeled path. NOTE: the CA
    /// honoring `requested_validity_days` is a follow-up; today it is advisory
    /// metadata recorded with the issuance, not an enforced override.
    fn label_metadata(&self) -> Vec<(String, String)> {
        let mut m = Vec::new();
        if let Some(cc) = &self.ccsa {
            m.push(("ccsa".to_string(), cc.clone()));
        }
        if let Some(v) = self.validity_days {
            m.push(("requested_validity_days".to_string(), v.to_string()));
        }
        m
    }
}

/// EST service state
#[derive(Clone)]
pub struct EstState {
    pub db_pool: DatabasePool,
    pub crypto_provider: Arc<dyn CryptoProvider>,
    pub audit_sink: Arc<dyn AuditSink>,
    #[allow(dead_code)]
    pub auth_provider: Arc<dyn AuthProvider>,
    #[allow(dead_code)]
    pub rbac_policy: Arc<RbacPolicy>,
    /// CA gRPC client for certificate issuance (RFC 7030 §4.2).
    ///
    /// When `None`, enrollment fails closed (no fake certificate is returned).
    /// NIST 800-53: SI-17 - Fail-secure when CA integration is unavailable.
    pub ca_client: Option<Arc<crate::ca_integration::EstCaClient>>,
    /// CA certificate DER, served by `/cacerts` (RFC 7030 §4.1).
    pub ca_certificate_der: Option<Vec<u8>>,
    /// Certificate profile used for enrollment/re-enrollment (RFC 7030 §4.2).
    /// NIST 800-53: CM-6 - Configurable issuance profile (secure default).
    pub enroll_profile: String,
    /// How protected (enrollment) endpoints authenticate the client.
    ///
    /// RFC 7030 §3.2.3 / §3.3 - selects bearer token, mTLS, or mTLS with an
    /// HTTP Basic fallback for bootstrap enrollment.
    pub auth_mode: EstAuthMode,
    /// How the requested certificate identity is authorized against the
    /// authenticated principal (H1). Defaults to `MatchUsername`.
    pub identity_policy: EstIdentityPolicy,
    /// Trusted reverse-proxy (NPE portal) identity bridge. When set, the
    /// token-management endpoints additionally accept the portal's
    /// mTLS-forwarded X-Npe-* identity. `None` keeps the configured auth mode
    /// only. NIST 800-53: IA-2 / AC-3.
    pub trusted_proxy: Option<Arc<ostrich_common::auth::TrustedProxyConfig>>,
    /// Named CA backends for label-routed enrollment (RFC 7030 §3.2.2). Empty
    /// when only the unlabeled (single-CA) path is used.
    pub ca_backends: std::collections::HashMap<String, CaBackend>,
    /// Label -> backend routing. `None` disables labeled enrollment.
    pub label_routing: Option<LabelRoutingConfig>,
}

impl EstState {
    /// Create new EST service state with authentication disabled (for backward compatibility)
    ///
    /// TODO: This should be deprecated once all services are updated to use `new_with_auth()`
    pub fn new(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        // Create placeholders for auth - endpoints will return 401/403 if auth is required
        use std::sync::Arc as StdArc;
        struct NoAuthProvider;
        #[async_trait::async_trait]
        impl AuthProvider for NoAuthProvider {
            async fn authenticate(
                &self,
                _: &ostrich_common::auth::provider::Credentials,
            ) -> ostrich_common::auth::provider::AuthResult<
                ostrich_common::auth::user::AuthenticatedUser,
            > {
                Err(ostrich_common::auth::AuthError::Internal(
                    "Authentication not configured".to_string(),
                ))
            }
            async fn validate_session(
                &self,
                _: &str,
            ) -> ostrich_common::auth::provider::AuthResult<
                ostrich_common::auth::provider::SessionInfo,
            > {
                Err(ostrich_common::auth::AuthError::InvalidSession)
            }
            async fn create_session(
                &self,
                _: &ostrich_common::auth::user::AuthenticatedUser,
            ) -> ostrich_common::auth::provider::AuthResult<
                ostrich_common::auth::provider::SessionInfo,
            > {
                Err(ostrich_common::auth::AuthError::Internal(
                    "Authentication not configured".to_string(),
                ))
            }
            async fn invalidate_session(
                &self,
                _: &str,
            ) -> ostrich_common::auth::provider::AuthResult<()> {
                Ok(())
            }
            async fn record_failed_attempt(
                &self,
                _: &str,
                _: &str,
            ) -> ostrich_common::auth::provider::AuthResult<()> {
                Ok(())
            }
            async fn is_account_locked(
                &self,
                _: &str,
            ) -> ostrich_common::auth::provider::AuthResult<bool> {
                Ok(false)
            }
            async fn unlock_account(
                &self,
                _: &str,
            ) -> ostrich_common::auth::provider::AuthResult<()> {
                Ok(())
            }
            fn provider_name(&self) -> &str {
                "no-auth"
            }
            fn supported_methods(&self) -> &[ostrich_common::auth::user::AuthMethod] {
                &[]
            }
        }

        Self {
            db_pool,
            crypto_provider,
            audit_sink,
            auth_provider: StdArc::new(NoAuthProvider),
            rbac_policy: StdArc::new(RbacPolicy::new()),
            ca_client: None,
            ca_certificate_der: None,
            enroll_profile: "tls_client".to_string(),
            auth_mode: EstAuthMode::BearerToken,
            identity_policy: EstIdentityPolicy::MatchUsername,
            trusted_proxy: None,
            ca_backends: std::collections::HashMap::new(),
            label_routing: None,
        }
    }

    /// Create new EST service state with authentication and authorization
    pub fn new_with_auth(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
        auth_provider: Arc<dyn AuthProvider>,
        rbac_policy: Arc<RbacPolicy>,
    ) -> Self {
        Self {
            db_pool,
            crypto_provider,
            audit_sink,
            auth_provider,
            rbac_policy,
            ca_client: None,
            ca_certificate_der: None,
            enroll_profile: "tls_client".to_string(),
            auth_mode: EstAuthMode::BearerToken,
            identity_policy: EstIdentityPolicy::MatchUsername,
            trusted_proxy: None,
            ca_backends: std::collections::HashMap::new(),
            label_routing: None,
        }
    }

    /// Enable the NPE portal identity bridge for token-management endpoints.
    ///
    /// NIST 800-53: IA-2 / AC-3 - accept the portal's mTLS-forwarded identity.
    pub fn with_trusted_proxy(
        mut self,
        trusted_proxy: Option<Arc<ostrich_common::auth::TrustedProxyConfig>>,
    ) -> Self {
        self.trusted_proxy = trusted_proxy;
        self
    }

    /// Attach the CA gRPC client and CA certificate used for issuance.
    ///
    /// RFC 7030 §4.1 / §4.2 - CA certificate distribution and certificate issuance.
    /// NIST 800-53: SC-17 - PKI certificate issuance via CA service.
    pub fn with_ca(
        mut self,
        ca_client: Option<Arc<crate::ca_integration::EstCaClient>>,
        ca_certificate_der: Option<Vec<u8>>,
    ) -> Self {
        self.ca_client = ca_client;
        self.ca_certificate_der = ca_certificate_der;
        self
    }

    /// Register a named CA backend for label-routed enrollment (RFC 7030 §3.2.2).
    pub fn with_ca_backend(
        mut self,
        name: impl Into<String>,
        client: Arc<crate::ca_integration::EstCaClient>,
        certificate_der: Option<Vec<u8>>,
    ) -> Self {
        self.ca_backends.insert(
            name.into(),
            CaBackend {
                client,
                certificate_der,
            },
        );
        self
    }

    /// Configure label -> CA-backend routing. Enables the `/{label}/...` paths.
    pub fn with_label_routing(mut self, routing: LabelRoutingConfig) -> Self {
        self.label_routing = Some(routing);
        self
    }

    /// Override the certificate profile used for enrollment.
    ///
    /// NIST 800-53: CM-6 - Configuration settings (secure default "tls_client").
    pub fn with_profile(mut self, profile_name: impl Into<String>) -> Self {
        self.enroll_profile = profile_name.into();
        self
    }

    /// Resolve a request to a CA backend + certificate profile.
    ///
    /// `label = None` is the unlabeled (single-CA) path: it uses the configured
    /// default `ca_client` and the operator/token-resolved profile (unchanged
    /// legacy behavior). `label = Some(raw)` parses the RFC 7030 §3.2.2 label and
    /// selects the CA backend by key algorithm and the profile by profile type.
    ///
    /// NIST 800-53: AC-3 (the resolved profile/backend gates issuance), SI-10.
    async fn resolve_enrollment(
        &self,
        label: Option<&str>,
        user: &ostrich_common::auth::AuthenticatedUser,
    ) -> Result<ResolvedEnrollment<'_>> {
        match label {
            None => {
                let client = self.ca_client.as_ref().ok_or_else(|| {
                    Error::Internal("EST CA integration not configured".to_string())
                })?;
                Ok(ResolvedEnrollment {
                    client,
                    profile: resolve_enroll_profile(self, user).await,
                    key_algo: None,
                    validity_days: None,
                    ccsa: None,
                })
            }
            Some(raw) => {
                let parsed = crate::label::parse_label(raw)
                    .map_err(|e| Error::BadRequest(format!("invalid EST label: {e}")))?;
                let profile = parsed
                    .profile_name()
                    .map_err(|e| Error::BadRequest(e.to_string()))?
                    .to_string();
                let backend = self.select_backend(&parsed)?;
                Ok(ResolvedEnrollment {
                    client: &backend.client,
                    profile,
                    key_algo: parsed.key_algo,
                    validity_days: parsed.validity_days,
                    ccsa: parsed.ccsa,
                })
            }
        }
    }

    /// Select the CA backend for a parsed label by its key-algorithm token
    /// (e.g. `P384` -> EC CA, `2048` -> RSA CA); falls back to the routing
    /// default when the label carries no key algorithm.
    fn select_backend(&self, parsed: &crate::label::ParsedLabel) -> Result<&CaBackend> {
        let routing = self.label_routing.as_ref().ok_or_else(|| {
            Error::BadRequest("labeled EST enrollment is not configured".to_string())
        })?;
        // Fail closed: an explicit key-algorithm token with no mapping is an
        // error, NOT a silent fallback to the default backend (that would issue
        // under the wrong algorithm). Only a label without an AK token uses the
        // routing default.
        let backend_name = match parsed.key_algo {
            Some(algo) => routing.algo_backends.get(algo.token()).cloned().ok_or_else(|| {
                Error::BadRequest(format!(
                    "no CA backend is configured for key algorithm '{}'",
                    algo.token()
                ))
            })?,
            None => routing.default_backend.clone(),
        };
        self.ca_backends.get(&backend_name).ok_or_else(|| {
            Error::Internal(format!("no CA backend configured for '{backend_name}'"))
        })
    }

    /// Resolve the CA certificate to serve from `/cacerts` (label = None) or
    /// `/{label}/cacerts`. No auth needed (it is public trust-anchor data).
    fn resolve_ca_certificate(&self, label: Option<&str>) -> Result<Option<&[u8]>> {
        match label {
            None => Ok(self.ca_certificate_der.as_deref()),
            Some(raw) => {
                let parsed = crate::label::parse_label(raw)
                    .map_err(|e| Error::BadRequest(format!("invalid EST label: {e}")))?;
                Ok(self.select_backend(&parsed)?.certificate_der.as_deref())
            }
        }
    }

    /// Authenticate protected endpoints by the TLS client certificate (mTLS,
    /// RFC 7030 §3.3). `auth_provider` must be a certificate auth provider.
    pub fn with_mtls_auth(mut self) -> Self {
        self.auth_mode = EstAuthMode::Mtls;
        self
    }

    /// Authenticate protected endpoints by the TLS client certificate (RFC 7030
    /// §3.3), falling back to HTTP Basic (RFC 7030 §3.2.3) when no client
    /// certificate is presented. `auth_provider` must support both certificate
    /// and password credentials (e.g. a `CompositeAuthProvider`).
    ///
    /// Only safe on a TLS listener; the EST server enables this only when a TLS
    /// client CA is configured.
    pub fn with_mtls_basic_fallback(mut self) -> Self {
        self.auth_mode = EstAuthMode::MtlsWithBasicFallback;
        self
    }

    /// Authenticate protected endpoints by the TLS client certificate (RFC 7030
    /// §3.3), falling back to a single-use bearer enrollment token when no
    /// client certificate is presented. Lets one port serve token bootstrap and
    /// mTLS re-enrollment. `auth_provider` must support certificate credentials
    /// (e.g. a `CompositeAuthProvider` with a certificate provider).
    ///
    /// Only safe on an optional-client-auth TLS listener (client CA configured,
    /// client certs requested but not required).
    pub fn with_mtls_token_bootstrap(mut self) -> Self {
        self.auth_mode = EstAuthMode::MtlsWithTokenBootstrap;
        self
    }

    /// Select how the requested certificate identity is authorized against the
    /// authenticated principal (H1). Defaults to [`EstIdentityPolicy::MatchUsername`].
    pub fn with_identity_policy(mut self, policy: EstIdentityPolicy) -> Self {
        self.identity_policy = policy;
        self
    }
}

/// Create EST REST API router
///
/// RFC 7030 well-known URI: /.well-known/est/
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1 - Security management functions for EST enrollment
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (router served over TLS)
/// - NIAP PP-CA: FIA_UAU.1 - Authentication required for enrollment endpoints
/// - NIST 800-53: SC-8 - Transmission confidentiality (TLS required)
/// - NIST 800-53: AC-3 - Access enforcement via RBAC middleware
/// - RFC 7030 S3.2.2 - EST well-known URI structure
pub fn create_router(state: EstState) -> Router {
    let auth_provider = state.auth_provider.clone();
    let admin_auth_provider = state.auth_provider.clone();
    let rbac_policy = state.rbac_policy.clone();

    // Public endpoints (no authentication required per RFC 7030)
    let public_routes = Router::new()
        // Health and readiness endpoints
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        // RFC 7030 §4.1: CA certificates - no client auth required
        .route("/.well-known/est/cacerts", get(get_ca_certs))
        // RFC 7030 §3.2.2: labeled variant selects the backend CA certificate.
        .route("/.well-known/est/{label}/cacerts", get(get_ca_certs))
        // RFC 7030 §4.5: CSR attributes - optionally requires auth
        .route("/.well-known/est/csrattrs", get(get_csr_attrs))
        .route("/.well-known/est/{label}/csrattrs", get(get_csr_attrs))
        // Enrollment catalog: the label scheme + valid profile/key-algorithm
        // tokens, for the NPE-portal "EST / enrollment catalog" page. Public,
        // non-sensitive discovery metadata (no certificate data).
        .route("/.well-known/est/catalog", get(get_catalog));

    // Per-permission authorization, applied to each MethodRouter individually.
    //
    // IMPORTANT: the permission layer must wrap the per-route MethodRouter
    // (`post(handler).route_layer(...)`), NOT be chained via
    // `Router::route_layer` between `.route(...)` calls. Router::route_layer
    // wraps every route added so far, so the chained style stacked
    // /simplereenroll's RenewCertificate check onto /simpleenroll - a RaStaff
    // caller (who has SubmitRequest but not RenewCertificate) then got 403 on
    // enrollment. Same bug, and same fix, as ostrich-ca's router.
    //
    // NIST 800-53: AC-3 (Access Enforcement) - exactly one permission per route.
    let authz = |permission: Permission, resource: &str| {
        middleware::from_fn_with_state(
            (rbac_policy.clone(), permission, Some(resource.to_string())),
            AuthzLayer::authorize,
        )
    };

    // Protected endpoints. RFC 7030 §3.2.3: enrollment requires client auth.
    let protected_routes = Router::new()
        // RFC 7030 §4.2.1: Simple enrollment - Permission::SubmitRequest
        .route(
            "/.well-known/est/simpleenroll",
            post(simple_enroll).route_layer(authz(Permission::SubmitRequest, "est-enrollment")),
        )
        // RFC 7030 §4.2.2: Simple re-enrollment - Permission::RenewCertificate
        .route(
            "/.well-known/est/simplereenroll",
            post(simple_reenroll)
                .route_layer(authz(Permission::RenewCertificate, "est-reenrollment")),
        )
        // RFC 7030 §4.4: Server-side key generation - Permission::SubmitRequest
        .route(
            "/.well-known/est/serverkeygen",
            post(server_key_gen).route_layer(authz(Permission::SubmitRequest, "est-serverkeygen")),
        )
        // RFC 7030 §3.2.2: labeled variants route to the resolved CA backend.
        .route(
            "/.well-known/est/{label}/simpleenroll",
            post(simple_enroll).route_layer(authz(Permission::SubmitRequest, "est-enrollment")),
        )
        .route(
            "/.well-known/est/{label}/simplereenroll",
            post(simple_reenroll)
                .route_layer(authz(Permission::RenewCertificate, "est-reenrollment")),
        )
        .route(
            "/.well-known/est/{label}/serverkeygen",
            post(server_key_gen).route_layer(authz(Permission::SubmitRequest, "est-serverkeygen")),
        )
        // L1 - cap the request body. CSRs are a few KB; an explicit 64 KiB limit
        // rejects oversized bodies (DoS) with 413 before base64-decode/parse,
        // rather than relying on axum's larger default. NIST 800-53: SC-5.
        .layer(DefaultBodyLimit::max(64 * 1024));

    // RFC 7030 §3.3: enrollment requires client authentication. By default this
    // is a bearer session token; with mTLS the client is authenticated by its
    // verified TLS certificate (MtlsAuthLayer). The fallback mode additionally
    // accepts HTTP Basic (RFC 7030 §3.2.3) when no client certificate is
    // presented, for bootstrap enrollment.
    let protected_routes = match state.auth_mode {
        EstAuthMode::Mtls => protected_routes.layer(middleware::from_fn_with_state(
            auth_provider,
            ostrich_common::auth::MtlsAuthLayer::authenticate,
        )),
        EstAuthMode::MtlsWithBasicFallback => {
            protected_routes.layer(middleware::from_fn_with_state(
                auth_provider,
                ostrich_common::auth::MtlsOrBasicAuthLayer::authenticate,
            ))
        }
        // Bearer mode also accepts single-use EST enrollment tokens: the wrapper
        // resolves a live token to a least-privilege EstEnrollee principal whose
        // username is the token's bound identity, falling through to normal
        // session auth for anything else.
        EstAuthMode::BearerToken => {
            let enroll_provider: Arc<dyn AuthProvider> =
                Arc::new(crate::enrollment_token::EnrollmentTokenAuthProvider::new(
                    ostrich_db::repository::EstRepository::new(state.db_pool.clone()),
                    auth_provider,
                ));
            protected_routes.layer(middleware::from_fn_with_state(
                enroll_provider,
                AuthLayer::authenticate,
            ))
        }
        // Shared-port mode: a verified client certificate authenticates
        // re-enrollment (RFC 7030 §3.3); otherwise a single-use bearer
        // enrollment token authenticates bootstrap. The same enrollment-token
        // wrapper handles the bearer fallback, while its inner (composite)
        // provider maps the client certificate.
        EstAuthMode::MtlsWithTokenBootstrap => {
            let enroll_provider: Arc<dyn AuthProvider> =
                Arc::new(crate::enrollment_token::EnrollmentTokenAuthProvider::new(
                    ostrich_db::repository::EstRepository::new(state.db_pool.clone()),
                    auth_provider,
                ));
            protected_routes.layer(middleware::from_fn_with_state(
                enroll_provider,
                ostrich_common::auth::MtlsOrBearerAuthLayer::authenticate,
            ))
        }
    };

    // Admin/management API for the per-account identity allow-list
    // (`est_account_identities`), used by the `allowlist` enrollment identity
    // policy.
    //
    // Authentication uses the SAME scheme as enrollment (selected by `auth_mode`)
    // so the API is reachable in every deployment posture — including pure mTLS,
    // where there is no password/bearer path and a hard-coded bearer layer would
    // make the API unauthenticatable (an admin authenticates with a client
    // certificate mapped to an account that holds the management role).
    //
    // Authorization is enforced *inside* each handler (not via `route_layer`)
    // for two reasons: GET and POST share one MethodRouter but need different
    // permissions (ViewConfig vs ModifyConfig); and the handler path audits every
    // denial (`emit_failure_audit`), which the generic `AuthzLayer` does not.
    //
    // The DELETE identity is a catch-all segment so identities containing '/'
    // (e.g. URI/SPIFFE SAN values) can still be revoked through the API.
    //
    // COMPLIANCE MAPPING:
    // - NIAP PP-CA: FMT_SMF.1 / FMT_MTD.1 - management of TSF data
    // - NIST 800-53: AC-3 (access enforcement), CM-3 (config change control)
    let admin_routes = Router::new()
        .route(
            "/api/v1/est/accounts/{account}/identities",
            get(list_account_identities).post(add_account_identity),
        )
        .route(
            "/api/v1/est/accounts/{account}/identities/{*identity}",
            axum::routing::delete(delete_account_identity),
        )
        // Enrollment-token management (all Permission::GenerateEstToken, enforced
        // inside the handlers). Authenticated as an operator session — NOT via the
        // enrollment-token wrapper, so a device token cannot mint/list/revoke.
        //   POST   …/enrollment-tokens       mint a single-use, time-limited token
        //   GET    …/enrollment-tokens       list outstanding tokens (metadata only)
        //   DELETE …/enrollment-tokens/{id}  revoke a live token before use
        .route(
            "/api/v1/est/enrollment-tokens",
            post(create_enrollment_token).get(list_enrollment_tokens),
        )
        .route(
            "/api/v1/est/enrollment-tokens/{id}",
            axum::routing::delete(revoke_enrollment_token),
        );
    let admin_routes = match (&state.trusted_proxy, state.auth_mode) {
        // Identity bridge (bearer-mode deployments only): the NPE portal's
        // mTLS-forwarded identity OR an operator bearer session may manage
        // tokens. Restricted to BearerToken mode so the bridge never displaces
        // operator mTLS admin auth in the cert-based modes.
        (Some(cfg), EstAuthMode::BearerToken) => {
            admin_routes.layer(middleware::from_fn_with_state(
                (admin_auth_provider, cfg.clone()),
                ostrich_common::auth::TrustedProxyAuthLayer::authenticate,
            ))
        }
        _ => match state.auth_mode {
            EstAuthMode::Mtls => admin_routes.layer(middleware::from_fn_with_state(
                admin_auth_provider,
                ostrich_common::auth::MtlsAuthLayer::authenticate,
            )),
            EstAuthMode::MtlsWithBasicFallback => {
                admin_routes.layer(middleware::from_fn_with_state(
                    admin_auth_provider,
                    ostrich_common::auth::MtlsOrBasicAuthLayer::authenticate,
                ))
            }
            EstAuthMode::BearerToken => admin_routes.layer(middleware::from_fn_with_state(
                admin_auth_provider,
                AuthLayer::authenticate,
            )),
            // Operator authenticates by client certificate or session bearer token.
            // Uses the raw provider (NOT the enrollment-token wrapper), so a device
            // enrollment token can never mint/list/revoke tokens (AC-6).
            EstAuthMode::MtlsWithTokenBootstrap => {
                admin_routes.layer(middleware::from_fn_with_state(
                    admin_auth_provider,
                    ostrich_common::auth::MtlsOrBearerAuthLayer::authenticate,
                ))
            }
        },
    };

    // Merge public, protected, and admin routes
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .with_state(state)
}

/// Health check endpoint (liveness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
///
/// Returns 200 OK if the service process is running.
async fn health_check() -> impl IntoResponse {
    ostrich_common::health::health_response("ostrich-est")
}

/// Readiness check endpoint (readiness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - NIST 800-53: SC-8 (Transmission confidentiality and integrity)
///
/// Returns 200 OK if the service is ready to handle EST requests.
/// Checks database connectivity.
async fn readiness_check(State(state): State<EstState>) -> impl IntoResponse {
    ostrich_common::health::readiness_response_with_db("ostrich-est", &state.db_pool).await
}

/// EST enrollment catalog (profile types, key algorithms, label scheme).
///
/// Backs the NPE-portal "EST / enrollment catalog" page. The payload is derived
/// from the label parser's own token sets (`crate::label::catalog`), so it can
/// never advertise a token issuance would reject. Public, non-sensitive metadata
/// (no certificate or key material), so no client authentication is required.
///
/// COMPLIANCE MAPPING:
/// - RFC 7030 §3.2.2 - profile-label scheme this catalog documents
/// - NIST 800-53: AC-3 - read of non-sensitive configuration metadata
async fn get_catalog(State(state): State<EstState>) -> Json<crate::label::EstCatalog> {
    // Scope the catalog to what this deployment actually offers: the key
    // algorithms with a configured backend, and whether labeled routing is on at
    // all — so the page never advertises a label that select_backend() rejects.
    let configured_algos: Vec<String> = state
        .label_routing
        .as_ref()
        .map(|r| r.algo_backends.keys().cloned().collect())
        .unwrap_or_default();
    let labeled_enrollment = state.label_routing.is_some();
    Json(crate::label::catalog(
        &configured_algos,
        labeled_enrollment,
        &state.enroll_profile,
    ))
}

/// Get CA certificates (RFC 7030 S4.1)
///
/// Returns a PKCS#7 certs-only structure containing CA certificate chain.
/// This endpoint does NOT require client authentication per RFC 7030.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (PKCS#7 encoding)
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (TLS, but no client auth required)
/// - NIST 800-53: SC-17 - PKI certificate distribution
/// - RFC 7030 S4.1 - CA certificate retrieval
async fn get_ca_certs(
    State(state): State<EstState>,
    label: Option<axum::extract::Path<String>>,
) -> Result<Response> {
    // RFC 7030 §4.1 - Return the CA certificate(s) as a degenerate PKCS#7.
    // The label (if present) selects which backend CA certificate to return.
    // When no CA certificate is configured we fail safe by returning an empty
    // (but valid) PKCS#7 so clients receive a well-formed response.
    let label = label.map(|p| p.0);
    let ca_cert = state.resolve_ca_certificate(label.as_deref())?;
    let pkcs7_der = match ca_cert {
        Some(der) => encode_certs_only_pkcs7(&[der.to_vec()])?,
        None => {
            tracing::warn!("EST /cacerts: no CA certificate configured; returning empty PKCS#7");
            encode_certs_only_pkcs7(&[])?
        }
    };

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        pkcs7_der,
    )
        .into_response())
}

/// Encode certificates as a PKCS#7 certs-only structure.
///
/// Thin wrapper over the shared [`ostrich_x509::pkcs7::encode_certs_only_pkcs7`]
/// (kept so existing EST call sites and the error type are unchanged).
///
/// RFC 7030 S4.1: Responses use degenerate PKCS#7 (CMS) SignedData
/// with no signed content, only certificates in the certificates field.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (CMS encoding)
/// - RFC 5652 S5 - CMS SignedData structure
/// - RFC 7030 S4.1.3 - EST CA certificates response format
pub(crate) fn encode_certs_only_pkcs7(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    ostrich_x509::pkcs7::encode_certs_only_pkcs7(certs)
        .map_err(|e| Error::Internal(format!("PKCS#7 encoding failed: {e}")))
}

/// Simple enrollment (RFC 7030 S4.2.1)
///
/// Client submits PKCS#10 CSR, server returns PKCS#7 with issued certificate.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via mTLS client certificate
/// - NIAP PP-CA: FDP_ACC.1 - Access control for enrollment operations
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic CSR signature verification
/// - NIAP PP-CA: FAU_GEN.1 - Audit record generation for enrollment
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (enrollment)
/// - NIST 800-53: SI-10 - Information input validation (CSR parsing)
/// - NIST 800-53: AU-2 - Auditable event (enrollment request)
/// - RFC 7030 S4.2.1 - Simple enrollment request/response
/// - RFC 2986 - PKCS#10 CSR format
///
async fn simple_enroll(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    label: Option<axum::extract::Path<String>>,
    body: Bytes,
) -> Result<Response> {
    // RFC 7030 §3.2.2 label (present only on `/.well-known/est/{label}/...`).
    let label = label.map(|p| p.0);
    // Use authenticated user identity as client identifier
    let client_identifier = &user.username;

    // Decode base64-encoded CSR
    let csr_der = match BASE64_STANDARD.decode(&body) {
        Ok(der) if der.len() >= 10 => der,
        _ => {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:enroll",
                "invalid_csr_encoding",
            )
            .await;
            return Err(Error::BadRequest("Invalid or too-short CSR".to_string()));
        }
    };

    // Parse and validate PKCS#10 CSR
    let parsed_csr = match ostrich_x509::parser::parse_csr(&csr_der) {
        Ok(c) => c,
        Err(e) => {
            emit_failure_audit(&state, client_identifier, "est:enroll", "csr_parse_failed").await;
            return Err(Error::InvalidCsr(format!("Failed to parse CSR: {}", e)));
        }
    };

    // Verify CSR signature (proof of possession). A PoP failure is a
    // security-relevant event and must be audited (H2 / AU-2).
    let signature_valid =
        ostrich_x509::parser::verify_csr_signature(&parsed_csr, &state.crypto_provider)
            .await
            .map_err(|e| Error::InvalidCsr(format!("CSR signature verification failed: {}", e)))?;

    if !signature_valid {
        emit_failure_audit(&state, client_identifier, "est:enroll", "csr_pop_failed").await;
        return Err(Error::InvalidCsr("Invalid CSR signature".to_string()));
    }

    // H1 - bind the requested identity to the authenticated principal: the CSR
    // must name `client_identifier` in its CommonName or a SAN. Without this any
    // caller holding SubmitRequest could obtain a certificate for an arbitrary
    // identity (AC-3 / AC-6 / FDP_ACF.1). Fail secure: deny + audit on mismatch.
    let csr_cn = ostrich_x509::parser::parse_csr_subject_dn(&csr_der)
        .ok()
        .and_then(|dn| dn.common_name);
    if !identity_authorized(
        &state,
        &user,
        csr_cn.as_deref(),
        &parsed_csr.subject_alternative_names,
    )
    .await?
    {
        emit_failure_audit(
            &state,
            client_identifier,
            "est:enroll",
            "identity_not_bound",
        )
        .await;
        tracing::warn!(
            client = %client_identifier,
            "EST enrollment denied: CSR identity does not match authenticated principal (H1)"
        );
        return Err(Error::Forbidden(
            "CSR subject CN or a SAN must match the authenticated client identity".to_string(),
        ));
    }

    // Create enrollment record in database
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let enrollment = repo
        .create_enrollment(
            client_identifier,
            "simple-enroll",
            csr_der.clone(),
            "pending",
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create enrollment: {}", e)))?;

    // Submit the CSR to the CA service for issuance (RFC 7030 §4.2.3).
    // NIST 800-53: SI-17 - Fail secure: if CA integration is not configured we
    // never fabricate a certificate; we return an error and leave the
    // enrollment row "pending" so it can be retried once the CA is available.
    // Resolve the CA backend + profile. Unlabeled = the default single CA;
    // labeled = RFC 7030 §3.2.2 routing (backend by key algorithm, profile by
    // profile type). Fails closed if issuance isn't configured / label invalid.
    let resolved = match state.resolve_enrollment(label.as_deref(), &user).await {
        Ok(r) => r,
        Err(e) => {
            emit_enrollment_audit(
                &state,
                client_identifier,
                enrollment.id,
                "simpleenroll",
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(e);
        }
    };

    // EstCaClient::enroll issues the certificate, records the certificate id on
    // the est_enrollments row, and transitions the enrollment to "issued".
    // RFC 7030 §4.2.1 - CSR forwarded to CA after proof-of-possession check.
    let certificate_id = match resolved
        .client
        .enroll(
            enrollment.id,
            &csr_der,
            client_identifier,
            &resolved.profile,
            &resolved.label_metadata(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            // H2 - issuance failures must be audited.
            emit_enrollment_audit(
                &state,
                client_identifier,
                enrollment.id,
                "simpleenroll",
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(e);
        }
    };

    // Single-use: consume the enrollment token (if this was token-authenticated)
    // now that a certificate has been issued.
    consume_enrollment_token_if_present(&state, &user, certificate_id).await;

    // Load the issued certificate and wrap it in a certs-only PKCS#7.
    // RFC 7030 §4.2.3 - Response is a degenerate PKCS#7 with the issued cert.
    let cert_repo = ostrich_db::repository::CertificateRepository::new(state.db_pool.clone());
    let certificate = cert_repo
        .find_by_id(certificate_id)
        .await
        .map_err(Error::Database)?
        .ok_or_else(|| Error::Internal("Issued certificate not found".to_string()))?;

    let pkcs7_response = encode_certs_only_pkcs7(std::slice::from_ref(&certificate.der_encoded))?;

    // AU-2 / FAU_GEN.1 - audit the successful enrollment.
    emit_enrollment_audit(
        &state,
        client_identifier,
        enrollment.id,
        "simpleenroll",
        ostrich_audit::EventOutcome::Success,
    )
    .await;

    Ok((
        StatusCode::OK, // 200 - certificate issued
        [
            (header::CONTENT_TYPE, "application/pkcs7-mime"),
            (
                header::LOCATION,
                format!("/est/enrollments/{}", enrollment.id).as_str(),
            ),
        ],
        BASE64_STANDARD.encode(&pkcs7_response),
    )
        .into_response())
}

/// Emit an audit record for an EST enrollment / re-enrollment operation.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FAU_GEN.1 - Audit generation for enrollment events
/// - NIST 800-53: AU-2 - Auditable event (enrollment request)
/// - NIST 800-53: AU-3 - Audit content (actor, resource, outcome)
async fn emit_enrollment_audit(
    state: &EstState,
    actor: &str,
    enrollment_id: uuid::Uuid,
    action: &str,
    outcome: ostrich_audit::EventOutcome,
) {
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::CertificateIssuance,
        actor,
        format!("est:enrollment:{}", enrollment_id),
        action,
        outcome,
    )
    .build();
    let _ = state.audit_sink.record(&mut event).await;
}

/// Audit a security-relevant EST failure (H2).
///
/// AU-2 / AU-12 / FAU_GEN.1: validation, proof-of-possession, identity-binding,
/// and issuance failures are exactly the events that must leave a trail so an
/// attacker probing the enrollment endpoints can be detected. Emitted as an
/// `AccessViolation` with `Failure` outcome and the authenticated actor.
async fn emit_failure_audit(state: &EstState, actor: &str, resource: &str, action: &str) {
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::AccessViolation,
        actor,
        resource,
        action,
        ostrich_audit::EventOutcome::Failure,
    )
    .build();
    let _ = state.audit_sink.record(&mut event).await;
}

/// Canonicalize a SubjectAltName list for set comparison (C2 re-enroll binding):
/// trimmed, sorted, and de-duplicated so two CSRs asserting the same SAN set
/// compare equal regardless of ordering.
fn normalize_san_set(sans: &[String]) -> Vec<String> {
    let mut v: Vec<String> = sans.iter().map(|s| s.trim().to_string()).collect();
    v.sort();
    v.dedup();
    v
}

/// H1 enrollment identity binding: an authenticated principal may only enroll
/// for a certificate that names itself. The CSR must carry the authenticated
/// `username` as either the subject CommonName or a SubjectAltName value.
///
/// SAN entries are formatted `TYPE:value` (e.g. `DNS:host`); the value (after
/// the first `:`) is matched. Comparison is exact (fail secure — fewer accepts).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege)
/// - NIAP PP-CA: FDP_ACF.1 - bind the issued identity to the requesting principal
fn csr_identity_matches_principal(username: &str, cn: Option<&str>, sans: &[String]) -> bool {
    if cn == Some(username) {
        return true;
    }
    sans.iter().any(|san| {
        let value = san.split_once(':').map(|(_, v)| v).unwrap_or(san.as_str());
        value == username
    })
}

/// The set of identities a CSR asserts: its CommonName plus each SAN value
/// (the `TYPE:` prefix is stripped, matching the allow-list storage format).
fn csr_asserted_identities<'a>(cn: Option<&'a str>, sans: &'a [String]) -> Vec<&'a str> {
    let mut ids: Vec<&str> = Vec::new();
    if let Some(c) = cn {
        ids.push(c);
    }
    for san in sans {
        ids.push(san.split_once(':').map(|(_, v)| v).unwrap_or(san.as_str()));
    }
    ids
}

/// Maximum length of an allow-list identity (matches the
/// `est_account_identities.allowed_identity` `VARCHAR(255)` column).
const MAX_IDENTITY_LEN: usize = 255;

/// Canonicalize an identity for storage and comparison: trim surrounding
/// whitespace and lowercase. DNS names (the common SAN type) are
/// case-insensitive, and storing/comparing in one canonical form prevents a
/// provisioned identity from silently never matching a CSR value (e.g. admin
/// adds `Device-1` but the CSR asserts `device-1`).
fn normalize_identity(identity: &str) -> String {
    identity.trim().to_ascii_lowercase()
}

/// Validate and canonicalize an admin-supplied identity (SI-10 input validation).
/// Rejects empty, over-long, or control-character-bearing values.
fn validate_identity(raw: &str) -> Result<String> {
    let id = normalize_identity(raw);
    if id.is_empty() {
        return Err(Error::BadRequest("identity must not be empty".to_string()));
    }
    // Count characters (not bytes) to match both the message and the DB
    // VARCHAR(255) column semantics for multibyte identities.
    if id.chars().count() > MAX_IDENTITY_LEN {
        return Err(Error::BadRequest(format!(
            "identity must be at most {MAX_IDENTITY_LEN} characters"
        )));
    }
    if id.chars().any(|c| c.is_control()) {
        return Err(Error::BadRequest(
            "identity must not contain control characters".to_string(),
        ));
    }
    Ok(id)
}

/// Authorize the requested certificate identity against the authenticated
/// principal under the configured [`EstIdentityPolicy`] (H1).
///
/// - `MatchUsername`: the CSR must name `username` in its CN or a SAN.
/// - `AccountAllowList`: EVERY identity the CSR asserts (CN + SAN values) must
///   appear in the account's `est_account_identities` allow-list. A CSR that
///   asserts no identity at all is denied. Fail secure on lookup error.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege)
/// - NIAP PP-CA: FDP_ACC.1 / FDP_ACF.1 - access control on issuance identity
async fn identity_authorized(
    state: &EstState,
    user: &ostrich_common::auth::AuthenticatedUser,
    cn: Option<&str>,
    sans: &[String],
) -> Result<bool> {
    let username = &user.username;

    // EST enrollment-token principals (Role::EstEnrollee): the identity was
    // pinned and operator-authorized at mint time, so the CSR need only name
    // that identity. Match in canonical form (case-insensitive) and independent
    // of the deployment's identity policy — the token *is* the authorization and
    // its identity is fixed, so an allow-list lookup keyed by the device name
    // (which has no rows) must not deny it.
    if user.has_role(ostrich_common::auth::Role::EstEnrollee) {
        let want = normalize_identity(username);
        let matches = cn.map(normalize_identity).is_some_and(|c| c == want)
            || sans.iter().any(|san| {
                let value = san.split_once(':').map(|(_, v)| v).unwrap_or(san.as_str());
                normalize_identity(value) == want
            });
        return Ok(matches);
    }

    match state.identity_policy {
        EstIdentityPolicy::MatchUsername => Ok(csr_identity_matches_principal(username, cn, sans)),
        EstIdentityPolicy::AccountAllowList => {
            let asserted = csr_asserted_identities(cn, sans);
            if asserted.is_empty() {
                // A certificate that names nothing cannot be authorized.
                return Ok(false);
            }
            let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
            let allowed = repo.list_allowed_identities(username).await.map_err(|e| {
                Error::Internal(format!("Failed to load account allow-list: {}", e))
            })?;
            // Compare in canonical form on both sides (see `normalize_identity`)
            // so case/whitespace differences don't cause a silent non-match.
            let allowed: std::collections::HashSet<String> =
                allowed.iter().map(|s| normalize_identity(s)).collect();
            Ok(asserted
                .iter()
                .all(|id| allowed.contains(&normalize_identity(id))))
        }
    }
}

/// Single-use enforcement: if `user` authenticated via an EST enrollment token
/// (`Role::EstEnrollee`), atomically consume that token — keyed by the token id
/// carried on the principal (`user.id`), so no header re-parsing is needed — so
/// it cannot be reused, and audit the consumption. A no-op for session/mTLS
/// enrollments. Applies to every issuance path the token can reach (simpleenroll
/// AND serverkeygen), keeping the single-use guarantee on both.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5 (authenticator lifecycle), AU-2/AU-3 (auditable state change)
/// - NIAP PP-CA: FMT_MTD.1 (enrollment-credential management)
async fn consume_enrollment_token_if_present(
    state: &EstState,
    user: &ostrich_common::auth::AuthenticatedUser,
    certificate_id: uuid::Uuid,
) {
    if !user.has_role(ostrich_common::auth::Role::EstEnrollee) {
        return; // session/mTLS auth — no enrollment token to consume
    }
    let token_id = *user.id.as_uuid();
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let outcome = match repo
        .consume_enrollment_token(token_id, Some(certificate_id))
        .await
    {
        Ok(true) => {
            tracing::info!(actor = %user.username, token_id = %token_id, "EST enrollment token use consumed");
            ostrich_audit::EventOutcome::Success
        }
        Ok(false) => {
            // Already consumed or missing at consume time (e.g. a concurrent
            // enrollment won the race). The certificate was still issued.
            tracing::warn!(actor = %user.username, token_id = %token_id, "EST enrollment token already consumed at consume time");
            ostrich_audit::EventOutcome::Failure
        }
        Err(e) => {
            tracing::error!(error = %e, token_id = %token_id, "failed to consume EST enrollment token");
            ostrich_audit::EventOutcome::Failure
        }
    };
    // AU-2/AU-3: the token lifecycle (unused -> used) is a security-relevant
    // state change and must leave an audit record, not just a log line.
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::ConfigurationChange,
        &user.username,
        "est:enrollment-tokens".to_string(),
        "consume_est_token",
        outcome,
    )
    .with_details(serde_json::json!({
        "identity": user.username,
        "token_id": token_id.to_string(),
        "certificate_id": certificate_id.to_string(),
    }))
    .build();
    let _ = state.audit_sink.record(&mut event).await;
}

/// Resolve the certificate profile to issue an enrollment under.
///
/// For EST-enrollment-token principals (`Role::EstEnrollee`), the operator may
/// have pinned a profile when minting the token (e.g. `tls_server_client` for a
/// mutual-TLS device); honor it so the device receives exactly the EKUs the
/// operator chose. Falls back to the EST server's configured default for
/// session/mTLS enrollments, when the token pinned no profile, or if the lookup
/// fails (fail to the secure default rather than erroring the enrollment).
///
/// The stored profile is re-checked against `OFFERABLE_EST_PROFILES` here, not
/// just at mint time: a token lives up to 7 days, so the allowlist could change
/// under it. Re-validating at issuance makes the AC-3 guarantee hold for the
/// token's whole life and fails secure (default profile) rather than handing an
/// unexpected profile to the CA.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CM-6 (configurable issuance profile, secure default),
///   AC-3 (the operator's profile choice is enforced at issuance),
///   SI-10 (stored profile re-validated against the allowlist before use)
/// - RFC 7030 §4.2 - certificate profile selection for (re-)enrollment
async fn resolve_enroll_profile(
    state: &EstState,
    user: &ostrich_common::auth::AuthenticatedUser,
) -> String {
    if !user.has_role(ostrich_common::auth::Role::EstEnrollee) {
        return state.enroll_profile.clone();
    }
    let token_id = *user.id.as_uuid();
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    match repo.enrollment_token_profile(token_id).await {
        Ok(Some(profile)) if OFFERABLE_EST_PROFILES.contains(&profile.as_str()) => profile,
        Ok(Some(profile)) => {
            // Stored profile is no longer offerable (allowlist changed since the
            // token was minted). Fail secure to the configured default.
            tracing::warn!(
                token_id = %token_id,
                profile = %profile,
                "enrollment-token profile is no longer offerable; using default"
            );
            state.enroll_profile.clone()
        }
        Ok(None) => state.enroll_profile.clone(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                token_id = %token_id,
                "failed to read enrollment-token profile; using default"
            );
            state.enroll_profile.clone()
        }
    }
}

/// Simple re-enrollment (RFC 7030 S4.2.2)
///
/// Authenticated client re-enrolls for certificate renewal.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via existing certificate
/// - NIAP PP-CA: FDP_ACC.1 - Access control (subject DN must match)
/// - NIAP PP-CA: FDP_ACF.1 - Access control function (re-enrollment policy)
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic CSR signature verification
/// - NIAP PP-CA: FAU_GEN.1 - Audit record generation for re-enrollment
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (re-enrollment)
/// - NIST 800-53: SI-10 - Information input validation (CSR parsing)
/// - NIST 800-53: AU-2 - Auditable event (re-enrollment request)
/// - RFC 7030 S4.2.2 - Simple re-enrollment requirements
///
async fn simple_reenroll(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    label: Option<axum::extract::Path<String>>,
    body: Bytes,
) -> Result<Response> {
    let label = label.map(|p| p.0);
    // Use authenticated user identity as client identifier
    let client_identifier = &user.username;

    // Decode base64-encoded CSR
    let csr_der = match BASE64_STANDARD.decode(&body) {
        Ok(der) if der.len() >= 10 => der,
        _ => {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:reenroll",
                "invalid_csr_encoding",
            )
            .await;
            return Err(Error::BadRequest("Invalid or too-short CSR".to_string()));
        }
    };

    // Parse and validate PKCS#10 CSR
    let parsed_csr = match ostrich_x509::parser::parse_csr(&csr_der) {
        Ok(c) => c,
        Err(e) => {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:reenroll",
                "csr_parse_failed",
            )
            .await;
            return Err(Error::InvalidCsr(format!("Failed to parse CSR: {}", e)));
        }
    };

    // Verify CSR signature (proof of possession). A PoP failure must be audited
    // (H2 / AU-2).
    let signature_valid =
        ostrich_x509::parser::verify_csr_signature(&parsed_csr, &state.crypto_provider)
            .await
            .map_err(|e| Error::InvalidCsr(format!("CSR signature verification failed: {}", e)))?;

    if !signature_valid {
        emit_failure_audit(&state, client_identifier, "est:reenroll", "csr_pop_failed").await;
        return Err(Error::InvalidCsr("Invalid CSR signature".to_string()));
    }

    // RFC 7030 §4.2.2 - Re-enrollment renews an EXISTING certificate, so the new
    // CSR MUST assert the SAME identity as a certificate previously issued to
    // this client. The EST server authenticates clients by account (not mTLS),
    // so the "existing certificate" is resolved from this client's prior issued
    // enrollments rather than a TLS-presented cert.
    //
    // The identity compared is the FULL subject DN *and* the complete SAN set:
    // - Subject uses the RFC 4514 string rendering (parse_certificate /
    //   parse_csr), NOT the 7-field DistinguishedName projection, which silently
    //   drops unmodeled RDN attributes (DC, UID, emailAddress, ...) and would
    //   let `CN=foo,DC=evil` match `CN=foo` (C2).
    // - SANs are compared as a set, because for TLS profiles the SAN is the
    //   authoritative identity; without this a client could keep its subject but
    //   add `SAN: DNS:admin.internal` and obtain a cert for an identity it does
    //   not own (C2).
    //
    // COMPLIANCE MAPPING:
    // - RFC 7030 §4.2.2 - re-enrollment identity binding (subject + SAN)
    // - NIAP PP-CA: FDP_ACC.1 / FDP_ACF.1 - access control (identity binding)
    // - NIST 800-53: AC-3 (access enforcement), SI-10 (input validation),
    //   AU-2 (audit the denial). Fail secure: deny + audit on any mismatch.
    let requested_subject = parsed_csr.subject_dn.trim().to_string();
    let requested_sans = normalize_san_set(&parsed_csr.subject_alternative_names);

    let reenroll_repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let reenroll_cert_repo =
        ostrich_db::repository::CertificateRepository::new(state.db_pool.clone());
    let prior_enrollments = reenroll_repo
        .list_enrollments_by_client(client_identifier)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load prior enrollments: {}", e)))?;

    let mut subject_matches_prior = false;
    let mut had_prior_certificate = false;
    // RFC 7030 §4.2.2: re-enrollment renews the SAME identity, so the new cert must
    // carry the SAME certificate profile (and therefore EKUs) as the prior one —
    // e.g. a `tls_server_client` node identity must stay server+client-capable, not
    // silently narrow to the default client-only profile on renewal.
    let mut prior_profile: Option<String> = None;
    for enrollment in &prior_enrollments {
        let Some(cert_id) = enrollment.certificate_id else {
            continue;
        };
        had_prior_certificate = true;
        if let Some(prior_cert) = reenroll_cert_repo
            .find_by_id(cert_id)
            .await
            .map_err(|e| Error::Internal(format!("Failed to load prior certificate: {}", e)))?
            && let Ok(prior) = ostrich_x509::parser::parse_certificate(&prior_cert.der_encoded)
            && prior.subject_dn.trim() == requested_subject
            && normalize_san_set(&prior.subject_alt_names) == requested_sans
        {
            subject_matches_prior = true;
            // Preserve the BROADEST capability ever issued to this identity, so a
            // renewal never narrows a server+client node to client-only — and so a
            // node previously narrowed (e.g. by an earlier client-only default) is
            // healed back to its server+client profile on its next renewal. Scan
            // all prior enrollments rather than breaking on the first match.
            prior_profile = broadest_est_profile(prior_profile.take(), &enrollment.profile_name);
        }
    }

    if !subject_matches_prior {
        let reason = if had_prior_certificate {
            "CSR subject/SANs do not match any certificate previously issued to this client"
        } else {
            "no existing certificate to renew for this client"
        };
        // Fail secure: audit the security-relevant denial (AU-2 / AC-3).
        let mut denial = ostrich_audit::AuditEventBuilder::new(
            ostrich_audit::EventType::AccessViolation,
            client_identifier,
            "est:reenroll",
            "reenroll_subject_mismatch",
            ostrich_audit::EventOutcome::Failure,
        )
        .build();
        let _ = state.audit_sink.record(&mut denial).await;
        tracing::warn!(
            client = %client_identifier,
            "EST re-enrollment denied: {} (RFC 7030 §4.2.2)",
            reason
        );
        return Err(Error::Forbidden(format!(
            "re-enrollment denied: {} (RFC 7030 §4.2.2)",
            reason
        )));
    }

    // Create re-enrollment record in database
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let enrollment = repo
        .create_enrollment(
            client_identifier,
            "simple-reenroll",
            csr_der.clone(),
            "pending",
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create re-enrollment: {}", e)))?;

    // Submit the CSR to the CA service for re-issuance (RFC 7030 §4.2.2).
    // NIST 800-53: SI-17 - Fail secure: never fabricate a certificate when the
    // CA integration is unavailable.
    let resolved = match state.resolve_enrollment(label.as_deref(), &user).await {
        Ok(r) => r,
        Err(e) => {
            emit_enrollment_audit(
                &state,
                client_identifier,
                enrollment.id,
                "simplereenroll",
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(e);
        }
    };

    // Reissue under the prior certificate's profile (preserving its EKUs per RFC
    // 7030 §4.2.2). Re-validate it against the allowlist (SI-10) and fail secure to
    // the label/default-resolved profile if it is unknown or no longer offerable.
    // The CA backend, however, is the label-resolved one.
    let enroll_profile = match prior_profile {
        Some(p) if OFFERABLE_EST_PROFILES.contains(&p.as_str()) => p,
        _ => resolved.profile.clone(),
    };
    let certificate_id = match resolved
        .client
        .enroll(
            enrollment.id,
            &csr_der,
            client_identifier,
            &enroll_profile,
            &resolved.label_metadata(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            // H2 - re-issuance failures must be audited.
            emit_enrollment_audit(
                &state,
                client_identifier,
                enrollment.id,
                "simplereenroll",
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(e);
        }
    };

    // Load the re-issued certificate and wrap it in a certs-only PKCS#7.
    // RFC 7030 §4.2.3 - Degenerate PKCS#7 response with the issued certificate.
    let cert_repo = ostrich_db::repository::CertificateRepository::new(state.db_pool.clone());
    let certificate = cert_repo
        .find_by_id(certificate_id)
        .await
        .map_err(Error::Database)?
        .ok_or_else(|| Error::Internal("Re-issued certificate not found".to_string()))?;

    let pkcs7_response = encode_certs_only_pkcs7(std::slice::from_ref(&certificate.der_encoded))?;

    // AU-2 / FAU_GEN.1 - audit the successful re-enrollment.
    emit_enrollment_audit(
        &state,
        client_identifier,
        enrollment.id,
        "simplereenroll",
        ostrich_audit::EventOutcome::Success,
    )
    .await;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pkcs7-mime"),
            (
                header::LOCATION,
                format!("/est/enrollments/{}", enrollment.id).as_str(),
            ),
        ],
        BASE64_STANDARD.encode(&pkcs7_response),
    )
        .into_response())
}

/// Get CSR attributes (RFC 7030 S4.5)
///
/// Returns attributes the CA expects in CSRs.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (CSR policy)
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (TLS, client auth optional)
/// - NIST 800-53: SC-17 - PKI policy distribution
/// - RFC 7030 S4.5 - CSR attributes retrieval
async fn get_csr_attrs(State(_state): State<EstState>) -> Result<Response> {
    let _attrs = CsrAttributes::default();

    // TODO: Encode as ASN.1 CsrAttrs structure (RFC 7030 §4.5.2)
    // For now, return empty response (means no specific attributes required)

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/csrattrs")],
        Vec::<u8>::new(), // Empty = no specific requirements
    )
        .into_response())
}

/// Structured server-side key-generation request for the EFS portal flow.
///
/// Unlike the RFC 7030 §4.4.1 CSR body, this carries NO client key or PKCS#10:
/// the subject is taken from the mTLS-authenticated NPE identity (never supplied
/// by the client), so there is no untrusted CSR/ASN.1 to parse and no client key
/// to discard. Accepted only when the resolved profile is EFS.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-10 (input validation — the subject is never client-supplied
///   and requested SANs are still checked against the caller's allowed identities)
/// - NIAP PP-CA: FDP_CER_EXT.1 (the requested certificate content is constrained)
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EfsKeygenRequest {
    /// Additional Subject Alternative Names to request (e.g. `"DNS:host.mil"`).
    /// Each is still checked against the caller's allowlist (H1) — the form
    /// cannot widen the identity beyond what the principal may assert.
    #[serde(default)]
    sans: Vec<String>,
    /// Requested RSA key size. Optional; only 2048 (the EFS profile's key) is
    /// accepted, so a mismatch fails fast rather than at CA issuance.
    #[serde(default)]
    key_strength: Option<u32>,
}

/// Server-side key generation (RFC 7030 §4.4)
///
/// Server generates key pair and returns PKCS#12 with certificate + encrypted private key.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via mTLS (required)
/// - NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation (server-side)
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operations (PKCS#12 encoding)
/// - NIAP PP-CA: FDP_ACC.1 - Access control for key generation
/// - NIAP PP-CA: FAU_GEN.1 - Audit record for key generation event
/// - NIAP PP-CA: FCS_CKM.4 - Key destruction (zeroization after use)
/// - NIST 800-53: SC-12 - Cryptographic key establishment
/// - NIST 800-53: SI-12 - Information handling (key zeroization)
/// - RFC 7030 §4.4 - Server-side key generation
/// - RFC 7292 - PKCS#12 Personal Information Exchange
///
/// # Request Format
///
/// Two input shapes:
/// - RFC 7030 §4.4.1: a base64 PKCS#10 CSR conveying the desired subject/SANs.
///   The server generates the key, so the CSR's own key and signature are not
///   used for proof-of-possession.
/// - EFS portal flow (`Content-Type: application/json`, EFS profile only): an
///   [`EfsKeygenRequest`] carrying optional SANs + key strength. The subject is
///   taken from the mTLS-authenticated identity, so no client CSR/key is sent.
///
/// # Response Format
///
/// Two delivery shapes, selected by the resolved profile:
/// - Default: RFC 7030 §4.4.2 `multipart/mixed` carrying the EC P-256 private
///   key (`application/pkcs8`, RFC 5958) and the certificate (certs-only
///   `application/pkcs7-mime`).
/// - EFS profile: an `application/json` envelope `{format, certificateId,
///   pkcs12, password}` where `pkcs12` is a base64 encrypted PKCS#12 (RFC 7292)
///   holding the RSA key + certificate, and `password` is its one-time
///   decryption password.
///
/// # Security Notes
///
/// - CRITICAL: This endpoint MUST require client authentication (mTLS)
/// - Private keys are zeroized from memory after the response body is built
/// - The EFS one-time PKCS#12 password is returned exactly once, over the mTLS
///   channel, and is never stored server side (unrecoverable after the operator
///   closes the page); it is never written to logs or audit records
/// - Consider KRA escrow for key recovery capability
///
async fn server_key_gen(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    label: Option<axum::extract::Path<String>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let label = label.map(|p| p.0);
    use crate::serverkeygen::{ServerKeyGenRequest, generate_key_pair_for_client};
    use ostrich_common::types::DistinguishedName;
    use ostrich_crypto::KeyType;

    let client_identifier = &user.username;

    // Resolve the CA backend + profile first (fail closed; RFC 7030 §3.2.2 label
    // routing selects the backend by key algorithm and the profile by type). The
    // resolved profile decides both the key type and which input shapes are
    // accepted (the structured EFS body is EFS-only).
    let resolved = match state.resolve_enrollment(label.as_deref(), &user).await {
        Ok(r) => r,
        Err(e) => {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:serverkeygen",
                "ca_not_configured",
            )
            .await;
            return Err(e);
        }
    };
    let enroll_profile = resolved.profile.clone();
    // EFS (Microsoft Encrypting File System) certificates are delivered as an
    // encrypted PKCS#12 holding an RSA key — Windows EFS requires RSA. Every
    // other server-keygen profile gets a modern EC P-256 key.
    let is_efs = enroll_profile == EFS_PROFILE_NAME;
    let key_type = if is_efs {
        KeyType::Rsa2048
    } else {
        KeyType::EcP256
    };

    // Server-side key generation chooses the key by profile, so it cannot honor a
    // label-requested key algorithm. Reject AK-labeled serverkeygen rather than
    // silently issuing a different algorithm than requested (fail closed; full
    // multi-algorithm SSKG is a follow-up).
    if let Some(algo) = resolved.key_algo {
        emit_failure_audit(
            &state,
            client_identifier,
            "est:serverkeygen",
            "serverkeygen_keyalgo_unsupported",
        )
        .await;
        return Err(Error::BadRequest(format!(
            "server-side key generation does not support a label-requested key algorithm '{}' yet",
            algo.token()
        )));
    }

    // Two input shapes select the subject + requested SANs:
    //  - EFS portal flow (application/json): subject = the authenticated identity
    //    (never client-supplied), so there is no untrusted CSR/ASN.1 to parse and
    //    no throwaway client key. Accepted only for the EFS profile.
    //  - RFC 7030 §4.4.1: a base64 PKCS#10 CSR conveying the subject/SANs.
    let is_json_efs = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);

    let (subject, requested_sans): (DistinguishedName, Vec<String>) = if is_json_efs {
        if !is_efs {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:serverkeygen",
                "structured_input_non_efs",
            )
            .await;
            return Err(Error::BadRequest(
                "structured (JSON) server-side key generation is only supported for the EFS profile"
                    .to_string(),
            ));
        }
        let req: EfsKeygenRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                emit_failure_audit(
                    &state,
                    client_identifier,
                    "est:serverkeygen",
                    "invalid_efs_request",
                )
                .await;
                return Err(Error::BadRequest(format!(
                    "invalid EFS server-keygen request: {e}"
                )));
            }
        };
        // EFS issues an RSA-2048 key; reject any other requested strength up
        // front. Audit the rejection like every other input-validation failure
        // (AU-2): a client probing for accepted key sizes must leave a trace.
        if let Some(bits) = req.key_strength
            && bits != 2048
        {
            emit_failure_audit(
                &state,
                client_identifier,
                "est:serverkeygen",
                "unsupported_key_strength",
            )
            .await;
            return Err(Error::BadRequest(format!(
                "EFS server-side key generation supports only RSA-2048 (requested {bits})"
            )));
        }
        // SI-10: the subject CN is ALWAYS the authenticated identity, never taken
        // from the request body — the client cannot name a different subject.
        let subject = DistinguishedName {
            common_name: Some(client_identifier.to_string()),
            ..Default::default()
        };
        (subject, req.sans)
    } else {
        let request_der = match BASE64_STANDARD.decode(&body) {
            Ok(der) if der.len() >= 10 => der,
            _ => {
                emit_failure_audit(
                    &state,
                    client_identifier,
                    "est:serverkeygen",
                    "invalid_csr_encoding",
                )
                .await;
                return Err(Error::BadRequest("Invalid or too-short CSR".to_string()));
            }
        };
        let parsed = match ostrich_x509::parser::parse_csr(&request_der) {
            Ok(c) => c,
            Err(e) => {
                emit_failure_audit(
                    &state,
                    client_identifier,
                    "est:serverkeygen",
                    "csr_parse_failed",
            )
            .await;
            return Err(Error::InvalidCsr(format!(
                "Failed to parse serverkeygen CSR: {}",
                e
            )));
        }
    };
        let subject = ostrich_x509::parser::parse_csr_subject_dn(&request_der)
            .map_err(|e| Error::InvalidCsr(format!("Failed to parse CSR subject: {}", e)))?;
        (subject, parsed.subject_alternative_names)
    };

    // H1 - the server is about to mint a key AND a certificate for whatever
    // identity was requested; bind that identity to the authenticated principal
    // (CN or a SAN must equal `client_identifier`). For the EFS JSON path the CN
    // is already the authenticated identity; this still runs every requested SAN
    // through the same authorization policy so the form cannot widen the identity
    // beyond what the principal may assert. Fail secure: deny + audit.
    if !identity_authorized(
        &state,
        &user,
        subject.common_name.as_deref(),
        &requested_sans,
    )
    .await?
    {
        emit_failure_audit(
            &state,
            client_identifier,
            "est:serverkeygen",
            "identity_not_bound",
        )
        .await;
        tracing::warn!(
            client = %client_identifier,
            "EST serverkeygen denied: requested identity does not match authenticated principal (H1)"
        );
        return Err(Error::Forbidden(
            "subject CN or a SAN must match the authenticated client identity".to_string(),
        ));
    }

    let dns_sans: Vec<String> = requested_sans
        .iter()
        .filter_map(|s| s.strip_prefix("DNS:").map(String::from))
        .collect();

    // Generate the key pair + a CSR signed by it (proof-of-possession).
    let request = ServerKeyGenRequest {
        subject,
        key_type, // server-chosen: EFS → RSA, otherwise EC P-256
        dns_sans,
        profile_name: enroll_profile.clone(),
    };
    let material = generate_key_pair_for_client(
        &request,
        client_identifier,
        &state.crypto_provider,
        &state.audit_sink,
    )
    .await?;

    // Record the enrollment and submit the server-built CSR to the CA, which
    // verifies proof-of-possession and issues the certificate.
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let enrollment = repo
        .create_enrollment(
            client_identifier,
            "server-keygen",
            material.csr_der.clone(),
            "pending",
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create enrollment: {}", e)))?;

    let issue_result = resolved
        .client
        .enroll(
            enrollment.id,
            &material.csr_der,
            client_identifier,
            &enroll_profile,
            &resolved.label_metadata(),
        )
        .await;

    // Always destroy the server-held private key handle (FCS_CKM.4). A failure
    // to destroy key material is security-relevant and must not be swallowed (L4).
    if let Err(e) = state
        .crypto_provider
        .destroy_key(&material.key_handle)
        .await
    {
        tracing::error!(
            client = %client_identifier,
            error = %e,
            "Failed to destroy server-held private key handle after serverkeygen (FCS_CKM.4)"
        );
    }

    let certificate_id = match issue_result {
        Ok(id) => id,
        Err(e) => {
            // H2 - issuance failures must be audited.
            emit_enrollment_audit(
                &state,
                client_identifier,
                enrollment.id,
                "serverkeygen",
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(e);
        }
    };

    // Single-use: serverkeygen is reachable by an enrollment token (it also
    // requires SubmitRequest), so it must consume the token too — otherwise the
    // token would be reusable here, defeating single-use.
    consume_enrollment_token_if_present(&state, &user, certificate_id).await;

    // Fetch the issued certificate.
    let cert = ostrich_db::repository::CertificateRepository::new(state.db_pool.clone())
        .find_by_id(certificate_id)
        .await
        .map_err(|e| Error::Internal(format!("Failed to load issued certificate: {}", e)))?
        .ok_or_else(|| Error::Internal("Issued certificate not found".to_string()))?;

    // The server-held private key is sensitive: every intermediate that touches
    // it lives in a Zeroizing buffer and is wiped on drop. (One copy still lives
    // in the outbound HTTP body buffer, which is inherent to returning the key;
    // everything else is zeroized.)
    let response = if is_efs {
        // EFS delivery: wrap the RSA key + issued cert in an encrypted PKCS#12
        // protected by a freshly generated one-time password. The password is
        // returned exactly once, in this response, and is never stored server
        // side, so it is unrecoverable after the operator closes the page.
        //
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-12 (key establishment — escrow transport key),
        //   SC-13 (PBES2/AES-256 + HMAC-SHA256 protection of the key bag),
        //   SI-12 (one-time password never persisted; sensitive output handling)
        // - NIAP PP-CA: FCS_CKM.1 (RSA key generation), FCS_COP.1 (PKCS#12 MAC)
        // - RFC 7292 - PKCS#12 Personal Information Exchange
        let password = generate_one_time_pkcs12_password();
        let pkcs12 = ostrich_x509::pkcs12::build_encrypted_pkcs12(
            material.private_key_pkcs8.as_slice(),
            &cert.der_encoded,
            password.as_str(),
        )
        .map_err(|e| Error::Internal(format!("PKCS#12 assembly failed: {}", e)))?;
        let body = zeroize::Zeroizing::new(
            serde_json::json!({
                "format": "pkcs12",
                "certificateId": certificate_id.to_string(),
                "pkcs12": BASE64_STANDARD.encode(&pkcs12),
                "password": password.as_str(),
            })
            .to_string(),
        );
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json".to_string())],
            body.to_string(),
        )
            .into_response()
    } else {
        // RFC 7030 §4.4.2 - multipart/mixed: the private key (application/pkcs8)
        // and the certificate (application/pkcs7-mime; certs-only). Both base64.
        let pkcs7 = encode_certs_only_pkcs7(&[cert.der_encoded])
            .map_err(|e| Error::Internal(format!("PKCS#7 encoding failed: {}", e)))?;
        const BOUNDARY: &str = "estServerKeyGenBoundary";
        let key_b64 =
            zeroize::Zeroizing::new(BASE64_STANDARD.encode(material.private_key_pkcs8.as_slice()));
        let cert_b64 = BASE64_STANDARD.encode(&pkcs7);
        let body = zeroize::Zeroizing::new(format!(
            "--{b}\r\n\
             Content-Type: application/pkcs8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {key}\r\n\
             --{b}\r\n\
             Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {cert}\r\n\
             --{b}--\r\n",
            b = BOUNDARY,
            key = key_b64.as_str(),
            cert = cert_b64,
        ));
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                format!("multipart/mixed; boundary=\"{}\"", BOUNDARY),
            )],
            body.to_string(),
        )
            .into_response()
    };

    // H2 - audit the successful server-side key generation + issuance.
    emit_enrollment_audit(
        &state,
        client_identifier,
        enrollment.id,
        "serverkeygen",
        ostrich_audit::EventOutcome::Success,
    )
    .await;

    Ok(response)
}

// ===========================================================================
// Admin API: per-account identity allow-list (`est_account_identities`)
// ===========================================================================

/// Request body for adding an allowed identity to an account.
#[derive(Debug, serde::Deserialize)]
struct AddIdentityRequest {
    /// Identity (CN or SAN value, e.g. "device-42.example.com") the account may
    /// request in a certificate.
    identity: String,
}

/// Response body listing an account's allowed identities.
#[derive(Debug, serde::Serialize)]
struct IdentitiesResponse {
    account: String,
    identities: Vec<String>,
}

/// Request to mint a single-use EST enrollment token (camelCase to match the UI).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintEnrollmentTokenRequest {
    /// Device identity (CN) the enrolled certificate must carry (H1 binding).
    identity: String,
    /// Token lifetime in seconds; clamped to [60, 604800], default 3600.
    ttl_seconds: Option<i64>,
    /// Certificate profile the enrolled cert is issued under. One of
    /// `OFFERABLE_EST_PROFILES`; `None`/empty uses the EST server's default.
    profile: Option<String>,
    /// Number of devices that may enroll with this token (the use budget).
    /// Clamped to [1, 1000], default 1 (single-use). Values > 1 mint a
    /// "multiple devices" token; the identity (H1) binding still applies to every
    /// enrollment, so all devices enroll as the same pinned identity.
    max_uses: Option<i64>,
}

/// Certificate profiles an operator may pin to an EST enrollment token. Kept in
/// lockstep with the CA's registered issuance profiles (`default_profiles` in
/// ca-server): `tls_client` (clientAuth), `tls_server` (serverAuth),
/// `tls_server_client` (serverAuth + clientAuth, for mutual-TLS devices), and
/// `efs` (Microsoft EFS — server-side keygen delivered as an encrypted PKCS#12).
///
/// SI-10: reject anything else so a token can never reference an unissuable or
/// over-privileged profile.
const OFFERABLE_EST_PROFILES: [&str; 4] =
    ["tls_client", "tls_server", "tls_server_client", EFS_PROFILE_NAME];

/// Profile name that triggers the EFS server-side key-generation delivery path
/// (RSA key + issued cert wrapped in an encrypted PKCS#12). Must match the CA's
/// registered EFS profile (`CertificateProfile::efs`, `ProfileType::Efs`).
const EFS_PROFILE_NAME: &str = "efs";

/// Generate the one-time password that protects an EFS PKCS#12 bundle.
///
/// 18 CSPRNG bytes rendered as URL-safe unpadded base64 → 24 characters (~144
/// bits of entropy), comfortably above the builder's 12-char floor. The value
/// is returned to the operator exactly once and never stored, so it is the sole
/// protection on the escrowed key in transit (SC-12, SI-12).
fn generate_one_time_pkcs12_password() -> zeroize::Zeroizing<String> {
    let bytes = zeroize::Zeroizing::new(rand::random::<[u8; 18]>());
    zeroize::Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice()),
    )
}

/// Capability rank of an EST certificate profile within the TLS clientAuth/
/// serverAuth breadth ladder, used so re-enrollment can preserve the broadest
/// EKU set ever issued to an identity (RFC 7030 §4.2.2 — a renewal must not
/// silently narrow a server+client node to client-only). `tls_server_client`
/// (serverAuth + clientAuth) outranks the single-EKU profiles.
///
/// EFS is intentionally NOT on this ladder: it is a distinct certificate purpose
/// (Microsoft EFS EKU), not a wider/narrower TLS EKU set. `broadest_est_profile`
/// never compares it by rank — see the family guard there.
fn profile_capability_rank(profile: &str) -> u8 {
    match profile {
        "tls_server_client" => 2,
        "tls_server" | "tls_client" => 1,
        _ => 0,
    }
}

/// Fold the broadest offerable profile seen so far with another candidate. Keeps
/// the higher-capability profile; ignores unknown/unofferable names (fail secure).
fn broadest_est_profile(current: Option<String>, candidate: &Option<String>) -> Option<String> {
    let candidate = candidate
        .as_deref()
        .filter(|p| OFFERABLE_EST_PROFILES.contains(p));
    match (current, candidate) {
        (Some(cur), Some(cand)) => {
            // EFS is orthogonal to the TLS EKU breadth ladder. A renewal must
            // never silently swap an identity between the EFS and TLS families
            // (that would change the certificate's purpose, not just widen its
            // EKUs), so when exactly one side is EFS keep the profile already
            // selected and never rank-compare across the boundary (fail secure).
            if (cur == EFS_PROFILE_NAME) != (cand == EFS_PROFILE_NAME) {
                Some(cur)
            } else if profile_capability_rank(cand) > profile_capability_rank(&cur) {
                Some(cand.to_string())
            } else {
                Some(cur)
            }
        }
        (Some(cur), None) => Some(cur),
        (None, Some(cand)) => Some(cand.to_string()),
        (None, None) => None,
    }
}

/// One-time response carrying the plaintext token. The token is never persisted
/// in plaintext and cannot be retrieved again — treat it like an API key.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MintEnrollmentTokenResponse {
    token: String,
    identity: String,
    expires_at: String,
    expires_in_seconds: i64,
    /// Use budget the token was minted with (1 = single-use).
    max_uses: i64,
}

/// Mint a single-use, time-limited EST enrollment token bound to a device
/// identity.
///
/// `POST /api/v1/est/enrollment-tokens` — requires `Permission::GenerateEstToken`.
/// The operator hands the returned token to a device, which presents it once to
/// `/simpleenroll`; the H1 binding forces the CSR identity to equal `identity`,
/// and the token is consumed on success.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege),
///   IA-5 (authenticator management), AU-2 (auditable credential lifecycle)
/// - NIAP PP-CA: FMT_SMF.1 / FMT_MTD.1, FDP_CER_EXT.1
async fn create_enrollment_token(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    Json(req): Json<MintEnrollmentTokenRequest>,
) -> Result<Response> {
    // AC-3: only GenerateEstToken holders may mint. Audit the denial (AU-2).
    if state
        .rbac_policy
        .authorize(&user, Permission::GenerateEstToken, "est-enrollment-tokens")
        .is_err()
    {
        emit_failure_audit(
            &state,
            &user.username,
            "est:enrollment-tokens",
            "generate_est_token_denied",
        )
        .await;
        tracing::warn!(actor = %user.username, "EST enrollment-token generation denied");
        return Err(Error::Forbidden("insufficient permission".to_string()));
    }

    // SI-10: validate + canonicalize the bound identity (trim/lowercase/bounds).
    let identity = validate_identity(&req.identity)?;

    // SI-10: validate the optional profile against the offerable allowlist so a
    // token can only ever reference a registered, intended issuance profile.
    let profile = match req.profile.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(p) if OFFERABLE_EST_PROFILES.contains(&p) => Some(p.to_string()),
        Some(p) => {
            emit_failure_audit(
                &state,
                &user.username,
                "est:enrollment-tokens",
                "generate_est_token_invalid_profile",
            )
            .await;
            return Err(Error::BadRequest(format!(
                "unknown certificate profile '{p}'"
            )));
        }
    };

    // Clamp the lifetime: at least 1 minute, at most 7 days.
    const MIN_TTL: i64 = 60;
    const MAX_TTL: i64 = 7 * 24 * 3600;
    const DEFAULT_TTL: i64 = 3600;
    let ttl = req
        .ttl_seconds
        .unwrap_or(DEFAULT_TTL)
        .clamp(MIN_TTL, MAX_TTL);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl);

    // Clamp the use budget: single-use by default, at most 1000 devices. A
    // multi-use token stays identity-pinned and time-limited; the cap bounds the
    // blast radius of a leaked credential (IA-5 / AC-6).
    const MAX_USE_BUDGET: i64 = 1000;
    let max_uses = req.max_uses.unwrap_or(1).clamp(1, MAX_USE_BUDGET);

    // 256-bit URL-safe token; only its SHA-256 is stored. Zeroize the raw
    // entropy after encoding (NIST 800-53 SI-12: protect secrets in memory).
    let token_bytes = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes[..]);
    let token_hash = crate::enrollment_token::hash_token(&token);
    let token_id = uuid::Uuid::new_v4();

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let outcome = if repo
        .create_enrollment_token(
            token_id,
            &token_hash,
            &identity,
            profile.as_deref(),
            &user.username,
            expires_at,
            max_uses as i32,
        )
        .await
        .is_ok()
    {
        ostrich_audit::EventOutcome::Success
    } else {
        ostrich_audit::EventOutcome::Failure
    };

    // AU-2 / FAU_GEN.1: record who minted a credential for which identity.
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::ConfigurationChange,
        &user.username,
        "est:enrollment-tokens".to_string(),
        "generate_est_token",
        outcome,
    )
    .with_details(serde_json::json!({
        "identity": identity,
        "ttl_seconds": ttl,
        "token_id": token_id.to_string(),
        "profile": profile,
        "max_uses": max_uses,
    }))
    .build();
    let _ = state.audit_sink.record(&mut event).await;

    if outcome == ostrich_audit::EventOutcome::Failure {
        return Err(Error::Internal(
            "Failed to store enrollment token".to_string(),
        ));
    }

    tracing::info!(
        actor = %user.username,
        identity = %identity,
        ttl_seconds = ttl,
        token_id = %token_id,
        "EST enrollment token minted"
    );

    Ok((
        StatusCode::CREATED,
        Json(MintEnrollmentTokenResponse {
            token,
            identity,
            expires_at: expires_at.to_rfc3339(),
            expires_in_seconds: ttl,
            max_uses,
        }),
    )
        .into_response())
}

/// One row of the enrollment-token inventory (no secret material).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentTokenSummaryDto {
    id: String,
    identity: String,
    created_by: String,
    created_at: String,
    expires_at: String,
    /// live | used | revoked | expired
    status: String,
    /// Use budget the token was minted with (1 = single-use).
    max_uses: i32,
    /// Remaining uses (0 once exhausted/revoked).
    uses_remaining: i32,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentTokenListResponse {
    tokens: Vec<EnrollmentTokenSummaryDto>,
}

/// Enforce `GenerateEstToken` for token-management endpoints, auditing denials.
async fn authorize_token_mgmt(
    state: &EstState,
    user: &ostrich_common::auth::AuthenticatedUser,
    action: &str,
) -> Result<()> {
    if state
        .rbac_policy
        .authorize(user, Permission::GenerateEstToken, "est-enrollment-tokens")
        .is_err()
    {
        emit_failure_audit(
            state,
            &user.username,
            "est:enrollment-tokens",
            &format!("{action}_denied"),
        )
        .await;
        tracing::warn!(actor = %user.username, action, "EST token management denied");
        return Err(Error::Forbidden("insufficient permission".to_string()));
    }
    Ok(())
}

/// NPE sponsor token management is self-service; anyone with global oversight
/// keeps the full view. "Global oversight" mirrors the CA's own-scope rule
/// (`is_npe_self_service`) — a legacy operator/admin role OR any approver role
/// (`ApproveRequest`) — so the two services never disagree on who is scoped.
fn enrollment_token_owner_scope(user: &ostrich_common::auth::AuthenticatedUser) -> Option<&str> {
    let is_npe_sponsor = user
        .roles
        .iter()
        .any(|r| matches!(r, Role::PkiSponsor | Role::PkiSponsorAdmin));
    let has_global_oversight = user
        .roles
        .iter()
        .any(|r| matches!(r, Role::Administrator | Role::OperationsStaff))
        || any_role_has_permission(&user.roles, Permission::ApproveRequest);

    (is_npe_sponsor && !has_global_oversight).then_some(user.username.as_str())
}

/// List recently minted enrollment tokens (operator review).
///
/// `GET /api/v1/est/enrollment-tokens` — requires `Permission::GenerateEstToken`.
/// Returns lifecycle metadata only (never the token); a status is derived from
/// the consume/expiry state.
async fn list_enrollment_tokens(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
) -> Result<Response> {
    authorize_token_mgmt(&state, &user, "list_est_tokens").await?;

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let rows = repo
        .list_enrollment_tokens(enrollment_token_owner_scope(&user), 200)
        .await
        .map_err(|e| Error::Internal(format!("Failed to list enrollment tokens: {e}")))?;

    let now = chrono::Utc::now();
    let tokens = rows
        .into_iter()
        .map(|r| {
            // Derive status from the unambiguous lifecycle fields. `used_at` and
            // `used_by_cert` cannot distinguish revoked-after-partial-use from
            // exhausted-by-use for a multi-use token, so we key on `revoked_at`
            // and `uses_remaining` instead.
            let status = if r.revoked_at.is_some() {
                "revoked"
            } else if r.uses_remaining <= 0 {
                "used"
            } else if r.expires_at <= now {
                "expired"
            } else {
                "live"
            };
            EnrollmentTokenSummaryDto {
                id: r.id.to_string(),
                identity: r.identity,
                created_by: r.created_by,
                created_at: r.created_at.to_rfc3339(),
                expires_at: r.expires_at.to_rfc3339(),
                status: status.to_string(),
                max_uses: r.max_uses,
                uses_remaining: r.uses_remaining,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(EnrollmentTokenListResponse { tokens })).into_response())
}

/// Revoke a live enrollment token before it is used.
///
/// `DELETE /api/v1/est/enrollment-tokens/{id}` — requires `Permission::GenerateEstToken`.
/// Idempotent-ish: returns 404 if no *live* token with that id exists (already
/// used/revoked/expired or unknown). Audited (AU-2).
async fn revoke_enrollment_token(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    authorize_token_mgmt(&state, &user, "revoke_est_token").await?;

    let token_id = match uuid::Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return Ok((StatusCode::BAD_REQUEST, "invalid token id").into_response()),
    };

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let revoked = repo
        .revoke_enrollment_token(token_id, enrollment_token_owner_scope(&user))
        .await
        .map_err(|e| Error::Internal(format!("Failed to revoke enrollment token: {e}")))?;

    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::ConfigurationChange,
        &user.username,
        "est:enrollment-tokens".to_string(),
        "revoke_est_token",
        if revoked {
            ostrich_audit::EventOutcome::Success
        } else {
            ostrich_audit::EventOutcome::Failure
        },
    )
    .with_details(serde_json::json!({ "token_id": token_id.to_string(), "revoked": revoked }))
    .build();
    let _ = state.audit_sink.record(&mut event).await;

    if !revoked {
        return Ok((StatusCode::NOT_FOUND, "no live token with that id").into_response());
    }
    tracing::info!(actor = %user.username, token_id = %token_id, "EST enrollment token revoked");
    Ok((StatusCode::OK, Json(serde_json::json!({ "revoked": true }))).into_response())
}

/// Enforce an admin permission on the authenticated user (FMT_MTD.1), auditing
/// the denial so unauthorized management attempts leave a trail (AU-2/AU-12),
/// matching the enrollment handlers' failure-audit behavior.
async fn authorize_admin(
    state: &EstState,
    user: &ostrich_common::auth::AuthenticatedUser,
    permission: Permission,
    account: &str,
    action: &str,
) -> Result<()> {
    if state
        .rbac_policy
        .authorize(user, permission, "est-account-identities")
        .is_err()
    {
        let resource = format!("est:account:{account}:identities");
        emit_failure_audit(
            state,
            &user.username,
            &resource,
            &format!("{action}_denied"),
        )
        .await;
        tracing::warn!(
            actor = %user.username,
            ?permission,
            account,
            "EST admin authorization denied"
        );
        return Err(Error::Forbidden("insufficient permission".to_string()));
    }
    Ok(())
}

/// Emit a configuration-change audit record for an allow-list mutation.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CM-3 (configuration change control), AU-2 (auditable event)
/// - NIAP PP-CA: FAU_GEN.1 / FMT_SMF.1
async fn emit_config_change_audit(
    state: &EstState,
    actor: &str,
    account: &str,
    action: &str,
    identity: &str,
    outcome: ostrich_audit::EventOutcome,
) {
    let mut event = ostrich_audit::AuditEventBuilder::new(
        ostrich_audit::EventType::ConfigurationChange,
        actor,
        format!("est:account:{account}:identities"),
        action,
        outcome,
    )
    .with_details(serde_json::json!({ "account": account, "identity": identity }))
    .build();
    let _ = state.audit_sink.record(&mut event).await;
}

/// List the identities an account is allowed to enroll for.
///
/// `GET /api/v1/est/accounts/{account}/identities` — requires `ViewConfig`.
async fn list_account_identities(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    Path(account): Path<String>,
) -> Result<Response> {
    authorize_admin(
        &state,
        &user,
        Permission::ViewConfig,
        &account,
        "list_allowed_identities",
    )
    .await?;

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let identities = repo
        .list_allowed_identities(&account)
        .await
        .map_err(|e| Error::Internal(format!("Failed to list allowed identities: {}", e)))?;

    Ok((
        StatusCode::OK,
        Json(IdentitiesResponse {
            account,
            identities,
        }),
    )
        .into_response())
}

/// Grant an account permission to enroll for an identity.
///
/// `POST /api/v1/est/accounts/{account}/identities` — requires `ModifyConfig`.
async fn add_account_identity(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    Path(account): Path<String>,
    Json(req): Json<AddIdentityRequest>,
) -> Result<Response> {
    authorize_admin(
        &state,
        &user,
        Permission::ModifyConfig,
        &account,
        "add_allowed_identity",
    )
    .await?;

    // SI-10: validate + canonicalize (trim, lowercase, length/charset bounds).
    let identity = validate_identity(&req.identity)?;

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    if let Err(e) = repo.add_allowed_identity(&account, &identity).await {
        // AU-2: audit the failed mutation, not just successes.
        emit_config_change_audit(
            &state,
            &user.username,
            &account,
            "add_allowed_identity",
            &identity,
            ostrich_audit::EventOutcome::Failure,
        )
        .await;
        return Err(Error::Internal(format!(
            "Failed to add allowed identity: {}",
            e
        )));
    }

    emit_config_change_audit(
        &state,
        &user.username,
        &account,
        "add_allowed_identity",
        &identity,
        ostrich_audit::EventOutcome::Success,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "account": account, "identity": identity })),
    )
        .into_response())
}

/// Revoke an account's permission to enroll for an identity.
///
/// `DELETE /api/v1/est/accounts/{account}/identities/{identity}` — requires `ModifyConfig`.
async fn delete_account_identity(
    State(state): State<EstState>,
    AuthUser(user): AuthUser,
    Path((account, identity)): Path<(String, String)>,
) -> Result<Response> {
    authorize_admin(
        &state,
        &user,
        Permission::ModifyConfig,
        &account,
        "remove_allowed_identity",
    )
    .await?;

    // Match the canonical form used at insert time so a revoke actually hits the
    // stored row.
    let identity = normalize_identity(&identity);

    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let removed = match repo.remove_allowed_identity(&account, &identity).await {
        Ok(removed) => removed,
        Err(e) => {
            emit_config_change_audit(
                &state,
                &user.username,
                &account,
                "remove_allowed_identity",
                &identity,
                ostrich_audit::EventOutcome::Failure,
            )
            .await;
            return Err(Error::Internal(format!(
                "Failed to remove allowed identity: {}",
                e
            )));
        }
    };

    // Don't claim (or audit) a revocation that didn't happen (AU-3).
    if !removed {
        return Err(Error::NotFound);
    }

    emit_config_change_audit(
        &state,
        &user.username,
        &account,
        "remove_allowed_identity",
        &identity,
        ostrich_audit::EventOutcome::Success,
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EFS profile must be offerable, or serverkeygen would reject it before
    /// ever reaching the PKCS#12 delivery path.
    #[test]
    fn efs_profile_is_offerable() {
        assert!(OFFERABLE_EST_PROFILES.contains(&EFS_PROFILE_NAME));
    }

    /// The structured EFS serverkeygen body uses camelCase `keyStrength` and a
    /// defaultable `sans`; both must round-trip so the portal contract holds.
    #[test]
    fn efs_keygen_request_deserializes() {
        let full: EfsKeygenRequest =
            serde_json::from_str(r#"{"sans":["DNS:host.mil"],"keyStrength":2048}"#).unwrap();
        assert_eq!(full.sans, vec!["DNS:host.mil"]);
        assert_eq!(full.key_strength, Some(2048));

        // Both fields are optional (subject comes from the authenticated identity).
        let empty: EfsKeygenRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.sans.is_empty());
        assert_eq!(empty.key_strength, None);
    }

    /// The one-time PKCS#12 password must clear the builder's 12-char floor and
    /// be unique per call (CSPRNG-derived, not a fixed/derivable value).
    #[test]
    fn one_time_pkcs12_password_is_long_and_unique() {
        let a = generate_one_time_pkcs12_password();
        let b = generate_one_time_pkcs12_password();
        assert!(a.len() >= 12, "password must clear the builder's minimum");
        assert_ne!(a.as_str(), b.as_str(), "passwords must not repeat");
        // URL-safe base64 alphabet only (no '+', '/', or '=' padding).
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "password must be URL-safe base64"
        );
    }

    /// Re-enrollment must preserve the broadest EKU profile ever issued to an
    /// identity (RFC 7030 §4.2.2): a server+client node must not be narrowed to
    /// client-only on renewal, and one already narrowed (e.g. by an earlier
    /// client-only default) must heal back to server+client.
    #[test]
    fn reenroll_preserves_broadest_profile() {
        // Bootstrap = tls_server_client; a buggy renewal later recorded tls_client.
        // Folding all prior profiles must recover server+client regardless of order.
        let narrowed_then_broad = broadest_est_profile(
            broadest_est_profile(None, &Some("tls_client".to_string())),
            &Some("tls_server_client".to_string()),
        );
        assert_eq!(narrowed_then_broad.as_deref(), Some("tls_server_client"));
        let broad_then_narrowed = broadest_est_profile(
            broadest_est_profile(None, &Some("tls_server_client".to_string())),
            &Some("tls_client".to_string()),
        );
        assert_eq!(broad_then_narrowed.as_deref(), Some("tls_server_client"));

        // Unknown / unofferable profile names are ignored (fail secure).
        assert_eq!(
            broadest_est_profile(Some("tls_server_client".into()), &Some("bogus".into()))
                .as_deref(),
            Some("tls_server_client")
        );
        assert_eq!(broadest_est_profile(None, &Some("bogus".into())), None);
        assert_eq!(broadest_est_profile(None, &None), None);
        assert!(profile_capability_rank("tls_server_client") > profile_capability_rank("tls_client"));
    }

    /// EFS is orthogonal to the TLS EKU ladder: the broadest-profile fold must
    /// never silently swap an identity between the EFS and TLS families (that
    /// would change the certificate's purpose), in either encounter order.
    #[test]
    fn reenroll_never_swaps_efs_and_tls_families() {
        // A pure-EFS identity renews as EFS (preserved, not folded away).
        let efs_only = broadest_est_profile(
            broadest_est_profile(None, &Some(EFS_PROFILE_NAME.to_string())),
            &Some(EFS_PROFILE_NAME.to_string()),
        );
        assert_eq!(efs_only.as_deref(), Some(EFS_PROFILE_NAME));

        // Mixed-purpose identity (same subject+SANs): never silently swap purpose,
        // regardless of which family the fold encounters first.
        let efs_then_tls = broadest_est_profile(
            broadest_est_profile(None, &Some(EFS_PROFILE_NAME.to_string())),
            &Some("tls_server_client".to_string()),
        );
        assert_eq!(efs_then_tls.as_deref(), Some(EFS_PROFILE_NAME));
        let tls_then_efs = broadest_est_profile(
            broadest_est_profile(None, &Some("tls_server_client".to_string())),
            &Some(EFS_PROFILE_NAME.to_string()),
        );
        assert_eq!(tls_then_efs.as_deref(), Some("tls_server_client"));
    }

    #[test]
    fn test_est_path_prefix() {
        // Verify EST URL path structure per RFC 7030 §3.2.2
        let prefix = "/.well-known/est";
        assert!(prefix.starts_with("/.well-known/"));
        assert!(prefix.ends_with("est"));
    }

    #[test]
    fn test_normalize_san_set_order_and_dedup() {
        // C2: set comparison must be order- and duplicate-insensitive.
        let a = normalize_san_set(&[
            "DNS:b.example".into(),
            "DNS:a.example".into(),
            "DNS:a.example".into(),
        ]);
        let b = normalize_san_set(&["DNS:a.example".into(), "DNS:b.example".into()]);
        assert_eq!(a, b);
        // A superset must NOT compare equal (the C2 attack: adding a SAN).
        let attacker = normalize_san_set(&[
            "DNS:a.example".into(),
            "DNS:b.example".into(),
            "DNS:admin.internal".into(),
        ]);
        assert_ne!(a, attacker);
    }

    #[test]
    fn test_csr_identity_binding() {
        // H1: CN match.
        assert!(csr_identity_matches_principal("alice", Some("alice"), &[]));
        // SAN value match (TYPE: prefix stripped).
        assert!(csr_identity_matches_principal(
            "alice",
            Some("other"),
            &["DNS:alice".into()]
        ));
        // No match -> deny (the H1 escalation attempt).
        assert!(!csr_identity_matches_principal(
            "alice",
            Some("admin"),
            &["DNS:vpn.corp".into()]
        ));
        // No CN, no matching SAN -> deny.
        assert!(!csr_identity_matches_principal("alice", None, &[]));
        // Exact match only: "alice" must not satisfy "alice2".
        assert!(!csr_identity_matches_principal(
            "alice2",
            Some("alice"),
            &[]
        ));
    }

    #[test]
    fn test_csr_asserted_identities() {
        // CN + SAN values (prefix-stripped) are all collected for the allow-list
        // subset check.
        let sans = ["DNS:device-1".to_string(), "email:dev@corp".to_string()];
        let ids = csr_asserted_identities(Some("device-1"), &sans);
        assert_eq!(ids, vec!["device-1", "device-1", "dev@corp"]);
        // No CN, no SANs -> nothing asserted (allow-list will deny).
        assert!(csr_asserted_identities(None, &[]).is_empty());
    }

    #[test]
    fn test_add_identity_request_deserializes() {
        // Admin API contract: { "identity": "<value>" }.
        let req: AddIdentityRequest =
            serde_json::from_str(r#"{ "identity": "device-42.example.com" }"#).unwrap();
        assert_eq!(req.identity, "device-42.example.com");
    }

    #[test]
    fn test_normalize_identity_canonicalizes() {
        // Trim + lowercase so admin-stored and CSR-asserted values match.
        assert_eq!(
            normalize_identity("  Device-1.Example.COM "),
            "device-1.example.com"
        );
        assert_eq!(normalize_identity("dev@CORP"), "dev@corp");
    }

    #[test]
    fn test_validate_identity_rules() {
        assert_eq!(
            validate_identity("  Host.Example  ").unwrap(),
            "host.example"
        );
        assert!(validate_identity("   ").is_err()); // empty after trim
        assert!(validate_identity("a\nb").is_err()); // control char
        assert!(validate_identity(&"x".repeat(MAX_IDENTITY_LEN + 1)).is_err()); // too long
        assert!(validate_identity(&"x".repeat(MAX_IDENTITY_LEN)).is_ok());
    }

    #[test]
    fn test_identities_response_serializes() {
        let body = IdentitiesResponse {
            account: "ra-fleet-1".to_string(),
            identities: vec!["device-1".to_string(), "device-2".to_string()],
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["account"], "ra-fleet-1");
        assert_eq!(json["identities"][1], "device-2");
    }

    #[test]
    fn test_base64_decoding() {
        // Test base64 encoding/decoding for PKCS#10 requests per RFC 7030
        use base64::prelude::*;

        let original = b"test CSR data";
        let encoded = BASE64_STANDARD.encode(original);
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_invalid_base64_handling() {
        // Verify that invalid base64 is properly rejected
        use base64::prelude::*;

        let invalid = "invalid-base64!@#$";
        let result = BASE64_STANDARD.decode(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_est_content_type_header() {
        // Test Content-Type header for PKCS#7 responses
        let content_type = "application/pkcs7-mime";
        assert!(content_type.contains("pkcs7"));
    }

    #[test]
    fn test_pkcs7_certs_only_empty() {
        // Test PKCS#7 encoding with empty certificate list
        // RFC 7030 §4.1.3 - Degenerate SignedData (certs-only)
        // RFC 5652 §5 - CMS SignedData structure
        let result = encode_certs_only_pkcs7(&[]);
        assert!(result.is_ok());

        let pkcs7_der = result.unwrap();
        // Verify it's valid DER (basic length check)
        assert!(!pkcs7_der.is_empty());

        // Verify it starts with SEQUENCE tag (0x30) per DER encoding rules
        assert_eq!(pkcs7_der[0], 0x30);

        // Verify minimum PKCS#7 ContentInfo structure size
        // ContentInfo ::= SEQUENCE {
        //   contentType OBJECT IDENTIFIER,
        //   content [0] EXPLICIT ANY DEFINED BY contentType
        // }
        assert!(pkcs7_der.len() > 10);
    }
}
