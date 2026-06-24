//! Device certificate authentication for EST re-enrollment (RFC 7030 §3.3).
//!
//! A device that completed an initial enrollment (typically via a single-use
//! bearer token, see [`crate::enrollment_token`]) holds the certificate the CA
//! issued it. To renew that certificate it re-enrolls over mTLS, presenting the
//! existing certificate as its TLS client certificate. There is no user-table
//! account for such a device, so the generic
//! [`ostrich_common::auth::CertificateAuthProvider`] (which maps a certificate
//! subject DN to a provisioned account) cannot authenticate it.
//!
//! [`EstDeviceCertAuthProvider`] fills that gap: it identifies a presented
//! client certificate as a device certificate by an exact DER match against the
//! certificate store *and* a mapping back to the EST enrollment that produced
//! it (whose `client_identifier` is the device identity). For such a
//! certificate it confirms it is neither revoked nor expired and yields a
//! least-privilege [`Role::EstDevice`] principal whose only capability is
//! `RenewCertificate`; the re-enroll handler then binds the new CSR's
//! subject/SAN to a certificate previously issued to that same client
//! (RFC 7030 §4.2.2). Any certificate that is not a device certificate — not in
//! the store, or in the store but issued through another path (operator, ACME,
//! server) with no owning EST enrollment — falls through to the wrapped (inner)
//! provider, so operator certificates mapped to real accounts keep working
//! unchanged. Only a positively-identified device certificate that is revoked
//! or expired fails closed.
//!
//! COMPLIANCE MAPPING:
//! - RFC 7030 §3.3 - certificate-based client authentication for re-enrollment
//! - NIAP PP-CA: FIA_UAU.1 - authentication by existing certificate
//! - NIST 800-53: IA-2 / AC-17 - identification via mTLS client certificate
//! - NIST 800-53: AC-6 - least privilege (RenewCertificate only)
//! - NIST 800-53: AC-3 - fail secure (revoked/expired/unowned certs denied)

use async_trait::async_trait;
use ostrich_common::auth::{
    AuthError, AuthMethod, AuthProvider, AuthResult, AuthenticatedUser, Credentials, Role,
    SessionInfo, UserId,
};
use ostrich_db::DatabasePool;
use ostrich_db::repository::{CertificateRepository, EstRepository};
use std::sync::Arc;

/// Authenticates a device by the CA-issued certificate it presents over mTLS,
/// delegating everything it does not recognise to an inner provider.
pub struct EstDeviceCertAuthProvider {
    certs: CertificateRepository,
    enrollments: EstRepository,
    inner: Arc<dyn AuthProvider>,
}

impl EstDeviceCertAuthProvider {
    /// Wrap `inner`, resolving presented client certificates against the
    /// certificate and EST enrollment stores backed by `pool`.
    pub fn new(pool: DatabasePool, inner: Arc<dyn AuthProvider>) -> Self {
        Self {
            certs: CertificateRepository::new(pool.clone()),
            enrollments: EstRepository::new(pool),
            inner,
        }
    }

    /// Try to authenticate the presented leaf certificate as an EST device
    /// certificate. Returns `Ok(None)` when the certificate is not a device
    /// re-enrollment subject (not one this CA stored, or stored but not produced
    /// by an EST enrollment — e.g. an operator/ACME/server certificate), so the
    /// caller defers to the inner provider. Returns an error only once the
    /// certificate is positively identified as a device certificate but is
    /// unusable (revoked or expired) — a device must not renew a dead cert.
    async fn authenticate_device_cert(
        &self,
        leaf_der: &[u8],
    ) -> AuthResult<Option<AuthenticatedUser>> {
        // Provenance: a presented certificate is one of ours iff it is
        // byte-identical to a stored DER encoding (encoding-independent, unlike
        // a serial- or subject-string lookup). Not ours → not a device cert.
        let cert = match self.certs.find_by_der(leaf_der).await.map_err(|e| {
            AuthError::CertificateValidationFailed {
                reason: format!("certificate store lookup failed: {e}"),
            }
        })? {
            Some(cert) => cert,
            None => return Ok(None),
        };

        // Classify: a certificate is a device re-enrollment subject only if it
        // maps back to the EST enrollment that produced it (its
        // `client_identifier` is the identity the re-enroll handler binds the
        // new CSR against). Every certificate this CA issues is in the store, so
        // store-membership alone is too broad — a cert with no owning EST
        // enrollment is an operator/ACME/server certificate and must fall
        // through to the account-mapping inner provider, NOT be denied here.
        let client_identifier = match self
            .enrollments
            .find_client_by_certificate_id(cert.id)
            .await
            .map_err(|e| AuthError::CertificateValidationFailed {
                reason: format!("enrollment lookup failed: {e}"),
            })? {
            Some(client_identifier) => client_identifier,
            None => return Ok(None),
        };

        // It is a device certificate. Fail secure from here: a revoked or
        // expired device certificate cannot renew itself, and must not fall
        // through to any weaker auth path.
        if cert.revoked {
            return Err(AuthError::CertificateRevoked);
        }
        if cert.not_after <= chrono::Utc::now() {
            return Err(AuthError::CertificateExpired);
        }

        let user = AuthenticatedUser::new(
            UserId::from_uuid(cert.id),
            client_identifier,
            vec![Role::EstDevice],
            AuthMethod::Certificate,
        )
        .with_certificate_subject(cert.subject_dn);

        Ok(Some(user))
    }
}

#[async_trait]
impl AuthProvider for EstDeviceCertAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
        if let Credentials::Certificate { cert_chain, .. } = credentials
            && let Some(leaf_der) = cert_chain.first()
            && let Some(user) = self.authenticate_device_cert(leaf_der).await?
        {
            return Ok(user);
        }
        // Not a recognised device certificate (or not a certificate credential):
        // defer to the inner provider (e.g. an operator certificate mapped to a
        // user account).
        self.inner.authenticate(credentials).await
    }

    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo> {
        self.inner.validate_session(token).await
    }

    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        self.inner.create_session(user).await
    }

    async fn invalidate_session(&self, token: &str) -> AuthResult<()> {
        self.inner.invalidate_session(token).await
    }

    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()> {
        self.inner.record_failed_attempt(username, reason).await
    }

    async fn is_account_locked(&self, username: &str) -> AuthResult<bool> {
        self.inner.is_account_locked(username).await
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        self.inner.unlock_account(username).await
    }

    async fn terminate_all_sessions_for_user(&self, user_id: &str) -> AuthResult<u32> {
        self.inner.terminate_all_sessions_for_user(user_id).await
    }

    fn provider_name(&self) -> &str {
        "est-device-certificate"
    }

    fn supported_methods(&self) -> &[AuthMethod] {
        // Certificate credentials are routed here; everything else is delegated.
        // Mirror the inner provider so composite routing is unchanged.
        self.inner.supported_methods()
    }
}
