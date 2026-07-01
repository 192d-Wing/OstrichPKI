//! Certificate OID -> NPE role resolution.
//!
//! The NPE portal authenticates operators by mTLS client certificate. The role
//! (PKI Sponsor / Administrator / Registration Authority / CA Admin) is derived
//! from the certificate's policy OIDs, not from an account record. A certificate
//! that carries the configured **Admin OID** elevates a Sponsor to Administrator.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (identification via the client certificate)
//! - NIST 800-53: AC-3 (access enforcement: OID-derived role)
//! - NIAP PP-CA: FIA_X509_EXT.2 (certificate-based authentication),
//!   FMT_SMR.2 (security roles)

use ostrich_common::auth::Role;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Configurable mapping from certificate policy OIDs to NPE roles.
///
/// Precedence (highest first): CAA, RA, Administrator (Sponsor + admin OID),
/// Sponsor. The first match wins so a single certificate resolves to exactly one
/// NPE role.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidRoleMapping {
    /// Policy OIDs that identify a PKI Sponsor (the baseline requester role).
    #[serde(default)]
    pub sponsor_oids: Vec<String>,

    /// Policy OID that, when present alongside a Sponsor OID, elevates the
    /// principal to NPE Administrator (adds bulk enrollment).
    #[serde(default)]
    pub admin_oid: Option<String>,

    /// Policy OIDs that identify a Registration Authority.
    #[serde(default)]
    pub ra_oids: Vec<String>,

    /// Policy OIDs that identify a Certificate Authority Admin (CAA).
    #[serde(default)]
    pub caa_oids: Vec<String>,

    /// Policy OIDs that identify a read-only NPE Auditor (audit review only).
    #[serde(default)]
    pub auditor_oids: Vec<String>,

    /// Optional issuer scoping. When non-empty, the client certificate's issuer
    /// DN (RFC 4514) MUST exactly match one of these values for any role to be
    /// granted. This prevents a lower-assurance CA in the trusted client-CA
    /// bundle from asserting a role-granting policy OID and escalating
    /// privilege; the role OID is only honored when asserted by an authorized
    /// issuing CA. Empty = no issuer constraint (development default).
    ///
    /// NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege)
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
}

impl Default for OidRoleMapping {
    fn default() -> Self {
        // Placeholder OID arcs under an example PEN. These MUST be overridden in
        // configuration with the deployment's real certificate-policy OIDs; the
        // defaults exist so the service starts in development, not so they are
        // used in production (CM-6: documented, overridable defaults).
        Self {
            sponsor_oids: vec!["1.3.6.1.4.1.99999.1.1".to_string()],
            admin_oid: Some("1.3.6.1.4.1.99999.1.2".to_string()),
            ra_oids: vec!["1.3.6.1.4.1.99999.1.3".to_string()],
            caa_oids: vec!["1.3.6.1.4.1.99999.1.4".to_string()],
            auditor_oids: vec!["1.3.6.1.4.1.99999.1.5".to_string()],
            // No issuer constraint by default; production deployments SHOULD set
            // this to the authorized issuing CA DN(s) (see field docs).
            allowed_issuers: Vec::new(),
        }
    }
}

impl OidRoleMapping {
    /// Resolve the NPE role from the set of certificate policy OIDs.
    ///
    /// Returns `None` when no configured OID matches (the certificate is valid
    /// per the TLS handshake but is not authorized for any portal role).
    pub fn resolve(&self, cert_oids: &HashSet<String>) -> Option<Role> {
        let has_any = |candidates: &[String]| candidates.iter().any(|o| cert_oids.contains(o));

        if has_any(&self.caa_oids) {
            return Some(Role::CaaAdmin);
        }
        // Auditor is read-only; resolve it before the acting roles so a cert
        // carrying an auditor OID can never be elevated to an approval/revoke
        // role (fail-safe toward least privilege, AC-6).
        if has_any(&self.auditor_oids) {
            return Some(Role::NpeAuditor);
        }
        if has_any(&self.ra_oids) {
            return Some(Role::RegistrationAuthority);
        }
        if has_any(&self.sponsor_oids) {
            let is_admin = self
                .admin_oid
                .as_ref()
                .map(|o| cert_oids.contains(o))
                .unwrap_or(false);
            return Some(if is_admin {
                Role::PkiSponsorAdmin
            } else {
                Role::PkiSponsor
            });
        }
        None
    }
}

/// The authenticated identity derived from a client certificate.
#[derive(Debug, Clone, Serialize)]
pub struct NpeIdentity {
    /// Common Name from the certificate subject (e.g. LAST.FIRST.M.ID_NUMBER).
    pub common_name: String,
    /// Full RFC 4514 subject DN.
    pub subject_dn: String,
    /// Resolved NPE role.
    pub role: Role,
    /// SHA-256 hex fingerprint of the certificate DER, used to bind the session
    /// to the authenticating certificate (NIST SC-23 session authenticity).
    pub fingerprint: String,
}

/// Errors that can occur while authenticating a client certificate.
#[derive(Debug, Error)]
pub enum CertAuthError {
    #[error("no client certificate presented")]
    NoCertificate,
    #[error("failed to parse client certificate: {0}")]
    ParseError(String),
    #[error("client certificate has no Common Name in its subject")]
    MissingCommonName,
    #[error("client certificate issuer is not an authorized role-issuing CA")]
    UntrustedIssuer,
    #[error("client certificate carries no policy OID mapped to an NPE role")]
    Unauthorized,
}

/// SHA-256 hex fingerprint of a DER-encoded certificate.
pub fn fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(cert_der))
}

/// Parsed identity material from a DER-encoded client certificate.
struct ParsedCert {
    common_name: String,
    subject_dn: String,
    issuer_dn: String,
    policy_oids: HashSet<String>,
}

/// Extract the subject CN, subject/issuer DNs, and certificate-policy OIDs from
/// a DER-encoded client certificate.
fn parse_cert(cert_der: &[u8]) -> Result<ParsedCert, CertAuthError> {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CertAuthError::ParseError(e.to_string()))?;

    let subject_dn = cert.subject().to_string();
    let issuer_dn = cert.issuer().to_string();

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .ok_or(CertAuthError::MissingCommonName)?;

    // Collect policy OIDs from the Certificate Policies extension (RFC 5280
    // §4.2.1.4) — the standard carrier for assurance/role identifiers.
    let mut policy_oids: HashSet<String> = HashSet::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
            for policy in policies.iter() {
                policy_oids.insert(policy.policy_id.to_id_string());
            }
        }
    }

    Ok(ParsedCert {
        common_name,
        subject_dn,
        issuer_dn,
        policy_oids,
    })
}

/// Authenticate a DER-encoded client certificate against the OID->role mapping.
///
/// The TLS layer (rustls `WebPkiClientVerifier`) has already verified the chain
/// to the configured client-CA bundle before this runs; here we (1) optionally
/// constrain the issuing CA (issuer scoping), then (2) map policy OIDs to a role.
pub fn authenticate(
    cert_der: Option<&[u8]>,
    mapping: &OidRoleMapping,
) -> Result<NpeIdentity, CertAuthError> {
    let der = cert_der.ok_or(CertAuthError::NoCertificate)?;
    let parsed = parse_cert(der)?;

    // Issuer scoping (AC-3/AC-6): when configured, only certificates issued by
    // an authorized CA may carry role-granting policy OIDs.
    if !mapping.allowed_issuers.is_empty()
        && !mapping.allowed_issuers.contains(&parsed.issuer_dn)
    {
        return Err(CertAuthError::UntrustedIssuer);
    }

    let role = mapping
        .resolve(&parsed.policy_oids)
        .ok_or(CertAuthError::Unauthorized)?;
    Ok(NpeIdentity {
        common_name: parsed.common_name,
        subject_dn: parsed.subject_dn,
        role,
        fingerprint: fingerprint(der),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> OidRoleMapping {
        OidRoleMapping {
            sponsor_oids: vec!["1.2.3.1".to_string()],
            admin_oid: Some("1.2.3.2".to_string()),
            ra_oids: vec!["1.2.3.3".to_string()],
            caa_oids: vec!["1.2.3.4".to_string()],
            auditor_oids: vec!["1.2.3.5".to_string()],
            allowed_issuers: Vec::new(),
        }
    }

    fn oids(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sponsor_oid_resolves_to_sponsor() {
        assert_eq!(mapping().resolve(&oids(&["1.2.3.1"])), Some(Role::PkiSponsor));
    }

    #[test]
    fn sponsor_plus_admin_oid_resolves_to_administrator() {
        assert_eq!(
            mapping().resolve(&oids(&["1.2.3.1", "1.2.3.2"])),
            Some(Role::PkiSponsorAdmin)
        );
    }

    #[test]
    fn ra_oid_takes_precedence_over_sponsor() {
        assert_eq!(
            mapping().resolve(&oids(&["1.2.3.1", "1.2.3.3"])),
            Some(Role::RegistrationAuthority)
        );
    }

    #[test]
    fn auditor_oid_resolves_to_auditor() {
        assert_eq!(mapping().resolve(&oids(&["1.2.3.5"])), Some(Role::NpeAuditor));
    }

    #[test]
    fn auditor_oid_never_elevates_to_acting_role() {
        // A cert carrying both an auditor and an RA OID stays read-only (AC-6).
        assert_eq!(
            mapping().resolve(&oids(&["1.2.3.5", "1.2.3.3"])),
            Some(Role::NpeAuditor)
        );
    }

    #[test]
    fn caa_oid_takes_highest_precedence() {
        assert_eq!(
            mapping().resolve(&oids(&["1.2.3.1", "1.2.3.3", "1.2.3.4"])),
            Some(Role::CaaAdmin)
        );
    }

    #[test]
    fn unmapped_oid_is_unauthorized() {
        assert_eq!(mapping().resolve(&oids(&["9.9.9.9"])), None);
    }

    #[test]
    fn no_certificate_is_rejected() {
        let err = authenticate(None, &mapping()).unwrap_err();
        assert!(matches!(err, CertAuthError::NoCertificate));
    }
}
