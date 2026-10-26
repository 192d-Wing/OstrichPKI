//! gRPC transport security: mutual TLS for the CA gRPC issuance listener and
//! its clients (acme-server, est-server).
//!
//! tonic is built WITHOUT any TLS feature (`tls-ring` / `tls-aws-lc`). Tonic's
//! own TLS builds private rustls configs with TLS 1.2 enabled, so neither the
//! TLS 1.3-only floor nor `fips()` could be asserted on the configs actually
//! used. Instead this module owns both rustls configs:
//!
//! - **Server**: [`grpc_server_config`] reuses [`TlsSettings::load`] (explicit
//!   aws-lc-rs FIPS provider, TLS 1.3 only, `WebPkiClientVerifier` on the same
//!   provider), makes client authentication mandatory, restricts ALPN to `h2`
//!   and asserts [`ensure_fips`]. [`bind_mtls_incoming`] binds the TCP socket
//!   up front (bind failure is fatal), runs each handshake in its own task under
//!   a timeout and a concurrency cap, and yields [`GrpcTlsStream`]s to
//!   `tonic::transport::Server::serve_with_incoming_shutdown`.
//! - **Authorization**: [`SubjectAllowlistLayer`] is a listener-wide tower
//!   layer that maps each verified client-certificate subject to one
//!   [`GrpcClientIdentity`] (role + requestor namespace, from
//!   [`GrpcClientRegistry`]) and admits a call only when the method table
//!   ([`GrpcMethodRule`]) grants that role the exact gRPC path. Anything else
//!   is answered `PERMISSION_DENIED` (or `UNAUTHENTICATED`) after an audit
//!   record is written. Default deny, including for RPCs added later. The
//!   service binds the client-asserted `requestor` to the caller's namespace
//!   with [`AuthorizedGrpcPeer::bind_requestor`] / [`AuthorizedGrpcPeer::deny`].
//! - **Client**: [`grpc_client_config`] builds the matching TLS 1.3-only client
//!   config with the client certificate and server trust anchors, asserted by
//!   [`ensure_fips_client`]; [`GrpcTlsConnector`] dials through it and requires
//!   ALPN `h2`.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: AC-17 (Remote Access) - mTLS for inter-service gRPC
//! - NIST 800-53: AC-3 / AC-6 (Access Enforcement / Least Privilege) - per-role
//!   subject lists and a per-method rule table, default deny; AC-5
//!   (Separation of Duties) - issuer and admin identities are disjoint
//! - NIST 800-53: AU-3 / AU-10 - the verified peer is the authoritative actor;
//!   the client-asserted requestor is bound to the caller's namespace
//! - NIST 800-53: IA-3 / IA-9 / IA-5(2) (Device and Service Identification /
//!   PKI-based Authentication) - client certificate path validation to
//!   configured anchors; leaf validity re-checked per call (RFC 5280
//!   §4.1.2.5); intermediates and anchor at handshake only
//! - NIST 800-53: CM-7 (Least Functionality) - only the RPCs in the method
//!   table are reachable (default deny); AC-6(9) (Log Use of Privileged
//!   Functions) - the RevokeCertificate and GenerateCrl admin RPCs are
//!   audited with the verified peer as actor; CheckRevocationStatus is an
//!   unaudited read (only its denials are audited)
//! - NIST 800-53: SC-8 / SC-8(1) (Transmission Confidentiality and Integrity) -
//!   TLS 1.3 only
//! - NIST 800-53: SC-13 (Cryptographic Protection) - aws-lc-rs FIPS provider,
//!   `fips()` asserted on server and client configs
//! - NIST 800-53: SC-23 (Session Authenticity), SC-24 (Fail in Known State;
//!   NIAP PP-CA FPT_FLS.1)
//! - NIST 800-53: AU-2 / AU-3 / AU-12 - handshake failures and denials audited
//! - NIST 800-53: SI-10 (Input Validation) - DN and configuration parsing
//! - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.1, FCS_TLSS_EXT.2, FCS_TLSC_EXT.2,
//!   FIA_X509_EXT.1, FDP_ACC.1, FDP_ACF.1, FAU_GEN.1, FAU_GEN.2, FMT_SMR.2
//! - RFC 8446 (TLS 1.3), RFC 9325, RFC 7301 (ALPN `h2`), RFC 4514 (DN strings),
//!   RFC 5280 §6 / §4.2.1.12 (path validation, EKU via webpki)
// POAM: POAM-2026-10-23-27 - client-certificate revocation is not checked on the
// gRPC listener: the `WebPkiClientVerifier` is built without CRLs, so a revoked
// acme/est/admin client certificate is accepted until it expires
// (FIA_X509_EXT.1.1 revocation, RFC 5280 §6.3). Admin-role impact: a
// compromised operator certificate keeps RevokeCertificate / GenerateCrl /
// CheckRevocationStatus until notAfter (the per-call validity check in
// `authorize_peer` ends it no later than that). Compensating guidance: issue
// admin certificates with short validity (one per named operator), and on
// compromise remove the subject from CA_GRPC_ADMIN_CLIENT_SUBJECTS and restart
// the CA (the role lists are read at startup only). Same gap as the REST mTLS
// listeners.
// POAM: POAM-2026-10-23-28 - client-list entries (acme / est / admin) bind the
// client-certificate subject DN only, not the issuing CA or the client key
// (SPKI): any anchor in CA_GRPC_TLS_CLIENT_CA_FILE (or any CA under it) that
// issues a certificate with an allow-listed subject authorises its holder.
// Admin-role impact: another anchor or a subordinate CA could mint an admin
// subject and revoke certificates; the CA therefore refuses to start with a
// non-empty admin list and more than one distinct client trust anchor, admits
// an admin call only for a leaf issued directly by that anchor (issuer DN =
// anchor subject and leaf AKI present and equal to the anchor SKI, no DN-only
// fallback; otherwise `admin_issuer_not_anchor`, SEC-101 / SEC-201; an anchor
// without an SKI is refused at startup), and records the peer certificate issuer
// DN and serial in every gRPC audit record so a forged identity is
// distinguishable. Issuer roles may still chain through intermediates. Further mitigated by requiring a dedicated
// service-identity client CA (ca-server refuses anchors in its own chain -
// issuing CA, CAs it issued, its issuer and every ancestor in the CA database,
// see [`ensure_dedicated_client_ca`]) and by refusing, per call, leaves issued
// by the issuing CA or its ancestors (`subscriber_issuing_ca`). Compensating
// guidance: one short-lived admin certificate per operator from the dedicated
// CA; on compromise remove the subject and restart. Issuer- or SPKI-bound
// allowlist entries (defence in depth) are pending (AC-3, IA-3, IA-9).

use crate::auth::{AuthAuditEvent, AuthAuditHook, AuthAuditKind};
use crate::tls::{TlsSettings, ensure_fips, ensure_fips_client};
use crate::{Error, Result};
use futures::Stream;
use hyper_util::rt::TokioIo;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tonic::codegen::http;
use tonic::transport::server::Connected;
use x509_cert::der::Decode;
use x509_cert::der::oid::AssociatedOid;

/// Maximum time a client gets to complete the TLS handshake. A connection that
/// has not finished by then is dropped (and audited), so a slow or stalled
/// client cannot hold a handshake slot indefinitely (SC-5).
pub const GRPC_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of TLS handshakes in flight on one gRPC listener. The accept
/// loop waits for a slot when the cap is reached (back-pressure into the
/// kernel accept queue) instead of spawning unbounded handshake tasks (SC-5).
pub const GRPC_MAX_INFLIGHT_HANDSHAKES: usize = 256;

/// Maximum number of TLS handshakes in flight from one source address (one
/// IPv4 address, or one IPv6 /64). Further connections from that source are
/// closed at once, so a single client cannot hold the listener's
/// [`GRPC_MAX_INFLIGHT_HANDSHAKES`] slots with idle connections (SC-5).
pub const GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP: usize = 8;

/// Maximum accepted length of one allow-listed subject DN (bytes).
pub const MAX_ALLOWED_SUBJECT_LEN: usize = 512;

/// Environment variable names for the CA gRPC server (CM-6 baseline). The
/// values are file paths / DN lists only, never secrets.
pub const ENV_GRPC_TLS_CERT_FILE: &str = "CA_GRPC_TLS_CERT_FILE";
/// See [`ENV_GRPC_TLS_CERT_FILE`].
pub const ENV_GRPC_TLS_KEY_FILE: &str = "CA_GRPC_TLS_KEY_FILE";
/// See [`ENV_GRPC_TLS_CERT_FILE`].
pub const ENV_GRPC_TLS_CLIENT_CA_FILE: &str = "CA_GRPC_TLS_CLIENT_CA_FILE";
/// Client subjects with the `Issuer` role in the `acme` requestor namespace
/// (`;`-delimited RFC 4514 DNs). See [`ENV_GRPC_TLS_CERT_FILE`].
pub const ENV_GRPC_ACME_CLIENT_SUBJECTS: &str = "CA_GRPC_ACME_CLIENT_SUBJECTS";
/// Client subjects with the `Issuer` role in the `est` requestor namespace.
pub const ENV_GRPC_EST_CLIENT_SUBJECTS: &str = "CA_GRPC_EST_CLIENT_SUBJECTS";
/// Client subjects with the `Admin` role (`admin` namespace). Empty by default:
/// nobody may revoke, generate CRLs or query revocation status over gRPC.
pub const ENV_GRPC_ADMIN_CLIENT_SUBJECTS: &str = "CA_GRPC_ADMIN_CLIENT_SUBJECTS";
/// Removed single allowlist. Kept only so a deployment that still sets it is
/// refused at startup with a migration message (CM-6, SC-24).
pub const ENV_GRPC_ALLOWED_CLIENT_SUBJECTS: &str = "CA_GRPC_ALLOWED_CLIENT_SUBJECTS";
/// See [`ENV_GRPC_TLS_CERT_FILE`].
pub const ENV_GRPC_INSECURE_DEV_PLAINTEXT: &str = "CA_GRPC_INSECURE_DEV_PLAINTEXT";

/// ALPN protocol id for HTTP/2 (RFC 7301 / RFC 9113). gRPC runs over HTTP/2
/// only, so it is the single protocol offered and accepted.
const ALPN_H2: &[u8] = b"h2";

/// Handshake-failure audit records allowed per window before suppression.
const HANDSHAKE_AUDIT_MAX_PER_WINDOW: u32 = 60;

/// Rate-limit window for handshake-failure audit records.
const HANDSHAKE_AUDIT_WINDOW: Duration = Duration::from_secs(60);

/// Completed TLS connections queued for tonic before the handshake tasks wait.
const INCOMING_QUEUE_DEPTH: usize = 64;

/// Upper bound on the best-effort TLS `close_notify` (RFC 8446 §6.1) sent
/// before dropping a connection that is refused after the handshake.
const CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(1);

/// RFC 4514 §2.4 characters that may follow a backslash (besides two hex
/// digits), as accepted by the `x509-cert` DN parser.
const DN_ESCAPABLE: &[u8] = b" \\\"#=+,;<>";

/// gRPC status message for a refused call. Generic on purpose: it does not
/// echo the client lists, the method table, the presented subject or which
/// check failed (no role or method enumeration).
const DENIED_MESSAGE: &str = "client is not authorised for this call";

/// Maximum length of a bound requestor (bytes): `certificates.requestor` is
/// `VARCHAR(255)`.
pub const MAX_REQUESTOR_LEN: usize = 255;

/// Parse the RFC 4514 subject DN from a DER certificate.
///
/// Uses `x509-cert`'s `Name` rendering (RFC 4514 escaping, last RDN first), the
/// same form as `auth::mtls` and the trusted-proxy check, so configured subjects
/// compare verbatim. Returns `None` when the certificate does not parse, the
/// name cannot be rendered, or the subject is empty (SAN-only certificates are
/// not supported for subject-based authorization). Never panics on untrusted
/// input (SI-10; fuzzed by `fuzz_grpc_peer_subject`).
pub fn certificate_subject_dn(cert_der: &[u8]) -> Option<String> {
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    subject_dn_of(&cert)
}

/// RFC 4514 rendering of a parsed certificate's subject; `None` when it
/// cannot be rendered or is empty.
fn subject_dn_of(cert: &x509_cert::Certificate) -> Option<String> {
    use std::fmt::Write as _;

    let mut dn = String::new();
    // `write!` instead of `to_string()`: a Display error must not panic.
    write!(dn, "{}", cert.tbs_certificate.subject).ok()?;
    (!dn.is_empty()).then_some(dn)
}

/// The certificate extension with `oid`, if present.
fn find_extension(
    cert: &x509_cert::Certificate,
    oid: x509_cert::der::oid::ObjectIdentifier,
) -> Option<&x509_cert::ext::Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == oid)
}

/// Whether the certificate carries an extendedKeyUsage extension that lists
/// id-kp-clientAuth (RFC 5280 §4.2.1.12). A certificate without the extension
/// is NOT accepted here, although webpki path validation allows it.
fn has_client_auth_eku(cert: &x509_cert::Certificate) -> bool {
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    find_extension(cert, ExtendedKeyUsage::OID)
        .and_then(|ext| ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).ok())
        .is_some_and(|eku| {
            eku.0
                .contains(&x509_cert::der::oid::db::rfc5280::ID_KP_CLIENT_AUTH)
        })
}

/// subjectKeyIdentifier value (RFC 5280 §4.2.1.2), if present and parsable.
fn subject_key_id(cert: &x509_cert::Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    let ext = find_extension(cert, SubjectKeyIdentifier::OID)?;
    SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
        .ok()
        .map(|ski| ski.0.as_bytes().to_vec())
}

/// authorityKeyIdentifier keyIdentifier (RFC 5280 §4.2.1.1), if present.
fn authority_key_id(cert: &x509_cert::Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;

    let ext = find_extension(cert, AuthorityKeyIdentifier::OID)?;
    AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
        .ok()?
        .key_identifier
        .map(|kid| kid.as_bytes().to_vec())
}

/// Allow-listed client-certificate subjects for a gRPC listener, held in the
/// canonical RFC 4514 form produced by [`certificate_subject_dn`].
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3, AC-6 - only listed service identities are authorised
/// - NIST 800-53: SI-10 - entries are parsed and canonicalised at startup
/// - NIAP PP-CA: FDP_ACF.1, FMT_SMF.1 (the allowlist is management data)
#[derive(Debug, Clone)]
pub struct ClientSubjectAllowlist {
    subjects: Vec<String>,
}

impl ClientSubjectAllowlist {
    /// Parse and canonicalise configured subject DNs.
    ///
    /// Leading and unescaped trailing ASCII space/tab/CR/LF are trimmed from
    /// each entry (an escaped trailing space, `\ ` or `\20`, is part of the
    /// value and kept); non-ASCII whitespace (e.g. U+00A0, U+3000) at either
    /// end of the entry or of an attribute is rejected, never trimmed.
    /// Insignificant spaces around RDN separators and `=` are removed, and the result is parsed as an RFC 4514 DN and
    /// re-rendered, so `"CN=acme-server, O=Ostrich"` matches a certificate
    /// whose subject renders as `CN=acme-server,O=Ostrich`. RDN order and
    /// attribute values are significant (exact, case-sensitive match).
    ///
    /// Blank entries (e.g. from a trailing `;` in
    /// `CA_GRPC_ACME_CLIENT_SUBJECTS`) are dropped. Rejects a list with no
    /// non-blank entry and any unparsable or over-long (>
    /// [`MAX_ALLOWED_SUBJECT_LEN`]) entry, including entries with a dangling
    /// `\` or an invalid / ambiguous escape sequence (for example `CN=a\`,
    /// which is what `CN=a\;CN=b` becomes after the `;` split), entries whose
    /// hex escapes decode to invalid UTF-8 (e.g. `CN=\FF`), and entries
    /// whose canonical form does not parse back to the same name: a
    /// misconfigured allowlist stops the service rather than authorising
    /// nobody, or the wrong party (CM-6, SC-24 / FPT_FLS.1, SI-10).
    pub fn parse(entries: &[String]) -> Result<Self> {
        Self::parse_labelled(entries, "gRPC allowed client subject")
    }

    /// [`Self::parse`] with `label` naming the list in error messages (e.g.
    /// the environment variable the entries came from).
    fn parse_labelled(entries: &[String], label: &str) -> Result<Self> {
        let entries: Vec<(usize, &String)> = entries
            .iter()
            .enumerate()
            .filter(|(_, raw)| !raw.trim_matches(is_dn_padding).is_empty())
            .collect();
        if entries.is_empty() {
            return Err(Error::Config(format!(
                "{label} list is empty; no client would be authorised"
            )));
        }
        let mut subjects = Vec::with_capacity(entries.len());
        for (index, raw) in entries {
            let canonical = canonicalize_dn(raw).map_err(|why| {
                Error::Config(format!("{label} #{} is invalid: {why}", index + 1))
            })?;
            if !subjects.contains(&canonical) {
                subjects.push(canonical);
            }
        }
        Ok(Self { subjects })
    }

    /// Whether a certificate subject DN (as rendered by
    /// [`certificate_subject_dn`]) is allow-listed. Exact match on the
    /// canonical form; an empty subject is never allowed.
    pub fn is_allowed(&self, subject_dn: &str) -> bool {
        !subject_dn.is_empty() && self.subjects.iter().any(|s| s == subject_dn)
    }

    /// The canonical allow-listed subjects (for startup logs and audit).
    pub fn subjects(&self) -> &[String] {
        &self.subjects
    }
}

/// Whether an allowlist entry list has no non-blank entry (blank entries are
/// ASCII padding only, see [`is_dn_padding`]).
fn all_blank(entries: &[String]) -> bool {
    entries
        .iter()
        .all(|raw| raw.trim_matches(is_dn_padding).is_empty())
}

/// Role of an authorised CA gRPC client identity.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-5 (Separation of Duties), AC-6 (Least Privilege)
/// - NIAP PP-CA: FMT_SMR.2 (Security Roles)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrpcClientRole {
    /// Registration authority (acme-server, est-server): issuance and the
    /// read-only CA information RPCs.
    Issuer,
    /// Operator identity: revocation, CRL generation, revocation status.
    Admin,
}

impl GrpcClientRole {
    /// Stable lowercase name for logs and audit details.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for GrpcClientRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a verified client-certificate subject is: a role plus the fixed
/// requestor namespace (`<namespace>::<id>`) it may claim. The namespace is
/// tied to the configuration list the subject is in, never derived from the
/// certificate (no spoofing through the CN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcClientIdentity {
    /// Authorised role.
    pub role: GrpcClientRole,
    /// Requestor namespace the caller may claim (`acme`, `est`, `admin`).
    pub namespace: &'static str,
}

impl GrpcClientIdentity {
    /// acme-server: `Issuer`, `acme::<account_id>`.
    pub const ACME: Self = Self {
        role: GrpcClientRole::Issuer,
        namespace: "acme",
    };
    /// est-server: `Issuer`, `est::<client_id>`.
    pub const EST: Self = Self {
        role: GrpcClientRole::Issuer,
        namespace: "est",
    };
    /// Operator identity: `Admin`, `admin::<id>` or no requestor.
    pub const ADMIN: Self = Self {
        role: GrpcClientRole::Admin,
        namespace: "admin",
    };
}

/// The CA gRPC client identities: three disjoint lists of canonical subject
/// DNs (`CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS`,
/// `CA_GRPC_ADMIN_CLIENT_SUBJECTS`), each mapped to one
/// [`GrpcClientIdentity`].
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3, AC-5, AC-6, IA-3 / IA-9 (service identity drives
///   authorization), CM-6 (fail-closed parsing, empty admin default)
/// - NIST 800-53: SI-10 - entries are parsed by [`ClientSubjectAllowlist`]
/// - NIAP PP-CA: FMT_SMR.2, FMT_MTD.1 (role lists are management data, set
///   at startup only), FDP_ACF.1
#[derive(Debug, Clone)]
pub struct GrpcClientRegistry {
    acme: Vec<String>,
    est: Vec<String>,
    admin: Vec<String>,
}

impl GrpcClientRegistry {
    /// Parse the three role lists, failing closed.
    ///
    /// Each list that has a non-blank entry goes through
    /// [`ClientSubjectAllowlist::parse`] (same RFC 4514 canonicalisation,
    /// escape checks and length limit); an all-blank list means "none".
    /// Refuses: any malformed entry; no ACME and no EST subject at all ("no
    /// issuer client configured"); a canonical subject in more than one list,
    /// also when the two entries differ only in ASCII letter case (a client
    /// identity holds exactly one role, so its namespace is never ambiguous
    /// and issuance and revocation stay separated, AC-5; RFC-006).
    /// Duplicates within one list are dropped.
    pub fn parse(acme: &[String], est: &[String], admin: &[String]) -> Result<Self> {
        let parse_list = |entries: &[String], env: &str| -> Result<Vec<String>> {
            if all_blank(entries) {
                return Ok(Vec::new());
            }
            let label = format!("{env} entry");
            Ok(ClientSubjectAllowlist::parse_labelled(entries, &label)?.subjects)
        };
        let registry = Self {
            acme: parse_list(acme, ENV_GRPC_ACME_CLIENT_SUBJECTS)?,
            est: parse_list(est, ENV_GRPC_EST_CLIENT_SUBJECTS)?,
            admin: parse_list(admin, ENV_GRPC_ADMIN_CLIENT_SUBJECTS)?,
        };
        if registry.acme.is_empty() && registry.est.is_empty() {
            return Err(Error::Config(format!(
                "no issuer client configured: set {ENV_GRPC_ACME_CLIENT_SUBJECTS} and/or \
                 {ENV_GRPC_EST_CLIENT_SUBJECTS}; refusing to start"
            )));
        }
        let lists = [
            (ENV_GRPC_ACME_CLIENT_SUBJECTS, &registry.acme),
            (ENV_GRPC_EST_CLIENT_SUBJECTS, &registry.est),
            (ENV_GRPC_ADMIN_CLIENT_SUBJECTS, &registry.admin),
        ];
        // Deterministic order: the first overlapping pair (acme/est,
        // acme/admin, est/admin) and the first shared subject are reported.
        // RFC-006: subjects that differ only in ASCII letter case are refused
        // too (attribute values are matched exactly at runtime, but a
        // case-variant pair across roles is almost certainly a mistake, and
        // some CAs normalise case when issuing). Within one list they are
        // two distinct, exact-match entries.
        for (i, (env_a, list_a)) in lists.iter().enumerate() {
            for (env_b, list_b) in lists.iter().skip(i + 1) {
                for dn in list_a.iter() {
                    let Some(other) = list_b.iter().find(|b| b.eq_ignore_ascii_case(dn)) else {
                        continue;
                    };
                    return Err(Error::Config(if other == dn {
                        format!(
                            "gRPC client subject {dn} is listed in both {env_a} and {env_b}; \
                             a client identity may hold one role"
                        )
                    } else {
                        format!(
                            "gRPC client subjects {dn} ({env_a}) and {other} ({env_b}) differ \
                             only in letter case; a client identity may hold one role, \
                             refusing to start"
                        )
                    }));
                }
            }
        }
        Ok(registry)
    }

    /// The identity of a certificate subject DN (as rendered by
    /// [`certificate_subject_dn`]): exact match on the canonical form; an
    /// empty subject never matches.
    pub fn identity(&self, subject_dn: &str) -> Option<GrpcClientIdentity> {
        if subject_dn.is_empty() {
            return None;
        }
        let has = |list: &[String]| list.iter().any(|s| s == subject_dn);
        if has(&self.acme) {
            Some(GrpcClientIdentity::ACME)
        } else if has(&self.est) {
            Some(GrpcClientIdentity::EST)
        } else if has(&self.admin) {
            Some(GrpcClientIdentity::ADMIN)
        } else {
            None
        }
    }

    /// The canonical subjects configured for `identity`'s list (empty when
    /// none), e.g. to require an issuance profile list for each configured
    /// issuer namespace.
    pub fn subjects_for(&self, identity: GrpcClientIdentity) -> &[String] {
        match identity.namespace {
            "acme" => &self.acme,
            "est" => &self.est,
            "admin" => &self.admin,
            _ => &[],
        }
    }

    /// `{acme: [..], est: [..], admin: [..]}` with the canonical subjects,
    /// for the startup log and the `grpc_listener_started` audit record
    /// (CM-3 evidence of the effective policy).
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "acme": self.acme,
            "est": self.est,
            "admin": self.admin,
        })
    }
}

/// One entry of a listener's method table: the full gRPC path
/// (`/<package>.<Service>/<Rpc>`) and the roles allowed to call it. A path
/// without an entry is denied (`method_not_mapped`).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3, AC-6 (per-method least privilege)
/// - NIAP PP-CA: FDP_ACC.1, FDP_ACF.1
#[derive(Debug, Clone, Copy)]
pub struct GrpcMethodRule {
    /// Full gRPC request path, matched exactly (case-sensitive).
    pub path: &'static str,
    /// Roles allowed to call the method.
    pub roles: &'static [GrpcClientRole],
}

/// `[{path, roles: [..]}]` for the startup log and audit record (CM-3).
pub fn grpc_method_rules_summary(rules: &[GrpcMethodRule]) -> serde_json::Value {
    serde_json::Value::Array(
        rules
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "path": rule.path,
                    "roles": rule.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

/// Why a client-asserted `requestor` was refused by [`validate_requestor`].
/// Every rejection is answered `PERMISSION_DENIED` and audited: the requestor
/// is the caller's authorization claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestorRejection {
    /// Empty requestor from an issuer identity.
    Missing,
    /// No `::`, or a prefix other than the caller's namespace.
    NamespaceMismatch,
    /// Empty id, longer than [`MAX_REQUESTOR_LEN`] bytes, or an id with a
    /// byte outside printable ASCII `0x21..=0x7E`.
    Invalid,
}

impl RequestorRejection {
    /// Audit reason.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "requestor_missing",
            Self::NamespaceMismatch => "requestor_namespace_mismatch",
            Self::Invalid => "requestor_invalid",
        }
    }
}

impl fmt::Display for RequestorRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// Bytes allowed in the id part of a requestor (after `<namespace>::`):
/// printable ASCII `0x21..=0x7E` only. An allowlist, not a denylist, so no
/// control, separator (U+2028 / U+2029), bidi (U+061C, U+202E, ...), invisible
/// format (U+00AD, U+2060, tags) or space character can reach logs, audit
/// records or `certificates.requestor` (log / audit injection, CWE-117).
fn is_allowed_requestor_byte(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

/// Bind a client-asserted `requestor` to the caller's identity.
///
/// - Issuer (`acme` / `est`): must be `<namespace>::<id>` with the caller's
///   namespace (exact, case-sensitive), a non-empty id of printable ASCII
///   (`0x21..=0x7E`) only, at most [`MAX_REQUESTOR_LEN`] bytes in total;
///   later `::` in the id are allowed. Empty is [`RequestorRejection::Missing`].
/// - Admin: empty means "no on-behalf-of principal" (`Ok(None)`); otherwise
///   the same rules with namespace `admin`.
///
/// Returns the requestor to record (`Some`) or `None`. Pure; fuzzed by
/// `fuzz_grpc_requestor`.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SI-10 (Input Validation), AU-3 (on_behalf_of is bound to
///   the authenticated caller), AC-3
/// - NIAP PP-CA: FAU_GEN.2 (user identity association), FDP_ACF.1
pub fn validate_requestor(
    identity: GrpcClientIdentity,
    requestor: &str,
) -> std::result::Result<Option<String>, RequestorRejection> {
    if requestor.is_empty() {
        return match identity.role {
            GrpcClientRole::Admin => Ok(None),
            GrpcClientRole::Issuer => Err(RequestorRejection::Missing),
        };
    }
    let Some((prefix, id)) = requestor.split_once("::") else {
        return Err(RequestorRejection::NamespaceMismatch);
    };
    if prefix != identity.namespace {
        return Err(RequestorRejection::NamespaceMismatch);
    }
    if id.is_empty()
        || requestor.len() > MAX_REQUESTOR_LEN
        || !id.bytes().all(is_allowed_requestor_byte)
    {
        return Err(RequestorRejection::Invalid);
    }
    Ok(Some(requestor.to_string()))
}

/// Canonicalise one configured DN. The error is a static reason so the caller
/// controls what reaches logs.
///
/// RFC 4514 §2.4 / §3: escapes are validated strictly before parsing because
/// the `x509-cert` 0.2 parser is lenient in two ways that would change what
/// is allow-listed: a dangling trailing `\` (or `\` + one hex digit) is
/// silently dropped, and its separator scan treats `\\\,` (escaped
/// backslash + escaped comma) as an RDN boundary. Both are rejected, and the
/// canonical form must parse back to the same name (round trip).
fn canonicalize_dn(raw: &str) -> std::result::Result<String, &'static str> {
    use std::fmt::Write as _;
    use x509_cert::der::Encode;

    let trimmed = trim_unescaped_trailing_whitespace(raw.trim_start_matches(is_dn_padding));
    if trimmed.is_empty() {
        return Err("empty subject");
    }
    if starts_or_ends_with_unicode_space(trimmed) {
        return Err("subject starts or ends with non-ASCII whitespace");
    }
    if trimmed.len() > MAX_ALLOWED_SUBJECT_LEN {
        return Err("subject is longer than 512 bytes");
    }
    let normalized = normalize_dn_spacing(trimmed);
    validate_dn_escapes(&normalized)?;
    validate_no_unicode_space_padding(&normalized)?;
    validate_attribute_types(&normalized)?;
    let name = x509_cert::name::RdnSequence::from_str(&normalized)
        .map_err(|_| "not a valid RFC 4514 distinguished name")?;
    if name.is_empty() {
        return Err("empty subject");
    }
    let mut canonical = String::new();
    write!(canonical, "{name}").map_err(|_| "subject cannot be rendered")?;
    if canonical.is_empty() {
        return Err("empty subject");
    }
    // Round trip: parse(render(parse(x))) must equal parse(x), compared on
    // the DER encoding, so the stored form means exactly what was configured.
    let reparsed = x509_cert::name::RdnSequence::from_str(&canonical)
        .map_err(|_| "subject does not round-trip through its canonical form")?;
    let original_der = name.to_der().map_err(|_| "subject cannot be encoded")?;
    let reparsed_der = reparsed
        .to_der()
        .map_err(|_| "subject does not round-trip through its canonical form")?;
    if original_der != reparsed_der {
        return Err("subject does not round-trip through its canonical form");
    }
    Ok(canonical)
}

/// Strict RFC 4514 §2.4 escape check: every `\` must be followed by one of
/// [`DN_ESCAPABLE`] or by two hex digits, and an escaped `,` / `+` must not
/// directly follow an escaped backslash (`\\\,`), which the `x509-cert`
/// separator scan would mis-split.
fn validate_dn_escapes(dn: &str) -> std::result::Result<(), &'static str> {
    let bytes = dn.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b != b'\\' {
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            None => return Err("dangling escape: the subject ends with a backslash"),
            Some(&next) if next == b',' || next == b'+' => {
                // `i` starts an escape, so a backslash right before it is the
                // second half of an escaped backslash.
                if i > 0 && bytes.get(i - 1) == Some(&b'\\') {
                    return Err("a value with a backslash directly followed by ',' or '+' \
                                is not supported in allowlist entries (ambiguous to the DN \
                                parser, also when hex-escaped)");
                }
                i += 2;
            }
            Some(next) if DN_ESCAPABLE.contains(next) => i += 2,
            Some(next) if next.is_ascii_hexdigit() => match bytes.get(i + 2) {
                Some(low) if low.is_ascii_hexdigit() => i += 3,
                _ => return Err("incomplete hex escape (\\ must be followed by two hex digits)"),
            },
            Some(_) => return Err("invalid escape sequence"),
        }
    }
    // RFC 4514 §3 / RFC 5280 §4.1.2.4: the value is a UTF8String, so hex
    // escapes must decode to valid UTF-8 (`CN=\FF` would otherwise become a
    // malformed UTF8String that no certificate subject renders to).
    if std::str::from_utf8(&unescape_dn_bytes(bytes)).is_err() {
        return Err("hex escapes do not decode to valid UTF-8");
    }
    Ok(())
}

/// `dn` with every RFC 4514 escape decoded to its byte (`\XX` -> 0xXX,
/// `\c` -> `c`). Only called after the escapes were validated.
fn unescape_dn_bytes(dn: &[u8]) -> Vec<u8> {
    let hex = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut out = Vec::with_capacity(dn.len());
    let mut i = 0;
    while let Some(&b) = dn.get(i) {
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        match (dn.get(i + 1).copied(), dn.get(i + 2).copied()) {
            (Some(h), Some(l)) if hex(h).is_some() && hex(l).is_some() => {
                out.push(hex(h).unwrap_or(0) << 4 | hex(l).unwrap_or(0));
                i += 3;
            }
            (Some(c), _) => {
                out.push(c);
                i += 2;
            }
            (None, _) => break,
        }
    }
    out
}

/// Check every attribute type (the text before `=` of each RDN component) is
/// an RFC 4514 §3 `descr` (letter, then letters / digits / `-`) or a
/// `numericoid` whose arcs fit in 32 bits. `const-oid` 0.9 accumulates arcs
/// without overflow checks, so an over-long numeric arc would panic in
/// overflow-checked builds (found by `fuzz_grpc_peer_subject`) or wrap in
/// release builds; both are refused here first (SI-10).
fn validate_attribute_types(dn: &str) -> std::result::Result<(), &'static str> {
    let mut escaped = false;
    let mut start = 0;
    for (i, b) in dn.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b',' | b'+' => {
                check_attribute_type(dn.get(start..i).ok_or("invalid subject")?)?;
                start = i + 1;
            }
            _ => {}
        }
    }
    check_attribute_type(dn.get(start..).ok_or("invalid subject")?)
}

/// One RDN component's attribute type; see [`validate_attribute_types`].
fn check_attribute_type(component: &str) -> std::result::Result<(), &'static str> {
    const MAX_TYPE_LEN: usize = 128;

    let Some((key, _)) = component.split_once('=') else {
        return Err("attribute without '='");
    };
    let Some(first) = key.bytes().next() else {
        return Err("invalid attribute type");
    };
    if key.len() > MAX_TYPE_LEN {
        return Err("invalid attribute type");
    }
    if first.is_ascii_alphabetic() {
        return if key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            Ok(())
        } else {
            Err("invalid attribute type")
        };
    }
    // numericoid: arc 1*("." arc), each arc a u32 without leading zeros.
    let mut arcs = 0usize;
    for arc in key.split('.') {
        arcs += 1;
        if arc.is_empty()
            || !arc.bytes().all(|b| b.is_ascii_digit())
            || (arc.len() > 1 && arc.starts_with('0'))
            || arc.parse::<u32>().is_err()
        {
            return Err("invalid numeric attribute type (OID)");
        }
    }
    if arcs < 2 {
        return Err("invalid numeric attribute type (OID)");
    }
    // SI-10: const-oid 0.9 can encode some large arcs that its own decoder
    // refuses, and its Display then panics ("OID malformed"). Accept only an
    // OID that decodes again from its own encoding (found by
    // fuzz_grpc_peer_subject; operator configuration must fail closed, not
    // panic).
    use x509_cert::der::oid::ObjectIdentifier;
    let decodable = ObjectIdentifier::new(key)
        .ok()
        .is_some_and(|oid| ObjectIdentifier::from_bytes(oid.as_bytes()).is_ok());
    if !decodable {
        return Err("invalid numeric attribute type (OID)");
    }
    Ok(())
}

/// Remove insignificant spaces around unescaped `,` / `+` separators and
/// around the `=` of each attribute. Escaped characters are preserved, and an
/// escaped trailing space (`\ `) is kept (RFC 4514 §2.4).
fn normalize_dn_spacing(dn: &str) -> String {
    let mut out = String::with_capacity(dn.len());
    let mut component = String::new();
    let mut escaped = false;
    for c in dn.chars() {
        if escaped {
            component.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                component.push(c);
                escaped = true;
            }
            ',' | '+' => {
                push_dn_component(&mut out, &component);
                out.push(c);
                component.clear();
            }
            _ => component.push(c),
        }
    }
    push_dn_component(&mut out, &component);
    out
}

fn push_dn_component(out: &mut String, component: &str) {
    match component.split_once('=') {
        Some((key, value)) => {
            out.push_str(key.trim_matches(is_dn_padding));
            out.push('=');
            out.push_str(trim_unescaped_trailing_whitespace(
                value.trim_start_matches(is_dn_padding),
            ));
        }
        None => out.push_str(component.trim_matches(is_dn_padding)),
    }
}

/// Insignificant padding in allowlist entries: ASCII space, tab, CR and LF
/// only (RFC 4514 §3 "insignificant spaces" are ASCII SPACE). Unicode
/// whitespace such as U+00A0 or U+3000 is never trimmed: it would otherwise
/// let an entry `CN=a<NBSP>` allow-list `CN=a` (RFC-015).
fn is_dn_padding(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Whitespace that [`is_dn_padding`] does not trim (non-ASCII whitespace).
fn is_unicode_space(c: char) -> bool {
    c.is_whitespace() && !c.is_ascii()
}

fn starts_or_ends_with_unicode_space(s: &str) -> bool {
    s.chars().next().is_some_and(is_unicode_space)
        || s.chars().next_back().is_some_and(is_unicode_space)
}

/// Reject non-ASCII whitespace at either end of an attribute type or value
/// (after [`normalize_dn_spacing`]): it is invisible in configuration and
/// would only match a certificate carrying exactly that character, so it is
/// treated as a configuration error (SI-10, CM-6).
fn validate_no_unicode_space_padding(dn: &str) -> std::result::Result<(), &'static str> {
    let mut component = String::new();
    let mut escaped = false;
    let check = |component: &str| {
        let (key, value) = component.split_once('=').unwrap_or((component, ""));
        if starts_or_ends_with_unicode_space(key) || starts_or_ends_with_unicode_space(value) {
            Err("attribute starts or ends with non-ASCII whitespace")
        } else {
            Ok(())
        }
    };
    for c in dn.chars() {
        if escaped {
            component.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                component.push(c);
                escaped = true;
            }
            ',' | '+' => {
                check(&component)?;
                component.clear();
            }
            _ => component.push(c),
        }
    }
    check(&component)
}

/// Strip trailing ASCII padding ([`is_dn_padding`]) that is not escaped: a
/// character preceded by an odd number of backslashes (`\ `) is part of the
/// value and stops the trim.
fn trim_unescaped_trailing_whitespace(value: &str) -> &str {
    let mut rest = value;
    while let Some(last) = rest.chars().next_back().filter(|c| is_dn_padding(*c)) {
        let stripped = &rest[..rest.len() - last.len_utf8()];
        let backslashes = stripped.bytes().rev().take_while(|b| *b == b'\\').count();
        if backslashes % 2 == 1 {
            break;
        }
        rest = stripped;
    }
    rest
}

/// CA gRPC listener options as configured (CLI/env). See
/// [`GrpcServerOptions::resolve`] for the fail-closed rules.
#[derive(Debug, Clone, Default)]
pub struct GrpcServerOptions {
    /// Server certificate chain (PEM, leaf first). `CA_GRPC_TLS_CERT_FILE`.
    pub cert_path: Option<String>,
    /// Server private key (PEM). `CA_GRPC_TLS_KEY_FILE`.
    pub key_path: Option<String>,
    /// Trust anchors for client certificates (PEM). `CA_GRPC_TLS_CLIENT_CA_FILE`.
    pub client_ca_path: Option<String>,
    /// Subject DNs of acme-server identities (`Issuer`, namespace `acme`).
    /// `CA_GRPC_ACME_CLIENT_SUBJECTS` (`;`-delimited).
    pub acme_subjects: Vec<String>,
    /// Subject DNs of est-server identities (`Issuer`, namespace `est`).
    /// `CA_GRPC_EST_CLIENT_SUBJECTS` (`;`-delimited).
    pub est_subjects: Vec<String>,
    /// Subject DNs of operator identities (`Admin`, namespace `admin`).
    /// `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (`;`-delimited); empty by default.
    pub admin_subjects: Vec<String>,
    /// The removed `CA_GRPC_ALLOWED_CLIENT_SUBJECTS`; any non-blank entry
    /// refuses startup with a migration message.
    pub legacy_allowed_subjects: Vec<String>,
    /// Debug-build-only plaintext escape hatch. `CA_GRPC_INSECURE_DEV_PLAINTEXT`.
    pub insecure_dev_plaintext: bool,
}

/// The resolved CA gRPC listener mode.
pub enum GrpcServerMode {
    /// TLS 1.3 mutual TLS with per-role client subjects (the only production
    /// mode).
    Mtls {
        /// FIPS-asserted server config (ALPN `h2`, mandatory client auth).
        config: Arc<ServerConfig>,
        /// Canonical client subjects per role / namespace.
        clients: Arc<GrpcClientRegistry>,
        /// The client-certificate trust anchors read from
        /// `CA_GRPC_TLS_CLIENT_CA_FILE`, for [`ensure_dedicated_client_ca`].
        client_anchors: Arc<[CertificateDer<'static>]>,
    },
    /// Plaintext HTTP/2 with no authentication. Debug builds only.
    InsecureDevPlaintext,
}

impl fmt::Debug for GrpcServerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mtls {
                clients,
                client_anchors,
                ..
            } => f
                .debug_struct("Mtls")
                .field("clients", &clients.summary())
                .field("client_anchors", &client_anchors.len())
                .finish_non_exhaustive(),
            Self::InsecureDevPlaintext => f.write_str("InsecureDevPlaintext"),
        }
    }
}

impl GrpcServerOptions {
    /// Resolve the options into a listener mode, failing closed.
    ///
    /// | Configuration | Result |
    /// |---|---|
    /// | `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` set (any mode) | error (removed; migration message) |
    /// | cert + key + client CA + ≥1 ACME or EST subject, insecure off | `Mtls` |
    /// | any partial cert / key / client CA | error |
    /// | full TLS but no ACME and no EST subject | error (no issuer client) |
    /// | a subject in more than one role list (also ASCII-case variants), or a malformed entry | error |
    /// | admin subjects with more than one anchor in the client CA file | error |
    /// | nothing configured, insecure off | error (refuse to start) |
    /// | insecure on with any TLS option or role list set | error (ambiguous) |
    /// | insecure on, `release_build` | error (not available in release builds) |
    /// | insecure on, debug build, nothing else | `InsecureDevPlaintext` |
    ///
    /// Certificate files are loaded (and `fips()` asserted) here, so a bad file
    /// stops the process before the database connects.
    ///
    /// # COMPLIANCE MAPPING
    /// - NIST 800-53: CM-6 (secure defaults; the dev flag is refused in release
    ///   builds; empty admin list by default), SC-24 (fail in a known state),
    ///   AC-17, SC-8, AC-5 (one role per identity)
    /// - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.2, FPT_FLS.1, FMT_SMR.2
    pub fn resolve(self, release_build: bool) -> Result<GrpcServerMode> {
        // CM-6: the single allowlist no longer exists; ignoring it would
        // silently change who may call which RPC.
        if !all_blank(&self.legacy_allowed_subjects) {
            return Err(Error::Config(format!(
                "{ENV_GRPC_ALLOWED_CLIENT_SUBJECTS} is no longer supported: the CA gRPC \
                 listener authorizes per method and role. List acme-server identities in \
                 {ENV_GRPC_ACME_CLIENT_SUBJECTS}, est-server identities in \
                 {ENV_GRPC_EST_CLIENT_SUBJECTS} and operator (revocation / CRL) identities \
                 in {ENV_GRPC_ADMIN_CLIENT_SUBJECTS}, then unset \
                 {ENV_GRPC_ALLOWED_CLIENT_SUBJECTS}; refusing to start"
            )));
        }
        let any_tls =
            self.cert_path.is_some() || self.key_path.is_some() || self.client_ca_path.is_some();
        let any_subject = !all_blank(&self.acme_subjects)
            || !all_blank(&self.est_subjects)
            || !all_blank(&self.admin_subjects);

        if self.insecure_dev_plaintext {
            // NIST 800-53: CM-6 - role lists would be silently ignored by the
            // unauthenticated listener, so they are as ambiguous as TLS options.
            if any_tls || any_subject {
                return Err(Error::Config(format!(
                    "{ENV_GRPC_INSECURE_DEV_PLAINTEXT} is set together with gRPC TLS options \
                     or a client subject list ({ENV_GRPC_ACME_CLIENT_SUBJECTS}, \
                     {ENV_GRPC_EST_CLIENT_SUBJECTS}, {ENV_GRPC_ADMIN_CLIENT_SUBJECTS}); the \
                     configuration is ambiguous, refusing to start"
                )));
            }
            if release_build {
                return Err(Error::Config(format!(
                    "{ENV_GRPC_INSECURE_DEV_PLAINTEXT} is not available in release builds; \
                     configure gRPC mTLS ({ENV_GRPC_TLS_CERT_FILE}, {ENV_GRPC_TLS_KEY_FILE}, \
                     {ENV_GRPC_TLS_CLIENT_CA_FILE}, {ENV_GRPC_ACME_CLIENT_SUBJECTS} / \
                     {ENV_GRPC_EST_CLIENT_SUBJECTS}); refusing to start"
                )));
            }
            return Ok(GrpcServerMode::InsecureDevPlaintext);
        }

        let (cert, key, client_ca) = match (self.cert_path, self.key_path, self.client_ca_path) {
            (Some(cert), Some(key), Some(client_ca)) => (cert, key, client_ca),
            (None, None, None) => {
                return Err(Error::Config(format!(
                    "CA gRPC requires mTLS: set {ENV_GRPC_TLS_CERT_FILE}, {ENV_GRPC_TLS_KEY_FILE}, \
                     {ENV_GRPC_TLS_CLIENT_CA_FILE} and {ENV_GRPC_ACME_CLIENT_SUBJECTS} and/or \
                     {ENV_GRPC_EST_CLIENT_SUBJECTS}; refusing to start"
                )));
            }
            _ => {
                return Err(Error::Config(format!(
                    "partial CA gRPC TLS configuration: {ENV_GRPC_TLS_CERT_FILE}, \
                     {ENV_GRPC_TLS_KEY_FILE} and {ENV_GRPC_TLS_CLIENT_CA_FILE} are all \
                     required; refusing to start"
                )));
            }
        };

        let clients = Arc::new(GrpcClientRegistry::parse(
            &self.acme_subjects,
            &self.est_subjects,
            &self.admin_subjects,
        )?);

        let settings = TlsSettings {
            cert_path: PathBuf::from(cert),
            key_path: PathBuf::from(key),
            client_ca_path: Some(PathBuf::from(&client_ca)),
            optional_client_auth: false,
        };
        let config = grpc_server_config(&settings)?;
        // Read again for the trust-anchor checks: `TlsSettings::load` keeps
        // its own copy inside the verifier. Both reads happen here, at startup.
        // RFC-103: a certificate repeated in the bundle is one trust anchor;
        // count (and keep) each distinct DER once.
        let client_anchors: Arc<[CertificateDer<'static>]> =
            dedup_certificates(read_pem_certificates(&client_ca)?).into();
        // RFC-001 / POAM-2026-10-23-28: roles bind the subject DN only, so with
        // several anchors any of them could mint an admin subject. An admin
        // role is only configurable with exactly one (dedicated) anchor, and
        // the layer admits admin leaves issued directly by it only (SEC-101,
        // `SubjectAllowlistLayer::with_client_trust_anchors`).
        //
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AC-3, AC-6, IA-3, IA-9, CM-6, SC-24
        // - NIAP PP-CA: FIA_X509_EXT.1, FMT_SMR.2, FPT_FLS.1
        if !clients.admin.is_empty() && client_anchors.len() > 1 {
            return Err(Error::Config(format!(
                "{ENV_GRPC_ADMIN_CLIENT_SUBJECTS} is set but {ENV_GRPC_TLS_CLIENT_CA_FILE} \
                 holds {} distinct trust anchors (duplicates counted once): with an admin \
                 role the gRPC client CA file must contain exactly one dedicated \
                 service-identity CA (any anchor could issue an admin subject); refusing \
                 to start",
                client_anchors.len()
            )));
        }
        Ok(GrpcServerMode::Mtls {
            config,
            clients,
            client_anchors,
        })
    }
}

/// `certs` with byte-identical DER duplicates removed (first occurrence kept,
/// order preserved).
fn dedup_certificates(certs: Vec<CertificateDer<'static>>) -> Vec<CertificateDer<'static>> {
    let mut seen = HashSet::new();
    certs
        .into_iter()
        .filter(|cert| seen.insert(cert.as_ref().to_vec()))
        .collect()
}

/// Read every certificate from a PEM file (errors name the path only).
fn read_pem_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::Config(format!("Failed to read {path}: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse {path}: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Config(format!("No certificates found in {path}")));
    }
    Ok(certs)
}

/// Refuse a gRPC client-CA bundle that would let this CA's own subscribers
/// call the CA gRPC API.
///
/// The allowlist matches the client-certificate subject only, so every anchor
/// in `CA_GRPC_TLS_CLIENT_CA_FILE` must be a dedicated service-identity CA
/// that issues nothing else. If an anchor is in this CA's own chain, anyone
/// who can obtain a subscriber certificate with an allow-listed subject (e.g.
/// `CN=est-server` through EST or REST enrollment) would pass the allowlist.
/// An anchor is refused (startup error) when it:
///
/// - has the issuing certificate's public key (SPKI);
/// - has the issuing certificate's subject (subject alone: a re-keyed or
///   re-issued CA certificate with the same name);
/// - was issued BY the issuing CA (anchor issuer = issuing subject, or anchor
///   authorityKeyIdentifier = issuing subjectKeyIdentifier), e.g. a
///   subordinate of this CA;
/// - is the issuer named in the issuing certificate (unless both key
///   identifiers are present and differ);
/// - matches (SPKI or subject) any certificate in `ancestor_ders`, the issuing
///   CA's ancestor chain from the CA database (`ca_certificates.parent_ca_id`).
///
/// More than one anchor is allowed but logged as a warning (each anchor can
/// mint any allow-listed subject).
///
/// `issuing_ca_der` is the CA certificate the server issues with.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3, IA-3, IA-5(2) (trust anchor separation), CM-6,
///   SC-24 (refuse to start)
/// - NIAP PP-CA: FIA_X509_EXT.1, FDP_ACF.1, FPT_FLS.1
/// - RFC 5280 §6.1 (trust anchor input), §4.2.1.1 / §4.2.1.2 (AKI / SKI)
pub fn ensure_dedicated_client_ca(
    client_anchors: &[CertificateDer<'_>],
    issuing_ca_der: &[u8],
    ancestor_ders: &[&[u8]],
) -> Result<()> {
    let issuing = x509_cert::Certificate::from_der(issuing_ca_der).map_err(|_| {
        Error::Config(
            "the CA issuing certificate cannot be parsed; cannot check the gRPC client CA"
                .to_string(),
        )
    })?;
    // Fail closed: an ancestor that cannot be compared could be the anchor.
    let ancestors = ancestor_ders
        .iter()
        .enumerate()
        .map(|(depth, der)| {
            x509_cert::Certificate::from_der(der).map_err(|_| {
                Error::Config(format!(
                    "ancestor #{} of the CA issuing certificate cannot be parsed; cannot check \
                     the gRPC client CA",
                    depth + 1
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if client_anchors.len() > 1 {
        tracing::warn!(
            anchors = client_anchors.len(),
            "{ENV_GRPC_TLS_CLIENT_CA_FILE} contains more than one trust anchor: every anchor \
             can issue a certificate for any allow-listed subject; use a single dedicated \
             service-identity CA (NIST 800-53: AC-3, IA-3)"
        );
    }
    for (index, anchor_der) in client_anchors.iter().enumerate() {
        let anchor = x509_cert::Certificate::from_der(anchor_der.as_ref()).map_err(|_| {
            Error::Config(format!(
                "{ENV_GRPC_TLS_CLIENT_CA_FILE} certificate #{} cannot be parsed",
                index + 1
            ))
        })?;
        if let Some(why) = anchor_conflict(&anchor, &issuing, &ancestors) {
            return Err(Error::Config(format!(
                "{ENV_GRPC_TLS_CLIENT_CA_FILE} certificate #{} {why}. The gRPC client CA must be \
                 a dedicated service-identity CA that issues nothing else: with this CA's own \
                 issuing chain as the anchor, any subscriber certificate with an allow-listed \
                 subject could call the CA gRPC API. Refusing to start the gRPC listener",
                index + 1
            )));
        }
    }
    Ok(())
}

/// Why `anchor` must not be a gRPC client trust anchor for a CA issuing with
/// `issuing` (whose ancestors from the CA database are `ancestors`), or `None`.
fn anchor_conflict(
    anchor: &x509_cert::Certificate,
    issuing: &x509_cert::Certificate,
    ancestors: &[x509_cert::Certificate],
) -> Option<String> {
    let a = &anchor.tbs_certificate;
    let i = &issuing.tbs_certificate;
    if a.subject_public_key_info == i.subject_public_key_info {
        return Some("has the same public key (SPKI) as this CA's issuing certificate".into());
    }
    if a.subject == i.subject {
        return Some("has the same subject as this CA's issuing certificate".into());
    }
    // Issued BY the issuing CA (e.g. a subordinate of this CA): every
    // subscriber chain the issuing CA can extend would be reachable.
    let issuing_ski = subject_key_id(issuing);
    if a.issuer == i.subject || (issuing_ski.is_some() && authority_key_id(anchor) == issuing_ski) {
        return Some("was issued by this CA's issuing certificate".into());
    }
    // Subordinate issuing CA: its issuer would accept every chain through it.
    // Without key identifiers on both sides the name match alone decides
    // (fail closed).
    if i.issuer != i.subject && a.subject == i.issuer {
        match (subject_key_id(anchor), authority_key_id(issuing)) {
            (Some(ski), Some(aki)) if ski != aki => {}
            _ => return Some("is the issuer of this CA's issuing certificate".into()),
        }
    }
    for (depth, ancestor) in ancestors.iter().enumerate() {
        let c = &ancestor.tbs_certificate;
        if a.subject_public_key_info == c.subject_public_key_info || a.subject == c.subject {
            return Some(format!(
                "matches (public key or subject) ancestor #{} of this CA's issuing certificate \
                 in the CA database",
                depth + 1
            ));
        }
    }
    None
}

/// A CA that issues subscriber certificates (the issuing CA, or one of its
/// ancestors): a gRPC client leaf issued by it is refused at request time
/// (`subscriber_issuing_ca`), whatever trust anchor the chain reached.
#[derive(Clone, Debug)]
struct SubscriberIssuer {
    subject: x509_cert::name::Name,
    subject_key_id: Option<Vec<u8>>,
}

impl SubscriberIssuer {
    /// True if `leaf` names this CA as its issuer (issuer DN, or
    /// authorityKeyIdentifier = this CA's subjectKeyIdentifier).
    fn issued(&self, leaf: &x509_cert::Certificate) -> bool {
        leaf.tbs_certificate.issuer == self.subject
            || (self.subject_key_id.is_some() && authority_key_id(leaf) == self.subject_key_id)
    }
}

/// The single client trust anchor (SEC-101): an admin-role leaf must be
/// issued directly by it, not by a subordinate CA under it (the subject-only
/// allowlist would otherwise let any intermediate under the anchor mint an
/// admin subject).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3, AC-6, IA-3, IA-9
/// - NIAP PP-CA: FIA_X509_EXT.1, FMT_SMR.2
/// - RFC 5280 §4.1.2.4 (issuer), §4.2.1.1 / §4.2.1.2 (AKI / SKI)
#[derive(Clone, Debug)]
struct AdminTrustAnchor {
    subject: x509_cert::name::Name,
    subject_key_id: Option<Vec<u8>>,
}

impl AdminTrustAnchor {
    /// Parse the anchor certificate (DER).
    fn from_der(der: &[u8]) -> Result<Self> {
        let cert = x509_cert::Certificate::from_der(der).map_err(|_| {
            Error::Config(format!(
                "the {ENV_GRPC_TLS_CLIENT_CA_FILE} trust anchor cannot be parsed"
            ))
        })?;
        Ok(Self {
            subject_key_id: subject_key_id(&cert),
            subject: cert.tbs_certificate.subject,
        })
    }

    /// True if `leaf` was issued directly by this anchor: its issuer DN
    /// equals the anchor subject AND its authorityKeyIdentifier keyIdentifier
    /// is present and equals the anchor's subjectKeyIdentifier. There is no
    /// DN-only fallback (SEC-201 / NIST-202): a leaf without an AKI, or an
    /// anchor without an SKI, is not "issued directly". With admin subjects
    /// configured an anchor without an SKI is refused at startup
    /// ([`SubjectAllowlistLayer::with_client_trust_anchors`]).
    ///
    /// # COMPLIANCE MAPPING
    /// - NIST 800-53: AC-3, IA-3, IA-9 (fail closed on missing key identifiers)
    /// - NIAP PP-CA: FIA_X509_EXT.1
    /// - RFC 5280 §4.2.1.1 - AKI keyIdentifier MUST be present in
    ///   non-self-signed certificates; §4.2.1.2 - SKI MUST be present in CA
    ///   certificates
    fn issued_directly(&self, leaf: &x509_cert::Certificate) -> bool {
        if leaf.tbs_certificate.issuer != self.subject {
            return false;
        }
        match (authority_key_id(leaf), self.subject_key_id.as_ref()) {
            (Some(aki), Some(ski)) => aki == *ski,
            _ => false,
        }
    }
}

/// Signature algorithms accepted on gRPC certificate chains and in the TLS 1.3
/// CertificateVerify: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA-PSS
/// (2048-8192 bit, SHA-256/384/512) and ML-DSA-44/65/87. Mismatched
/// curve/hash pairs, P-521, Ed25519 and RSA PKCS#1 v1.5 are refused.
static GRPC_SIGNATURE_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki::aws_lc_rs::ECDSA_P256_SHA256,
        webpki::aws_lc_rs::ECDSA_P384_SHA384,
        webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki::aws_lc_rs::ML_DSA_44,
        webpki::aws_lc_rs::ML_DSA_65,
        webpki::aws_lc_rs::ML_DSA_87,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[webpki::aws_lc_rs::ECDSA_P384_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[webpki::aws_lc_rs::ECDSA_P256_SHA256],
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (SignatureScheme::ML_DSA_44, &[webpki::aws_lc_rs::ML_DSA_44]),
        (SignatureScheme::ML_DSA_65, &[webpki::aws_lc_rs::ML_DSA_65]),
        (SignatureScheme::ML_DSA_87, &[webpki::aws_lc_rs::ML_DSA_87]),
    ],
};

/// The rustls provider for the CA gRPC listener and its clients: the
/// aws-lc-rs FIPS provider with
///
/// - key exchange `SECP256R1MLKEM768` first (ECDH P-256 + ML-KEM-768, both
///   halves FIPS-approved, classical share first per SP 800-56C), then
///   `X25519MLKEM768`, P-256, P-384 (no plain X25519);
/// - signature verification narrowed to [`GRPC_SIGNATURE_ALGORITHMS`].
///
/// `fips()` stays true (asserted on every config built from it).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SC-13, SC-12 (key establishment), SC-8
/// - NIAP PP-CA: FCS_CKM.2, FCS_COP.1, FCS_TLSS_EXT.1, FCS_TLSC_EXT.2
/// - FIPS 203 (ML-KEM-768), FIPS 186-5 (ECDSA), SP 800-56A / 800-56C (hybrid)
/// - draft-ietf-tls-ecdhe-mlkem (SecP256r1MLKEM768, X25519MLKEM768)
pub fn grpc_crypto_provider() -> CryptoProvider {
    use rustls::crypto::aws_lc_rs::kx_group;

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        kx_group::SECP256R1MLKEM768,
        kx_group::X25519MLKEM768,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ];
    provider.signature_verification_algorithms = GRPC_SIGNATURE_ALGORITHMS;
    provider
}

/// Build the gRPC listener's rustls server config: [`TlsSettings::load`] on
/// [`grpc_crypto_provider`] (aws-lc-rs FIPS, TLS 1.3 only, client verifier on
/// the same provider) with mandatory client authentication and ALPN `h2`
/// only, checked by [`ensure_fips`].
///
/// Refuses settings without a client CA or with optional client auth: the gRPC
/// listener is always mutually authenticated.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SC-8, SC-13, AC-17, IA-5(2)
/// - NIAP PP-CA: FCS_TLSS_EXT.1, FCS_TLSS_EXT.2 (mutual authentication)
/// - RFC 8446 §4.4.2 (client Certificate), RFC 7301 (ALPN)
pub fn grpc_server_config(settings: &TlsSettings) -> Result<Arc<ServerConfig>> {
    if settings.client_ca_path.is_none() {
        return Err(Error::Config(format!(
            "gRPC listener requires a client CA ({ENV_GRPC_TLS_CLIENT_CA_FILE}): mutual TLS \
             is mandatory"
        )));
    }
    if settings.optional_client_auth {
        return Err(Error::Config(
            "optional client authentication is not permitted on the gRPC listener".to_string(),
        ));
    }
    let mut config = settings.load_with_provider(Arc::new(grpc_crypto_provider()))?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    ensure_fips(&config)?;
    Ok(Arc::new(config))
}

/// Build a gRPC client rustls config: explicit aws-lc-rs FIPS provider
/// ([`grpc_crypto_provider`]), TLS 1.3 only, the given trust anchors for the server certificate (verifier on the
/// same provider), the client certificate for mutual auth and ALPN `h2`,
/// checked by [`ensure_fips_client`].
///
/// Errors never include key material.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SC-8, SC-13, IA-5(2), SC-12 (client key handling)
/// - NIAP PP-CA: FCS_TLSC_EXT.2 (TLS client with mutual authentication)
/// - RFC 8446, RFC 5280 §6 (server path validation via webpki)
pub fn grpc_client_config(
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> Result<Arc<ClientConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Config(format!("Invalid gRPC client certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Config(
            "No certificates found in the gRPC client certificate PEM".to_string(),
        ));
    }

    // The pem error text describes the PEM framing only; it is still replaced
    // by a fixed message so nothing derived from the key reaches a log.
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|_| Error::Config("Invalid gRPC client private key PEM".to_string()))?;

    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let ca = ca.map_err(|e| Error::Config(format!("Invalid gRPC CA certificate PEM: {e}")))?;
        roots
            .add(ca)
            .map_err(|e| Error::Config(format!("Invalid gRPC CA certificate: {e}")))?;
    }
    if roots.is_empty() {
        return Err(Error::Config(
            "No CA certificates found for verifying the CA gRPC server".to_string(),
        ));
    }

    // Same explicit provider as the server side (SC-13): never the process
    // default, never ring.
    let provider = Arc::new(grpc_crypto_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(format!("TLS protocol configuration failed: {e}")))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::Config(format!("gRPC client certificate/key rejected: {e}")))?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    ensure_fips_client(&config)?;
    Ok(Arc::new(config))
}

/// Per-connection information exposed to the gRPC service stack (inserted into
/// every request's extensions by tonic's connect-info layer).
#[derive(Clone, Debug)]
pub struct GrpcPeerInfo {
    /// Remote socket address of the client.
    pub remote_addr: Option<SocketAddr>,
    /// The client's verified leaf certificate (DER). `Some` on every mTLS
    /// connection, since client auth is mandatory.
    pub peer_leaf: Option<CertificateDer<'static>>,
}

/// A completed server-side TLS connection on the gRPC listener.
pub struct GrpcTlsStream(tokio_rustls::server::TlsStream<TcpStream>);

impl GrpcTlsStream {
    /// Connection information (remote address, verified client leaf).
    pub fn peer_info(&self) -> GrpcPeerInfo {
        let (io, conn) = self.0.get_ref();
        GrpcPeerInfo {
            remote_addr: io.peer_addr().ok(),
            peer_leaf: conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| c.clone().into_owned()),
        }
    }
}

impl Connected for GrpcTlsStream {
    type ConnectInfo = GrpcPeerInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_info()
    }
}

impl AsyncRead for GrpcTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for GrpcTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

/// Stream of completed mTLS connections for
/// `tonic::transport::Server::serve_with_incoming_shutdown`. Dropping it (when
/// the server stops) stops the accept loop and closes the listening socket.
pub struct GrpcMtlsIncoming {
    rx: mpsc::Receiver<GrpcTlsStream>,
    local_addr: SocketAddr,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl GrpcMtlsIncoming {
    /// The bound address (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Take the accept-loop task handle (once). The loop stops when this
    /// stream is dropped (the server finished) and then writes the final
    /// suppressed-handshake summary; await the handle after `serve` returns
    /// so that record is written before the process exits (AU-2, SEC-012).
    pub fn take_accept_task(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        self.accept_task.take()
    }
}

impl Stream for GrpcMtlsIncoming {
    type Item = std::io::Result<GrpcTlsStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx).map(|item| item.map(Ok))
    }
}

/// Resource and audit limits of one gRPC mTLS listener (SC-5; supports AU-4). The
/// [`Default`] values are the production settings; tests narrow them.
#[derive(Debug, Clone)]
pub struct GrpcListenerLimits {
    /// Time a client gets to complete the TLS handshake.
    pub handshake_timeout: Duration,
    /// TLS handshakes in flight on the listener.
    pub max_inflight_handshakes: usize,
    /// TLS handshakes in flight from one source (IPv4 address / IPv6 /64).
    pub max_inflight_handshakes_per_ip: usize,
    /// Audit records of one kind (handshake failure, access denial) written
    /// per window before further ones are suppressed and summarised.
    pub audit_max_per_window: u32,
    /// Audit rate-limit window; also the period of the summary flush timer.
    pub audit_window: Duration,
}

impl Default for GrpcListenerLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: GRPC_TLS_HANDSHAKE_TIMEOUT,
            max_inflight_handshakes: GRPC_MAX_INFLIGHT_HANDSHAKES,
            max_inflight_handshakes_per_ip: GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP,
            audit_max_per_window: HANDSHAKE_AUDIT_MAX_PER_WINDOW,
            audit_window: HANDSHAKE_AUDIT_WINDOW,
        }
    }
}

impl GrpcListenerLimits {
    fn validate(&self) -> Result<()> {
        if self.handshake_timeout.is_zero()
            || self.max_inflight_handshakes == 0
            || self.max_inflight_handshakes_per_ip == 0
            || self.audit_max_per_window == 0
            || self.audit_window.is_zero()
        {
            return Err(Error::Config(
                "gRPC listener limits must all be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Bind the gRPC mTLS listener and start accepting connections.
///
/// The socket is bound before this returns, so a bind failure is a startup
/// error. Each TLS handshake runs in its own task, bounded by
/// [`GRPC_TLS_HANDSHAKE_TIMEOUT`], [`GRPC_MAX_INFLIGHT_HANDSHAKES`] and
/// [`GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP`]; only connections that complete a
/// TLS 1.3 handshake with a verified client certificate AND negotiate ALPN
/// `h2` reach tonic. Every other failure is logged and, rate-limited, audited
/// as `tls_handshake_failed` with `listener` as the target; connections that
/// close before sending anything (port probes, health checks) are logged at
/// debug level only. Suppressed-record summaries are written when the window
/// ends (timer) and when the accept loop stops.
///
/// `config` must come from [`grpc_server_config`]; it is re-checked with
/// [`ensure_fips`] and for ALPN `h2` here. Uses [`GrpcListenerLimits::default`];
/// see [`bind_mtls_incoming_with`].
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SC-8, SC-13, AC-17, SC-5 (handshake timeout and caps), AU-2,
///   supports AU-4 (audit rate limit), AU-12
/// - NIAP PP-CA: FCS_TLSS_EXT.2 (reject missing/invalid client certificates),
///   FAU_GEN.1 (TLS session establishment failures)
pub async fn bind_mtls_incoming(
    addr: SocketAddr,
    config: Arc<ServerConfig>,
    audit: Option<Arc<dyn AuthAuditHook>>,
    listener: &'static str,
) -> Result<GrpcMtlsIncoming> {
    bind_mtls_incoming_with(addr, config, audit, listener, GrpcListenerLimits::default()).await
}

/// [`bind_mtls_incoming`] with explicit [`GrpcListenerLimits`].
pub async fn bind_mtls_incoming_with(
    addr: SocketAddr,
    config: Arc<ServerConfig>,
    audit: Option<Arc<dyn AuthAuditHook>>,
    listener: &'static str,
    limits: GrpcListenerLimits,
) -> Result<GrpcMtlsIncoming> {
    ensure_fips(&config)?;
    if config.alpn_protocols != [ALPN_H2.to_vec()] {
        return Err(Error::Config(
            "gRPC listener config must offer ALPN h2 only; build it with grpc_server_config"
                .to_string(),
        ));
    }
    limits.validate()?;

    let tcp = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Config(format!("Failed to bind gRPC listener on {addr}: {e}")))?;
    let local_addr = tcp.local_addr()?;

    let (tx, rx) = mpsc::channel(INCOMING_QUEUE_DEPTH);
    let rate = RateLimitedAudit::new(
        audit,
        listener,
        AuthAuditKind::TlsHandshakeFailuresSuppressed,
        limits.audit_max_per_window,
        limits.audit_window,
    );
    let ctx = Arc::new(HandshakeContext {
        listener,
        rate,
        per_source: Mutex::new(HashMap::new()),
        max_per_source: limits.max_inflight_handshakes_per_ip,
        handshake_timeout: limits.handshake_timeout,
    });
    let accept_task = tokio::spawn(accept_loop(
        tcp,
        tokio_rustls::TlsAcceptor::from(config),
        tx,
        ctx,
        limits.max_inflight_handshakes,
    ));

    Ok(GrpcMtlsIncoming {
        rx,
        local_addr,
        accept_task: Some(accept_task),
    })
}

async fn accept_loop(
    tcp: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    tx: mpsc::Sender<GrpcTlsStream>,
    ctx: Arc<HandshakeContext>,
    max_inflight: usize,
) {
    let permits = Arc::new(Semaphore::new(max_inflight));
    loop {
        let permit = tokio::select! {
            _ = tx.closed() => break,
            permit = permits.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let (stream, remote) = tokio::select! {
            _ = tx.closed() => break,
            accepted = tcp.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Transient (e.g. EMFILE): back off briefly, keep serving.
                    tracing::warn!(listener = ctx.listener, error = %e, "gRPC accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // SC-5: per-source cap, so one client cannot hold every slot.
        let Some(source_permit) = HandshakeContext::try_acquire_source(&ctx, remote.ip()) else {
            drop(stream);
            drop(permit);
            let ctx = ctx.clone();
            tokio::spawn(async move {
                ctx.handshake_failed(remote, "per_source_handshake_limit", None)
                    .await;
            });
            continue;
        };
        // Latency matters more than throughput for unary RPCs.
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(listener = ctx.listener, error = %e, "set_nodelay failed");
        }

        let acceptor = acceptor.clone();
        let tx = tx.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let handshake =
                tokio::time::timeout(ctx.handshake_timeout, acceptor.accept(stream)).await;
            // The handshake slots are released before queueing for tonic.
            drop(source_permit);
            drop(permit);
            match handshake {
                Ok(Ok(mut tls)) => {
                    // RFC 7301: a client that offered no ALPN completes the
                    // handshake without one; gRPC requires h2.
                    if tls.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
                        // The client certificate WAS verified: record it as the
                        // actor (AU-3), then close cleanly (RFC 8446 §6.1).
                        let subject = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|certs| certs.first())
                            .and_then(|leaf| certificate_subject_dn(leaf.as_ref()));
                        let _ = tokio::time::timeout(CLOSE_NOTIFY_TIMEOUT, tls.shutdown()).await;
                        ctx.handshake_failed(remote, "no_alpn_h2", subject).await;
                        return;
                    }
                    // Err only when the server is shutting down.
                    let _ = tx.send(GrpcTlsStream(tls)).await;
                }
                Ok(Err(e)) => match classify_handshake_error(&e) {
                    Some(reason) => ctx.handshake_failed(remote, reason, None).await,
                    None => tracing::debug!(
                        listener = ctx.listener,
                        remote = %remote,
                        error = %e,
                        "gRPC connection closed before the TLS handshake"
                    ),
                },
                Err(_) => {
                    ctx.handshake_failed(remote, "handshake_timeout", None)
                        .await
                }
            }
        });
    }
    tracing::info!(listener = ctx.listener, "gRPC mTLS accept loop stopped");
    // AU-2: do not lose the count of records suppressed in the last window.
    ctx.rate.flush_all().await;
}

/// Map a server-side handshake error to an audit reason, or `None` when the
/// peer simply went away before or during the ClientHello (EOF / reset), which
/// is not a security event and is not audited (avoids audit floods from TCP
/// health checks and port scans).
fn classify_handshake_error(err: &std::io::Error) -> Option<&'static str> {
    use rustls::CertificateError as C;

    if let Some(tls) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return Some(match tls {
            rustls::Error::NoCertificatesPresented => "no_client_certificate",
            rustls::Error::InvalidCertificate(C::UnknownIssuer) => "untrusted_client_certificate",
            rustls::Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. }) => {
                "expired_client_certificate"
            }
            rustls::Error::InvalidCertificate(C::NotValidYet | C::NotValidYetContext { .. }) => {
                "client_certificate_not_yet_valid"
            }
            rustls::Error::InvalidCertificate(
                C::InvalidPurpose | C::InvalidPurposeContext { .. },
            ) => "client_certificate_wrong_eku",
            rustls::Error::InvalidCertificate(_) => "invalid_client_certificate",
            rustls::Error::PeerIncompatible(_) => "peer_incompatible",
            rustls::Error::NoApplicationProtocol => "no_application_protocol",
            rustls::Error::AlertReceived(_) => "alert_received",
            rustls::Error::PeerMisbehaved(_) => "peer_misbehaved",
            rustls::Error::InvalidMessage(_)
            | rustls::Error::InappropriateMessage { .. }
            | rustls::Error::InappropriateHandshakeMessage { .. } => "invalid_message",
            _ => "tls_error",
        });
    }
    match err.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe => None,
        _ => Some("io_error"),
    }
}

/// Source key for the per-source handshake cap: the IPv4 address (IPv4-mapped
/// IPv6 included) or the IPv6 /64, since one IPv6 host usually controls a /64.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

/// Shared state of one listener's handshake tasks.
struct HandshakeContext {
    listener: &'static str,
    rate: Arc<RateLimitedAudit>,
    /// In-flight handshakes per [`source_key`]; bounded by the listener cap.
    per_source: Mutex<HashMap<IpAddr, usize>>,
    max_per_source: usize,
    handshake_timeout: Duration,
}

/// One in-flight handshake slot of a source; released on drop.
struct SourcePermit {
    ctx: Arc<HandshakeContext>,
    key: IpAddr,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let mut map = lock_ignoring_poison(&self.ctx.per_source);
        if let Some(count) = map.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl HandshakeContext {
    /// Take a handshake slot for `ip`'s source, or `None` at the cap.
    fn try_acquire_source(ctx: &Arc<Self>, ip: IpAddr) -> Option<SourcePermit> {
        let key = source_key(ip);
        let mut map = lock_ignoring_poison(&ctx.per_source);
        let count = map.entry(key).or_insert(0);
        if *count >= ctx.max_per_source {
            return None;
        }
        *count += 1;
        Some(SourcePermit {
            ctx: ctx.clone(),
            key,
        })
    }

    /// Log and (rate-limited) audit a failed handshake.
    ///
    /// NIST 800-53: AU-2 / AU-3 (who = the verified peer subject when the
    /// handshake itself succeeded, else "unauthenticated"; what =
    /// tls_handshake_failed; where = remote IP + listener; outcome = failure).
    async fn handshake_failed(
        &self,
        remote: SocketAddr,
        reason: &'static str,
        verified_subject: Option<String>,
    ) {
        let decision = self.rate.admit(Some(remote.ip()));
        if decision.record {
            tracing::warn!(
                listener = self.listener,
                remote = %remote,
                reason,
                peer_subject = verified_subject.as_deref().unwrap_or("unauthenticated"),
                "gRPC TLS handshake failed"
            );
        } else {
            tracing::debug!(
                listener = self.listener,
                remote = %remote,
                reason,
                "gRPC TLS handshake failed (audit suppressed by rate limit)"
            );
        }
        if let Some(summary) = decision.flushed_suppressed {
            self.rate.write_summary(summary).await;
        }
        if decision.record {
            self.rate
                .record(AuthAuditEvent {
                    kind: AuthAuditKind::TlsHandshakeFailed,
                    subject: verified_subject.unwrap_or_else(|| "unauthenticated".to_string()),
                    ip_address: Some(remote.ip().to_string()),
                    reason: Some(reason.to_string()),
                    actor: None,
                    resource: Some(self.listener.to_string()),
                    details: None,
                })
                .await;
        }
    }
}

/// Lock a mutex, recovering the data if a holder panicked (the guarded state
/// is plain counters that stay consistent).
fn lock_ignoring_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Upper bound on the distinct sources a limiter window remembers for its
/// summary; beyond it the count is reported as a lower bound
/// (`distinct_sources_capped`), so a spoofed-source flood cannot grow memory.
const SUMMARY_MAX_TRACKED_SOURCES: usize = 4096;

/// What one limiter window suppressed: reported as a single summary record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SuppressedSummary {
    /// Records suppressed in the window.
    count: u64,
    /// Wall-clock start of the window (AU-8 time source of the host).
    window_start: chrono::DateTime<chrono::Utc>,
    /// Wall-clock time the window was closed for this summary.
    window_end: chrono::DateTime<chrono::Utc>,
    /// Distinct [`source_key`]s among the suppressed events (lower bound when
    /// `distinct_sources_capped`).
    distinct_sources: usize,
    distinct_sources_capped: bool,
}

/// Outcome of [`AuditRateLimiter::on_event`].
#[derive(Debug, PartialEq, Eq)]
struct LimiterDecision {
    /// Write the audit record for this event.
    record: bool,
    /// A previous window suppressed records: write one summary.
    flushed_suppressed: Option<SuppressedSummary>,
}

/// Fixed-window limiter for one kind of audit record: at most `max` per
/// `window`; the number suppressed in a window is reported once, by the first
/// event of a later window, by the flush timer, or at shutdown (AU-2 without
/// letting unauthenticated peers flood the audit store; supports AU-4, SC-5).
#[derive(Debug)]
struct AuditRateLimiter {
    max: u32,
    window: Duration,
    window_start: Instant,
    window_start_wall: chrono::DateTime<chrono::Utc>,
    recorded: u32,
    suppressed: u64,
    suppressed_sources: HashSet<IpAddr>,
    sources_capped: bool,
}

impl AuditRateLimiter {
    fn new(now: Instant, max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            window_start: now,
            window_start_wall: chrono::Utc::now(),
            recorded: 0,
            suppressed: 0,
            suppressed_sources: HashSet::new(),
            sources_capped: false,
        }
    }

    /// Start a new window if the current one has ended; returns what the ended
    /// window suppressed, if anything.
    fn roll(&mut self, now: Instant) -> Option<SuppressedSummary> {
        if now.saturating_duration_since(self.window_start) < self.window {
            return None;
        }
        let flushed = self.take_suppressed();
        self.window_start = now;
        self.window_start_wall = chrono::Utc::now();
        self.recorded = 0;
        flushed
    }

    /// Take what has been suppressed so far (for a summary), leaving zero.
    /// The next summary's window starts where this one ended.
    fn take_suppressed(&mut self) -> Option<SuppressedSummary> {
        let count = std::mem::take(&mut self.suppressed);
        let sources = std::mem::take(&mut self.suppressed_sources);
        let capped = std::mem::take(&mut self.sources_capped);
        if count == 0 {
            return None;
        }
        let window_end = chrono::Utc::now();
        let window_start = std::mem::replace(&mut self.window_start_wall, window_end);
        Some(SuppressedSummary {
            count,
            window_start,
            window_end,
            distinct_sources: sources.len(),
            distinct_sources_capped: capped,
        })
    }

    /// Count one event from `source` (the [`source_key`] of the peer, if
    /// known) and decide whether to record it.
    fn on_event(&mut self, now: Instant, source: Option<IpAddr>) -> LimiterDecision {
        let flushed_suppressed = self.roll(now);
        if self.recorded < self.max {
            self.recorded += 1;
            LimiterDecision {
                record: true,
                flushed_suppressed,
            }
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            if let Some(ip) = source {
                let key = source_key(ip);
                if self.suppressed_sources.len() < SUMMARY_MAX_TRACKED_SOURCES {
                    self.suppressed_sources.insert(key);
                } else if !self.suppressed_sources.contains(&key) {
                    self.sources_capped = true;
                }
            }
            LimiterDecision {
                record: false,
                flushed_suppressed,
            }
        }
    }
}

/// Rate-limited audit emission for one listener and one record kind, with a
/// summary record (`summary_kind`; details `count`, `window_secs`,
/// `window_start`, `window_end`, `distinct_sources`,
/// `distinct_sources_capped`) for what was suppressed. A background task
/// flushes the summary every window; the last count is flushed on
/// [`Self::flush_all`] or, best effort, on drop.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AU-2; supports AU-4 (Audit Log Storage Capacity) and AU-5
///   (the summary is the alertable signal of suppressed records); SC-5
/// - NIAP PP-CA: FAU_GEN.1
struct RateLimitedAudit {
    audit: Option<Arc<dyn AuthAuditHook>>,
    listener: &'static str,
    summary_kind: AuthAuditKind,
    window: Duration,
    limiter: Mutex<AuditRateLimiter>,
}

impl RateLimitedAudit {
    /// Create the limiter and, inside a Tokio runtime, its flush timer (which
    /// holds only a weak reference and stops when the limiter is dropped).
    fn new(
        audit: Option<Arc<dyn AuthAuditHook>>,
        listener: &'static str,
        summary_kind: AuthAuditKind,
        max: u32,
        window: Duration,
    ) -> Arc<Self> {
        let rate = Arc::new(Self {
            audit,
            listener,
            summary_kind,
            window,
            limiter: Mutex::new(AuditRateLimiter::new(Instant::now(), max, window)),
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&rate);
            handle.spawn(async move {
                let mut tick = tokio::time::interval(window);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await; // the first tick completes immediately
                loop {
                    tick.tick().await;
                    let Some(rate) = weak.upgrade() else { break };
                    rate.flush_expired().await;
                }
            });
        }
        rate
    }

    fn admit(&self, source: Option<IpAddr>) -> LimiterDecision {
        lock_ignoring_poison(&self.limiter).on_event(Instant::now(), source)
    }

    async fn record(&self, event: AuthAuditEvent) {
        if let Some(audit) = &self.audit {
            audit.record_auth_event(event).await;
        }
    }

    /// Timer: write the summary of a window that has ended.
    async fn flush_expired(&self) {
        let flushed = lock_ignoring_poison(&self.limiter).roll(Instant::now());
        if let Some(summary) = flushed {
            self.write_summary(summary).await;
        }
    }

    /// Shutdown: write whatever has been suppressed so far.
    async fn flush_all(&self) {
        let flushed = lock_ignoring_poison(&self.limiter).take_suppressed();
        if let Some(summary) = flushed {
            self.write_summary(summary).await;
        }
    }

    fn summary_event(&self, summary: &SuppressedSummary) -> AuthAuditEvent {
        AuthAuditEvent {
            kind: self.summary_kind,
            subject: "system".to_string(),
            ip_address: None,
            reason: None,
            actor: None,
            resource: Some(self.listener.to_string()),
            details: Some(serde_json::json!({
                "count": summary.count,
                "window_secs": self.window.as_secs(),
                "window_start": summary.window_start.to_rfc3339(),
                "window_end": summary.window_end.to_rfc3339(),
                "distinct_sources": summary.distinct_sources,
                "distinct_sources_capped": summary.distinct_sources_capped,
            })),
        }
    }

    async fn write_summary(&self, summary: SuppressedSummary) {
        tracing::warn!(
            listener = self.listener,
            kind = ?self.summary_kind,
            count = summary.count,
            distinct_sources = summary.distinct_sources,
            "gRPC audit records suppressed by rate limit"
        );
        self.record(self.summary_event(&summary)).await;
    }
}

impl Drop for RateLimitedAudit {
    fn drop(&mut self) {
        let flushed = match self.limiter.get_mut() {
            Ok(limiter) => limiter.take_suppressed(),
            Err(poisoned) => poisoned.into_inner().take_suppressed(),
        };
        let Some(summary) = flushed else { return };
        tracing::warn!(
            listener = self.listener,
            kind = ?self.summary_kind,
            count = summary.count,
            "gRPC audit records suppressed by rate limit (final)"
        );
        let event = self.summary_event(&summary);
        if let (Some(audit), Ok(handle)) =
            (self.audit.take(), tokio::runtime::Handle::try_current())
        {
            handle.spawn(async move { audit.record_auth_event(event).await });
        }
    }
}

/// Request extension inserted by [`SubjectAllowlistLayer`] for an authorised
/// call: the verified client-certificate subject and its
/// [`GrpcClientIdentity`]. Service handlers bind the client-asserted
/// requestor with [`Self::bind_requestor`] and refuse with [`Self::deny`],
/// which audits through the listener's rate limiter.
///
/// It can only be built by the layer (private fields), so its presence in
/// the request extensions means the call passed authentication and the
/// method table.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AU-3 (who = verified peer, with the certificate issuer and
///   serial that authenticated it), IA-3, IA-9, AC-3
/// - NIAP PP-CA: FAU_GEN.2 (user identity association)
/// - RFC 5280 §4.1.2.2 / §4.1.2.4 (serialNumber, issuer)
#[derive(Clone)]
pub struct AuthorizedGrpcPeer {
    /// Canonical RFC 4514 subject DN of the client certificate.
    pub subject_dn: String,
    /// Role and requestor namespace of the subject.
    pub identity: GrpcClientIdentity,
    /// RFC 4514 issuer DN of the client certificate (RFC-001: the role binds
    /// the subject only, so the issuer is recorded to tell certificates from
    /// different anchors apart).
    pub issuer_dn: String,
    /// Client certificate serial number: lowercase hex of the DER INTEGER
    /// content octets, sign byte included (RFC 5280 §4.1.2.2; e.g. serial
    /// 0x80 is `"0080"`; a non-conforming negative serial is rendered as its
    /// two's-complement octets, no `-`). RFC-102.
    pub serial_hex: String,
    method: String,
    remote_ip: Option<IpAddr>,
    rate: Arc<RateLimitedAudit>,
    listener: &'static str,
}

impl fmt::Debug for AuthorizedGrpcPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedGrpcPeer")
            .field("subject_dn", &self.subject_dn)
            .field("identity", &self.identity)
            .field("issuer_dn", &self.issuer_dn)
            .field("serial_hex", &self.serial_hex)
            .field("method", &self.method)
            .field("remote_ip", &self.remote_ip)
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl AuthorizedGrpcPeer {
    /// The gRPC method path of the call.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Bind a client-asserted requestor to this caller
    /// ([`validate_requestor`] with this peer's identity).
    pub fn bind_requestor(
        &self,
        requestor: &str,
    ) -> std::result::Result<Option<String>, RequestorRejection> {
        validate_requestor(self.identity, requestor)
    }

    /// Refuse the call after the listener layer admitted it (e.g. a requestor
    /// outside the caller's namespace): logs, writes a rate-limited
    /// `access_denied` record (subject = peer DN, resource = method path,
    /// remote IP, `reason`; details = `{listener, role, namespace}` merged
    /// with `details`) and resolves to `PERMISSION_DENIED`.
    ///
    /// The record is written by a task spawned when this is called, before
    /// the returned future is polled, so a client that cancels the call
    /// cannot cancel the record; awaiting the future keeps the
    /// record-before-response order. Shares the layer's limiter, so service
    /// denials and layer denials count against one window. `details` must not
    /// contain secrets.
    ///
    /// # COMPLIANCE MAPPING
    /// - NIST 800-53: AC-3 (fail closed), AU-2 / AU-3 / AU-12, supports AU-4
    /// - NIAP PP-CA: FAU_GEN.1, FDP_ACF.1, FPT_FLS.1
    pub fn deny(
        &self,
        reason: &'static str,
        details: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = tonic::Status> + Send>> {
        self.deny_with_message(reason, details, DENIED_MESSAGE)
    }

    /// [`Self::deny`] with a caller-chosen, static `PERMISSION_DENIED`
    /// message, for refusals the client can act on (e.g. a certificate
    /// profile the caller's namespace may not use). The message must not
    /// echo client input, configuration or secrets.
    pub fn deny_with_message(
        &self,
        reason: &'static str,
        details: serde_json::Value,
        message: &'static str,
    ) -> Pin<Box<dyn Future<Output = tonic::Status> + Send>> {
        let decision = self.rate.admit(self.remote_ip);
        if decision.record {
            tracing::warn!(
                listener = self.listener,
                path = %self.method,
                peer_subject = %self.subject_dn,
                role = self.identity.role.as_str(),
                remote_ip = ?self.remote_ip,
                reason,
                "gRPC call denied by the service (requestor binding)"
            );
        } else {
            tracing::debug!(
                listener = self.listener,
                path = %self.method,
                reason,
                "gRPC call denied by the service (audit suppressed by rate limit)"
            );
        }
        let mut merged = denial_details(
            self.listener,
            Some(self.identity),
            Some((&self.issuer_dn, &self.serial_hex)),
        );
        if let (Some(target), serde_json::Value::Object(extra)) = (merged.as_object_mut(), details)
        {
            target.extend(extra);
        }
        let event = decision.record.then(|| AuthAuditEvent {
            kind: AuthAuditKind::AccessDenied,
            subject: self.subject_dn.clone(),
            ip_address: self.remote_ip.map(|ip| ip.to_string()),
            reason: Some(reason.to_string()),
            actor: None,
            resource: Some(self.method.clone()),
            details: Some(merged),
        });
        let written = deny_detached(self.rate.clone(), event, decision.flushed_suppressed);
        Box::pin(async move {
            written.await;
            tonic::Status::permission_denied(message)
        })
    }
}

/// `details` of an `access_denied` record: the listener; when the subject is
/// a known client, its role and namespace; when the leaf parsed, its issuer
/// DN and serial (`peer_issuer`, `peer_serial`; RFC-001).
fn denial_details(
    listener: &'static str,
    identity: Option<GrpcClientIdentity>,
    certificate: Option<(&str, &str)>,
) -> serde_json::Value {
    let mut details = serde_json::json!({ "listener": listener });
    if let Some(map) = details.as_object_mut() {
        if let Some(identity) = identity {
            map.insert("role".to_string(), identity.role.as_str().into());
            map.insert("namespace".to_string(), identity.namespace.into());
        }
        if let Some((issuer, serial)) = certificate {
            map.insert("peer_issuer".to_string(), issuer.into());
            map.insert("peer_serial".to_string(), serial.into());
        }
    }
    details
}

/// Write a denial record (and a pending suppression summary) in a task
/// spawned NOW, and return a future that waits for it.
///
/// SEC-010 (AU-2, AU-12): the write is spawned before the caller's response
/// future exists, so dropping that future (client RST_STREAM / disconnect)
/// cannot cancel it. Dropping the returned future detaches the task; awaiting
/// it keeps the record-before-response order for calls that are not
/// cancelled. Audit failures never change the denial.
fn deny_detached(
    rate: Arc<RateLimitedAudit>,
    event: Option<AuthAuditEvent>,
    summary: Option<SuppressedSummary>,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    if event.is_none() && summary.is_none() {
        return Box::pin(std::future::ready(()));
    }
    let write = async move {
        if let Some(summary) = summary {
            rate.write_summary(summary).await;
        }
        if let Some(event) = event {
            rate.record(event).await;
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let task = handle.spawn(write);
            Box::pin(async move {
                if let Err(e) = task.await {
                    tracing::error!(error = %e, "gRPC access-denied audit task failed");
                }
            })
        }
        // Not reachable under tonic (always a Tokio runtime).
        Err(_) => Box::pin(write),
    }
}

/// Listener-wide tower layer enforcing per-method, per-role authorization on
/// every gRPC call (default deny, including RPCs added later).
///
/// Requests are authorised from the connection's [`GrpcPeerInfo`] and the
/// request path, in this order:
/// - no peer info or no client certificate: `UNAUTHENTICATED`,
///   `no_client_certificate` (defence in depth; unreachable with mandatory
///   mTLS);
/// - unparsable or empty certificate subject: `UNAUTHENTICATED`,
///   `unparsable_certificate`;
/// - leaf outside its notBefore / notAfter at call time (long-lived
///   connection, RFC-002): `UNAUTHENTICATED`, `certificate_not_valid_now`;
/// - no extendedKeyUsage extension listing clientAuth (webpki accepts a leaf
///   without the extension): `PERMISSION_DENIED`, `missing_client_auth_eku`;
/// - leaf issued by a configured subscriber-issuing CA
///   ([`Self::with_subscriber_issuing_cas`]): `PERMISSION_DENIED`,
///   `subscriber_issuing_ca`;
/// - subject in none of the [`GrpcClientRegistry`] lists:
///   `PERMISSION_DENIED`, `subject_not_allowlisted`;
/// - path not in the method table (exact, case-sensitive match):
///   `PERMISSION_DENIED`, `method_not_mapped` (not `UNIMPLEMENTED`, so the
///   method set cannot be enumerated);
/// - the subject's role not granted by the path's rule: `PERMISSION_DENIED`,
///   `method_not_permitted`.
///
/// Each denial is logged and audited (`access_denied`, target = gRPC method
/// path, details `{listener, role?, namespace?, peer_issuer?, peer_serial?}`). The audit write runs in a
/// detached task started before the response future is returned, so a client
/// that cancels the call (HTTP/2 RST_STREAM) cannot cancel the record; the
/// status is sent once the write has finished. Audit failures never turn a
/// denial into an allow. Denial records are rate limited per listener like
/// handshake failures (the overflow is summarised as
/// `access_denied_suppressed`); [`AuthorizedGrpcPeer::deny`] shares the same
/// limiter. Allowed calls carry an [`AuthorizedGrpcPeer`] extension.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: AC-3 (Access Enforcement), AC-5 / AC-6 (Separation of
///   Duties / Least Privilege: per-method role rules), CM-7 (default deny),
///   IA-3 / IA-9, AU-2, AU-3, AC-6(9) (privileged-function denials logged),
///   supports AU-4 (rate-limited denial records), AU-12, SC-24 (fail closed)
/// - RFC 5280 §4.2.1.12 (clientAuth EKU required on the leaf)
/// - NIAP PP-CA: FDP_ACC.1, FDP_ACF.1, FMT_SMR.2, FAU_GEN.1, FPT_FLS.1
#[derive(Clone)]
pub struct SubjectAllowlistLayer {
    clients: Arc<GrpcClientRegistry>,
    methods: &'static [GrpcMethodRule],
    subscriber_issuers: Arc<[SubscriberIssuer]>,
    admin_anchor: Option<Arc<AdminTrustAnchor>>,
    rate: Arc<RateLimitedAudit>,
    listener: &'static str,
}

impl SubjectAllowlistLayer {
    /// Create the layer with the default audit limits
    /// ([`GrpcListenerLimits::default`]). `methods` is the listener's method
    /// table; `listener` names the listener in logs and audit details (e.g.
    /// `"ca-grpc"`).
    pub fn new(
        clients: Arc<GrpcClientRegistry>,
        methods: &'static [GrpcMethodRule],
        audit: Option<Arc<dyn AuthAuditHook>>,
        listener: &'static str,
    ) -> Self {
        Self::with_limits(
            clients,
            methods,
            audit,
            listener,
            &GrpcListenerLimits::default(),
        )
    }

    /// Create the layer with explicit audit limits (`audit_max_per_window`,
    /// `audit_window`).
    pub fn with_limits(
        clients: Arc<GrpcClientRegistry>,
        methods: &'static [GrpcMethodRule],
        audit: Option<Arc<dyn AuthAuditHook>>,
        listener: &'static str,
        limits: &GrpcListenerLimits,
    ) -> Self {
        let rate = RateLimitedAudit::new(
            audit,
            listener,
            AuthAuditKind::AccessDeniedSuppressed,
            limits.audit_max_per_window.max(1),
            if limits.audit_window.is_zero() {
                HANDSHAKE_AUDIT_WINDOW
            } else {
                limits.audit_window
            },
        );
        Self {
            clients,
            methods,
            subscriber_issuers: Arc::from(Vec::new()),
            admin_anchor: None,
            rate,
            listener,
        }
    }

    /// Refuse client leaves issued by any of these CA certificates (DER): the
    /// CA's own issuing certificate and its ancestors. A leaf matches when its
    /// issuer DN equals the CA subject or its authorityKeyIdentifier equals the
    /// CA's subjectKeyIdentifier; the call is denied with reason
    /// `subscriber_issuing_ca` even if the chain reached a configured anchor
    /// (e.g. through a cross-certificate). Errors if a certificate cannot be
    /// parsed.
    ///
    /// # COMPLIANCE MAPPING
    /// - NIST 800-53: AC-3, IA-3 (subscriber certificates are not service
    ///   identities), SC-24
    /// - NIAP PP-CA: FIA_X509_EXT.1, FDP_ACF.1
    /// - RFC 5280 §4.1.2.4 (issuer), §4.2.1.1 / §4.2.1.2 (AKI / SKI)
    pub fn with_subscriber_issuing_cas(mut self, ca_ders: &[&[u8]]) -> Result<Self> {
        let issuers = ca_ders
            .iter()
            .enumerate()
            .map(|(index, der)| {
                let cert = x509_cert::Certificate::from_der(der).map_err(|_| {
                    Error::Config(format!(
                        "subscriber-issuing CA certificate #{} cannot be parsed",
                        index + 1
                    ))
                })?;
                Ok(SubscriberIssuer {
                    subject_key_id: subject_key_id(&cert),
                    subject: cert.tbs_certificate.subject,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.subscriber_issuers = Arc::from(issuers);
        Ok(self)
    }

    /// Set the client trust anchors (`CA_GRPC_TLS_CLIENT_CA_FILE`, as
    /// resolved into [`GrpcServerMode::Mtls`]). With exactly one distinct
    /// anchor, admin-role calls are admitted only for leaves issued directly
    /// by it (issuer DN = anchor subject and leaf AKI keyIdentifier present
    /// and equal to the anchor SKI); otherwise they are denied
    /// `admin_issuer_not_anchor` (PERMISSION_DENIED, audited). Without this
    /// call no admin call is admitted (fail closed). Errors if the registry
    /// has admin subjects and `anchors` does not hold exactly one distinct
    /// certificate, if that certificate cannot be parsed, or if it has no
    /// subjectKeyIdentifier.
    ///
    /// # COMPLIANCE MAPPING
    /// - NIST 800-53: AC-3, AC-6, IA-3, IA-9, SC-24 (fail closed)
    /// - NIAP PP-CA: FIA_X509_EXT.1, FMT_SMR.2, FPT_FLS.1
    /// - RFC 5280 §4.1.2.4, §4.2.1.1 / §4.2.1.2
    pub fn with_client_trust_anchors(mut self, anchors: &[CertificateDer<'_>]) -> Result<Self> {
        let distinct: HashSet<&[u8]> = anchors.iter().map(|a| a.as_ref()).collect();
        match distinct.len() {
            1 => {
                let der = anchors.first().map(|a| a.as_ref()).unwrap_or_default();
                let anchor = AdminTrustAnchor::from_der(der)?;
                // SEC-201 / NIST-202: the admin check matches the leaf AKI to
                // the anchor SKI (no DN-only fallback), so an anchor without
                // an SKI could never admit an admin; refuse it at startup
                // instead of failing every admin call.
                //
                // COMPLIANCE MAPPING:
                // - NIST 800-53: CM-6, IA-3, IA-9 (fail closed at startup)
                // - NIAP PP-CA: FIA_X509_EXT.1, FPT_FLS.1
                // - RFC 5280 §4.2.1.2 - CA certificates MUST include an SKI
                if !self.clients.admin.is_empty() && anchor.subject_key_id.is_none() {
                    return Err(Error::Config(format!(
                        "{ENV_GRPC_ADMIN_CLIENT_SUBJECTS} is set but the \
                         {ENV_GRPC_TLS_CLIENT_CA_FILE} trust anchor has no \
                         subjectKeyIdentifier: admin certificates are matched to the \
                         anchor by authorityKeyIdentifier (RFC 5280 §4.2.1.1/§4.2.1.2); \
                         refusing to start"
                    )));
                }
                self.admin_anchor = Some(Arc::new(anchor));
            }
            n if !self.clients.admin.is_empty() => {
                return Err(Error::Config(format!(
                    "{ENV_GRPC_ADMIN_CLIENT_SUBJECTS} is set but {ENV_GRPC_TLS_CLIENT_CA_FILE} \
                     holds {n} distinct trust anchors: admin certificates must be issued \
                     directly by a single client trust anchor; refusing to start"
                )));
            }
            _ => self.admin_anchor = None,
        }
        Ok(self)
    }

    /// Write the summary of access-denial records suppressed so far. Call
    /// after the server has stopped, so the last window's count is recorded
    /// before the process exits (AU-2, SEC-012).
    pub async fn flush_suppressed_audit(&self) {
        self.rate.flush_all().await;
    }
}

impl<S> tower::Layer<S> for SubjectAllowlistLayer {
    type Service = SubjectAllowlistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SubjectAllowlistService {
            inner,
            clients: self.clients.clone(),
            methods: self.methods,
            subscriber_issuers: self.subscriber_issuers.clone(),
            admin_anchor: self.admin_anchor.clone(),
            rate: self.rate.clone(),
            listener: self.listener,
        }
    }
}

/// Service produced by [`SubjectAllowlistLayer`].
#[derive(Clone)]
pub struct SubjectAllowlistService<S> {
    inner: S,
    clients: Arc<GrpcClientRegistry>,
    methods: &'static [GrpcMethodRule],
    subscriber_issuers: Arc<[SubscriberIssuer]>,
    admin_anchor: Option<Arc<AdminTrustAnchor>>,
    rate: Arc<RateLimitedAudit>,
    listener: &'static str,
}

/// Why a call was refused.
#[derive(Debug, PartialEq, Eq)]
struct Denial {
    code: tonic::Code,
    reason: &'static str,
    subject: Option<String>,
    /// Set when the subject is a known client (method denials).
    identity: Option<GrpcClientIdentity>,
    /// `(issuer DN, serial hex)` of the leaf, when it parsed.
    certificate: Option<(String, String)>,
}

impl Denial {
    fn permission(reason: &'static str, subject: Option<String>) -> Self {
        Self {
            code: tonic::Code::PermissionDenied,
            reason,
            subject,
            identity: None,
            certificate: None,
        }
    }
}

/// An authorised call's verified leaf: subject, identity, issuer, serial.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizedLeaf {
    subject: String,
    identity: GrpcClientIdentity,
    issuer_dn: String,
    serial_hex: String,
}

/// RFC 4514 rendering of a name (empty when it cannot be rendered).
fn name_string(name: &x509_cert::name::Name) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    if write!(out, "{name}").is_err() {
        out.clear();
    }
    out
}

/// [`authorize_peer_at`] at the current time.
fn authorize_peer(
    peer: Option<&GrpcPeerInfo>,
    clients: &GrpcClientRegistry,
    methods: &[GrpcMethodRule],
    path: &str,
    subscriber_issuers: &[SubscriberIssuer],
    admin_anchor: Option<&AdminTrustAnchor>,
) -> std::result::Result<AuthorizedLeaf, Denial> {
    authorize_peer_at(
        peer,
        clients,
        methods,
        path,
        subscriber_issuers,
        std::time::SystemTime::now(),
        admin_anchor,
    )
}

/// Authorise a call at time `now`: authenticate the connection's peer
/// (a parsable leaf that is valid at `now`; refusing leaves issued by a
/// subscriber-issuing CA), map its subject to an identity in `clients`, then
/// check `path` against the method table. Pure, for testing.
///
/// RFC-002: the leaf's validity is re-checked on every call, because the TLS
/// handshake only checked it once and an HTTP/2 connection can outlive the
/// certificate (`certificate_not_valid_now`, `UNAUTHENTICATED`: the
/// credential itself is no longer acceptable, so this is an authentication
/// failure, not an authorization one). Only the leaf is re-checked: the
/// validity of intermediates and the anchor is checked at the handshake only
/// (RFC-101 / SEC-104; the admin role has no intermediates, see SEC-101).
///
/// SEC-101: a call the method table grants to the admin role is admitted
/// only when the leaf was issued directly by `admin_anchor` (the single
/// client trust anchor); otherwise, or when no anchor is set, it is denied
/// `admin_issuer_not_anchor` (PERMISSION_DENIED).
///
/// `now` is the system clock in production ([`authorize_peer`]).
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: IA-3 / IA-9 / IA-5(2) (credential validity per call),
///   AC-3, AC-6, CM-7 (default deny), AU-8 (system clock as time source)
/// - NIAP PP-CA: FIA_X509_EXT.1, FDP_ACF.1, FMT_SMR.2, FPT_STM.1 (reliable
///   time stamps for the validity check)
/// - RFC 5280 §4.1.2.5 (leaf validity: notBefore <= now <= notAfter)
fn authorize_peer_at(
    peer: Option<&GrpcPeerInfo>,
    clients: &GrpcClientRegistry,
    methods: &[GrpcMethodRule],
    path: &str,
    subscriber_issuers: &[SubscriberIssuer],
    now: std::time::SystemTime,
    admin_anchor: Option<&AdminTrustAnchor>,
) -> std::result::Result<AuthorizedLeaf, Denial> {
    let Some(leaf) = peer.and_then(|p| p.peer_leaf.as_ref()) else {
        return Err(Denial {
            code: tonic::Code::Unauthenticated,
            reason: "no_client_certificate",
            subject: None,
            identity: None,
            certificate: None,
        });
    };
    // RFC-005: a leaf that cannot be parsed is an authentication failure.
    let Some((cert, subject)) = x509_cert::Certificate::from_der(leaf.as_ref())
        .ok()
        .and_then(|cert| subject_dn_of(&cert).map(|subject| (cert, subject)))
    else {
        return Err(Denial {
            code: tonic::Code::Unauthenticated,
            ..Denial::permission("unparsable_certificate", None)
        });
    };
    let issuer_dn = name_string(&cert.tbs_certificate.issuer);
    // RFC-102 / RFC 5280 §4.1.2.2: hex of the DER INTEGER content octets,
    // sign byte included (see `AuthorizedGrpcPeer::serial_hex`).
    let serial_hex = hex::encode(cert.tbs_certificate.serial_number.as_bytes());
    let certificate = Some((issuer_dn.clone(), serial_hex.clone()));
    let deny = |code: tonic::Code, reason: &'static str, identity| Denial {
        code,
        reason,
        subject: Some(subject.clone()),
        identity,
        certificate: certificate.clone(),
    };
    let validity = &cert.tbs_certificate.validity;
    if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
        return Err(deny(
            tonic::Code::Unauthenticated,
            "certificate_not_valid_now",
            None,
        ));
    }
    // RFC 5280 §4.2.1.12: webpki only checks the EKU when the extension is
    // present; service identities must assert clientAuth explicitly.
    if !has_client_auth_eku(&cert) {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "missing_client_auth_eku",
            None,
        ));
    }
    // Defence in depth for the startup trust-anchor check: a subscriber
    // certificate of this CA is never a service identity (AC-3, IA-3).
    if subscriber_issuers.iter().any(|ca| ca.issued(&cert)) {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "subscriber_issuing_ca",
            None,
        ));
    }
    let Some(identity) = clients.identity(&subject) else {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "subject_not_allowlisted",
            None,
        ));
    };
    // AC-3 / AC-6 / CM-7: exact path match; anything not in the table is denied.
    let Some(rule) = methods.iter().find(|rule| rule.path == path) else {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "method_not_mapped",
            Some(identity),
        ));
    };
    if !rule.roles.contains(&identity.role) {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "method_not_permitted",
            Some(identity),
        ));
    }
    // SEC-101 / POAM-2026-10-23-28: the admin role binds the subject only, so
    // the leaf must come straight from the single client trust anchor; a
    // subordinate CA under it cannot mint an admin identity. Fail closed when
    // no anchor is configured.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3, AC-6, IA-3, IA-9, SC-24
    // - NIAP PP-CA: FIA_X509_EXT.1, FMT_SMR.2, FDP_ACF.1
    // - RFC 5280 §4.1.2.4 (issuer), §4.2.1.1 (AKI)
    if identity.role == GrpcClientRole::Admin
        && !admin_anchor.is_some_and(|anchor| anchor.issued_directly(&cert))
    {
        return Err(deny(
            tonic::Code::PermissionDenied,
            "admin_issuer_not_anchor",
            Some(identity),
        ));
    }
    Ok(AuthorizedLeaf {
        subject,
        identity,
        issuer_dn,
        serial_hex,
    })
}

impl<S, B, ResBody> tower::Service<http::Request<B>> for SubjectAllowlistService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let peer = req.extensions().get::<GrpcPeerInfo>().cloned();
        let path = req.uri().path().to_string();
        let remote = peer.as_ref().and_then(|p| p.remote_addr).map(|a| a.ip());
        match authorize_peer(
            peer.as_ref(),
            &self.clients,
            self.methods,
            &path,
            &self.subscriber_issuers,
            self.admin_anchor.as_deref(),
        ) {
            Ok(leaf) => {
                tracing::debug!(
                    listener = self.listener,
                    path = %path,
                    peer_subject = %leaf.subject,
                    peer_issuer = %leaf.issuer_dn,
                    peer_serial = %leaf.serial_hex,
                    role = leaf.identity.role.as_str(),
                    "gRPC call authorised by the method table"
                );
                req.extensions_mut().insert(AuthorizedGrpcPeer {
                    subject_dn: leaf.subject,
                    identity: leaf.identity,
                    issuer_dn: leaf.issuer_dn,
                    serial_hex: leaf.serial_hex,
                    method: path,
                    remote_ip: remote,
                    rate: self.rate.clone(),
                    listener: self.listener,
                });
                // Call the instance that was driven to readiness.
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(async move { inner.call(req).await })
            }
            Err(denial) => {
                let remote_ip = remote.map(|ip| ip.to_string());
                let decision = self.rate.admit(remote);
                if decision.record {
                    tracing::warn!(
                        listener = self.listener,
                        path = %path,
                        peer_subject = denial.subject.as_deref().unwrap_or("unknown"),
                        remote_ip = remote_ip.as_deref().unwrap_or("unknown"),
                        reason = denial.reason,
                        "gRPC call denied by the listener authorization layer"
                    );
                } else {
                    tracing::debug!(
                        listener = self.listener,
                        path = %path,
                        reason = denial.reason,
                        "gRPC call denied (audit suppressed by rate limit)"
                    );
                }
                let status = match (denial.code, denial.reason) {
                    (tonic::Code::Unauthenticated, "no_client_certificate") => {
                        tonic::Status::unauthenticated("client certificate required")
                    }
                    (tonic::Code::Unauthenticated, _) => {
                        tonic::Status::unauthenticated("client certificate not accepted")
                    }
                    _ => tonic::Status::permission_denied(DENIED_MESSAGE),
                };
                let event = decision.record.then(|| AuthAuditEvent {
                    kind: AuthAuditKind::AccessDenied,
                    subject: denial.subject.unwrap_or_else(|| "unknown".to_string()),
                    ip_address: remote_ip,
                    reason: Some(denial.reason.to_string()),
                    actor: None,
                    resource: Some(path),
                    details: Some(denial_details(
                        self.listener,
                        denial.identity,
                        denial
                            .certificate
                            .as_ref()
                            .map(|(issuer, serial)| (issuer.as_str(), serial.as_str())),
                    )),
                });
                let written = deny_detached(self.rate.clone(), event, decision.flushed_suppressed);
                Box::pin(async move {
                    written.await;
                    Ok(status.into_http())
                })
            }
        }
    }
}

/// tower connector that dials the CA gRPC server over TCP + TLS 1.3 with a
/// [`grpc_client_config`] config, for `Endpoint::connect_with_connector`.
///
/// Verifies the server certificate against `server_name` (not the dialled
/// host, when they differ) and refuses a connection that did not negotiate
/// ALPN `h2`. Because tonic is built without a TLS feature, the endpoint's
/// `https://` scheme does not make tonic add its own TLS layer.
///
/// # COMPLIANCE MAPPING
/// - NIST 800-53: SC-8, SC-13, IA-5(2), SC-23
/// - NIAP PP-CA: FCS_TLSC_EXT.2, FTP_ITC.1
#[derive(Clone)]
pub struct GrpcTlsConnector {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
}

impl GrpcTlsConnector {
    /// Create a connector. `config` must report FIPS and offer ALPN `h2` only;
    /// `server_name` is the DNS name or IP address the server certificate must
    /// be valid for.
    pub fn new(config: Arc<ClientConfig>, server_name: &str) -> Result<Self> {
        ensure_fips_client(&config)?;
        if config.alpn_protocols != [ALPN_H2.to_vec()] {
            return Err(Error::Config(
                "gRPC client config must offer ALPN h2 only; build it with grpc_client_config"
                    .to_string(),
            ));
        }
        let server_name = ServerName::try_from(server_name.to_string()).map_err(|e| {
            Error::InvalidConfiguration(format!("Invalid gRPC TLS server name: {e}"))
        })?;
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(config),
            server_name,
        })
    }
}

/// Host (without IPv6 brackets) and port of a gRPC endpoint URI.
fn uri_host_port(uri: &http::Uri) -> std::io::Result<(String, u16)> {
    let host = uri
        .host()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "gRPC endpoint has no host",
            )
        })?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("http") {
            80
        } else {
            443
        });
    Ok((host.to_string(), port))
}

/// Default TLS server name for an endpoint URL: its host.
pub(crate) fn endpoint_host(uri: &http::Uri) -> Option<String> {
    uri_host_port(uri).ok().map(|(host, _)| host)
}

impl tower::Service<http::Uri> for GrpcTlsConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let connector = self.connector.clone();
        let server_name = self.server_name.clone();
        Box::pin(async move {
            let (host, port) = uri_host_port(&uri)?;
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            if let Err(e) = tcp.set_nodelay(true) {
                tracing::debug!(error = %e, "set_nodelay failed");
            }
            let mut tls = connector.connect(server_name, tcp).await?;
            if tls.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
                // Best-effort close_notify before dropping (RFC 8446 §6.1).
                let _ = tokio::time::timeout(CLOSE_NOTIFY_TIMEOUT, tls.shutdown()).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "CA gRPC server did not negotiate ALPN h2",
                ));
            }
            Ok(TokioIo::new(tls))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };

    fn s(v: &str) -> String {
        v.to_string()
    }

    struct Pki {
        ca: CertifiedIssuer<'static, KeyPair>,
        /// PKCS#8 DER of the CA key (for re-signing tests).
        ca_key_der: Vec<u8>,
    }

    impl Pki {
        fn new(cn: &str) -> Self {
            Self::new_with(cn, &rcgen::PKCS_ECDSA_P256_SHA256)
        }

        fn new_with(cn: &str, alg: &'static rcgen::SignatureAlgorithm) -> Self {
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("ca params");
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, cn);
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let key = KeyPair::generate_for(alg).expect("ca key");
            let ca_key_der = key.serialize_der();
            Self {
                ca: CertifiedIssuer::self_signed(p, key).expect("ca cert"),
                ca_key_der,
            }
        }

        /// Issue a leaf with an explicit key algorithm and EKU list (empty =
        /// no extendedKeyUsage extension); returns (cert PEM, cert DER, key PEM).
        fn leaf_with(
            &self,
            cn: &str,
            san: &str,
            ekus: Vec<ExtendedKeyUsagePurpose>,
            alg: &'static rcgen::SignatureAlgorithm,
        ) -> (String, Vec<u8>, String) {
            let mut p = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, cn);
            p.extended_key_usages = ekus;
            // RFC 5280 §4.2.1.1: AKI in non-self-signed certificates (the
            // admin anchor check requires it, SEC-201).
            p.use_authority_key_identifier_extension = true;
            let key = KeyPair::generate_for(alg).expect("leaf key");
            let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
            (cert.pem(), cert.der().to_vec(), key.serialize_pem())
        }

        /// Issue a leaf with the given DN (ASN.1 order) and EKU; returns
        /// (cert PEM, cert DER, key PEM).
        fn leaf(
            &self,
            dn: &[(DnType, &str)],
            san: &str,
            eku: ExtendedKeyUsagePurpose,
        ) -> (String, Vec<u8>, String) {
            let mut p = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
            p.distinguished_name = DistinguishedName::new();
            for (t, v) in dn {
                p.distinguished_name.push(t.clone(), *v);
            }
            p.extended_key_usages = vec![eku];
            // RFC 5280 §4.2.1.1: AKI in non-self-signed certificates (the
            // admin anchor check requires it, SEC-201).
            p.use_authority_key_identifier_extension = true;
            let key = KeyPair::generate().expect("leaf key");
            let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
            (cert.pem(), cert.der().to_vec(), key.serialize_pem())
        }
    }

    fn write_tmp(tag: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ostrich-grpc-tls-{}-{tag}-{:?}.pem",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).expect("write temp pem");
        path
    }

    // ---- allowlist (AC-3 / SI-10) ----

    #[test]
    fn allowlist_canonicalises_spacing() {
        let list =
            ClientSubjectAllowlist::parse(&[s("  CN = acme-server ,  O=Ostrich ")]).expect("parse");
        assert_eq!(list.subjects(), &[s("CN=acme-server,O=Ostrich")]);

        // Certificate whose subject renders the same (ASN.1 order O, CN).
        let pki = Pki::new("Allowlist CA");
        let (_, der, _) = pki.leaf(
            &[
                (DnType::OrganizationName, "Ostrich"),
                (DnType::CommonName, "acme-server"),
            ],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let dn = certificate_subject_dn(&der).expect("dn");
        assert_eq!(dn, "CN=acme-server,O=Ostrich");
        assert!(list.is_allowed(&dn));
    }

    /// SI-10 (fuzz `fuzz_grpc_peer_subject`, round 2): a numeric attribute
    /// type that const-oid 0.9 encodes but cannot decode again (its Display
    /// would panic) is refused as a configuration error, never a panic.
    #[test]
    fn allowlist_refuses_undecodable_numeric_oid() {
        for entry in [
            "2.2.106.2.2.2122195112=x",
            "2.2.106.2.2.2122195112=.9.06.2.2.212219519=#9",
            "1.2.4294967295=x",
            "2.4294967295=x",
        ] {
            let got = std::panic::catch_unwind(|| ClientSubjectAllowlist::parse(&[s(entry)]));
            let Ok(result) = got else {
                panic!("{entry:?} panicked");
            };
            if let Ok(list) = result {
                // Accepted entries must render without panicking.
                assert!(!list.subjects().is_empty(), "{entry:?}");
            }
        }
        // Ordinary numeric types still work.
        let list = ClientSubjectAllowlist::parse(&[s("2.5.4.3=acme-server")]).expect("cn oid");
        assert_eq!(list.subjects(), &[s("CN=acme-server")]);
    }

    #[test]
    fn allowlist_rdn_order_matters() {
        let list = ClientSubjectAllowlist::parse(&[s("CN=a,O=b")]).expect("parse");
        assert!(list.is_allowed("CN=a,O=b"));
        assert!(!list.is_allowed("O=b,CN=a"));
    }

    #[test]
    fn allowlist_matches_escaped_comma_value() {
        let list = ClientSubjectAllowlist::parse(&[s(r"CN=Ostrich\, Inc.")]).expect("parse");
        let pki = Pki::new("Escape CA");
        let (_, der, _) = pki.leaf(
            &[(DnType::CommonName, "Ostrich, Inc.")],
            "ostrich.example",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let dn = certificate_subject_dn(&der).expect("dn");
        assert_eq!(dn, r"CN=Ostrich\, Inc.");
        assert!(list.is_allowed(&dn));
    }

    #[test]
    fn allowlist_keeps_escaped_trailing_space() {
        assert_eq!(trim_unescaped_trailing_whitespace(r"abc\ "), r"abc\ ");
        assert_eq!(trim_unescaped_trailing_whitespace(r"abc\  \t"), r"abc\  \t");
        assert_eq!(trim_unescaped_trailing_whitespace("abc\\  \n"), r"abc\ ");
        assert_eq!(trim_unescaped_trailing_whitespace(r"abc\\  "), r"abc\\");
        assert_eq!(trim_unescaped_trailing_whitespace("abc   "), "abc");
        // RFC-011: a whole entry ending in an escaped space keeps it (the
        // entry-level trim honours the escape), as a raw `\ ` or `\20`, and
        // matches a certificate whose CN ends in a space.
        for entry in [r"CN=a\ ", "CN=a\\  ", r"CN=a\20", " CN = a\\  \t"] {
            let list = ClientSubjectAllowlist::parse(&[s(entry)]).expect(entry);
            assert_eq!(list.subjects(), &[s(r"CN=a\ ")], "{entry:?}");
        }
        let pki = Pki::new("Trailing Space CA");
        let (_, der, _) = pki.leaf(
            &[(DnType::CommonName, "a ")],
            "a.example",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let subject = certificate_subject_dn(&der).expect("subject");
        assert!(
            ClientSubjectAllowlist::parse(&[s(r"CN=a\ ")])
                .expect("parse")
                .is_allowed(&subject)
        );
        // Unescaped trailing spaces are insignificant.
        let plain = ClientSubjectAllowlist::parse(&[s("CN=a   ")]).expect("plain");
        assert_eq!(plain.subjects(), &[s("CN=a")]);
    }

    /// RFC-015: only ASCII space/tab/CR/LF is insignificant padding. NBSP
    /// (U+00A0) and IDEOGRAPHIC SPACE (U+3000) are never trimmed: at either
    /// end of the entry or of an attribute they are rejected, so `CN=a<NBSP>`
    /// can never allow-list `CN=a`.
    #[test]
    fn allowlist_does_not_trim_unicode_whitespace() {
        for bad in [
            "CN=a\u{a0}",
            "\u{a0}CN=a",
            "CN=a\u{3000}",
            "\u{3000}CN=a",
            "CN=\u{a0}a",
            "CN=\u{3000}a",
            "CN=a\u{3000} \t",
            " \u{a0}CN=a",
            "CN=a\u{a0},O=x",
            "O=x,CN=a\u{3000}",
            "O=x+CN=\u{a0}a",
            "CN\u{a0}=a",
            "\u{a0}",
            "\u{3000}",
        ] {
            let err = ClientSubjectAllowlist::parse(&[s(bad)])
                .expect_err(bad)
                .to_string();
            assert!(err.contains("non-ASCII whitespace"), "{bad:?}: {err}");
        }
        // Interior Unicode whitespace is significant (kept, exact match).
        let list = ClientSubjectAllowlist::parse(&[s("CN=a\u{a0}b")]).expect("interior NBSP");
        assert_eq!(list.subjects(), &[s("CN=a\u{a0}b")]);
        assert!(!list.is_allowed("CN=a b"));
        assert!(!list.is_allowed("CN=ab"));
        // ASCII padding is still trimmed.
        let list =
            ClientSubjectAllowlist::parse(&[s(" \t\r\nCN = a , O = x \r\n")]).expect("ascii");
        assert_eq!(list.subjects(), &[s("CN=a,O=x")]);
        assert_eq!(trim_unescaped_trailing_whitespace("a\u{a0}"), "a\u{a0}");
        assert_eq!(trim_unescaped_trailing_whitespace("a\u{3000}"), "a\u{3000}");
    }

    #[test]
    fn allowlist_rejects_hex_escapes_that_are_not_utf8() {
        for bad in [
            r"CN=\FF",
            r"CN=\E9",
            r"CN=a\C3",
            r"CN=\C3\28",
            r"O=x,CN=\80",
        ] {
            let err = ClientSubjectAllowlist::parse(&[s(bad)])
                .expect_err(bad)
                .to_string();
            assert!(err.contains("UTF-8"), "{bad:?}: {err}");
        }
        // Valid multi-byte UTF-8 via hex escapes is accepted.
        let ok = ClientSubjectAllowlist::parse(&[s(r"CN=\C3\A9")]).expect("utf-8");
        assert_eq!(ok.subjects(), &[s("CN=\u{e9}")]);
        // The ambiguous-escape hint no longer recommends hex escapes, which
        // fail the round trip as well.
        let err = ClientSubjectAllowlist::parse(&[s(r"CN=a\\\,O=b")])
            .expect_err("ambiguous")
            .to_string();
        assert!(!err.contains(r"\5C"), "{err}");
        assert!(err.contains("not supported"), "{err}");
        assert!(ClientSubjectAllowlist::parse(&[s(r"CN=a\5C\2CO=b")]).is_err());
    }

    #[test]
    fn allowlist_rejects_invalid_entries() {
        assert!(ClientSubjectAllowlist::parse(&[]).is_err(), "empty list");
        assert!(
            ClientSubjectAllowlist::parse(&[s("")]).is_err(),
            "empty entry"
        );
        assert!(
            ClientSubjectAllowlist::parse(&[s("   ")]).is_err(),
            "blank entry"
        );
        assert!(
            ClientSubjectAllowlist::parse(&[s("not a dn")]).is_err(),
            "unparsable entry"
        );
        assert!(
            ClientSubjectAllowlist::parse(&[s("CN=ok"), s("bogus")]).is_err(),
            "one bad entry fails the whole list"
        );
        let long = format!("CN={}", "a".repeat(MAX_ALLOWED_SUBJECT_LEN));
        assert!(ClientSubjectAllowlist::parse(&[long]).is_err(), "too long");
    }

    #[test]
    fn allowlist_never_allows_empty_subject() {
        let list = ClientSubjectAllowlist::parse(&[s("CN=acme-server")]).expect("parse");
        assert!(!list.is_allowed(""));
        assert!(!list.is_allowed("CN=est-server"));
    }

    #[test]
    fn certificate_subject_dn_handles_garbage_and_empty_subject() {
        assert_eq!(certificate_subject_dn(b"not a certificate"), None);
        assert_eq!(certificate_subject_dn(&[]), None);
        let pki = Pki::new("Empty CA");
        let (_, der, _) = pki.leaf(&[], "san-only.example", ExtendedKeyUsagePurpose::ClientAuth);
        assert_eq!(certificate_subject_dn(&der), None, "empty subject");
    }

    // ---- GrpcServerOptions::resolve truth table (CM-6 / SC-24) ----

    fn full_options(pki_tag: &str) -> GrpcServerOptions {
        let srv = Pki::new("Resolve Server CA");
        let cli = Pki::new("Resolve Client CA");
        let (cert, _, key) = srv.leaf(
            &[(DnType::CommonName, "ca-service")],
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        GrpcServerOptions {
            cert_path: Some(
                write_tmp(&format!("{pki_tag}-cert"), &cert)
                    .display()
                    .to_string(),
            ),
            key_path: Some(
                write_tmp(&format!("{pki_tag}-key"), &key)
                    .display()
                    .to_string(),
            ),
            client_ca_path: Some(
                write_tmp(&format!("{pki_tag}-ca"), &cli.ca.pem())
                    .display()
                    .to_string(),
            ),
            acme_subjects: vec![s("CN=acme-server")],
            est_subjects: vec![s("CN=est-server")],
            ..Default::default()
        }
    }

    #[test]
    fn resolve_full_config_is_mtls() {
        let mode = full_options("full").resolve(true).expect("mtls");
        match mode {
            GrpcServerMode::Mtls {
                config,
                clients,
                client_anchors,
            } => {
                assert!(config.fips());
                assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
                assert_eq!(
                    clients.identity("CN=acme-server"),
                    Some(GrpcClientIdentity::ACME)
                );
                assert_eq!(
                    clients.identity("CN=est-server"),
                    Some(GrpcClientIdentity::EST)
                );
                assert_eq!(client_anchors.len(), 1);
            }
            _ => panic!("expected Mtls mode"),
        }
    }

    #[test]
    fn resolve_rejects_partial_tls() {
        for drop_field in 0..3 {
            let mut o = full_options(&format!("partial{drop_field}"));
            match drop_field {
                0 => o.cert_path = None,
                1 => o.key_path = None,
                _ => o.client_ca_path = None,
            }
            assert!(o.resolve(true).is_err(), "partial #{drop_field} accepted");
        }
    }

    #[test]
    fn resolve_rejects_empty_allowlist() {
        let mut o = full_options("noallow");
        o.acme_subjects.clear();
        o.est_subjects = vec![s(" ")];
        o.admin_subjects = vec![s("CN=ops-admin")];
        let err = o.resolve(true).expect_err("no issuer");
        assert!(
            err.to_string().contains("no issuer client configured"),
            "{err}"
        );
    }

    #[test]
    fn resolve_refuses_to_start_without_config() {
        let err = GrpcServerOptions::default()
            .resolve(true)
            .expect_err("unconfigured");
        assert!(err.to_string().contains("refusing to start"));
        assert!(err.to_string().contains(ENV_GRPC_TLS_CERT_FILE));
        assert!(GrpcServerOptions::default().resolve(false).is_err());
    }

    #[test]
    fn resolve_insecure_rules() {
        // Ambiguous: insecure + TLS options.
        let mut o = full_options("ambig");
        o.insecure_dev_plaintext = true;
        assert!(o.resolve(false).is_err());

        // Ambiguous: insecure + an allow-listed subject (NIST-013).
        let err = GrpcServerOptions {
            insecure_dev_plaintext: true,
            admin_subjects: vec![s("CN=ops-admin")],
            ..Default::default()
        }
        .resolve(false)
        .expect_err("insecure + role list");
        assert!(err.to_string().contains("ambiguous"), "{err}");
        // A blank allowlist value does not count.
        assert!(matches!(
            GrpcServerOptions {
                insecure_dev_plaintext: true,
                acme_subjects: vec![s(" ")],
                est_subjects: vec![s("")],
                admin_subjects: vec![s("\t")],
                ..Default::default()
            }
            .resolve(false),
            Ok(GrpcServerMode::InsecureDevPlaintext)
        ));

        let insecure = || GrpcServerOptions {
            insecure_dev_plaintext: true,
            ..Default::default()
        };
        let err = insecure().resolve(true).expect_err("release build");
        assert!(err.to_string().contains("not available in release builds"));
        assert!(matches!(
            insecure().resolve(false),
            Ok(GrpcServerMode::InsecureDevPlaintext)
        ));
    }

    // ---- grpc_server_config / grpc_client_config (SC-8 / SC-13) ----

    #[test]
    fn grpc_server_config_requires_mandatory_client_ca() {
        let srv = Pki::new("Cfg Server CA");
        let (cert, _, key) = srv.leaf(
            &[(DnType::CommonName, "ca-service")],
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let mut settings = TlsSettings {
            cert_path: write_tmp("cfg-cert", &cert),
            key_path: write_tmp("cfg-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        assert!(grpc_server_config(&settings).is_err(), "no client CA");
        settings.client_ca_path = Some(write_tmp("cfg-ca", &srv.ca.pem()));
        settings.optional_client_auth = true;
        assert!(
            grpc_server_config(&settings).is_err(),
            "optional client auth"
        );
        settings.optional_client_auth = false;
        let config = grpc_server_config(&settings).expect("config");
        assert!(config.fips());
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn grpc_client_config_is_fips_tls13_h2() {
        let pki = Pki::new("Client Cfg CA");
        let (cert, _, key) = pki.leaf(
            &[(DnType::CommonName, "acme-server")],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let config = grpc_client_config(&cert, &key, &pki.ca.pem()).expect("client config");
        assert!(config.fips());
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(config.crypto_provider().kx_groups.iter().all(|g| g.fips()));

        assert!(grpc_client_config(&cert, "garbage", &pki.ca.pem()).is_err());
        assert!(grpc_client_config(&cert, &key, "garbage").is_err());
        assert!(grpc_client_config("", &key, &pki.ca.pem()).is_err());
        // Wrong key for the certificate.
        let other = KeyPair::generate().expect("key").serialize_pem();
        assert!(grpc_client_config(&cert, &other, &pki.ca.pem()).is_err());
    }

    #[test]
    fn grpc_client_config_error_never_contains_key_text() {
        let pki = Pki::new("Redact CA");
        let (cert, _, key) = pki.leaf(
            &[(DnType::CommonName, "acme-server")],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        // Corrupt the key body so parsing fails.
        let broken = key.replace('A', "!");
        let err = grpc_client_config(&cert, &broken, &pki.ca.pem())
            .expect_err("broken key")
            .to_string();
        assert!(!err.contains("PRIVATE KEY"));
        assert_eq!(
            err,
            "Configuration error: Invalid gRPC client private key PEM"
        );
    }

    /// TLS 1.3-only + ALPN: an in-memory handshake between the two configs
    /// negotiates TLS 1.3 / h2; a TLS 1.2-only client is refused.
    #[test]
    fn grpc_configs_handshake_tls13_h2_only() {
        let srv = Pki::new("HS Server CA");
        let cli = Pki::new("HS Client CA");
        let (s_cert, _, s_key) = srv.leaf(
            &[(DnType::CommonName, "ca-service")],
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (c_cert, _, c_key) = cli.leaf(
            &[(DnType::CommonName, "acme-server")],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let server = grpc_server_config(&TlsSettings {
            cert_path: write_tmp("hs-cert", &s_cert),
            key_path: write_tmp("hs-key", &s_key),
            client_ca_path: Some(write_tmp("hs-ca", &cli.ca.pem())),
            optional_client_auth: false,
        })
        .expect("server config");
        let client = grpc_client_config(&c_cert, &c_key, &srv.ca.pem()).expect("client config");

        let conn = handshake(server.clone(), client).expect("handshake");
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(srv.ca.pem().as_bytes()).expect("root"))
            .expect("add");
        let tls12 = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls12")
        .with_root_certificates(roots)
        .with_client_auth_cert(
            CertificateDer::pem_slice_iter(c_cert.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("certs"),
            PrivateKeyDer::from_pem_slice(c_key.as_bytes()).expect("key"),
        )
        .expect("client auth");
        assert!(handshake(server, Arc::new(tls12)).is_err());
    }

    fn handshake(
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
    ) -> std::result::Result<rustls::ServerConnection, rustls::Error> {
        let mut s = rustls::ServerConnection::new(server)?;
        let mut c = rustls::ClientConnection::new(
            client,
            ServerName::try_from("localhost").expect("name"),
        )?;
        for _ in 0..20 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).expect("client write");
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd).expect("server read");
            }
            s.process_new_packets()?;
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).expect("server write");
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                c.read_tls(&mut rd).expect("client read");
            }
            c.process_new_packets()?;
            if !s.is_handshaking() && !c.is_handshaking() {
                return Ok(s);
            }
        }
        panic!("handshake did not complete");
    }

    // ---- authorization decision ----

    const P_ISSUE: &str = "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate";
    const P_REVOKE: &str = "/ostrich.ca.v1.CertificateAuthorityService/RevokeCertificate";
    const P_CRL: &str = "/ostrich.ca.v1.CertificateAuthorityService/GenerateCrl";
    const P_STATUS: &str = "/ostrich.ca.v1.CertificateAuthorityService/CheckRevocationStatus";
    const P_INFO: &str = "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo";
    const P_PROFILES: &str = "/ostrich.ca.v1.CertificateAuthorityService/ListProfiles";

    /// The CA policy table (mirrors `ostrich_ca::grpc_authz`).
    const RULES: &[GrpcMethodRule] = &[
        GrpcMethodRule {
            path: P_ISSUE,
            roles: &[GrpcClientRole::Issuer],
        },
        GrpcMethodRule {
            path: P_REVOKE,
            roles: &[GrpcClientRole::Admin],
        },
        GrpcMethodRule {
            path: P_CRL,
            roles: &[GrpcClientRole::Admin],
        },
        GrpcMethodRule {
            path: P_STATUS,
            roles: &[GrpcClientRole::Admin],
        },
        GrpcMethodRule {
            path: P_INFO,
            roles: &[GrpcClientRole::Issuer, GrpcClientRole::Admin],
        },
        GrpcMethodRule {
            path: P_PROFILES,
            roles: &[GrpcClientRole::Issuer, GrpcClientRole::Admin],
        },
    ];

    /// `(subject, identity)` of an authorisation decision.
    fn si(
        r: std::result::Result<AuthorizedLeaf, Denial>,
    ) -> std::result::Result<(String, GrpcClientIdentity), Denial> {
        r.map(|leaf| (leaf.subject, leaf.identity))
    }

    fn registry(acme: &[&str], est: &[&str], admin: &[&str]) -> Result<GrpcClientRegistry> {
        let v = |l: &[&str]| l.iter().map(|x| s(x)).collect::<Vec<_>>();
        GrpcClientRegistry::parse(&v(acme), &v(est), &v(admin))
    }

    fn acme_only(subject: &str) -> GrpcClientRegistry {
        registry(&[subject], &[], &[]).expect("registry")
    }

    #[test]
    fn authorize_peer_decisions() {
        let pki = Pki::new("Authz CA");
        let allow = acme_only("CN=acme-server");
        let cert = |cn: &str| {
            let (_, der, _) = pki.leaf(
                &[(DnType::CommonName, cn)],
                "x.example",
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            }
        };

        assert_eq!(
            si(authorize_peer(
                Some(&cert("acme-server")),
                &allow,
                RULES,
                P_ISSUE,
                &[],
                None
            )),
            Ok((s("CN=acme-server"), GrpcClientIdentity::ACME))
        );
        let denied = authorize_peer(Some(&cert("intruder")), &allow, RULES, P_ISSUE, &[], None)
            .expect_err("deny");
        assert_eq!(denied.code, tonic::Code::PermissionDenied);
        assert_eq!(denied.reason, "subject_not_allowlisted");
        assert_eq!(denied.subject.as_deref(), Some("CN=intruder"));

        let none = authorize_peer(None, &allow, RULES, P_ISSUE, &[], None).expect_err("no peer");
        assert_eq!(none.code, tonic::Code::Unauthenticated);
        let no_leaf = GrpcPeerInfo {
            remote_addr: None,
            peer_leaf: None,
        };
        assert_eq!(
            authorize_peer(Some(&no_leaf), &allow, RULES, P_ISSUE, &[], None)
                .expect_err("no leaf")
                .code,
            tonic::Code::Unauthenticated
        );
        let garbage = GrpcPeerInfo {
            remote_addr: None,
            peer_leaf: Some(CertificateDer::from(b"junk".to_vec())),
        };
        let bad =
            authorize_peer(Some(&garbage), &allow, RULES, P_ISSUE, &[], None).expect_err("garbage");
        // RFC-005: an unparsable leaf is an authentication failure.
        assert_eq!(bad.code, tonic::Code::Unauthenticated);
        assert_eq!(bad.reason, "unparsable_certificate");
    }

    // ---- handshake-failure classification and rate limiting (AU-2 / SC-5) ----

    #[test]
    fn classify_handshake_errors() {
        let eof = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        assert_eq!(classify_handshake_error(&eof), None, "EOF is not audited");
        let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert_eq!(classify_handshake_error(&reset), None);

        let wrap = |e: rustls::Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        assert_eq!(
            classify_handshake_error(&wrap(rustls::Error::NoCertificatesPresented)),
            Some("no_client_certificate")
        );
        assert_eq!(
            classify_handshake_error(&wrap(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))),
            Some("untrusted_client_certificate")
        );
        assert_eq!(
            classify_handshake_error(&wrap(rustls::Error::NoApplicationProtocol)),
            Some("no_application_protocol")
        );
        let other = std::io::Error::other("boom");
        assert_eq!(classify_handshake_error(&other), Some("io_error"));
    }

    #[test]
    fn handshake_audit_limiter_suppresses_and_summarises() {
        let t0 = Instant::now();
        let ip = |last: u8| Some(IpAddr::from([10, 0, 0, last]));
        let mut limiter =
            AuditRateLimiter::new(t0, HANDSHAKE_AUDIT_MAX_PER_WINDOW, HANDSHAKE_AUDIT_WINDOW);
        for _ in 0..HANDSHAKE_AUDIT_MAX_PER_WINDOW {
            assert_eq!(
                limiter.on_event(t0, ip(1)),
                LimiterDecision {
                    record: true,
                    flushed_suppressed: None
                }
            );
        }
        // 5 suppressed from 3 distinct sources (and one unknown source).
        for source in [ip(1), ip(2), ip(2), ip(3), None] {
            assert!(!limiter.on_event(t0, source).record);
        }
        let next = limiter.on_event(t0 + HANDSHAKE_AUDIT_WINDOW, ip(1));
        assert!(next.record);
        let summary = next.flushed_suppressed.expect("summary");
        assert_eq!(summary.count, 5);
        assert_eq!(summary.distinct_sources, 3);
        assert!(!summary.distinct_sources_capped);
        assert!(summary.window_start <= summary.window_end);
        // The summary is emitted once.
        assert_eq!(
            limiter
                .on_event(t0 + HANDSHAKE_AUDIT_WINDOW, ip(1))
                .flushed_suppressed,
            None
        );

        // Timer flush (`roll`) and shutdown flush (`take_suppressed`).
        let mut limiter = AuditRateLimiter::new(t0, 1, Duration::from_secs(1));
        assert!(limiter.on_event(t0, ip(1)).record);
        assert!(!limiter.on_event(t0, ip(1)).record);
        assert!(!limiter.on_event(t0, ip(1)).record);
        assert_eq!(limiter.roll(t0), None, "window not over");
        let rolled = limiter.roll(t0 + Duration::from_secs(1)).expect("rolled");
        assert_eq!((rolled.count, rolled.distinct_sources), (2, 1));
        assert_eq!(limiter.roll(t0 + Duration::from_secs(2)), None, "once");
        let t3 = t0 + Duration::from_secs(3);
        assert!(limiter.on_event(t3, ip(1)).record);
        assert!(!limiter.on_event(t3, ip(9)).record);
        assert_eq!(limiter.take_suppressed().map(|s| s.count), Some(1));
        assert_eq!(limiter.take_suppressed(), None);
    }

    /// NIST NIT-1: the distinct-source set is bounded; past the bound the
    /// count is a lower bound and flagged.
    #[test]
    fn suppressed_summary_source_count_is_bounded() {
        let t0 = Instant::now();
        let mut limiter = AuditRateLimiter::new(t0, 0, Duration::from_secs(60));
        let total = SUMMARY_MAX_TRACKED_SOURCES + 10;
        for n in 0..total {
            let n = u32::try_from(n).expect("small");
            limiter.on_event(t0, Some(IpAddr::from(n.to_be_bytes())));
        }
        let summary = limiter.take_suppressed().expect("summary");
        assert_eq!(summary.count, total as u64);
        assert_eq!(summary.distinct_sources, SUMMARY_MAX_TRACKED_SOURCES);
        assert!(summary.distinct_sources_capped);
    }

    /// SI-10 robustness (interim for `fuzz_grpc_peer_subject`): random bytes,
    /// bit-flipped real certificates and random DN strings never panic the
    /// subject parser or the allowlist. Deterministic xorshift for replay.
    #[test]
    fn subject_parsing_never_panics_on_mutated_input() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let allow = ClientSubjectAllowlist::parse(&[s("CN=acme-server")]).expect("parse");
        let pki = Pki::new("Fuzz CA");
        let (_, der, _) = pki.leaf(
            &[
                (DnType::OrganizationName, "Ostrich"),
                (DnType::CommonName, "acme-server"),
            ],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        for _ in 0..3000 {
            // Bit-flip / truncate a real certificate.
            let mut m = der.clone();
            for _ in 0..(next() % 8 + 1) {
                let i = (next() as usize) % m.len();
                m[i] ^= 1 << (next() % 8);
            }
            m.truncate((next() as usize) % (m.len() + 1));
            if let Some(dn) = certificate_subject_dn(&m) {
                let _ = allow.is_allowed(&dn);
            }
            // Random bytes.
            let random: Vec<u8> = (0..(next() % 96)).map(|_| next() as u8).collect();
            let _ = certificate_subject_dn(&random);
            // Random DN-ish strings for the config parser.
            const ALPHABET: &[u8] = b"CNOU=,+\\ #\"abc019;";
            let text: String = (0..(next() % 64))
                .map(|_| ALPHABET[(next() as usize) % ALPHABET.len()] as char)
                .collect();
            let _ = ClientSubjectAllowlist::parse(std::slice::from_ref(&text));
            let _ = canonicalize_dn(&text);
        }
    }

    #[test]
    fn uri_host_port_defaults_and_ipv6() {
        let uri: http::Uri = "https://ca-service:50051".parse().expect("uri");
        assert_eq!(uri_host_port(&uri).expect("hp"), (s("ca-service"), 50051));
        let uri: http::Uri = "https://[::1]:50051".parse().expect("uri");
        assert_eq!(uri_host_port(&uri).expect("hp"), (s("::1"), 50051));
        let uri: http::Uri = "https://ca.example".parse().expect("uri");
        assert_eq!(uri_host_port(&uri).expect("hp").1, 443);
    }

    // ---- R3: allowlist escape handling (RFC 4514 §2.4, SI-10) ----

    #[test]
    fn allowlist_rejects_dangling_and_ambiguous_escapes() {
        for bad in [
            "2333333333333333333333333333=x", // OID arc overflow (fuzz crash)
            "2.5.4.99999999999=x",            // OID arc > u32
            "2.=x",                           // malformed numeric OID
            "C N=x",                          // invalid descriptor
            r"CN=a\",                         // dangling escape (what `CN=a\;CN=b` splits into)
            r"CN=a\\\,O=b", // escaped backslash + escaped comma: x509-cert mis-splits
            r"CN=a\\\+O=b", // same for a multi-valued RDN separator
            r"CN=a\4",      // incomplete hex escape
            r"CN=a\4g",     // invalid hex escape
            r"CN=a\x",      // not an RFC 4514 escapable character
        ] {
            assert!(
                ClientSubjectAllowlist::parse(&[s(bad)]).is_err(),
                "accepted {bad:?}"
            );
        }
        // The `;` split of `CN=a\;CN=b` must not allow-list anything.
        assert!(ClientSubjectAllowlist::parse(&[s(r"CN=a\"), s("CN=b")]).is_err());
    }

    #[test]
    fn allowlist_accepts_valid_escapes_and_drops_blank_entries() {
        // A single entry with an escaped `;` is ONE subject whose CN contains
        // `;` (no widening).
        let one = ClientSubjectAllowlist::parse(&[s(r"CN=a\;CN=b")]).expect("escaped ;");
        assert_eq!(one.subjects(), &[s(r"CN=a\;CN=b")]);
        assert!(!one.is_allowed("CN=a"));
        assert!(!one.is_allowed("CN=b"));
        // Even backslash run before a separator: escaped backslash, then a
        // real RDN boundary.
        let two = ClientSubjectAllowlist::parse(&[s(r"CN=a\\,O=b")]).expect("escaped \\");
        assert_eq!(two.subjects(), &[s(r"CN=a\\,O=b")]);
        // Numeric OID attribute types are accepted (2.5.4.3 = CN).
        let oid = ClientSubjectAllowlist::parse(&[s("2.5.4.3=acme-server")]).expect("oid");
        assert_eq!(oid.subjects(), &[s("CN=acme-server")]);
        // Hex escape renders canonically.
        let hex = ClientSubjectAllowlist::parse(&[s(r"CN=a\2Cb")]).expect("hex");
        assert_eq!(hex.subjects(), &[s(r"CN=a\,b")]);
        // Trailing `;` -> blank entry, dropped.
        let trailing = ClientSubjectAllowlist::parse(&[s("CN=a"), s("CN=b"), s("")]).expect("ok");
        assert_eq!(trailing.subjects(), &[s("CN=a"), s("CN=b")]);
        // All blank is still empty -> refused.
        assert!(ClientSubjectAllowlist::parse(&[s(""), s(" ")]).is_err());
    }

    // ---- R1: trust-anchor separation (SEC-001 / RFC-001 / NIST-003) ----

    fn der_of(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).expect("pem")
    }

    #[test]
    fn dedicated_client_ca_check() {
        let issuing = Pki::new("OstrichPKI Issuing CA");
        let issuing_der = issuing.ca.der().to_vec();

        // Same certificate.
        let err = ensure_dedicated_client_ca(&[der_of(&issuing.ca.pem())], &issuing_der, &[])
            .expect_err("same cert")
            .to_string();
        assert!(err.contains("same public key"), "{err}");
        assert!(err.contains("dedicated service-identity CA"), "{err}");

        // Re-issued certificate for the same key (same SPKI).
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name
            .push(DnType::CommonName, "Renamed Issuing CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let same_key = KeyPair::try_from(issuing.ca_key_der.as_slice()).expect("key");
        let renamed = p.self_signed(&same_key).expect("cert");
        assert!(
            ensure_dedicated_client_ca(&[der_of(&renamed.pem())], &issuing_der, &[]).is_err(),
            "same SPKI under another name"
        );

        // A subordinate issuing CA: its parent must not be the client anchor.
        let root = Pki::new("Offline Root CA");
        let mut sub = CertificateParams::new(Vec::<String>::new()).expect("params");
        sub.distinguished_name = DistinguishedName::new();
        sub.distinguished_name
            .push(DnType::CommonName, "Subordinate Issuing CA");
        sub.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        sub.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        sub.use_authority_key_identifier_extension = true;
        let sub_key = KeyPair::generate().expect("key");
        let sub_cert = sub.signed_by(&sub_key, &root.ca).expect("sub");
        let err = ensure_dedicated_client_ca(&[der_of(&root.ca.pem())], sub_cert.der(), &[])
            .expect_err("parent")
            .to_string();
        assert!(
            err.contains("issuer of this CA's issuing certificate"),
            "{err}"
        );

        // A dedicated service-identity CA is accepted, also alongside another
        // unrelated anchor (warning only).
        let dedicated = Pki::new("Service Identity CA");
        ensure_dedicated_client_ca(&[der_of(&dedicated.ca.pem())], &issuing_der, &[])
            .expect("dedicated");
        let other = Pki::new("Second Service Identity CA");
        ensure_dedicated_client_ca(
            &[der_of(&dedicated.ca.pem()), der_of(&other.ca.pem())],
            &issuing_der,
            &[],
        )
        .expect("two dedicated anchors");
        // ... but not when any anchor conflicts.
        assert!(
            ensure_dedicated_client_ca(
                &[der_of(&dedicated.ca.pem()), der_of(&issuing.ca.pem())],
                &issuing_der,
                &[]
            )
            .is_err()
        );
        assert!(
            ensure_dedicated_client_ca(&[], b"junk", &[]).is_err(),
            "bad issuing cert"
        );
    }

    /// The resolved mode carries exactly the anchors from the client-CA file.
    #[test]
    fn resolve_exposes_client_anchors_for_the_check() {
        let mode = full_options("anchors").resolve(true).expect("mtls");
        let GrpcServerMode::Mtls { client_anchors, .. } = mode else {
            panic!("expected Mtls");
        };
        assert_eq!(client_anchors.len(), 1);
        let anchor = x509_cert::Certificate::from_der(client_anchors[0].as_ref()).expect("der");
        assert_eq!(
            anchor.tbs_certificate.subject.to_string(),
            "CN=Resolve Client CA"
        );
    }

    // ---- R1 / RFC-008: clientAuth EKU must be present ----

    #[test]
    fn authorize_peer_requires_client_auth_eku_extension() {
        let pki = Pki::new("EKU CA");
        let allow = acme_only("CN=acme-server");
        let peer = |ekus: Vec<ExtendedKeyUsagePurpose>| {
            let (_, der, _) = pki.leaf_with(
                "acme-server",
                "acme-server",
                ekus,
                &rcgen::PKCS_ECDSA_P256_SHA256,
            );
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            }
        };
        let denied = authorize_peer(Some(&peer(vec![])), &allow, RULES, P_ISSUE, &[], None)
            .expect_err("no EKU");
        assert_eq!(denied.code, tonic::Code::PermissionDenied);
        assert_eq!(denied.reason, "missing_client_auth_eku");
        assert_eq!(denied.subject.as_deref(), Some("CN=acme-server"));

        let server_only = authorize_peer(
            Some(&peer(vec![ExtendedKeyUsagePurpose::ServerAuth])),
            &allow,
            RULES,
            P_ISSUE,
            &[],
            None,
        )
        .expect_err("serverAuth only");
        assert_eq!(server_only.reason, "missing_client_auth_eku");

        assert_eq!(
            si(authorize_peer(
                Some(&peer(vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth
                ])),
                &allow,
                RULES,
                P_ISSUE,
                &[],
                None
            )),
            Ok((s("CN=acme-server"), GrpcClientIdentity::ACME))
        );
    }

    // ---- R13 / R14 / R15: gRPC provider (PQC-001/002/003) ----

    #[test]
    fn grpc_provider_groups_and_signature_algorithms() {
        use rustls::NamedGroup;
        let provider = grpc_crypto_provider();
        assert!(provider.fips());
        let groups: Vec<NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            vec![
                NamedGroup::secp256r1MLKEM768,
                NamedGroup::X25519MLKEM768,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]
        );
        let schemes: Vec<SignatureScheme> = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect();
        for refused in [
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
        ] {
            assert!(!schemes.contains(&refused), "{refused:?} offered");
        }
        assert_eq!(provider.signature_verification_algorithms.all.len(), 8);
    }

    /// Server + client on a P-384 / SHA-384 chain negotiate the FIPS hybrid
    /// group SecP256r1MLKEM768 and report `fips()` on the live connection.
    #[test]
    fn p384_chain_negotiates_secp256r1mlkem768() {
        let p384 = &rcgen::PKCS_ECDSA_P384_SHA384;
        let srv = Pki::new_with("P384 Server CA", p384);
        let cli = Pki::new_with("P384 Client CA", p384);
        let (s_cert, _, s_key) = srv.leaf_with(
            "ca-service",
            "localhost",
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            p384,
        );
        let (c_cert, _, c_key) = cli.leaf_with(
            "acme-server",
            "acme-server",
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            p384,
        );
        let server = grpc_server_config(&TlsSettings {
            cert_path: write_tmp("p384-cert", &s_cert),
            key_path: write_tmp("p384-key", &s_key),
            client_ca_path: Some(write_tmp("p384-ca", &cli.ca.pem())),
            optional_client_auth: false,
        })
        .expect("server");
        let client = grpc_client_config(&c_cert, &c_key, &srv.ca.pem()).expect("client");
        let conn = handshake(server, client).expect("handshake");
        assert!(conn.fips(), "live server connection reports FIPS");
        assert_eq!(
            conn.negotiated_key_exchange_group().map(|g| g.name()),
            Some(rustls::NamedGroup::secp256r1MLKEM768)
        );
    }

    /// A client offering only plain X25519 (not FIPS-approved) cannot connect.
    #[test]
    fn x25519_only_client_is_refused() {
        let srv = Pki::new("X25519 Server CA");
        let cli = Pki::new("X25519 Client CA");
        let (s_cert, _, s_key) = srv.leaf(
            &[(DnType::CommonName, "ca-service")],
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (c_cert, _, c_key) = cli.leaf(
            &[(DnType::CommonName, "acme-server")],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let server = grpc_server_config(&TlsSettings {
            cert_path: write_tmp("x25519-cert", &s_cert),
            key_path: write_tmp("x25519-key", &s_key),
            client_ca_path: Some(write_tmp("x25519-ca", &cli.ca.pem())),
            optional_client_auth: false,
        })
        .expect("server");
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(srv.ca.pem().as_bytes()).expect("root"))
            .expect("add");
        let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_root_certificates(roots)
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(c_cert.as_bytes())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .expect("certs"),
                PrivateKeyDer::from_pem_slice(c_key.as_bytes()).expect("key"),
            )
            .expect("client auth");
        client.alpn_protocols = vec![b"h2".to_vec()];
        assert!(handshake(server, Arc::new(client)).is_err());
    }

    /// Re-sign `cert_der` with ECDSA P-384 over SHA-256 (a curve/hash
    /// mismatch). aws-lc-rs has no P-384/SHA-256 signing algorithm, so the
    /// SHA-256 digest is left-padded to 48 bytes: ECDSA's bits2int gives the
    /// same integer, i.e. a valid ecdsa-with-SHA256 signature.
    fn resign_p384_sha256(cert_der: &[u8], ca_key_pkcs8: &[u8]) -> Vec<u8> {
        use aws_lc_rs::signature::KeyPair as _;
        use aws_lc_rs::{digest, signature};
        use x509_cert::der::Encode;
        use x509_cert::der::asn1::BitString;
        use x509_cert::spki::AlgorithmIdentifierOwned;

        let mut cert = x509_cert::Certificate::from_der(cert_der).expect("cert");
        let alg = AlgorithmIdentifierOwned {
            oid: x509_cert::der::oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        };
        cert.tbs_certificate.signature = alg.clone();
        cert.signature_algorithm = alg;
        let tbs = cert.tbs_certificate.to_der().expect("tbs");
        let sha256 = digest::digest(&digest::SHA256, &tbs);
        let mut padded = [0u8; 48];
        padded[16..].copy_from_slice(sha256.as_ref());
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            ca_key_pkcs8,
        )
        .expect("p384 key");
        let sig = key
            .sign_digest(&digest::Digest::import_less_safe(&padded, &digest::SHA384).expect("d"))
            .expect("sign");
        // Self-check: it really is a P-384 / SHA-256 signature.
        let spki_point = key.public_key().as_ref().to_vec();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA256_ASN1, &spki_point)
            .verify(&tbs, sig.as_ref())
            .expect("valid P-384/SHA-256 signature");
        cert.signature = BitString::from_bytes(sig.as_ref()).expect("bits");
        cert.to_der().expect("cert der")
    }

    /// PQC-003: a client leaf signed with ECDSA P-384 / SHA-256 chains under
    /// the stock aws-lc-rs verifier but is refused by the narrowed gRPC one,
    /// on the server (client certificate) and on the client (server
    /// certificate).
    #[test]
    fn p384_sha256_signed_leaf_is_rejected() {
        let p384 = &rcgen::PKCS_ECDSA_P384_SHA384;
        let srv = Pki::new_with("Mismatch Server CA", p384);
        let cli = Pki::new_with("Mismatch Client CA", p384);
        let (s_cert, s_der, s_key) = srv.leaf_with(
            "ca-service",
            "localhost",
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            p384,
        );
        let (_, c_der, c_key) = cli.leaf_with(
            "acme-server",
            "acme-server",
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            p384,
        );
        let bad_client_pem =
            pem_rfc7468_wrap("CERTIFICATE", &resign_p384_sha256(&c_der, &cli.ca_key_der));
        let bad_server_pem =
            pem_rfc7468_wrap("CERTIFICATE", &resign_p384_sha256(&s_der, &srv.ca_key_der));

        let settings = |cert: &str, tag: &str| TlsSettings {
            cert_path: write_tmp(&format!("{tag}-cert"), cert),
            key_path: write_tmp(&format!("{tag}-key"), &s_key),
            client_ca_path: Some(write_tmp(&format!("{tag}-ca"), &cli.ca.pem())),
            optional_client_auth: false,
        };

        // Server side: gRPC server refuses the re-signed client leaf ...
        let grpc_server = grpc_server_config(&settings(&s_cert, "mm-ok")).expect("server");
        let client = grpc_client_config(&bad_client_pem, &c_key, &srv.ca.pem()).expect("client");
        assert!(
            handshake(grpc_server.clone(), client).is_err(),
            "server accepted P-384/SHA-256"
        );
        // ... which the stock aws-lc-rs verifier would have accepted.
        let stock_server = Arc::new(settings(&s_cert, "mm-stock").load().expect("stock"));
        let mut stock_client =
            (*grpc_client_config(&bad_client_pem, &c_key, &srv.ca.pem()).expect("client")).clone();
        stock_client.alpn_protocols = vec![b"h2".to_vec()];
        handshake(stock_server, Arc::new(stock_client)).expect("stock verifier accepts");

        // Client side: gRPC client refuses a re-signed server leaf.
        let bad_server = grpc_server_config(&settings(&bad_server_pem, "mm-bad")).expect("server");
        let (c_cert_ok, _, c_key_ok) = cli.leaf_with(
            "acme-server",
            "acme-server",
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            p384,
        );
        let good_client = grpc_client_config(&c_cert_ok, &c_key_ok, &srv.ca.pem()).expect("client");
        assert!(
            handshake(bad_server, good_client).is_err(),
            "client accepted P-384/SHA-256"
        );
    }

    fn pem_rfc7468_wrap(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("ascii"));
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }

    // ---- R8: per-source handshake cap (SEC-002) ----

    #[test]
    fn source_key_groups_ipv6_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(c));
        let v4: IpAddr = "10.0.0.7".parse().unwrap();
        assert_eq!(source_key(v4), v4);
        let mapped: IpAddr = "::ffff:10.0.0.7".parse().unwrap();
        assert_eq!(source_key(mapped), v4);
    }

    /// Audit hook collecting events.
    struct Collect(tokio::sync::mpsc::UnboundedSender<AuthAuditEvent>);

    #[async_trait::async_trait]
    impl AuthAuditHook for Collect {
        async fn record_auth_event(&self, event: AuthAuditEvent) {
            let _ = self.0.send(event);
        }
    }

    fn test_server_config(tag: &str) -> Arc<ServerConfig> {
        let srv = Pki::new("Listener Server CA");
        let cli = Pki::new("Listener Client CA");
        let (s_cert, _, s_key) = srv.leaf(
            &[(DnType::CommonName, "ca-service")],
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        grpc_server_config(&TlsSettings {
            cert_path: write_tmp(&format!("{tag}-cert"), &s_cert),
            key_path: write_tmp(&format!("{tag}-key"), &s_key),
            client_ca_path: Some(write_tmp(&format!("{tag}-ca"), &cli.ca.pem())),
            optional_client_auth: false,
        })
        .expect("server config")
    }

    /// A ninth idle connection from the same address is closed at once and
    /// audited; the first eight stay open (waiting for their ClientHello).
    #[tokio::test]
    async fn per_source_handshake_cap() {
        use tokio::io::AsyncReadExt;
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let incoming = bind_mtls_incoming(
            "127.0.0.1:0".parse().unwrap(),
            test_server_config("persrc"),
            Some(Arc::new(Collect(tx))),
            "test-grpc",
        )
        .await
        .expect("bind");
        let addr = incoming.local_addr();
        let mut held = Vec::new();
        for _ in 0..GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP {
            held.push(TcpStream::connect(addr).await.expect("connect"));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut extra = TcpStream::connect(addr).await.expect("connect");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
            .await
            .expect("over-cap connection must be closed promptly");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let ev = tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .expect("audit")
            .expect("event");
        assert_eq!(ev.kind, AuthAuditKind::TlsHandshakeFailed);
        assert_eq!(ev.reason.as_deref(), Some("per_source_handshake_limit"));
        // The held connections are still open (no EOF yet).
        let still_open =
            tokio::time::timeout(Duration::from_millis(300), held[0].read(&mut buf)).await;
        assert!(
            still_open.is_err(),
            "held connection was closed: {still_open:?}"
        );
        drop(held);
        drop(incoming);
    }

    /// QA-003 / SEC-006: suppressed-record summaries are flushed by the timer
    /// without further failures, and on accept-loop exit.
    #[tokio::test]
    async fn suppressed_summary_flushed_by_timer_and_on_shutdown() {
        use tokio::io::AsyncWriteExt as _;
        let limits = GrpcListenerLimits {
            audit_max_per_window: 1,
            audit_window: Duration::from_millis(500),
            ..Default::default()
        };
        let garbage = |addr: SocketAddr| async move {
            let mut tcp = TcpStream::connect(addr).await.expect("connect");
            let _ = tcp.write_all(b"GARBAGE-NOT-TLS\r\n\r\n").await;
            let mut buf = [0u8; 16];
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::io::AsyncReadExt::read(&mut tcp, &mut buf),
            )
            .await;
        };

        // Timer flush.
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let incoming = bind_mtls_incoming_with(
            "127.0.0.1:0".parse().unwrap(),
            test_server_config("flush-timer"),
            Some(Arc::new(Collect(tx))),
            "test-grpc",
            limits.clone(),
        )
        .await
        .expect("bind");
        for _ in 0..4 {
            garbage(incoming.local_addr()).await;
        }
        let summary = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ev = events.recv().await.expect("open");
                if ev.kind == AuthAuditKind::TlsHandshakeFailuresSuppressed {
                    return ev;
                }
            }
        })
        .await
        .expect("timer summary");
        assert_eq!(summary.details.as_ref().expect("d")["count"], 3);
        assert_eq!(summary.resource.as_deref(), Some("test-grpc"));
        drop(incoming);

        // Shutdown flush: a long window, so only the accept-loop exit flushes.
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let incoming = bind_mtls_incoming_with(
            "127.0.0.1:0".parse().unwrap(),
            test_server_config("flush-exit"),
            Some(Arc::new(Collect(tx))),
            "test-grpc",
            GrpcListenerLimits {
                audit_window: Duration::from_secs(3600),
                ..limits
            },
        )
        .await
        .expect("bind");
        for _ in 0..3 {
            garbage(incoming.local_addr()).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(incoming);
        let summary = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ev = events.recv().await.expect("open");
                if ev.kind == AuthAuditKind::TlsHandshakeFailuresSuppressed {
                    return ev;
                }
            }
        })
        .await
        .expect("shutdown summary");
        assert_eq!(summary.details.as_ref().expect("d")["count"], 2);
    }

    #[test]
    fn listener_limits_must_be_non_zero() {
        assert!(GrpcListenerLimits::default().validate().is_ok());
        for broken in [
            GrpcListenerLimits {
                max_inflight_handshakes_per_ip: 0,
                ..Default::default()
            },
            GrpcListenerLimits {
                audit_window: Duration::ZERO,
                ..Default::default()
            },
            GrpcListenerLimits {
                handshake_timeout: Duration::ZERO,
                ..Default::default()
            },
        ] {
            assert!(broken.validate().is_err());
        }
    }

    // ---- R2-2: trust-anchor guard covers the whole CA chain (SEC-009) ----

    fn ca_params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.use_authority_key_identifier_extension = true;
        p
    }

    #[test]
    fn dedicated_client_ca_refuses_chain_relatives() {
        // root -> intermediate -> issuing (the CA that serves gRPC).
        let root = Pki::new("Chain Root CA");
        let inter_key = KeyPair::generate().expect("key");
        let inter =
            CertifiedIssuer::signed_by(ca_params("Chain Intermediate CA"), inter_key, &root.ca)
                .expect("intermediate");
        let issuing_key = KeyPair::generate().expect("key");
        let issuing =
            CertifiedIssuer::signed_by(ca_params("Chain Issuing CA"), issuing_key, &inter)
                .expect("issuing");
        let issuing_der = issuing.der().to_vec();
        let ancestors: [&[u8]; 2] = [inter.der().as_ref(), root.ca.der().as_ref()];

        // Subject alone: same name, different key and no matching SKI.
        let same_name = Pki::new("Chain Issuing CA");
        let err = ensure_dedicated_client_ca(&[der_of(&same_name.ca.pem())], &issuing_der, &[])
            .expect_err("same subject")
            .to_string();
        assert!(err.contains("same subject"), "{err}");

        // A CA issued BY the issuing CA (issuer name and AKI = issuing SKI).
        let child_key = KeyPair::generate().expect("key");
        let child = ca_params("Sub of Issuing CA")
            .signed_by(&child_key, &issuing)
            .expect("child");
        let err = ensure_dedicated_client_ca(&[der_of(&child.pem())], &issuing_der, &[])
            .expect_err("issued by issuing CA")
            .to_string();
        assert!(err.contains("was issued by this CA's issuing"), "{err}");

        // The root is two levels up: only the DB ancestor walk catches it.
        ensure_dedicated_client_ca(&[der_of(&root.ca.pem())], &issuing_der, &[])
            .expect("not detectable without the ancestor chain");
        let err = ensure_dedicated_client_ca(&[der_of(&root.ca.pem())], &issuing_der, &ancestors)
            .expect_err("grand-parent")
            .to_string();
        assert!(err.contains("ancestor #2"), "{err}");
        // ... also a re-keyed root under the same subject (subject match).
        let rekeyed_root = Pki::new("Chain Root CA");
        let err =
            ensure_dedicated_client_ca(&[der_of(&rekeyed_root.ca.pem())], &issuing_der, &ancestors)
                .expect_err("re-keyed ancestor")
                .to_string();
        assert!(err.contains("ancestor #2"), "{err}");
        // The direct parent is caught with or without the walk.
        assert!(ensure_dedicated_client_ca(&[der_of(&inter.pem())], &issuing_der, &[]).is_err());

        // A dedicated service-identity CA still passes with the full chain.
        let dedicated = Pki::new("Chain Service Identity CA");
        ensure_dedicated_client_ca(&[der_of(&dedicated.ca.pem())], &issuing_der, &ancestors)
            .expect("dedicated");
        // An unparsable ancestor fails closed.
        assert!(
            ensure_dedicated_client_ca(
                &[der_of(&dedicated.ca.pem())],
                &issuing_der,
                &[b"junk".as_slice()]
            )
            .is_err()
        );
    }

    /// RFC-016: the two "issued by the issuing CA" tests (issuer DN, and
    /// AKI == issuing SKI) are exercised one at a time, in `anchor_conflict`
    /// and in `SubscriberIssuer::issued`. "Name only" certificates come from a
    /// different key under the issuing CA's name; "key id only" certificates
    /// come from the issuing CA's key under a different name.
    #[test]
    fn issued_by_checks_cover_name_and_key_id_independently() {
        let parse = |der: &[u8]| x509_cert::Certificate::from_der(der).expect("der");
        let issuing = Pki::new("Branch Issuing CA");
        let issuing_cert = parse(issuing.ca.der());
        let issuing_ski = subject_key_id(&issuing_cert);
        assert!(issuing_ski.is_some(), "issuing CA has an SKI");
        let same_name = Pki::new("Branch Issuing CA");
        let same_key = CertifiedIssuer::self_signed(
            ca_params("Branch Renamed CA"),
            KeyPair::try_from(issuing.ca_key_der.as_slice()).expect("key"),
        )
        .expect("renamed CA");
        let unrelated = Pki::new("Branch Unrelated CA");

        let sub_ca = |cn: &str, aki: bool, by: &CertifiedIssuer<'static, KeyPair>| {
            let mut p = ca_params(cn);
            p.use_authority_key_identifier_extension = aki;
            let key = KeyPair::generate().expect("key");
            parse(p.signed_by(&key, by).expect("sub CA").der())
        };
        let leaf = |aki: bool, by: &CertifiedIssuer<'static, KeyPair>| {
            let mut p = CertificateParams::new(vec![s("est-server")]).expect("params");
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, "est-server");
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            p.use_authority_key_identifier_extension = aki;
            let key = KeyPair::generate().expect("key");
            parse(p.signed_by(&key, by).expect("leaf").der())
        };
        let issued_by = "was issued by this CA's issuing certificate";

        // anchor_conflict, issuer-name branch only: issuer DN matches, and the
        // AKI is absent or names a different key.
        for aki in [false, true] {
            let anchor = sub_ca("Name Branch Sub CA", aki, &same_name.ca);
            assert_eq!(
                anchor.tbs_certificate.issuer,
                issuing_cert.tbs_certificate.subject
            );
            assert_ne!(authority_key_id(&anchor), issuing_ski);
            assert_eq!(
                anchor_conflict(&anchor, &issuing_cert, &[]).as_deref(),
                Some(issued_by),
                "name branch (aki={aki})"
            );
        }
        // anchor_conflict, AKI == SKI branch only: issuer DN differs.
        let anchor = sub_ca("Key Branch Sub CA", true, &same_key);
        assert_ne!(
            anchor.tbs_certificate.issuer,
            issuing_cert.tbs_certificate.subject
        );
        assert_eq!(authority_key_id(&anchor), issuing_ski);
        assert_eq!(
            anchor_conflict(&anchor, &issuing_cert, &[]).as_deref(),
            Some(issued_by),
            "AKI branch"
        );
        // Without the AKI the same certificate is not related: it was the
        // key identifier, not anything else, that matched above.
        let anchor = sub_ca("Key Branch Sub CA", false, &same_key);
        assert_eq!(anchor_conflict(&anchor, &issuing_cert, &[]), None);
        let anchor = sub_ca("Unrelated Sub CA", true, &unrelated.ca);
        assert_eq!(anchor_conflict(&anchor, &issuing_cert, &[]), None);

        // SubscriberIssuer::issued, the same two branches.
        let issuer = SubscriberIssuer {
            subject: issuing_cert.tbs_certificate.subject.clone(),
            subject_key_id: issuing_ski.clone(),
        };
        let name_only = leaf(false, &same_name.ca);
        assert!(authority_key_id(&name_only).is_none());
        assert!(issuer.issued(&name_only), "issuer-name branch");
        let key_only = leaf(true, &same_key);
        assert_ne!(key_only.tbs_certificate.issuer, issuer.subject);
        assert!(issuer.issued(&key_only), "AKI branch");
        assert!(
            !issuer.issued(&leaf(false, &same_key)),
            "no AKI, other name"
        );
        assert!(!issuer.issued(&leaf(true, &unrelated.ca)), "unrelated");
        // An issuer without an SKI never matches on a missing AKI.
        let no_ski = SubscriberIssuer {
            subject: issuer.subject.clone(),
            subject_key_id: None,
        };
        assert!(!no_ski.issued(&leaf(false, &unrelated.ca)));
        assert!(!no_ski.issued(&key_only), "AKI branch needs an SKI");
        assert!(no_ski.issued(&name_only));
    }

    #[test]
    fn authorize_peer_refuses_subscriber_issuing_ca_leaf() {
        let issuing = Pki::new("Subscriber Issuing CA");
        let dedicated = Pki::new("Service Identity CA");
        let allow = registry(&[], &["CN=est-server"], &[]).expect("registry");
        let issuers = [SubscriberIssuer {
            subject: x509_cert::Certificate::from_der(issuing.ca.der())
                .expect("der")
                .tbs_certificate
                .subject,
            subject_key_id: subject_key_id(
                &x509_cert::Certificate::from_der(issuing.ca.der()).expect("der"),
            ),
        }];
        let peer = |pki: &Pki| {
            let (_, der, _) = pki.leaf(
                &[(DnType::CommonName, "est-server")],
                "est-server",
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            }
        };
        let denied = authorize_peer(
            Some(&peer(&issuing)),
            &allow,
            RULES,
            P_ISSUE,
            &issuers,
            None,
        )
        .expect_err("subscriber");
        assert_eq!(denied.code, tonic::Code::PermissionDenied);
        assert_eq!(denied.reason, "subscriber_issuing_ca");
        assert_eq!(
            si(authorize_peer(
                Some(&peer(&dedicated)),
                &allow,
                RULES,
                P_ISSUE,
                &issuers,
                None
            )),
            Ok((s("CN=est-server"), GrpcClientIdentity::EST))
        );

        // Builder: parses the CA certificates, fails closed on garbage.
        let layer = SubjectAllowlistLayer::new(Arc::new(allow.clone()), RULES, None, "test-grpc")
            .with_subscriber_issuing_cas(&[issuing.ca.der().as_ref()])
            .expect("layer");
        assert_eq!(layer.subscriber_issuers.len(), 1);
        assert!(
            SubjectAllowlistLayer::new(Arc::new(allow), RULES, None, "test-grpc")
                .with_subscriber_issuing_cas(&[b"junk".as_slice()])
                .is_err()
        );
    }

    // ---- R2-3: denial audit survives a cancelled request (SEC-010) ----

    /// Inner service that must never be reached by a denied call.
    #[derive(Clone)]
    struct Unreachable;

    impl tower::Service<http::Request<()>> for Unreachable {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: http::Request<()>) -> Self::Future {
            panic!("denied call reached the inner service");
        }
    }

    #[tokio::test]
    async fn access_denied_audit_survives_cancelled_request() {
        use tower::{Layer as _, Service as _};
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let allow = acme_only("CN=acme-server");
        let mut svc = SubjectAllowlistLayer::new(
            Arc::new(allow),
            RULES,
            Some(Arc::new(Collect(tx))),
            "test-grpc",
        )
        .layer(Unreachable);

        // No peer info: UNAUTHENTICATED. Drop the response future unpolled,
        // as hyper does on RST_STREAM.
        let mut req = http::Request::new(());
        *req.uri_mut() = "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate"
            .parse()
            .expect("uri");
        let fut = svc.call(req);
        drop(fut);

        let ev = tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .expect("audit record written although the call was cancelled")
            .expect("event");
        assert_eq!(ev.kind, AuthAuditKind::AccessDenied);
        assert_eq!(ev.reason.as_deref(), Some("no_client_certificate"));
        assert_eq!(
            ev.resource.as_deref(),
            Some("/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate")
        );

        // A call that is not cancelled still gets its status after the write.
        let resp = svc.call(http::Request::new(())).await.expect("infallible");
        assert_eq!(
            resp.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"16".as_slice())
        );
        assert!(
            events.try_recv().is_ok(),
            "record written before the response"
        );
    }

    // ---- per-method authorization: registry, method table, requestor ----

    #[test]
    fn registry_parses_three_lists_and_maps_namespaces() {
        let r = registry(
            &["CN=acme-server, O=Ostrich"],
            &["CN=est-server"],
            &["CN=ops-admin"],
        )
        .expect("registry");
        assert_eq!(
            r.identity("CN=acme-server,O=Ostrich"),
            Some(GrpcClientIdentity::ACME)
        );
        assert_eq!(r.identity("CN=est-server"), Some(GrpcClientIdentity::EST));
        assert_eq!(r.identity("CN=ops-admin"), Some(GrpcClientIdentity::ADMIN));
        assert_eq!(r.identity("CN=stranger"), None);
        assert_eq!(r.identity(""), None);
        assert_eq!(GrpcClientIdentity::ACME.role, GrpcClientRole::Issuer);
        assert_eq!(GrpcClientIdentity::EST.namespace, "est");
        assert_eq!(GrpcClientIdentity::ADMIN.role, GrpcClientRole::Admin);
        assert_eq!(
            r.summary(),
            serde_json::json!({
                "acme": ["CN=acme-server,O=Ostrich"],
                "est": ["CN=est-server"],
                "admin": ["CN=ops-admin"],
            })
        );
        // Duplicates within one list are dropped.
        let dup = registry(&["CN=a", "CN=a "], &[], &[]).expect("dup");
        assert_eq!(dup.summary()["acme"], serde_json::json!(["CN=a"]));
    }

    #[test]
    fn registry_rejects_overlap_canonical() {
        let err = registry(&["CN=a, O=b"], &["CN=e"], &["CN=a,O=b"]).expect_err("overlap");
        let msg = err.to_string();
        assert!(msg.contains(ENV_GRPC_ACME_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains("CN=a,O=b"), "{msg}");
        assert!(msg.contains("may hold one role"), "{msg}");

        let err = registry(&["CN=x"], &[" CN = x "], &[]).expect_err("acme/est overlap");
        let msg = err.to_string();
        assert!(msg.contains(ENV_GRPC_ACME_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains(ENV_GRPC_EST_CLIENT_SUBJECTS), "{msg}");

        let err = registry(&["CN=a"], &["CN=x"], &["CN=x"]).expect_err("est/admin overlap");
        assert!(err.to_string().contains(ENV_GRPC_EST_CLIENT_SUBJECTS));
    }

    #[test]
    fn registry_requires_an_issuer() {
        let err = registry(&[], &[], &["CN=ops-admin"]).expect_err("admin only");
        assert!(
            err.to_string().contains("no issuer client configured"),
            "{err}"
        );
        assert!(registry(&[" "], &["", ";"], &[]).is_err(), "all blank");
        assert!(registry(&[], &[], &[]).is_err(), "nothing");
        // Either issuer list alone is enough.
        assert!(registry(&[], &["CN=est-server"], &[]).is_ok());
        assert!(registry(&["CN=acme-server"], &[], &[]).is_ok());
    }

    #[test]
    fn registry_admin_blank_is_none() {
        let r = registry(&["CN=acme-server"], &[" "], &[" ", "", "\t"]).expect("blank admin");
        assert_eq!(r.summary()["admin"], serde_json::json!([]));
        assert_eq!(r.summary()["est"], serde_json::json!([]));
        // A blank entry next to a real one is dropped.
        let r = registry(&["CN=acme-server", " "], &[], &["", "CN=ops"]).expect("mixed");
        assert_eq!(r.identity("CN=ops"), Some(GrpcClientIdentity::ADMIN));
    }

    #[test]
    fn registry_rejects_malformed_entry_in_each_list() {
        let bad = r"CN=a\";
        for (i, env) in [
            ENV_GRPC_ACME_CLIENT_SUBJECTS,
            ENV_GRPC_EST_CLIENT_SUBJECTS,
            ENV_GRPC_ADMIN_CLIENT_SUBJECTS,
        ]
        .iter()
        .enumerate()
        {
            let mut lists = [vec!["CN=acme-server"], vec!["CN=est-server"], vec![]];
            lists[i].push(bad);
            let err = registry(&lists[0], &lists[1], &lists[2]).expect_err("malformed");
            assert!(err.to_string().contains(env), "{env}: {err}");
        }
    }

    #[test]
    fn resolve_rejects_legacy_allowed_subjects() {
        let mut o = full_options("legacy");
        o.legacy_allowed_subjects = vec![s("CN=acme-server")];
        let err = o.resolve(true).expect_err("legacy in mTLS mode");
        let msg = err.to_string();
        assert!(msg.contains(ENV_GRPC_ALLOWED_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains(ENV_GRPC_ACME_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains("refusing to start"), "{msg}");

        let err = GrpcServerOptions {
            insecure_dev_plaintext: true,
            legacy_allowed_subjects: vec![s("CN=acme-server")],
            ..Default::default()
        }
        .resolve(false)
        .expect_err("legacy in insecure mode");
        assert!(err.to_string().contains("no longer supported"), "{err}");

        // A blank legacy value (an unset `${VAR:-}`) is ignored.
        let mut o = full_options("legacy-blank");
        o.legacy_allowed_subjects = vec![s(" ")];
        assert!(o.resolve(true).is_ok());
    }

    #[test]
    fn resolve_insecure_with_role_list_is_ambiguous() {
        for i in 0..3 {
            let mut o = GrpcServerOptions {
                insecure_dev_plaintext: true,
                ..Default::default()
            };
            let list = vec![s("CN=x")];
            match i {
                0 => o.acme_subjects = list,
                1 => o.est_subjects = list,
                _ => o.admin_subjects = list,
            }
            let err = o.resolve(false).expect_err("ambiguous");
            assert!(err.to_string().contains("ambiguous"), "#{i}: {err}");
        }
    }

    #[test]
    fn resolve_rejects_overlap_and_malformed_admin() {
        let mut o = full_options("overlap");
        o.admin_subjects = vec![s("CN=est-server")];
        assert!(o.resolve(true).is_err());
        let mut o = full_options("bad-admin");
        o.admin_subjects = vec![s(r"CN=a\")];
        let err = o.resolve(true).expect_err("malformed admin");
        assert!(err.to_string().contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS));
    }

    #[test]
    fn authorize_peer_method_matrix() {
        let pki = Pki::new("Matrix CA");
        let anchor = anchor_of(&pki);
        let clients =
            registry(&["CN=acme-server"], &["CN=est-server"], &["CN=ops-admin"]).expect("registry");
        let peer = |cn: &str| {
            let (_, der, _) = pki.leaf(
                &[(DnType::CommonName, cn)],
                "x.example",
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            }
        };
        let issuer_allowed = [P_ISSUE, P_INFO, P_PROFILES];
        let admin_allowed = [P_REVOKE, P_CRL, P_STATUS, P_INFO, P_PROFILES];
        let all = [P_ISSUE, P_REVOKE, P_CRL, P_STATUS, P_INFO, P_PROFILES];
        for (cn, identity, allowed) in [
            ("acme-server", GrpcClientIdentity::ACME, &issuer_allowed[..]),
            ("est-server", GrpcClientIdentity::EST, &issuer_allowed[..]),
            ("ops-admin", GrpcClientIdentity::ADMIN, &admin_allowed[..]),
        ] {
            let p = peer(cn);
            for path in all {
                let got = si(authorize_peer(
                    Some(&p),
                    &clients,
                    RULES,
                    path,
                    &[],
                    Some(&anchor),
                ));
                if allowed.contains(&path) {
                    assert_eq!(got, Ok((format!("CN={cn}"), identity)), "{cn} {path}");
                } else {
                    let d = got.expect_err("denied");
                    assert_eq!(d.code, tonic::Code::PermissionDenied, "{cn} {path}");
                    assert_eq!(d.reason, "method_not_permitted", "{cn} {path}");
                    assert_eq!(d.identity, Some(identity));
                    assert_eq!(d.subject, Some(format!("CN={cn}")));
                }
            }
            for path in [
                "/ostrich.ca.v1.CertificateAuthorityService/Foo",
                "/grpc.health.v1.Health/Check",
                "",
                "/",
                "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate/",
                "/ostrich.ca.v1.certificateauthorityservice/IssueCertificate",
                "/ostrich.ca.v1.CertificateAuthorityService/issuecertificate",
            ] {
                let d = authorize_peer(Some(&p), &clients, RULES, path, &[], Some(&anchor))
                    .expect_err("unmapped");
                assert_eq!(d.reason, "method_not_mapped", "{cn} {path:?}");
                assert_eq!(d.code, tonic::Code::PermissionDenied);
                assert_eq!(d.identity, Some(identity));
            }
        }
        // A stranger is refused before the method table, on every path.
        let stranger = peer("stranger");
        for path in all {
            let d = authorize_peer(Some(&stranger), &clients, RULES, path, &[], Some(&anchor))
                .expect_err("stranger");
            assert_eq!(d.reason, "subject_not_allowlisted");
            assert_eq!(d.identity, None);
        }
        // An empty method table denies everything (default deny).
        let d = authorize_peer(
            Some(&peer("acme-server")),
            &clients,
            &[],
            P_ISSUE,
            &[],
            Some(&anchor),
        )
        .expect_err("empty table");
        assert_eq!(d.reason, "method_not_mapped");
        // Denial details carry the role and namespace of a known subject.
        assert_eq!(
            denial_details("l", Some(GrpcClientIdentity::EST), None),
            serde_json::json!({"listener": "l", "role": "issuer", "namespace": "est"})
        );
        assert_eq!(
            denial_details("l", None, Some(("CN=Client CA", "0a"))),
            serde_json::json!({"listener": "l", "peer_issuer": "CN=Client CA", "peer_serial": "0a"})
        );
    }

    #[test]
    fn validate_requestor_cases() {
        use RequestorRejection as R;
        let acme = GrpcClientIdentity::ACME;
        let est = GrpcClientIdentity::EST;
        let admin = GrpcClientIdentity::ADMIN;
        let ok =
            |id, r: &str| assert_eq!(validate_requestor(id, r), Ok(Some(r.to_string())), "{r:?}");
        let err = |id, r: &str, e| assert_eq!(validate_requestor(id, r), Err(e), "{r:?}");

        ok(acme, "acme::1");
        ok(est, "est::client-7");
        err(acme, "est::1", R::NamespaceMismatch);
        err(est, "acme::1", R::NamespaceMismatch);
        err(acme, "ACME::1", R::NamespaceMismatch);
        err(acme, "acme1", R::NamespaceMismatch);
        err(acme, "acme:1", R::NamespaceMismatch);
        err(acme, " acme::1", R::NamespaceMismatch);
        err(acme, "acme::", R::Invalid);
        err(acme, "", R::Missing);
        err(est, "", R::Missing);
        assert_eq!(validate_requestor(admin, ""), Ok(None));
        ok(admin, "admin::x");
        err(admin, "acme::x", R::NamespaceMismatch);
        err(admin, "admin", R::NamespaceMismatch);

        let max = format!("acme::{}", "a".repeat(MAX_REQUESTOR_LEN - 6));
        assert_eq!(max.len(), 255);
        ok(acme, &max);
        err(acme, &format!("{max}a"), R::Invalid);

        err(acme, "acme::a\nb", R::Invalid);
        err(acme, "acme::a\u{0}b", R::Invalid);
        err(acme, "acme::a\u{7f}", R::Invalid);
        err(acme, "acme::\u{202E}gpj", R::Invalid);
        err(acme, "acme::a\u{200B}", R::Invalid);
        err(acme, "acme::a\u{2066}", R::Invalid);
        err(acme, "acme::\u{FEFF}a", R::Invalid);
        ok(acme, "acme::est::x");
        ok(acme, "acme::!~@.+_-=");
        // SEC-002: the id is printable ASCII only (allowlist 0x21..=0x7E).
        err(acme, "acme::компания-ü", R::Invalid);
        err(acme, "acme::a b", R::Invalid);
        for c in [
            '\u{2028}',
            '\u{2029}',
            '\u{061C}',
            '\u{2060}',
            '\u{2064}',
            '\u{00AD}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{E0001}',
            '\u{E007F}',
            '\u{FE0F}',
        ] {
            err(acme, &format!("acme::a{c}b"), R::Invalid);
            err(est, &format!("est::{c}"), R::Invalid);
        }

        assert_eq!(R::Missing.reason(), "requestor_missing");
        assert_eq!(
            R::NamespaceMismatch.reason(),
            "requestor_namespace_mismatch"
        );
        assert_eq!(R::Invalid.reason(), "requestor_invalid");
    }

    #[test]
    fn method_rules_summary_lists_paths_and_roles() {
        let summary = grpc_method_rules_summary(RULES);
        assert_eq!(summary.as_array().map(Vec::len), Some(6));
        assert_eq!(summary[0]["path"], P_ISSUE);
        assert_eq!(summary[0]["roles"], serde_json::json!(["issuer"]));
        assert_eq!(summary[4]["roles"], serde_json::json!(["issuer", "admin"]));
    }

    /// Inner service that captures the `AuthorizedGrpcPeer` extension.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<AuthorizedGrpcPeer>>>);

    impl tower::Service<http::Request<()>> for Capture {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<()>) -> Self::Future {
            *lock_ignoring_poison(&self.0) = req.extensions().get::<AuthorizedGrpcPeer>().cloned();
            std::future::ready(Ok(http::Response::new(tonic::body::Body::default())))
        }
    }

    fn request_with_peer(path: &str, peer: GrpcPeerInfo) -> http::Request<()> {
        let mut req = http::Request::new(());
        *req.uri_mut() = path.parse().expect("uri");
        req.extensions_mut().insert(peer);
        req
    }

    #[tokio::test]
    async fn peer_deny_is_rate_limited_and_shares_limiter() {
        use tower::{Layer as _, Service as _};
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let pki = Pki::new("Deny CA");
        let (_, der, _) = pki.leaf(
            &[(DnType::CommonName, "acme-server")],
            "acme-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let peer_info = GrpcPeerInfo {
            remote_addr: Some("10.1.2.3:4444".parse().expect("addr")),
            peer_leaf: Some(CertificateDer::from(der)),
        };
        let capture = Capture::default();
        let mut svc = SubjectAllowlistLayer::with_limits(
            Arc::new(acme_only("CN=acme-server")),
            RULES,
            Some(Arc::new(Collect(tx))),
            "test-grpc",
            &GrpcListenerLimits {
                audit_max_per_window: 2,
                audit_window: Duration::from_secs(3600),
                ..Default::default()
            },
        )
        .layer(capture.clone());

        // Layer denial #1: acme may not revoke.
        let resp = svc
            .call(request_with_peer(P_REVOKE, peer_info.clone()))
            .await
            .expect("infallible");
        assert_eq!(
            resp.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"7".as_slice())
        );
        let ev = events.try_recv().expect("layer denial recorded");
        assert_eq!(ev.reason.as_deref(), Some("method_not_permitted"));
        assert_eq!(ev.subject, "CN=acme-server");
        assert_eq!(ev.resource.as_deref(), Some(P_REVOKE));
        let d = ev.details.expect("details");
        assert_eq!(d["role"], "issuer");
        assert_eq!(d["namespace"], "acme");

        // An allowed call carries the peer extension.
        svc.call(request_with_peer(P_ISSUE, peer_info))
            .await
            .expect("infallible");
        let peer = lock_ignoring_poison(&capture.0)
            .clone()
            .expect("AuthorizedGrpcPeer inserted");
        assert_eq!(peer.subject_dn, "CN=acme-server");
        assert_eq!(peer.identity, GrpcClientIdentity::ACME);
        assert_eq!(peer.method(), P_ISSUE);
        assert_eq!(peer.issuer_dn, "CN=Deny CA");
        assert!(!peer.serial_hex.is_empty());
        assert!(
            !format!("{peer:?}").contains("rate"),
            "Debug omits the limiter"
        );
        assert_eq!(peer.bind_requestor("acme::1"), Ok(Some(s("acme::1"))));

        // Service denial #2 is recorded with the merged details ...
        let status = peer
            .deny(
                "requestor_namespace_mismatch",
                serde_json::json!({"claimed_namespace": "est", "expected_namespace": "acme"}),
            )
            .await;
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status.message(), DENIED_MESSAGE);
        let ev = events
            .try_recv()
            .expect("service denial recorded before the status");
        assert_eq!(ev.kind, AuthAuditKind::AccessDenied);
        assert_eq!(ev.reason.as_deref(), Some("requestor_namespace_mismatch"));
        assert_eq!(ev.subject, "CN=acme-server");
        assert_eq!(ev.resource.as_deref(), Some(P_ISSUE));
        assert_eq!(ev.ip_address.as_deref(), Some("10.1.2.3"));
        let d = ev.details.expect("details");
        assert_eq!(d["listener"], "test-grpc");
        assert_eq!(d["role"], "issuer");
        assert_eq!(d["claimed_namespace"], "est");
        assert_eq!(d["expected_namespace"], "acme");
        assert_eq!(d["peer_issuer"], "CN=Deny CA");
        assert_eq!(d["peer_serial"], peer.serial_hex.as_str());

        // ... and #3 exceeds the shared window of 2: suppressed, still denied.
        let status = peer.deny("requestor_invalid", serde_json::json!({})).await;
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        tokio::task::yield_now().await;
        assert!(events.try_recv().is_err(), "third denial is suppressed");
        drop(svc);
        drop(peer);
        drop(capture);
    }

    #[tokio::test]
    async fn peer_deny_record_survives_dropped_future() {
        use tower::{Layer as _, Service as _};
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let pki = Pki::new("Cancel CA");
        let (_, der, _) = pki.leaf(
            &[(DnType::CommonName, "est-server")],
            "est-server",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let capture = Capture::default();
        let mut svc = SubjectAllowlistLayer::new(
            Arc::new(registry(&[], &["CN=est-server"], &[]).expect("registry")),
            RULES,
            Some(Arc::new(Collect(tx))),
            "test-grpc",
        )
        .layer(capture.clone());
        svc.call(request_with_peer(
            P_ISSUE,
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            },
        ))
        .await
        .expect("infallible");
        let peer = lock_ignoring_poison(&capture.0).clone().expect("peer");
        // Never polled: the write was spawned by `deny` itself.
        drop(peer.deny("requestor_missing", serde_json::json!({})));
        let ev = tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .expect("record written although the future was dropped")
            .expect("event");
        assert_eq!(ev.reason.as_deref(), Some("requestor_missing"));
        assert_eq!(ev.subject, "CN=est-server");
    }

    // ---- QA additions (SA-11 / CA-2 evidence) ----

    /// Non-canonical spellings of a mapped path that a router or proxy might
    /// treat as equivalent. The listener matches the raw `:path` exactly, so
    /// every one is `method_not_mapped` for every known role (AC-3, SI-10).
    const QA_UNMAPPED_PATH_VARIANTS: &[&str] = &[
        // percent-encoding of a letter and of the separator
        "/ostrich.ca.v1.CertificateAuthorityService/Issue%43ertificate",
        "/ostrich.ca.v1.CertificateAuthorityService%2FIssueCertificate",
        "%2Fostrich.ca.v1.CertificateAuthorityService/IssueCertificate",
        // extra and empty segments
        "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate/extra",
        "/ostrich.ca.v1.CertificateAuthorityService//IssueCertificate",
        "//ostrich.ca.v1.CertificateAuthorityService/IssueCertificate",
        "/x/ostrich.ca.v1.CertificateAuthorityService/RevokeCertificate",
        "/ostrich.ca.v1.CertificateAuthorityService/./GenerateCrl",
        "/ostrich.ca.v1.CertificateAuthorityService/../ostrich.ca.v1.CertificateAuthorityService/GenerateCrl",
        // other service names carrying a mapped RPC name
        "/ostrich.ca.v2.CertificateAuthorityService/IssueCertificate",
        "/ostrich.ca.v1.CertificateAuthorityServiceX/GetCaInfo",
        "/CertificateAuthorityService/GetCaInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.health.v1.Health/Watch",
        // case variants of the admin RPCs
        "/ostrich.ca.v1.CertificateAuthorityService/revokeCertificate",
        "/OSTRICH.CA.V1.CERTIFICATEAUTHORITYSERVICE/GENERATECRL",
        // no leading slash, trailing whitespace / NUL
        "ostrich.ca.v1.CertificateAuthorityService/GetCaInfo",
        "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo ",
        "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo\0",
    ];

    /// QA: AC-3 default deny over non-canonical path spellings, for every
    /// role; an unknown subject is refused first (`subject_not_allowlisted`).
    #[test]
    fn qa_authorize_peer_non_canonical_paths_are_not_mapped() {
        let pki = Pki::new("QA Path CA");
        let clients =
            registry(&["CN=acme-server"], &["CN=est-server"], &["CN=ops-admin"]).expect("registry");
        let peer = |cn: &str| {
            let (_, der, _) = pki.leaf(
                &[(DnType::CommonName, cn)],
                "x.example",
                ExtendedKeyUsagePurpose::ClientAuth,
            );
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(der)),
            }
        };
        for (cn, identity) in [
            ("acme-server", GrpcClientIdentity::ACME),
            ("est-server", GrpcClientIdentity::EST),
            ("ops-admin", GrpcClientIdentity::ADMIN),
        ] {
            let p = peer(cn);
            for path in QA_UNMAPPED_PATH_VARIANTS {
                let d = authorize_peer(Some(&p), &clients, RULES, path, &[], None)
                    .expect_err("non-canonical path must be denied");
                assert_eq!(d.code, tonic::Code::PermissionDenied, "{cn} {path:?}");
                assert_eq!(d.reason, "method_not_mapped", "{cn} {path:?}");
                assert_eq!(d.identity, Some(identity), "{cn} {path:?}");
            }
        }
        let stranger = peer("stranger");
        for path in QA_UNMAPPED_PATH_VARIANTS {
            let d = authorize_peer(Some(&stranger), &clients, RULES, path, &[], None)
                .expect_err("stranger");
            assert_eq!(d.reason, "subject_not_allowlisted", "{path:?}");
        }
    }

    /// QA: through the real tower layer, unmapped paths never reach the inner
    /// service, answer PERMISSION_DENIED (grpc-status 7, not 12
    /// UNIMPLEMENTED) and are audited with the raw path as resource and the
    /// caller's role / namespace (AU-2, AU-3).
    #[tokio::test]
    async fn qa_layer_denies_and_audits_unmapped_paths() {
        use tower::{Layer as _, Service as _};
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let pki = Pki::new("QA Layer CA");
        let (_, der, _) = pki.leaf(
            &[(DnType::CommonName, "ops-admin")],
            "ops-admin",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let peer_info = GrpcPeerInfo {
            remote_addr: Some("10.9.8.7:1".parse().expect("addr")),
            peer_leaf: Some(CertificateDer::from(der)),
        };
        let capture = Capture::default();
        let mut svc = SubjectAllowlistLayer::new(
            Arc::new(registry(&["CN=acme-server"], &[], &["CN=ops-admin"]).expect("registry")),
            RULES,
            Some(Arc::new(Collect(tx))),
            "qa-grpc",
        )
        .with_client_trust_anchors(&[CertificateDer::from(pki.ca.der().to_vec())])
        .expect("anchor")
        .layer(capture.clone());
        let paths = [
            "/ostrich.ca.v1.CertificateAuthorityService/Issue%43ertificate",
            "/ostrich.ca.v1.CertificateAuthorityService/RevokeCertificate/extra",
            "/ostrich.ca.v2.CertificateAuthorityService/GenerateCrl",
            "/ostrich.ca.v1.certificateauthorityservice/GenerateCrl",
            "/ostrich.ca.v1.CertificateAuthorityService/GenerateCrl/",
        ];
        for path in paths {
            let resp = svc
                .call(request_with_peer(path, peer_info.clone()))
                .await
                .expect("infallible");
            assert_eq!(
                resp.headers().get("grpc-status").map(|v| v.as_bytes()),
                Some(b"7".as_slice()),
                "{path}"
            );
            let ev = events.try_recv().expect("denial recorded before status");
            assert_eq!(ev.kind, AuthAuditKind::AccessDenied);
            assert_eq!(ev.reason.as_deref(), Some("method_not_mapped"), "{path}");
            assert_eq!(ev.resource.as_deref(), Some(path));
            assert_eq!(ev.subject, "CN=ops-admin");
            assert_eq!(ev.ip_address.as_deref(), Some("10.9.8.7"));
            let d = ev.details.expect("details");
            assert_eq!(d["role"], "admin");
            assert_eq!(d["namespace"], "admin");
            assert_eq!(d["listener"], "qa-grpc");
        }
        assert!(
            lock_ignoring_poison(&capture.0).is_none(),
            "inner service never reached"
        );
        // Admin may not issue either, at the exact path.
        let resp = svc
            .call(request_with_peer(P_ISSUE, peer_info.clone()))
            .await
            .expect("infallible");
        assert_eq!(
            resp.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"7".as_slice())
        );
        let ev = events.try_recv().expect("recorded");
        assert_eq!(ev.reason.as_deref(), Some("method_not_permitted"));
        assert!(lock_ignoring_poison(&capture.0).is_none());
        // The canonical admin path is admitted (sanity check of the harness).
        svc.call(request_with_peer(P_CRL, peer_info))
            .await
            .expect("infallible");
        assert!(lock_ignoring_poison(&capture.0).is_some());
    }

    /// QA: SI-10 boundaries of `validate_requestor` not covered by
    /// `validate_requestor_cases`: bare namespaces for every role, the byte
    /// (not char) length limit with multibyte UTF-8, every forbidden format
    /// character range end point, C1 controls, and rule precedence.
    #[test]
    fn qa_validate_requestor_boundaries() {
        use RequestorRejection as R;
        let acme = GrpcClientIdentity::ACME;
        let est = GrpcClientIdentity::EST;
        let admin = GrpcClientIdentity::ADMIN;

        // `<ns>::` alone is invalid for every role; `::x` / `::` mismatch.
        for (id, ns) in [(acme, "acme"), (est, "est"), (admin, "admin")] {
            assert_eq!(validate_requestor(id, &format!("{ns}::")), Err(R::Invalid));
            assert_eq!(validate_requestor(id, "::x"), Err(R::NamespaceMismatch));
            assert_eq!(validate_requestor(id, "::"), Err(R::NamespaceMismatch));
            assert_eq!(validate_requestor(id, ns), Err(R::NamespaceMismatch));
            assert_eq!(
                validate_requestor(id, &format!("{}::x", ns.to_uppercase())),
                Err(R::NamespaceMismatch)
            );
        }
        // Only admin may send an empty requestor.
        assert_eq!(validate_requestor(acme, ""), Err(R::Missing));
        assert_eq!(validate_requestor(est, ""), Err(R::Missing));
        assert_eq!(validate_requestor(admin, ""), Ok(None));
        // Whitespace is not "empty".
        assert_eq!(validate_requestor(admin, " "), Err(R::NamespaceMismatch));
        assert_eq!(validate_requestor(acme, "\t"), Err(R::NamespaceMismatch));

        // Byte limit: 255 bytes accepted, 256 refused; multibyte UTF-8 is
        // refused whatever its length (printable ASCII allowlist, SEC-002).
        let id_255 = format!("est::{}", "e".repeat(250)); // 5 + 250 = 255 bytes
        assert_eq!(id_255.len(), MAX_REQUESTOR_LEN);
        assert_eq!(validate_requestor(est, &id_255), Ok(Some(id_255.clone())));
        let id_256 = format!("est::{}x", "e".repeat(250));
        assert_eq!(id_256.len(), MAX_REQUESTOR_LEN + 1);
        assert_eq!(validate_requestor(est, &id_256), Err(R::Invalid));
        let multibyte = format!("est::{}", "é".repeat(10));
        assert_eq!(validate_requestor(est, &multibyte), Err(R::Invalid));
        let admin_256 = format!("admin::{}", "a".repeat(MAX_REQUESTOR_LEN - 6));
        assert_eq!(admin_256.len(), MAX_REQUESTOR_LEN + 1);
        assert_eq!(validate_requestor(admin, &admin_256), Err(R::Invalid));
        // A 4-byte char straddling the limit.
        let straddle = format!("acme::{}\u{1F600}", "a".repeat(MAX_REQUESTOR_LEN - 6 - 3));
        assert_eq!(straddle.len(), MAX_REQUESTOR_LEN + 1);
        assert_eq!(validate_requestor(acme, &straddle), Err(R::Invalid));
        // Huge input is rejected without panicking.
        let huge = format!("acme::{}", "z".repeat(1 << 20));
        assert_eq!(validate_requestor(acme, &huge), Err(R::Invalid));

        // Every forbidden format char range end point, in the id.
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}',
            '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{FEFF}',
        ] {
            for id in [acme, admin] {
                let r = format!("{}::a{c}b", id.namespace);
                assert_eq!(validate_requestor(id, &r), Err(R::Invalid), "{c:?}");
            }
        }
        // C0 and C1 controls, incl. NEL (U+0085) and CSI (U+009B).
        for c in [
            '\u{1}', '\u{1f}', '\r', '\t', '\u{80}', '\u{85}', '\u{9b}', '\u{9f}',
        ] {
            assert_eq!(
                validate_requestor(acme, &format!("acme::a{c}")),
                Err(R::Invalid),
                "{c:?}"
            );
        }
        // Allowlist boundaries: 0x21 and 0x7E accepted; 0x20, 0x7F and any
        // non-ASCII character refused.
        for c in ['!', '~'] {
            let r = format!("acme::a{c}");
            assert_eq!(validate_requestor(acme, &r), Ok(Some(r.clone())), "{c:?}");
        }
        for c in [' ', '\u{7f}', '\u{a0}', '\u{2010}', '\u{FF00}'] {
            let r = format!("acme::a{c}");
            assert_eq!(validate_requestor(acme, &r), Err(R::Invalid), "{c:?}");
        }

        // Precedence: the namespace is checked before content and length, so
        // a wrong-namespace oversized / control value is a mismatch.
        assert_eq!(
            validate_requestor(acme, &format!("est::{}", "a".repeat(400))),
            Err(R::NamespaceMismatch)
        );
        assert_eq!(
            validate_requestor(acme, "est::\n"),
            Err(R::NamespaceMismatch)
        );
        // Spaces in the id are refused, never trimmed.
        assert_eq!(validate_requestor(acme, "acme:: x "), Err(R::Invalid));
        // Accepted value is returned verbatim (no normalisation).
        assert_eq!(
            validate_requestor(acme, "acme::X:y"),
            Ok(Some("acme::X:y".to_string()))
        );
    }

    /// QA: config fail-closed details not covered above: a malformed entry in
    /// a list otherwise blank, a cross-list duplicate that only matches after
    /// canonicalisation of escapes, an over-long entry, and an overlap
    /// combined with an issuer-less configuration (the issuer check runs
    /// first; either way startup is refused).
    #[test]
    fn qa_registry_fail_closed_edges() {
        // Malformed admin entry next to blanks.
        let err = registry(&["CN=acme-server"], &[], &[" ", r"CN=a\", ""]).expect_err("bad");
        assert!(
            err.to_string().contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS),
            "{err}"
        );
        // Escaped-value overlap: `CN=a\,b` and `CN = a\2Cb` are the same name.
        let err = registry(&[r"CN=a\,b"], &[], &[r"CN = a\2Cb"]).expect_err("escaped overlap");
        assert!(err.to_string().contains("listed in both"), "{err}");
        // Over-long entry.
        let long = format!("CN={}", "a".repeat(MAX_ALLOWED_SUBJECT_LEN));
        assert!(registry(&[&long], &[], &[]).is_err());
        // Blank issuer lists + a (deduplicated) admin list: no issuer, refused.
        assert!(registry(&[" "], &[], &["CN=x", "CN=x"]).is_err());
        // An entry that is only Unicode whitespace is not "blank": refused.
        assert!(registry(&["CN=acme-server"], &[], &["\u{a0}"]).is_err());
        // Identity lookup never matches a non-canonical spelling.
        let r = registry(&["CN=acme-server,O=Ostrich"], &[], &[]).expect("registry");
        assert_eq!(r.identity("CN=acme-server, O=Ostrich"), None);
        assert_eq!(r.identity("cn=acme-server,O=Ostrich"), None);
        assert_eq!(
            r.identity("CN=acme-server,O=Ostrich"),
            Some(GrpcClientIdentity::ACME)
        );
    }

    /// QA: the debug output of an authorised peer and of the resolved mode
    /// carries no key material (only subjects / counts).
    #[test]
    fn qa_grpc_server_mode_debug_has_no_key_material() {
        let o = full_options("qa-debug");
        let key_path = o.key_path.clone().expect("key path");
        let key_pem = std::fs::read_to_string(&key_path).expect("key");
        let mode = o.resolve(true).expect("mtls");
        let dbg = format!("{mode:?}");
        assert!(!dbg.contains("PRIVATE KEY"), "{dbg}");
        let body: String = key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert!(!dbg.contains(&body[..body.len().min(32)]), "{dbg}");
        assert!(dbg.contains("clients"), "{dbg}");
    }

    // ---- fix round 1: RFC-001 / RFC-002 / RFC-005 / RFC-006 ----

    /// Leaf for `cn` (clientAuth) with an explicit validity window.
    fn leaf_valid(
        pki: &Pki,
        cn: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> GrpcPeerInfo {
        let mut p = CertificateParams::new(vec![s("x.example")]).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        p.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().expect("key");
        let cert = p.signed_by(&key, &pki.ca).expect("cert");
        GrpcPeerInfo {
            remote_addr: None,
            peer_leaf: Some(CertificateDer::from(cert.der().to_vec())),
        }
    }

    /// RFC-002 (IA-3 / IA-9, RFC 5280 §4.1.2.5): the leaf's validity is
    /// checked on every call; outside notBefore..=notAfter the call is
    /// `UNAUTHENTICATED`, `certificate_not_valid_now`, with the subject and
    /// certificate recorded.
    #[test]
    fn authorize_peer_refuses_leaf_outside_validity() {
        let pki = Pki::new("Validity CA");
        let allow = acme_only("CN=acme-server");
        let expired = leaf_valid(&pki, "acme-server", (2020, 1, 1), (2021, 1, 1));
        let d =
            authorize_peer(Some(&expired), &allow, RULES, P_ISSUE, &[], None).expect_err("expired");
        assert_eq!(d.code, tonic::Code::Unauthenticated);
        assert_eq!(d.reason, "certificate_not_valid_now");
        assert_eq!(d.subject.as_deref(), Some("CN=acme-server"));
        assert!(d.certificate.is_some());

        let future = leaf_valid(&pki, "acme-server", (2999, 1, 1), (3000, 1, 1));
        let d =
            authorize_peer(Some(&future), &allow, RULES, P_ISSUE, &[], None).expect_err("future");
        assert_eq!(d.reason, "certificate_not_valid_now");

        // Boundaries with an explicit clock: valid on notBefore and notAfter.
        let window = leaf_valid(&pki, "acme-server", (2030, 1, 1), (2030, 1, 2));
        let at = |secs: u64| std::time::UNIX_EPOCH + Duration::from_secs(secs);
        let nb = 1_893_456_000; // 2030-01-01T00:00:00Z
        let na = nb + 86_400;
        for (t, ok) in [(nb - 1, false), (nb, true), (na, true), (na + 1, false)] {
            let got = authorize_peer_at(Some(&window), &allow, RULES, P_ISSUE, &[], at(t), None);
            assert_eq!(got.is_ok(), ok, "t={t}");
        }
        // The time check runs before the allowlist: an expired stranger is
        // an authentication failure too.
        let stranger = leaf_valid(&pki, "intruder", (2020, 1, 1), (2021, 1, 1));
        let d = authorize_peer(Some(&stranger), &allow, RULES, P_ISSUE, &[], None).expect_err("x");
        assert_eq!(d.reason, "certificate_not_valid_now");
    }

    /// RFC-001 (AU-3): an authorised call carries the leaf issuer DN and the
    /// serial as hex; denials of a parsed leaf record both.
    #[test]
    fn authorize_peer_records_issuer_and_serial() {
        let pki = Pki::new("Serial CA");
        let allow = acme_only("CN=acme-server");
        let mut p = CertificateParams::new(vec![s("x.example")]).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, "acme-server");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x01, 0xAB, 0xCD]));
        let key = KeyPair::generate().expect("key");
        let cert = p.signed_by(&key, &pki.ca).expect("cert");
        let peer = GrpcPeerInfo {
            remote_addr: None,
            peer_leaf: Some(CertificateDer::from(cert.der().to_vec())),
        };
        let leaf = authorize_peer(Some(&peer), &allow, RULES, P_ISSUE, &[], None).expect("allowed");
        assert_eq!(leaf.issuer_dn, "CN=Serial CA");
        assert_eq!(leaf.serial_hex, "01abcd");
        let d =
            authorize_peer(Some(&peer), &allow, RULES, P_REVOKE, &[], None).expect_err("revoke");
        assert_eq!(d.reason, "method_not_permitted");
        assert_eq!(d.certificate, Some((s("CN=Serial CA"), s("01abcd"))));

        // RFC-102: the DER sign byte of a serial with the high bit set is
        // part of the rendering.
        let mut p = CertificateParams::new(vec![s("x.example")]).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, "acme-server");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x80, 0x01]));
        let key = KeyPair::generate().expect("key");
        let cert = p.signed_by(&key, &pki.ca).expect("cert");
        let peer = GrpcPeerInfo {
            remote_addr: None,
            peer_leaf: Some(CertificateDer::from(cert.der().to_vec())),
        };
        let leaf = authorize_peer(Some(&peer), &allow, RULES, P_ISSUE, &[], None).expect("ok");
        assert_eq!(leaf.serial_hex, "008001");
    }

    /// RFC-006: subjects that differ only in ASCII case across role lists
    /// refuse startup; within one list they stay distinct exact entries,
    /// and runtime matching stays exact.
    #[test]
    fn registry_refuses_case_variant_overlap() {
        let err = registry(&["CN=Acme-Server"], &[], &["CN=acme-server"]).expect_err("case");
        let msg = err.to_string();
        assert!(msg.contains("letter case"), "{msg}");
        assert!(msg.contains(ENV_GRPC_ACME_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS), "{msg}");
        assert!(registry(&["CN=a"], &["cn=A"], &[]).is_err());
        let ok = registry(&["CN=a", "CN=A"], &["CN=b"], &[]).expect("same list");
        assert_eq!(ok.identity("CN=A"), Some(GrpcClientIdentity::ACME));
        assert_eq!(ok.identity("cn=a"), None);
        assert_eq!(ok.subjects_for(GrpcClientIdentity::ACME).len(), 2);
        assert!(ok.subjects_for(GrpcClientIdentity::ADMIN).is_empty());
    }

    /// RFC-001: with admin subjects the client CA file must hold exactly
    /// one trust anchor; without admin subjects several are still accepted.
    #[test]
    fn resolve_refuses_admin_with_several_client_anchors() {
        let other = Pki::new("Second Client CA");
        let mut o = full_options("two-anchors");
        let path = o.client_ca_path.clone().expect("ca path");
        let mut bundle = std::fs::read_to_string(&path).expect("read");
        bundle.push_str(&other.ca.pem());
        std::fs::write(&path, bundle).expect("write");

        let mut with_admin = o.clone();
        with_admin.admin_subjects = vec![s("CN=ops-admin")];
        let err = with_admin.resolve(true).expect_err("admin + 2 anchors");
        let msg = err.to_string();
        assert!(msg.contains(ENV_GRPC_ADMIN_CLIENT_SUBJECTS), "{msg}");
        assert!(msg.contains("2 distinct trust anchors"), "{msg}");

        o.admin_subjects = vec![s(" ")];
        let GrpcServerMode::Mtls { client_anchors, .. } = o.resolve(true).expect("no admin") else {
            panic!("expected Mtls");
        };
        assert_eq!(client_anchors.len(), 2);

        let mut single = full_options("one-anchor");
        single.admin_subjects = vec![s("CN=ops-admin")];
        assert!(single.resolve(true).is_ok());

        // RFC-103: the same anchor repeated in the bundle counts once.
        let mut dup = full_options("dup-anchor");
        let path = dup.client_ca_path.clone().expect("ca path");
        let pem = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, format!("{pem}{pem}")).expect("write");
        dup.admin_subjects = vec![s("CN=ops-admin")];
        let GrpcServerMode::Mtls { client_anchors, .. } = dup.resolve(true).expect("dup") else {
            panic!("expected Mtls");
        };
        assert_eq!(client_anchors.len(), 1);
    }

    fn anchor_of(pki: &Pki) -> AdminTrustAnchor {
        AdminTrustAnchor::from_der(pki.ca.der()).expect("anchor")
    }

    /// SEC-101: an admin leaf must be issued directly by the single client
    /// trust anchor. A leaf under an intermediate of the anchor (or with no
    /// anchor configured) is denied `admin_issuer_not_anchor`; issuer roles
    /// under the same intermediate are still admitted.
    #[test]
    fn admin_requires_leaf_issued_directly_by_anchor() {
        let root = Pki::new("Admin Anchor CA");
        let anchor = anchor_of(&root);
        let inter_key = KeyPair::generate().expect("key");
        let inter =
            CertifiedIssuer::signed_by(ca_params("Admin Anchor Sub CA"), inter_key, &root.ca)
                .expect("intermediate");
        let clients = registry(&["CN=acme-server"], &[], &["CN=ops-admin"]).expect("registry");
        let leaf = |cn: &str, issuer: &CertifiedIssuer<'static, KeyPair>, aki: bool| {
            let mut p = CertificateParams::new(vec![s("x.example")]).expect("params");
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, cn);
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            p.use_authority_key_identifier_extension = aki;
            let key = KeyPair::generate().expect("key");
            let cert = p.signed_by(&key, issuer).expect("cert");
            GrpcPeerInfo {
                remote_addr: None,
                peer_leaf: Some(CertificateDer::from(cert.der().to_vec())),
            }
        };
        let check = |p: &GrpcPeerInfo, path: &str, a: Option<&AdminTrustAnchor>| {
            authorize_peer(Some(p), &clients, RULES, path, &[], a)
        };

        // Directly under the anchor with a matching AKI: admitted.
        let direct = leaf("ops-admin", &root.ca, true);
        let ok = check(&direct, P_REVOKE, Some(&anchor)).expect("direct admin");
        assert_eq!(ok.identity, GrpcClientIdentity::ADMIN);
        // No anchor configured: fail closed.
        let d = check(&direct, P_REVOKE, None).expect_err("no anchor");
        assert_eq!(d.reason, "admin_issuer_not_anchor");
        assert_eq!(d.code, tonic::Code::PermissionDenied);

        // SEC-201: directly under the anchor (issuer DN matches) but with no
        // AKI: denied, there is no DN-only fallback.
        let no_aki = leaf("ops-admin", &root.ca, false);
        let d = check(&no_aki, P_REVOKE, Some(&anchor)).expect_err("no AKI");
        assert_eq!(d.reason, "admin_issuer_not_anchor");
        assert_eq!(d.code, tonic::Code::PermissionDenied);
        // An anchor without an SKI never admits an admin (the builder also
        // refuses it at startup, see layer_admin_anchor_builder_and_denial).
        let ski_less = AdminTrustAnchor {
            subject_key_id: None,
            ..anchor.clone()
        };
        for p in [&direct, &no_aki] {
            assert_eq!(
                check(p, P_REVOKE, Some(&ski_less))
                    .expect_err("anchor without SKI")
                    .reason,
                "admin_issuer_not_anchor"
            );
        }

        // Under an intermediate of the anchor: denied for admin on every
        // admin RPC, with identity and certificate recorded.
        let sub_admin = leaf("ops-admin", &inter, true);
        for path in [P_REVOKE, P_CRL, P_STATUS, P_INFO, P_PROFILES] {
            let d = check(&sub_admin, path, Some(&anchor)).expect_err("sub admin");
            assert_eq!(d.code, tonic::Code::PermissionDenied, "{path}");
            assert_eq!(d.reason, "admin_issuer_not_anchor", "{path}");
            assert_eq!(d.identity, Some(GrpcClientIdentity::ADMIN));
            assert_eq!(d.subject.as_deref(), Some("CN=ops-admin"));
            assert_eq!(
                d.certificate.as_ref().map(|(issuer, _)| issuer.as_str()),
                Some("CN=Admin Anchor Sub CA")
            );
        }
        // ... the method table still decides first (Issue is not an admin RPC).
        assert_eq!(
            check(&sub_admin, P_ISSUE, Some(&anchor))
                .expect_err("issue")
                .reason,
            "method_not_permitted"
        );

        // Issuer roles under the same intermediate are still admitted.
        let sub_acme = leaf("acme-server", &inter, true);
        assert_eq!(
            check(&sub_acme, P_ISSUE, Some(&anchor))
                .expect("issuer under intermediate")
                .identity,
            GrpcClientIdentity::ACME
        );
        assert!(check(&sub_acme, P_ISSUE, None).is_ok());

        // Same issuer DN but AKI naming another key (a re-keyed look-alike
        // anchor signed the leaf): denied.
        let lookalike = Pki::new("Admin Anchor CA");
        let forged = leaf("ops-admin", &lookalike.ca, true);
        assert_eq!(
            check(&forged, P_REVOKE, Some(&anchor))
                .expect_err("forged")
                .reason,
            "admin_issuer_not_anchor"
        );
    }

    /// SEC-101: the layer builder takes the single client anchor; with admin
    /// subjects it refuses anything but exactly one distinct anchor, and
    /// denies (and audits) an admin leaf from an intermediate.
    #[tokio::test]
    async fn layer_admin_anchor_builder_and_denial() {
        use tower::{Layer as _, Service as _};
        let root = Pki::new("Layer Anchor CA");
        let other = Pki::new("Layer Other CA");
        let root_der = CertificateDer::from(root.ca.der().to_vec());
        let other_der = CertificateDer::from(other.ca.der().to_vec());
        let with_admin =
            || Arc::new(registry(&["CN=acme-server"], &[], &["CN=ops-admin"]).expect("registry"));
        let layer = |clients| SubjectAllowlistLayer::new(clients, RULES, None, "t");

        assert!(
            layer(with_admin())
                .with_client_trust_anchors(&[root_der.clone(), other_der.clone()])
                .is_err()
        );
        assert!(layer(with_admin()).with_client_trust_anchors(&[]).is_err());
        assert!(
            layer(with_admin())
                .with_client_trust_anchors(&[root_der.clone(), root_der.clone()])
                .is_ok()
        );
        let garbage = CertificateDer::from(b"junk".to_vec());
        assert!(
            layer(with_admin())
                .with_client_trust_anchors(&[garbage])
                .is_err()
        );
        // SEC-201: with admin subjects, a single anchor without a
        // subjectKeyIdentifier is refused (admin leaves are matched by AKI).
        let mut ski_less = CertificateParams::new(Vec::<String>::new()).expect("params");
        ski_less.distinguished_name = DistinguishedName::new();
        ski_less
            .distinguished_name
            .push(DnType::CommonName, "SKI-less Anchor");
        let ski_less = ski_less
            .self_signed(&KeyPair::generate().expect("key"))
            .expect("ski-less anchor");
        let ski_less_der = CertificateDer::from(ski_less.der().to_vec());
        assert!(
            subject_key_id(&x509_cert::Certificate::from_der(&ski_less_der).expect("parse"))
                .is_none()
        );
        let err = layer(with_admin())
            .with_client_trust_anchors(std::slice::from_ref(&ski_less_der))
            .err()
            .expect("ski-less anchor refused");
        assert!(err.to_string().contains("no subjectKeyIdentifier"), "{err}");
        // Without admin subjects several anchors, or an SKI-less one, are fine.
        let no_admin = Arc::new(acme_only("CN=acme-server"));
        assert!(
            layer(no_admin.clone())
                .with_client_trust_anchors(&[root_der.clone(), other_der])
                .is_ok()
        );
        assert!(
            layer(no_admin)
                .with_client_trust_anchors(&[ski_less_der])
                .is_ok()
        );

        let inter_key = KeyPair::generate().expect("key");
        let inter = CertifiedIssuer::signed_by(ca_params("Layer Sub CA"), inter_key, &root.ca)
            .expect("intermediate");
        let mut p = CertificateParams::new(vec![s("x.example")]).expect("params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, "ops-admin");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate().expect("key");
        let cert = p.signed_by(&key, &inter).expect("cert");
        let peer_info = GrpcPeerInfo {
            remote_addr: Some("10.1.2.3:4".parse().expect("addr")),
            peer_leaf: Some(CertificateDer::from(cert.der().to_vec())),
        };
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let capture = Capture::default();
        let mut svc =
            SubjectAllowlistLayer::new(with_admin(), RULES, Some(Arc::new(Collect(tx))), "t")
                .with_client_trust_anchors(&[root_der])
                .expect("anchor")
                .layer(capture.clone());
        let resp = svc
            .call(request_with_peer(P_REVOKE, peer_info))
            .await
            .expect("infallible");
        assert_eq!(
            resp.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"7".as_slice())
        );
        let ev = events.try_recv().expect("denial audited");
        assert_eq!(ev.kind, AuthAuditKind::AccessDenied);
        assert_eq!(ev.reason.as_deref(), Some("admin_issuer_not_anchor"));
        assert_eq!(ev.subject, "CN=ops-admin");
        let d = ev.details.expect("details");
        assert_eq!(d["role"], "admin");
        assert_eq!(d["peer_issuer"], "CN=Layer Sub CA");
        assert!(lock_ignoring_poison(&capture.0).is_none());
    }
}
