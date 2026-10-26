//! Per-method authorization for the CA gRPC service.
//!
//! [`CA_GRPC_METHOD_RULES`] is the method table enforced by
//! `ostrich_common::SubjectAllowlistLayer` on the CA gRPC listener (default
//! deny: a path without a rule is refused with `method_not_mapped`, including
//! RPCs added to `proto/ca_service.proto` later). [`bind_caller`] binds the
//! client-asserted `requestor` to the verified caller inside the service.
//!
//! | RPC | Issuer (acme / est) | Admin |
//! |---|---|---|
//! | IssueCertificate | allow | deny |
//! | GetCaInfo | allow | allow |
//! | ListProfiles | allow | allow |
//! | RevokeCertificate | deny | allow |
//! | GenerateCrl | deny | allow |
//! | CheckRevocationStatus | deny | allow |
//!
//! Admin may not issue: a stolen admin key cannot mint certificates, and
//! admin issuance would bypass the RA validation ACME and EST perform
//! (human-driven issuance uses the REST approval workflow). A stolen issuer
//! key cannot revoke. A future scoped ACME revoke grant (RFC 8555 §7.6) would
//! add `Issuer` to the RevokeCertificate rule plus a service-side check that
//! the target certificate's stored requestor namespace equals the caller's.
//!
//! Issuance is further limited per namespace by [`IssuerProfilePolicy`]
//! (`CA_GRPC_ACME_ALLOWED_PROFILES`, `CA_GRPC_EST_ALLOWED_PROFILES`): an
//! issuer may only request the end-entity profiles listed for its namespace;
//! CA profiles (`basic_constraints_ca`) are never allowed, and startup is
//! refused if one is listed (SEC-001). Other profiles are refused with
//! `profile_not_permitted` before `issue()` runs.
//!
//! Residual (POAM-2026-10-23-35, recorded in NIAP_GAP_ANALYSIS.md): the CA cannot
//! verify ACME account or EST client binding, so a compromised acme-server
//! can still claim any `acme::<id>` (and est-server any `est::<id>`). The
//! blast radius is its own namespace: IssueCertificate limited to that
//! namespace's allowed end-entity profiles, plus the read-only GetCaInfo and
//! ListProfiles. The audit actor is always the verified peer (with its
//! certificate issuer and serial).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement), AC-5 (Separation of Duties),
//!   AC-6 / AC-6(10) (Least Privilege; issuers cannot execute revocation or
//!   obtain CA certificates), CM-7 (only listed profiles), AU-3 / AU-10
//!   (verified caller is the actor), IA-3 / IA-9, SI-10 (requestor and
//!   profile validation), SC-24 (fail closed)
//! - NIAP PP-CA: FDP_ACC.1, FDP_ACF.1, FDP_IFC.1, FMT_SMR.2, FMT_MTD.1,
//!   FAU_GEN.2
// POAM: POAM-2026-10-23-35 - RA namespace confused deputy: a
// compromised acme-server / est-server can issue under any id of its own
// namespace with that namespace's allowed end-entity profiles; residual
// recorded in NIAP_GAP_ANALYSIS.md (AC-3, AU-10).

use std::future::Future;

use ostrich_common::grpc_tls::{
    AuthorizedGrpcPeer, GrpcClientIdentity, GrpcClientRegistry, GrpcClientRole, GrpcMethodRule,
};
use ostrich_x509::profile::CertificateProfile;
use serde_json::json;
use tonic::{Request, Status};

use crate::issuance::AuthenticatedCaller;

/// Profiles the `acme` namespace may request (`;`-delimited profile names).
pub const ENV_GRPC_ACME_ALLOWED_PROFILES: &str = "CA_GRPC_ACME_ALLOWED_PROFILES";
/// Profiles the `est` namespace may request (`;`-delimited profile names).
pub const ENV_GRPC_EST_ALLOWED_PROFILES: &str = "CA_GRPC_EST_ALLOWED_PROFILES";
/// Default for [`ENV_GRPC_ACME_ALLOWED_PROFILES`].
pub const DEFAULT_ACME_ALLOWED_PROFILES: &str = "acme-default";
/// Default for [`ENV_GRPC_EST_ALLOWED_PROFILES`].
pub const DEFAULT_EST_ALLOWED_PROFILES: &str = "tls_client;tls_server;tls_server_client;efs";

/// gRPC status message for `profile_not_permitted` (static: it never echoes
/// the requested profile or the configured lists).
pub const PROFILE_DENIED_MESSAGE: &str = "certificate profile is not permitted for this client";

/// Maximum characters of a refused profile name copied into the audit record.
const MAX_AUDITED_PROFILE_CHARS: usize = 64;

const ISSUER: &[GrpcClientRole] = &[GrpcClientRole::Issuer];
const ADMIN: &[GrpcClientRole] = &[GrpcClientRole::Admin];
const ISSUER_AND_ADMIN: &[GrpcClientRole] = &[GrpcClientRole::Issuer, GrpcClientRole::Admin];

/// The CA gRPC method table (see the module docs). Paths are
/// `/{SERVICE_NAME}/{Rpc}` for `ostrich.ca.v1.CertificateAuthorityService`;
/// `rules_cover_every_proto_rpc` ties them to `proto/ca_service.proto`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, AC-6, CM-7 (Least Functionality: only these RPCs are
///   reachable, default deny), AC-6(9) (RevokeCertificate and GenerateCrl
///   record the verified admin peer as audit actor; CheckRevocationStatus is
///   an unaudited read, NIST-102)
/// - NIAP PP-CA: FDP_ACC.1, FDP_ACF.1, FMT_SMR.2
pub const CA_GRPC_METHOD_RULES: &[GrpcMethodRule] = &[
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate",
        roles: ISSUER,
    },
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/RevokeCertificate",
        roles: ADMIN,
    },
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/GenerateCrl",
        roles: ADMIN,
    },
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/CheckRevocationStatus",
        roles: ADMIN,
    },
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo",
        roles: ISSUER_AND_ADMIN,
    },
    GrpcMethodRule {
        path: "/ostrich.ca.v1.CertificateAuthorityService/ListProfiles",
        roles: ISSUER_AND_ADMIN,
    },
];

/// The audit identity of a gRPC call after requestor binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundCaller {
    /// Verified peer (subject DN = the audit actor, plus its certificate
    /// issuer and serial); `None` only on the debug-only plaintext listener.
    pub caller: Option<AuthenticatedCaller>,
    /// The requestor to store and record as `on_behalf_of`: validated against
    /// the caller's namespace, or `""` for an admin call without one.
    pub requestor: String,
}

impl BoundCaller {
    /// The audit actor (verified peer subject DN), if any.
    pub fn actor(&self) -> Option<&str> {
        self.caller.as_ref().map(|c| c.subject_dn.as_str())
    }
}

/// The [`AuthenticatedCaller`] of a verified peer (subject, issuer, serial).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-3, IA-3 / IA-9; NIAP PP-CA: FAU_GEN.2
pub fn authenticated_caller(peer: &AuthorizedGrpcPeer) -> AuthenticatedCaller {
    AuthenticatedCaller {
        subject_dn: peer.subject_dn.clone(),
        issuer_dn: peer.issuer_dn.clone(),
        serial_hex: peer.serial_hex.clone(),
    }
}

/// Per-namespace issuance profile allowlist for the `Issuer` role (SEC-001).
///
/// Built once at startup from `CA_GRPC_ACME_ALLOWED_PROFILES` /
/// `CA_GRPC_EST_ALLOWED_PROFILES` and the registered profiles. Exact,
/// case-sensitive profile-name match at call time.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, AC-6 / AC-6(10) (an RA cannot obtain a CA
///   certificate), CM-6 / CM-7 (fail-closed configuration, least
///   functionality), SC-24
/// - NIAP PP-CA: FDP_ACF.1, FDP_IFC.1 (issuance policy), FMT_MTD.1
/// - RFC 5280 §4.2.1.9 (cA = TRUE profiles are never issuable over gRPC)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerProfilePolicy {
    acme: Vec<String>,
    est: Vec<String>,
}

impl IssuerProfilePolicy {
    /// Parse and validate the two lists against `profiles` (the profiles the
    /// CA registers), failing closed.
    ///
    /// Blank entries (ASCII padding only, e.g. a trailing `;`) are dropped.
    /// Refuses: an entry that names no registered profile; an entry naming a
    /// CA profile (`basic_constraints_ca`); an empty list for a namespace
    /// that has client subjects in `clients` (neither "nothing allowed" nor
    /// "everything allowed" is implied). An empty list for a namespace
    /// without subjects is accepted (e.g. the EST-only deployment). With
    /// `clients = None` (debug-only plaintext listener) only the entries are
    /// checked.
    pub fn parse(
        acme: &[String],
        est: &[String],
        clients: Option<&GrpcClientRegistry>,
        profiles: &[CertificateProfile],
    ) -> ostrich_common::Result<Self> {
        let list = |entries: &[String],
                    env: &str,
                    identity: GrpcClientIdentity|
         -> ostrich_common::Result<Vec<String>> {
            let mut out: Vec<String> = Vec::new();
            for raw in entries {
                let name = raw.trim_matches([' ', '\t', '\r', '\n']);
                if name.is_empty() {
                    continue;
                }
                let Some(profile) = profiles.iter().find(|p| p.name == name) else {
                    return Err(ostrich_common::Error::Config(format!(
                        "{env} lists {:?}, which is not a registered certificate profile; \
                         refusing to start",
                        name.escape_debug().to_string()
                    )));
                };
                if profile.basic_constraints_ca {
                    return Err(ostrich_common::Error::Config(format!(
                        "{env} lists the CA profile {name}: CA certificates are never issuable \
                         over gRPC by an issuer client; refusing to start"
                    )));
                }
                if !out.iter().any(|n| n == name) {
                    out.push(name.to_string());
                }
            }
            let has_subjects = clients.is_some_and(|c| !c.subjects_for(identity).is_empty());
            if out.is_empty() && has_subjects {
                return Err(ostrich_common::Error::Config(format!(
                    "{env} is empty but {} client subjects are configured; list the \
                     end-entity profiles they may request; refusing to start",
                    identity.namespace
                )));
            }
            Ok(out)
        };
        Ok(Self {
            acme: list(
                acme,
                ENV_GRPC_ACME_ALLOWED_PROFILES,
                GrpcClientIdentity::ACME,
            )?,
            est: list(est, ENV_GRPC_EST_ALLOWED_PROFILES, GrpcClientIdentity::EST)?,
        })
    }

    /// Whether the requestor namespace `namespace` may request `profile`.
    /// Only `acme` and `est` have lists; any other namespace (admin) is
    /// never allowed.
    pub fn allows(&self, namespace: &str, profile: &str) -> bool {
        let list = match namespace {
            "acme" => &self.acme,
            "est" => &self.est,
            _ => return false,
        };
        list.iter().any(|p| p == profile)
    }

    /// Whether any namespace may request `profile` (the debug-only plaintext
    /// listener, which has no namespace).
    pub fn allows_any(&self, profile: &str) -> bool {
        self.allows("acme", profile) || self.allows("est", profile)
    }

    /// `{acme: [..], est: [..]}` for the startup log and the
    /// `grpc_listener_started` audit record (CM-3).
    pub fn summary(&self) -> serde_json::Value {
        json!({ "acme": self.acme, "est": self.est })
    }
}

/// Maximum characters of a refused requestor's namespace copied into the
/// denial audit record.
const MAX_CLAIMED_NAMESPACE_CHARS: usize = 32;

/// The namespace part (before `::`, or the whole value) of a refused
/// requestor, truncated and `escape_debug`'d so it cannot inject control or
/// bidi characters into logs or audit records.
fn claimed_namespace(requestor: &str) -> String {
    let prefix = requestor.split_once("::").map_or(requestor, |(p, _)| p);
    prefix
        .chars()
        .take(MAX_CLAIMED_NAMESPACE_CHARS)
        .collect::<String>()
        .escape_debug()
        .to_string()
}

/// The verified peer of a call, failing closed when it is required.
///
/// `Ok(None)` only when `require_peer` is false (debug-only plaintext
/// listener). With `require_peer` and no [`AuthorizedGrpcPeer`] the call is
/// refused: unreachable behind the listener layer, which always inserts it,
/// so this is defence in depth (there is no listener limiter to audit
/// through, so it is logged at error level).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, SC-24 (fail closed); NIAP PP-CA: FPT_FLS.1
pub fn authorized_peer<T>(
    request: &Request<T>,
    require_peer: bool,
) -> Result<Option<&AuthorizedGrpcPeer>, Status> {
    match request.extensions().get::<AuthorizedGrpcPeer>() {
        Some(peer) => Ok(Some(peer)),
        None if require_peer => {
            tracing::error!(
                "CA gRPC call without an authorised peer on an mTLS service; denied \
                 (the authorization layer is missing from the server stack)"
            );
            Err(Status::permission_denied(
                "client is not authorised for this call",
            ))
        }
        None => Ok(None),
    }
}

/// Bind the client-asserted `requestor` of a call to its verified caller.
///
/// - Peer present: [`AuthorizedGrpcPeer::bind_requestor`]; on a rejection the
///   call is refused through [`AuthorizedGrpcPeer::deny`] (`PERMISSION_DENIED`,
///   rate-limited `access_denied` record with the rejection reason and
///   `{claimed_namespace, expected_namespace}`), else
///   `BoundCaller { caller: Some(peer), requestor }`.
/// - No peer: see [`authorized_peer`]; on the plaintext dev listener the
///   requestor is passed through unchecked with no caller.
///
/// The denial record is spawned when this function is called (not when the
/// returned future is first polled), and the future borrows nothing from the
/// request, so a cancelled call cannot cancel the record.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-3 / AU-10 (actor = verified peer, on_behalf_of =
///   bound requestor), SI-10, AC-3, AU-2 / AU-12 (denials audited)
/// - NIAP PP-CA: FAU_GEN.2, FDP_ACF.1
pub fn bind_caller<T>(
    request: &Request<T>,
    requestor: &str,
    require_peer: bool,
) -> impl Future<Output = Result<BoundCaller, Status>> + Send + use<T> {
    bind(request, requestor, None, require_peer)
}

/// [`bind_caller`] for IssueCertificate, then the per-namespace profile check
/// ([`IssuerProfilePolicy`]): a profile the caller's namespace may not
/// request is refused with `profile_not_permitted` through
/// [`AuthorizedGrpcPeer::deny_with_message`] (`PERMISSION_DENIED`
/// [`PROFILE_DENIED_MESSAGE`], audited with `{requested_profile, namespace}`)
/// before any issuance work. On the plaintext dev listener (no namespace) the
/// profile must be in either list, and a refusal is only logged.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, AC-6(10), CM-7, AU-2 / AU-12 (denial audited), SI-10
/// - NIAP PP-CA: FDP_ACF.1, FDP_IFC.1, FAU_GEN.1
pub fn authorize_issue<T>(
    request: &Request<T>,
    requestor: &str,
    profile: &str,
    policy: &IssuerProfilePolicy,
    require_peer: bool,
) -> impl Future<Output = Result<BoundCaller, Status>> + Send + use<T> {
    bind(request, requestor, Some((profile, policy)), require_peer)
}

type DenialFuture = std::pin::Pin<Box<dyn Future<Output = Status> + Send>>;

/// [`bind_caller`] / [`authorize_issue`].
fn bind<T>(
    request: &Request<T>,
    requestor: &str,
    profile: Option<(&str, &IssuerProfilePolicy)>,
    require_peer: bool,
) -> impl Future<Output = Result<BoundCaller, Status>> + Send + use<T> {
    let outcome: Result<BoundCaller, DenialFuture> = match authorized_peer(request, require_peer) {
        Err(status) => Err(Box::pin(std::future::ready(status))),
        Ok(None) => match profile {
            Some((name, policy)) if !policy.allows_any(name) => {
                tracing::warn!(
                    reason = "profile_not_permitted",
                    "CA gRPC (plaintext dev listener) refused a profile outside the allow lists"
                );
                Err(Box::pin(std::future::ready(Status::permission_denied(
                    PROFILE_DENIED_MESSAGE,
                ))))
            }
            _ => Ok(BoundCaller {
                caller: None,
                requestor: requestor.to_string(),
            }),
        },
        Ok(Some(peer)) => match peer.bind_requestor(requestor) {
            Err(rejection) => Err(peer.deny(
                rejection.reason(),
                json!({
                    "claimed_namespace": claimed_namespace(requestor),
                    "expected_namespace": peer.identity.namespace,
                }),
            )),
            Ok(_)
                if profile.is_some_and(|(name, policy)| {
                    !policy.allows(peer.identity.namespace, name)
                }) =>
            {
                let requested = profile.map(|(name, _)| name).unwrap_or_default();
                Err(peer.deny_with_message(
                    "profile_not_permitted",
                    json!({
                        "requested_profile": requested
                            .chars()
                            .take(MAX_AUDITED_PROFILE_CHARS)
                            .collect::<String>()
                            .escape_debug()
                            .to_string(),
                        "namespace": peer.identity.namespace,
                    }),
                    PROFILE_DENIED_MESSAGE,
                ))
            }
            Ok(bound) => Ok(BoundCaller {
                caller: Some(authenticated_caller(peer)),
                requestor: bound.unwrap_or_default(),
            }),
        },
    };
    async move {
        match outcome {
            Ok(bound) => Ok(bound),
            Err(denied) => Err(denied.await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_protocol::certificate_authority_service_server::SERVICE_NAME;

    /// RPC names declared in `service CertificateAuthorityService`.
    fn proto_rpcs() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/ca_service.proto");
        let proto = std::fs::read_to_string(path).expect("read proto/ca_service.proto");
        proto
            .lines()
            .map(str::trim_start)
            .filter_map(|line| line.strip_prefix("rpc "))
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<String>()
            })
            .collect()
    }

    /// SA-11: every RPC in the proto has exactly one rule and every rule maps
    /// to an RPC; a new RPC fails this test (and is denied at runtime).
    #[test]
    fn rules_cover_every_proto_rpc() {
        let rpcs = proto_rpcs();
        assert_eq!(rpcs.len(), 6, "{rpcs:?}");
        assert_eq!(SERVICE_NAME, "ostrich.ca.v1.CertificateAuthorityService");
        for rpc in &rpcs {
            let path = format!("/{SERVICE_NAME}/{rpc}");
            let count = CA_GRPC_METHOD_RULES
                .iter()
                .filter(|r| r.path == path)
                .count();
            assert_eq!(count, 1, "rules for {path}");
        }
        for rule in CA_GRPC_METHOD_RULES {
            let rpc = rule
                .path
                .strip_prefix(&format!("/{SERVICE_NAME}/"))
                .unwrap_or_else(|| panic!("{} outside the CA service", rule.path));
            assert!(rpcs.iter().any(|r| r == rpc), "{} not in proto", rule.path);
            assert!(!rule.roles.is_empty(), "{} has no roles", rule.path);
        }
    }

    /// AC-5 / AC-6: issuers only on Issue + reads; admin never on Issue.
    #[test]
    fn rules_match_policy_table() {
        let roles = |rpc: &str| {
            CA_GRPC_METHOD_RULES
                .iter()
                .find(|r| r.path.ends_with(&format!("/{rpc}")))
                .map(|r| r.roles)
                .unwrap_or_else(|| panic!("no rule for {rpc}"))
        };
        assert_eq!(roles("IssueCertificate"), &[GrpcClientRole::Issuer]);
        for rpc in ["RevokeCertificate", "GenerateCrl", "CheckRevocationStatus"] {
            assert_eq!(roles(rpc), &[GrpcClientRole::Admin], "{rpc}");
        }
        for rpc in ["GetCaInfo", "ListProfiles"] {
            assert_eq!(
                roles(rpc),
                &[GrpcClientRole::Issuer, GrpcClientRole::Admin],
                "{rpc}"
            );
        }
        for rule in CA_GRPC_METHOD_RULES {
            if rule.roles.contains(&GrpcClientRole::Issuer) {
                assert!(
                    ["IssueCertificate", "GetCaInfo", "ListProfiles"]
                        .iter()
                        .any(|rpc| rule.path.ends_with(&format!("/{rpc}"))),
                    "issuer granted {}",
                    rule.path
                );
            }
        }
    }

    #[tokio::test]
    async fn bind_caller_requires_peer_by_default() {
        let request = Request::new(());
        let status = bind_caller(&request, "acme::1", true)
            .await
            .expect_err("no peer, required");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(authorized_peer(&request, true).is_err());
    }

    #[tokio::test]
    async fn bind_caller_dev_plaintext_passes_requestor_through() {
        let request = Request::new(());
        let bound = bind_caller(&request, "anything", false)
            .await
            .expect("dev plaintext");
        assert_eq!(
            bound,
            BoundCaller {
                caller: None,
                requestor: "anything".to_string()
            }
        );
        assert_eq!(bound.actor(), None);
        assert!(matches!(authorized_peer(&request, false), Ok(None)));
    }

    #[test]
    fn claimed_namespace_is_truncated_and_escaped() {
        assert_eq!(claimed_namespace("est::x"), "est");
        assert_eq!(claimed_namespace("nonamespace"), "nonamespace");
        assert_eq!(claimed_namespace("a\nb::x"), "a\\nb");
        assert_eq!(claimed_namespace("\u{202E}x::y"), "\\u{202e}x");
        let long = "n".repeat(100);
        assert_eq!(claimed_namespace(&long).len(), MAX_CLAIMED_NAMESPACE_CHARS);
    }

    fn profiles() -> Vec<CertificateProfile> {
        let named = |mut p: CertificateProfile, name: &str| {
            p.name = name.to_string();
            p
        };
        vec![
            named(CertificateProfile::tls_server(90), "acme-default"),
            named(CertificateProfile::tls_client(365), "tls_client"),
            named(CertificateProfile::tls_server(397), "tls_server"),
            named(
                CertificateProfile::intermediate_ca(1825, 0),
                "intermediate_ca",
            ),
        ]
    }

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn clients(acme: &[&str], est: &[&str]) -> GrpcClientRegistry {
        GrpcClientRegistry::parse(&v(acme), &v(est), &[]).expect("registry")
    }

    /// SEC-001 (AC-6(10), CM-6): per-namespace profile lists, exact match;
    /// admin and unknown namespaces are never allowed.
    #[test]
    fn profile_policy_allows_only_listed_profiles() {
        let c = clients(&["CN=acme-server"], &["CN=est-server"]);
        let policy = IssuerProfilePolicy::parse(
            &v(&["acme-default", " ", ""]),
            &v(&["tls_client", "tls_server", "tls_client"]),
            Some(&c),
            &profiles(),
        )
        .expect("policy");
        assert!(policy.allows("acme", "acme-default"));
        assert!(!policy.allows("acme", "tls_client"));
        assert!(!policy.allows("acme", "intermediate_ca"));
        assert!(!policy.allows("acme", "ACME-DEFAULT"));
        assert!(policy.allows("est", "tls_server"));
        assert!(!policy.allows("est", "acme-default"));
        assert!(!policy.allows("admin", "acme-default"));
        assert!(!policy.allows("other", "tls_client"));
        assert!(policy.allows_any("tls_client"));
        assert!(!policy.allows_any("intermediate_ca"));
        assert_eq!(
            policy.summary(),
            json!({"acme": ["acme-default"], "est": ["tls_client", "tls_server"]})
        );
    }

    /// SEC-001: startup refusals (unknown profile, CA profile, empty list for
    /// a namespace with subjects); an empty list without subjects is fine.
    #[test]
    fn profile_policy_refuses_bad_configuration() {
        let both = clients(&["CN=acme-server"], &["CN=est-server"]);
        let err = |acme: &[&str], est: &[&str], c: &GrpcClientRegistry| {
            IssuerProfilePolicy::parse(&v(acme), &v(est), Some(c), &profiles())
                .expect_err("refused")
                .to_string()
        };
        let msg = err(&["acme-default", "nope"], &["tls_client"], &both);
        assert!(
            msg.contains(ENV_GRPC_ACME_ALLOWED_PROFILES) && msg.contains("nope"),
            "{msg}"
        );
        let msg = err(&["acme-default"], &["intermediate_ca"], &both);
        assert!(msg.contains(ENV_GRPC_EST_ALLOWED_PROFILES), "{msg}");
        assert!(msg.contains("CA profile"), "{msg}");
        let msg = err(&[" ", ""], &["tls_client"], &both);
        assert!(msg.contains("is empty"), "{msg}");
        let msg = err(&["acme-default"], &[], &both);
        assert!(msg.contains(ENV_GRPC_EST_ALLOWED_PROFILES), "{msg}");
        // Control characters in an unknown name are escaped in the error.
        let msg = err(&["bad\nname"], &["tls_client"], &both);
        assert!(!msg.contains('\n'), "{msg}");

        // EST-only deployment: ACME list empty or default, no ACME subjects.
        let est_only = clients(&[], &["CN=est-server"]);
        for acme in [&[][..], &[""][..], &["acme-default"][..]] {
            IssuerProfilePolicy::parse(&v(acme), &v(&["tls_client"]), Some(&est_only), &profiles())
                .expect("est-only");
        }
        // A CA profile is refused even for a namespace without subjects.
        assert!(
            IssuerProfilePolicy::parse(
                &v(&["intermediate_ca"]),
                &v(&["tls_client"]),
                Some(&est_only),
                &profiles()
            )
            .is_err()
        );
        // Plaintext dev (no registry): entries are still validated.
        assert!(IssuerProfilePolicy::parse(&v(&["nope"]), &[], None, &profiles()).is_err());
        assert!(IssuerProfilePolicy::parse(&[], &[], None, &profiles()).is_ok());
    }

    /// The default lists parse against the profiles ca-server registers.
    #[test]
    fn default_profile_lists_name_end_entity_profiles() {
        let split = |d: &str| d.split(';').map(str::to_string).collect::<Vec<_>>();
        assert_eq!(split(DEFAULT_ACME_ALLOWED_PROFILES), v(&["acme-default"]));
        assert_eq!(
            split(DEFAULT_EST_ALLOWED_PROFILES),
            v(&["tls_client", "tls_server", "tls_server_client", "efs"])
        );
    }

    #[tokio::test]
    async fn authorize_issue_dev_plaintext_checks_union() {
        let policy = IssuerProfilePolicy::parse(
            &v(&["acme-default"]),
            &v(&["tls_client"]),
            None,
            &profiles(),
        )
        .expect("policy");
        let request = Request::new(());
        let ok = authorize_issue(&request, "x", "tls_client", &policy, false)
            .await
            .expect("listed");
        assert_eq!(ok.caller, None);
        let st = authorize_issue(&request, "x", "intermediate_ca", &policy, false)
            .await
            .expect_err("CA profile");
        assert_eq!(st.code(), tonic::Code::PermissionDenied);
        assert_eq!(st.message(), PROFILE_DENIED_MESSAGE);
        assert!(st.message().contains("profile"));
        // No peer with require_peer: refused before the profile check.
        let st = authorize_issue(&request, "acme::1", "acme-default", &policy, true)
            .await
            .expect_err("no peer");
        assert_eq!(st.code(), tonic::Code::PermissionDenied);
        assert_ne!(st.message(), PROFILE_DENIED_MESSAGE);
    }
}
