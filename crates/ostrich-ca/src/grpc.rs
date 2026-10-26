//! gRPC service implementation for Certificate Authority
//!
//! This module provides gRPC service endpoints for certificate issuance, revocation,
//! and CA management operations.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: Security management functions - gRPC endpoints for CA operations
//! - **FDP_ACC.1 / FDP_ACF.1**: Access control - per-method, per-role rules
//!   ([`crate::grpc_authz::CA_GRPC_METHOD_RULES`]) enforced on the listener;
//!   the client-asserted requestor is bound to the caller's namespace
//! - **FAU_GEN.2**: issuance / revocation / CRL audit actor = verified peer
//! - **FIA_AFL.1**: N/A - certificate-based (mTLS) authentication, no
//!   password/lockout path; see FIA_X509_EXT.1 (`ostrich_common::grpc_tls`)
//! - **FTP_ITC.1**: Inter-TSF trusted channel - mTLS for gRPC transport
//!
//! ## RFC Compliance
//! - RFC 5280: X.509 Public Key Infrastructure
//!
//! ## NIST 800-53 Controls
//! - SC-8: Transmission confidentiality (mTLS)
//! - AC-3: Access enforcement; AC-5 / AC-6: issuer and admin RPCs separated
//! - AU-3 / AU-10: authenticated caller is the audit actor
//! - AC-17: Remote access (mTLS authentication)

use crate::grpc_authz::{
    BoundCaller, IssuerProfilePolicy, authenticated_caller, authorize_issue, authorized_peer,
    bind_caller,
};
use crate::issuance::AuthenticatedCaller;
use crate::revocation::CrlActor;
use crate::{CertificateAuthority, Error, IssuanceRequest, Result, RevocationRequest};
use ostrich_common::GrpcServerMode;
use ostrich_common::types::DistinguishedName;
use ostrich_protocol::{
    CertificateProfile as ProtoCertificateProfile, CheckRevocationStatusRequest,
    CheckRevocationStatusResponse, DistinguishedName as ProtoDistinguishedName, GenerateCrlRequest,
    GenerateCrlResponse, GetCaInfoRequest, GetCaInfoResponse, IssueCertificateRequest,
    IssueCertificateResponse, ListProfilesRequest, ListProfilesResponse,
    RevocationReason as ProtoRevocationReason, RevokeCertificateRequest, RevokeCertificateResponse,
    SubjectAltName as ProtoSubjectAltName,
    certificate_authority_service_server::CertificateAuthorityService,
};
use ostrich_x509::{
    extensions::SubjectAltName, parser::RevocationReason, profile::CertificateProfile,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Map a CA error to a gRPC status without leaking internals (SI-11):
/// client-correctable errors (unknown profile, invalid request, approval
/// state, not found, already revoked) keep their message; everything else
/// (database, crypto, audit, encoding) is logged server-side with `op` and
/// answered with a generic `INTERNAL`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-11 (Error Handling), AU-3 (detail kept in the log)
fn grpc_status(op: &'static str, e: Error) -> Status {
    match e {
        Error::ProfileNotFound(_) | Error::InvalidRequest(_) => {
            Status::invalid_argument(e.to_string())
        }
        Error::NotFound(_) | Error::ApprovalRequestNotFound(_) => Status::not_found(e.to_string()),
        Error::SelfApprovalProhibited
        | Error::InvalidApprovalState { .. }
        | Error::ApprovalRequestExpired { .. }
        | Error::Revocation(_) => Status::failed_precondition(e.to_string()),
        Error::InsufficientRole { .. } | Error::ProfileNotPermitted => {
            Status::permission_denied(e.to_string())
        }
        other => {
            tracing::error!(op, error = %other, "CA gRPC call failed");
            Status::internal(format!("{op} failed: internal error"))
        }
    }
}

/// Whether a [`CaGrpcService`] for `mode` must refuse calls without an
/// `AuthorizedGrpcPeer`: always for mTLS, and for the plaintext dev mode in
/// release builds too (fail closed; `GrpcServerOptions::resolve` refuses
/// that mode in release builds anyway). SEC-004 / QA-003.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-24, AC-3; NIAP PP-CA: FPT_FLS.1
pub fn mode_requires_peer(mode: &GrpcServerMode) -> bool {
    match mode {
        GrpcServerMode::Mtls { .. } => true,
        GrpcServerMode::InsecureDevPlaintext => !cfg!(debug_assertions),
    }
}

/// Build the `IssuanceRequest` for an authorised IssueCertificate call:
/// `requestor` = bound requestor, `authenticated_caller` = verified peer
/// (AU-3 / AU-10, FAU_GEN.2; NIST-006). Pure, for testing.
fn issuance_request(
    req: IssueCertificateRequest,
    caller: BoundCaller,
    request_id: uuid::Uuid,
) -> std::result::Result<IssuanceRequest, Status> {
    let subject = CaGrpcService::convert_dn(req.subject)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let subject_alt_names = req
        .subject_alt_names
        .into_iter()
        .map(CaGrpcService::convert_san)
        .collect::<Result<Vec<SubjectAltName>>>()
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let metadata = if req.metadata.is_empty() {
        None
    } else {
        Some(
            serde_json::to_value(req.metadata)
                .map_err(|_| Status::invalid_argument("invalid metadata"))?,
        )
    };
    Ok(IssuanceRequest {
        profile_name: req.profile_name,
        subject,
        subject_alt_names,
        public_key: req.public_key,
        requestor: caller.requestor,
        authenticated_caller: caller.caller,
        metadata,
        // CSR is optional on the wire; an empty field means "not provided".
        // When present, issue() verifies proof-of-possession (RFC 2986 / SI-10).
        csr_der: if req.csr_der.is_empty() {
            None
        } else {
            Some(req.csr_der)
        },
        approval_request_id: None, // TODO: Accept from request
        request_id: Some(request_id),
    })
}

/// Build the `RevocationRequest` for an authorised RevokeCertificate call
/// (`authenticated_caller` = verified admin peer). `Err` is the audit
/// failure reason (`invalid_certificate_id`, `invalid_reason`). Pure, for
/// testing.
fn revocation_request(
    req: RevokeCertificateRequest,
    caller: BoundCaller,
) -> std::result::Result<RevocationRequest, &'static str> {
    let certificate_id =
        uuid::Uuid::parse_str(&req.certificate_id).map_err(|_| "invalid_certificate_id")?;
    let reason =
        CaGrpcService::convert_reason_from_proto(req.reason).map_err(|_| "invalid_reason")?;
    Ok(RevocationRequest {
        certificate_id,
        reason,
        requestor: caller.requestor,
        authenticated_caller: caller.caller,
        justification: (!req.justification.is_empty()).then_some(req.justification),
    })
}

/// The `CrlGeneration` actor of a GenerateCrl call: the verified admin peer,
/// or `unauthenticated` on the debug-only plaintext listener. Pure, for
/// testing (QA-002 / M13).
fn crl_actor(caller: Option<&AuthenticatedCaller>) -> CrlActor<'_> {
    match caller {
        Some(caller) => CrlActor::Peer(caller),
        None => CrlActor::Unauthenticated,
    }
}

/// Authenticated gRPC caller for logs: the allow-listed client-certificate
/// subject inserted by `ostrich_common::grpc_tls::SubjectAllowlistLayer`, or
/// `"unauthenticated"` on the debug-only plaintext listener.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-3 correlation: the mTLS-authenticated (IA-3 / IA-9) service
///   identity is logged next to the request id. The audit records' actor is
///   set from the same peer through [`crate::grpc_authz::bind_caller`].
fn peer_subject<T>(request: &Request<T>) -> String {
    request
        .extensions()
        .get::<ostrich_common::AuthorizedGrpcPeer>()
        .map(|p| p.subject_dn.clone())
        .unwrap_or_else(|| "unauthenticated".to_string())
}

/// Correlation id for a call without a request-id field: the caller's
/// `x-request-id` metadata when it is a UUID, else a fresh one (SI-10: the
/// header is untrusted, so it is only accepted in UUID form).
fn correlation_id<T>(request: &Request<T>) -> uuid::Uuid {
    request
        .metadata()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
        .unwrap_or_else(uuid::Uuid::new_v4)
}

/// gRPC service wrapper for Certificate Authority
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1 - Exposes CA security management functions via gRPC
/// - NIAP PP-CA: FTP_ITC.1 - Requires mTLS for trusted channel
/// - NIST 800-53: SC-24 - every handler refuses a call without an
///   `AuthorizedGrpcPeer` unless built for the dev plaintext listener
pub struct CaGrpcService {
    ca: Arc<CertificateAuthority>,
    /// Refuse calls without an `AuthorizedGrpcPeer` (fail closed). False
    /// only for the debug-only plaintext listener.
    require_peer: bool,
    /// Per-namespace issuance profile allowlist (SEC-001).
    profiles: Arc<IssuerProfilePolicy>,
}

impl CaGrpcService {
    /// Create the service for the resolved listener `mode` (the single
    /// constructor ca-server uses, so the peer requirement always follows
    /// the listener: [`mode_requires_peer`]).
    pub fn for_mode(
        mode: &GrpcServerMode,
        ca: Arc<CertificateAuthority>,
        profiles: Arc<IssuerProfilePolicy>,
    ) -> Self {
        Self {
            ca,
            require_peer: mode_requires_peer(mode),
            profiles,
        }
    }

    /// Create the service for the mTLS listener: every call must carry the
    /// `AuthorizedGrpcPeer` inserted by `SubjectAllowlistLayer`.
    pub fn new(ca: Arc<CertificateAuthority>, profiles: Arc<IssuerProfilePolicy>) -> Self {
        Self {
            ca,
            require_peer: true,
            profiles,
        }
    }

    /// Create the service for the debug-only, unauthenticated plaintext
    /// listener (`CA_GRPC_INSECURE_DEV_PLAINTEXT`): there is no peer, the
    /// requestor is not bound and the audit actor is the requestor.
    /// NIST 800-53: CM-6 - debug builds only (and refused in release builds
    /// by `GrpcServerOptions`).
    #[cfg(debug_assertions)]
    pub fn new_insecure_dev_plaintext(
        ca: Arc<CertificateAuthority>,
        profiles: Arc<IssuerProfilePolicy>,
    ) -> Self {
        Self {
            ca,
            require_peer: false,
            profiles,
        }
    }

    /// Whether calls without a verified peer are refused (SC-24).
    pub fn requires_peer(&self) -> bool {
        self.require_peer
    }

    /// Convert proto DistinguishedName to internal type
    fn convert_dn(proto_dn: Option<ProtoDistinguishedName>) -> Result<DistinguishedName> {
        let proto_dn = proto_dn.ok_or_else(|| Error::InvalidRequest("Missing DN".to_string()))?;

        Ok(DistinguishedName {
            common_name: proto_dn.common_name,
            organization: proto_dn.organization,
            organizational_unit: proto_dn.organizational_unit,
            locality: proto_dn.locality,
            state_or_province: proto_dn.state_or_province,
            country: proto_dn.country,
            serial_number: proto_dn.serial_number,
        })
    }

    /// Convert proto SubjectAltName to internal type
    fn convert_san(proto_san: ProtoSubjectAltName) -> Result<SubjectAltName> {
        use ostrich_protocol::subject_alt_name::Name;

        let name = proto_san
            .name
            .ok_or_else(|| Error::InvalidRequest("Missing SAN name".to_string()))?;

        Ok(match name {
            Name::DnsName(dns) => SubjectAltName::DnsName(dns),
            Name::Rfc822Name(email) => SubjectAltName::Rfc822Name(email),
            Name::Uri(uri) => SubjectAltName::UniformResourceIdentifier(uri),
            Name::IpAddress(ip) => {
                let ip_addr: std::net::IpAddr = ip
                    .parse()
                    .map_err(|_| Error::InvalidRequest("Invalid IP address".to_string()))?;
                SubjectAltName::IpAddress(ip_addr)
            }
            Name::DirectoryName(dn) => SubjectAltName::DirectoryName(dn),
        })
    }

    /// Convert internal RevocationReason to proto
    #[allow(dead_code)] // TODO: Use when implementing full revocation status retrieval
    fn convert_reason_to_proto(reason: RevocationReason) -> ProtoRevocationReason {
        match reason {
            RevocationReason::Unspecified => ProtoRevocationReason::Unspecified,
            RevocationReason::KeyCompromise => ProtoRevocationReason::KeyCompromise,
            RevocationReason::CaCompromise => ProtoRevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged => ProtoRevocationReason::AffiliationChanged,
            RevocationReason::Superseded => ProtoRevocationReason::Superseded,
            RevocationReason::CessationOfOperation => ProtoRevocationReason::CessationOfOperation,
            RevocationReason::CertificateHold => ProtoRevocationReason::CertificateHold,
            RevocationReason::RemoveFromCrl => ProtoRevocationReason::RemoveFromCrl,
            RevocationReason::PrivilegeWithdrawn => ProtoRevocationReason::PrivilegeWithdrawn,
            RevocationReason::AaCompromise => ProtoRevocationReason::AaCompromise,
        }
    }

    /// Convert proto RevocationReason to internal
    fn convert_reason_from_proto(reason: i32) -> Result<RevocationReason> {
        RevocationReason::from_i32(reason)
            .ok_or_else(|| Error::InvalidRequest("Invalid revocation reason".to_string()))
    }

    /// Convert internal CertificateProfile to proto
    fn convert_profile_to_proto(profile: &CertificateProfile) -> ProtoCertificateProfile {
        ProtoCertificateProfile {
            name: profile.name.clone(),
            profile_type: profile.profile_type.as_str().to_string(),
            description: profile.description.clone().unwrap_or_default(),
            validity_days: profile.validity_days,
            key_type: profile.key_type.clone(),
            algorithm: profile.algorithm.clone(),
            basic_constraints_ca: profile.basic_constraints_ca,
            basic_constraints_path_len: profile.basic_constraints_path_len.map(|v| v as u32),
            subject_alt_name_required: profile.subject_alt_name_required,
        }
    }
}

#[tonic::async_trait]
impl CertificateAuthorityService for CaGrpcService {
    /// Issue a new certificate via gRPC
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Certificate issuance security function
    /// NIAP PP-CA: FDP_ACC.1.1 - caller is an mTLS-authenticated `Issuer`
    /// identity (method table enforced by `SubjectAllowlistLayer`); the
    /// requestor is bound to its namespace before any other processing
    /// NIAP PP-CA: FAU_GEN.2 - audit actor = verified peer, on_behalf_of =
    /// bound requestor
    async fn issue_certificate(
        &self,
        request: Request<IssueCertificateRequest>,
    ) -> std::result::Result<Response<IssueCertificateResponse>, Status> {
        let caller = authorize_issue(
            &request,
            &request.get_ref().requestor,
            &request.get_ref().profile_name,
            &self.profiles,
            self.require_peer,
        )
        .await?;
        let peer = peer_subject(&request);
        let req = request.into_inner();
        // Caller-supplied request id (ACME order / EST enrollment) for
        // traceability (FDP_CER_EXT.2); generated here when empty or
        // unparseable (same rule as `issue()`), so the logged id matches the
        // stored one.
        let request_id =
            uuid::Uuid::parse_str(&req.request_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        tracing::info!(
            request_id = %request_id,
            peer_subject = %peer,
            requestor = %caller.requestor,
            profile = %req.profile_name,
            "gRPC IssueCertificate"
        );

        let issuance_req = issuance_request(req, caller, request_id)?;

        // Issue certificate
        let issued = self
            .ca
            .issuer()
            .issue(issuance_req)
            .await
            .map_err(|e| grpc_status("IssueCertificate", e))?;

        // Convert to proto response
        let response = IssueCertificateResponse {
            certificate_id: issued.certificate_id.to_string(),
            serial_number: issued.serial_number,
            der_encoded: issued.der_encoded,
            pem_encoded: issued.pem_encoded,
            not_before: issued.not_before.timestamp(),
            not_after: issued.not_after.timestamp(),
        };

        Ok(Response::new(response))
    }

    /// Revoke a certificate via gRPC
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Certificate revocation security function
    /// NIAP PP-CA: FDP_ACC.1.1 - caller is an mTLS-authenticated `Admin`
    /// identity (method table enforced by `SubjectAllowlistLayer`); a
    /// requestor, if given, must be `admin::<id>`
    /// NIAP PP-CA: FAU_GEN.2 - audit actor = verified admin peer
    async fn revoke_certificate(
        &self,
        request: Request<RevokeCertificateRequest>,
    ) -> std::result::Result<Response<RevokeCertificateResponse>, Status> {
        let caller = bind_caller(&request, &request.get_ref().requestor, self.require_peer).await?;
        let peer = peer_subject(&request);
        let request_id = correlation_id(&request);
        let req = request.into_inner();
        tracing::info!(
            request_id = %request_id,
            peer_subject = %peer,
            requestor = %caller.requestor,
            certificate_id = %req.certificate_id,
            "gRPC RevokeCertificate"
        );

        // NIST-007: a request refused here is audited (Failure) with the
        // same identity a successful revocation would carry.
        let target = req.certificate_id.clone();
        let reason_code = req.reason;
        let failure_identity = (caller.requestor.clone(), caller.caller.clone());
        let revocation_req = match revocation_request(req, caller) {
            Ok(r) => r,
            Err(failure) => {
                self.ca
                    .revocation_manager()
                    .record_rejected_revocation(
                        &target,
                        reason_code,
                        &failure_identity.0,
                        failure_identity.1.as_ref(),
                        failure,
                    )
                    .await;
                return Err(Status::invalid_argument(match failure {
                    "invalid_certificate_id" => "Invalid certificate ID",
                    _ => "Invalid revocation reason",
                }));
            }
        };

        // Revoke certificate
        self.ca
            .revocation_manager()
            .revoke(revocation_req)
            .await
            .map_err(|e| grpc_status("RevokeCertificate", e))?;

        // Return response with current time as revocation time
        let response = RevokeCertificateResponse {
            success: true,
            revocation_time: chrono::Utc::now().timestamp(),
        };

        Ok(Response::new(response))
    }

    /// Generate a new CRL via gRPC
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - CRL generation security function
    /// NIAP PP-CA: FDP_ACC.1.1 - the caller is an mTLS-authenticated `Admin`
    /// identity (method table enforced by `SubjectAllowlistLayer`)
    /// NIAP PP-CA: FAU_GEN.2 - CrlGeneration audit actor = verified admin peer
    async fn generate_crl(
        &self,
        request: Request<GenerateCrlRequest>,
    ) -> std::result::Result<Response<GenerateCrlResponse>, Status> {
        let caller = authorized_peer(&request, self.require_peer)?.map(authenticated_caller);
        let peer = peer_subject(&request);
        tracing::info!(
            request_id = %correlation_id(&request),
            peer_subject = %peer,
            "gRPC GenerateCrl"
        );
        // Generate CRL (FAU_GEN.2: actor = verified admin peer)
        let crl = self
            .ca
            .revocation_manager()
            .generate_crl_by(self.ca.ca_dn.clone(), crl_actor(caller.as_ref()))
            .await
            .map_err(|e| grpc_status("GenerateCrl", e))?;

        // Convert to proto response
        let response = GenerateCrlResponse {
            crl_number: crl.crl_number,
            this_update: crl.this_update.timestamp(),
            next_update: crl.next_update.timestamp(),
            revoked_count: crl.revoked_count as u32,
            der_encoded: crl.der_encoded,
            pem_encoded: crl.pem_encoded,
        };

        Ok(Response::new(response))
    }

    /// Check certificate revocation status via gRPC
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Revocation status query function
    /// NIAP PP-CA: FDP_ACC.1.1 - `Admin` identities only (method table)
    async fn check_revocation_status(
        &self,
        request: Request<CheckRevocationStatusRequest>,
    ) -> std::result::Result<Response<CheckRevocationStatusResponse>, Status> {
        authorized_peer(&request, self.require_peer)?;
        let req = request.into_inner();

        // Convert certificate ID
        let certificate_id = uuid::Uuid::parse_str(&req.certificate_id)
            .map_err(|_| Status::invalid_argument("Invalid certificate ID"))?;

        // Check revocation status with time and reason
        // RFC 6960 §2.2 / RFC 5280 §5.3.1 - status answer includes
        // revocationTime and CRLReason, not just the boolean
        let (revoked, revocation_time, reason) = self
            .ca
            .revocation_manager()
            .revocation_status(&certificate_id)
            .await
            .map_err(|e| grpc_status("CheckRevocationStatus", e))?;

        let response = CheckRevocationStatusResponse {
            revoked,
            revocation_time: revocation_time.map(|t| t.timestamp()),
            reason,
        };

        Ok(Response::new(response))
    }

    /// NIAP PP-CA: FDP_ACC.1.1 - `Issuer` and `Admin` identities (method table)
    async fn get_ca_info(
        &self,
        request: Request<GetCaInfoRequest>,
    ) -> std::result::Result<Response<GetCaInfoResponse>, Status> {
        authorized_peer(&request, self.require_peer)?;
        let info = self.ca.info();

        let response = GetCaInfoResponse {
            ca_id: info.ca_id.to_string(),
            ca_dn: info.ca_dn,
        };

        Ok(Response::new(response))
    }

    /// NIAP PP-CA: FDP_ACC.1.1 - `Issuer` and `Admin` identities (method table)
    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> std::result::Result<Response<ListProfilesResponse>, Status> {
        authorized_peer(&request, self.require_peer)?;
        // TODO: Get profiles from CA
        // For now, return example profiles
        let profiles = [
            CertificateProfile::root_ca(3650),
            CertificateProfile::intermediate_ca(1825, 0),
            CertificateProfile::tls_server(365),
            CertificateProfile::tls_client(365),
            CertificateProfile::code_signing(365),
            CertificateProfile::ocsp_signing(90),
        ];

        let proto_profiles: Vec<ProtoCertificateProfile> = profiles
            .iter()
            .map(Self::convert_profile_to_proto)
            .collect();

        let response = ListProfilesResponse {
            profiles: proto_profiles,
        };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_conversion() {
        let reason = RevocationReason::KeyCompromise;
        let proto_reason = CaGrpcService::convert_reason_to_proto(reason);
        assert_eq!(proto_reason, ProtoRevocationReason::KeyCompromise);

        let converted_back =
            CaGrpcService::convert_reason_from_proto(ProtoRevocationReason::KeyCompromise as i32)
                .unwrap();
        assert_eq!(converted_back, RevocationReason::KeyCompromise);
    }

    fn bound(subject: Option<&str>, requestor: &str) -> BoundCaller {
        BoundCaller {
            caller: subject.map(crate::issuance::tests::test_caller),
            requestor: requestor.to_string(),
        }
    }

    /// NIST-006 / QA-002 (M12): the IssueCertificate request carries the
    /// verified peer as `authenticated_caller` and the bound requestor.
    #[test]
    fn issuance_request_carries_verified_caller() {
        let req = IssueCertificateRequest {
            profile_name: "acme-default".to_string(),
            subject: Some(ProtoDistinguishedName {
                common_name: Some("host.example".to_string()),
                ..Default::default()
            }),
            requestor: "acme::forged-in-body-is-ignored".to_string(),
            public_key: vec![1, 2],
            ..Default::default()
        };
        let id = uuid::Uuid::new_v4();
        let built = issuance_request(
            req.clone(),
            bound(Some("CN=acme-server"), "acme::acct-1"),
            id,
        )
        .expect("built");
        assert_eq!(
            built.authenticated_caller,
            Some(crate::issuance::tests::test_caller("CN=acme-server"))
        );
        assert_eq!(built.requestor, "acme::acct-1");
        assert_eq!(built.profile_name, "acme-default");
        assert_eq!(built.request_id, Some(id));
        assert!(built.csr_der.is_none());
        // Dev plaintext: no caller, requestor passed through.
        let dev = issuance_request(req.clone(), bound(None, "x"), id).expect("dev");
        assert!(dev.authenticated_caller.is_none());
        // Missing subject is refused before issuance.
        let no_subject = IssueCertificateRequest {
            subject: None,
            ..req
        };
        let err = issuance_request(no_subject, bound(Some("CN=a"), "acme::1"), id)
            .expect_err("no subject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// NIST-006 (M12 for revoke): the RevokeCertificate request carries the
    /// admin peer and `on_behalf_of` requestor; invalid id / reason are
    /// reported as audit failure reasons (NIST-007).
    #[test]
    fn revocation_request_carries_verified_caller() {
        let id = uuid::Uuid::new_v4();
        let req = RevokeCertificateRequest {
            certificate_id: id.to_string(),
            reason: ProtoRevocationReason::KeyCompromise as i32,
            requestor: String::new(),
            justification: "lost laptop".to_string(),
        };
        let built = revocation_request(req.clone(), bound(Some("CN=ops-admin"), "admin::oncall"))
            .expect("built");
        assert_eq!(
            built.authenticated_caller,
            Some(crate::issuance::tests::test_caller("CN=ops-admin"))
        );
        assert_eq!(built.requestor, "admin::oncall");
        assert_eq!(built.certificate_id, id);
        assert_eq!(built.reason, RevocationReason::KeyCompromise);
        assert_eq!(built.justification.as_deref(), Some("lost laptop"));
        let bad_id = RevokeCertificateRequest {
            certificate_id: "nope".to_string(),
            ..req.clone()
        };
        assert_eq!(
            revocation_request(bad_id, bound(Some("CN=ops-admin"), "")).err(),
            Some("invalid_certificate_id")
        );
        let bad_reason = RevokeCertificateRequest { reason: 99, ..req };
        assert_eq!(
            revocation_request(bad_reason, bound(Some("CN=ops-admin"), "")).err(),
            Some("invalid_reason")
        );
    }

    /// QA-002 (M13): GenerateCrl's audit actor is the verified admin peer.
    #[test]
    fn crl_actor_is_verified_peer() {
        let peer = crate::issuance::tests::test_caller("CN=ops-admin");
        assert_eq!(crl_actor(Some(&peer)), CrlActor::Peer(&peer));
        assert_eq!(crl_actor(None), CrlActor::Unauthenticated);
    }

    /// SEC-004 / QA-003 (M18): the service built for the plaintext dev mode
    /// skips the peer requirement only in debug builds.
    #[test]
    fn plaintext_mode_peer_requirement() {
        assert_eq!(
            mode_requires_peer(&GrpcServerMode::InsecureDevPlaintext),
            !cfg!(debug_assertions)
        );
    }

    /// NIST-010 (SI-11): internal errors never reach the client verbatim;
    /// client-correctable errors keep their message.
    #[test]
    fn grpc_status_hides_internal_errors() {
        let st = grpc_status("IssueCertificate", Error::Internal("db at 10.0.0.5".into()));
        assert_eq!(st.code(), tonic::Code::Internal);
        assert!(!st.message().contains("10.0.0.5"), "{}", st.message());
        let st = grpc_status("IssueCertificate", Error::ProfileNotFound("x".into()));
        assert_eq!(st.code(), tonic::Code::InvalidArgument);
        assert!(st.message().to_lowercase().contains("profile"));
        let st = grpc_status(
            "RevokeCertificate",
            Error::Revocation("already revoked".into()),
        );
        assert_eq!(st.code(), tonic::Code::FailedPrecondition);
        // SEC-102: a CA profile refused at call time is PERMISSION_DENIED
        // with the fixed profile message.
        let st = grpc_status("IssueCertificate", Error::ProfileNotPermitted);
        assert_eq!(st.code(), tonic::Code::PermissionDenied);
        assert_eq!(st.message(), crate::grpc_authz::PROFILE_DENIED_MESSAGE);
        // NIST-105: CRL generation errors (incl. an unsupported CA key type)
        // are internal and never echo their detail.
        let st = grpc_status(
            "GenerateCrl",
            Error::CrlGeneration("CRL signing is not available for the CA key".into()),
        );
        assert_eq!(st.code(), tonic::Code::Internal);
        assert_eq!(st.message(), "GenerateCrl failed: internal error");
    }
}
