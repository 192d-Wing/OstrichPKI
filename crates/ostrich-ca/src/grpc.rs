//! gRPC service implementation for Certificate Authority
//!
//! This module provides gRPC service endpoints for certificate issuance, revocation,
//! and CA management operations.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: Security management functions - gRPC endpoints for CA operations
//! - **FDP_ACC.1**: Access control - gRPC authentication and authorization
//! - **FIA_AFL.1**: Authentication failure handling - Rate limiting, lockout
//! - **FTP_ITC.1**: Inter-TSF trusted channel - mTLS for gRPC transport
//!
//! ## RFC Compliance
//! - RFC 5280: X.509 Public Key Infrastructure
//!
//! ## NIST 800-53 Controls
//! - SC-8: Transmission confidentiality (mTLS)
//! - SC-12: Cryptographic key establishment and management
//! - AC-3: Access enforcement
//! - AC-17: Remote access (mTLS authentication)

use crate::{CertificateAuthority, Error, IssuanceRequest, Result, RevocationRequest};
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

/// gRPC service wrapper for Certificate Authority
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1 - Exposes CA security management functions via gRPC
/// - NIAP PP-CA: FTP_ITC.1 - Requires mTLS for trusted channel
pub struct CaGrpcService {
    ca: Arc<CertificateAuthority>,
}

impl CaGrpcService {
    /// Create a new gRPC service wrapper
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca }
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
    /// NIAP PP-CA: FDP_ACC.1.1 - Requires authenticated and authorized caller
    async fn issue_certificate(
        &self,
        request: Request<IssueCertificateRequest>,
    ) -> std::result::Result<Response<IssueCertificateResponse>, Status> {
        let req = request.into_inner();

        // Convert proto types to internal types
        let subject =
            Self::convert_dn(req.subject).map_err(|e| Status::invalid_argument(e.to_string()))?;

        let subject_alt_names: Result<Vec<SubjectAltName>> = req
            .subject_alt_names
            .into_iter()
            .map(Self::convert_san)
            .collect();

        let subject_alt_names =
            subject_alt_names.map_err(|e| Status::invalid_argument(e.to_string()))?;

        // Create issuance request
        let metadata = if req.metadata.is_empty() {
            None
        } else {
            Some(
                serde_json::to_value(req.metadata)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?,
            )
        };

        let issuance_req = IssuanceRequest {
            profile_name: req.profile_name,
            subject,
            subject_alt_names,
            public_key: req.public_key,
            requestor: req.requestor,
            metadata,
            csr_der: None,             // gRPC API doesn't currently accept CSR
            approval_request_id: None, // TODO: Accept from request
            // CA generates a request_id (FDP_CER_EXT.2). TODO: carry the calling
            // protocol's id (ACME order / EST enrollment) once added to the proto.
            request_id: None,
        };

        // Issue certificate
        let issued = self
            .ca
            .issuer()
            .issue(issuance_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

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
    /// NIAP PP-CA: FDP_ACC.1.1 - Requires authenticated and authorized caller
    async fn revoke_certificate(
        &self,
        request: Request<RevokeCertificateRequest>,
    ) -> std::result::Result<Response<RevokeCertificateResponse>, Status> {
        let req = request.into_inner();

        // Convert certificate ID
        let certificate_id = uuid::Uuid::parse_str(&req.certificate_id)
            .map_err(|_| Status::invalid_argument("Invalid certificate ID"))?;

        // Convert revocation reason
        let reason = Self::convert_reason_from_proto(req.reason)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        // Create revocation request
        let justification = if req.justification.is_empty() {
            None
        } else {
            Some(req.justification)
        };

        let revocation_req = RevocationRequest {
            certificate_id,
            reason,
            requestor: req.requestor,
            justification,
        };

        // Revoke certificate
        self.ca
            .revocation_manager()
            .revoke(revocation_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

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
    /// NIAP PP-CA: FDP_ACC.1.1 - Requires authenticated administrator
    async fn generate_crl(
        &self,
        _request: Request<GenerateCrlRequest>,
    ) -> std::result::Result<Response<GenerateCrlResponse>, Status> {
        // Generate CRL
        let crl = self
            .ca
            .revocation_manager()
            .generate_crl(self.ca.ca_dn.clone())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

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
    async fn check_revocation_status(
        &self,
        request: Request<CheckRevocationStatusRequest>,
    ) -> std::result::Result<Response<CheckRevocationStatusResponse>, Status> {
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
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = CheckRevocationStatusResponse {
            revoked,
            revocation_time: revocation_time.map(|t| t.timestamp()),
            reason,
        };

        Ok(Response::new(response))
    }

    async fn get_ca_info(
        &self,
        _request: Request<GetCaInfoRequest>,
    ) -> std::result::Result<Response<GetCaInfoResponse>, Status> {
        let info = self.ca.info();

        let response = GetCaInfoResponse {
            ca_id: info.ca_id.to_string(),
            ca_dn: info.ca_dn,
        };

        Ok(Response::new(response))
    }

    async fn list_profiles(
        &self,
        _request: Request<ListProfilesRequest>,
    ) -> std::result::Result<Response<ListProfilesResponse>, Status> {
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
}
