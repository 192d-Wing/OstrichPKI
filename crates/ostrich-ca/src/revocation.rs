//! Certificate revocation functionality
//!
//! This module handles certificate revocation including CRL generation and
//! revocation status checking.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1.1**: Revoke certificates - Security management function for revocation
//! - **FCS_COP.1.1**: Cryptographic operations - CRL signing using CA private key
//! - **FDP_IFC.1.1**: Information flow control - Revocation policy enforcement
//! - **FAU_GEN.1.1**: Audit data generation - Revocation and CRL generation events
//! - **FPT_STM.1.1**: Reliable time stamps - Revocation time, thisUpdate, nextUpdate
//!
//! ## RFC Compliance
//! - RFC 5280 §5 - Certificate Revocation Lists
//! - RFC 5280 §5.3.1 - Revocation reasons
//! - RFC 6960 §2.2 - OCSP response (revocation status)
//!
//! ## NIST 800-53 Controls
//! - SC-12: Key revocation management
//! - AU-2: Audit revocation events

use crate::issuance::{AuthenticatedCaller, add_caller_details, audit_identity};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ostrich_audit::{AuditEvent, AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{CryptoProvider, KeyHandle};
use ostrich_db::{
    DatabasePool, Uuid,
    repository::{CertificateRepository, CrlRepository},
};
use ostrich_x509::{
    crl::{CrlGenerator, RevokedCertificateInfo},
    parser::RevocationReason,
};
use serde::{Deserialize, Serialize};

/// Certificate revocation request
///
/// RFC 5280 §5.3.1 - Revocation reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Certificate ID or serial number
    pub certificate_id: Uuid,

    /// Revocation reason
    pub reason: RevocationReason,

    /// Requestor: the principal the revocation is made for (REST: the
    /// authenticated user; gRPC: the bound `admin::<id>` or empty). The audit
    /// actor unless `authenticated_caller` is set.
    pub requestor: String,

    /// The authenticated service that made the call (verified gRPC mTLS
    /// peer). When set its subject DN is the audit actor and a non-empty
    /// `requestor` is recorded as `on_behalf_of` (AU-3, FAU_GEN.2). Never
    /// deserialized (SEC-005): set from the verified peer only.
    #[serde(default, skip_deserializing)]
    pub authenticated_caller: Option<AuthenticatedCaller>,

    /// Justification
    pub justification: Option<String>,
}

/// Who generated a CRL, for the `CrlGeneration` audit record.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-3 (who), AC-6(9) (privileged function use logged)
/// - NIAP PP-CA: FAU_GEN.2 (user identity association)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlActor<'a> {
    /// The CA's own scheduler (actor `"system"`).
    System,
    /// An authenticated REST user (actor = username).
    User(&'a str),
    /// A verified gRPC admin peer (actor = subject DN; issuer and serial in
    /// the details).
    Peer(&'a AuthenticatedCaller),
    /// The debug-only plaintext gRPC listener (actor `"unauthenticated"`).
    Unauthenticated,
}

/// CRL audit action of a full CRL.
pub(crate) const CRL_ACTION_GENERATE: &str = "generate";
/// CRL audit action of a delta CRL (RFC 5280 §5.2.4).
pub(crate) const CRL_ACTION_GENERATE_DELTA: &str = "generate_delta";

/// The `CrlGeneration` audit event (outcome Success; the caller adds the CRL
/// number and count) for `actor` and `action` ([`CRL_ACTION_GENERATE`] or
/// [`CRL_ACTION_GENERATE_DELTA`]). Pure, for testing.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-3 (who / what / outcome), AU-12
/// - NIAP PP-CA: FAU_GEN.1, FAU_GEN.2
pub(crate) fn crl_audit_event(
    ca_certificate_id: Uuid,
    actor: CrlActor<'_>,
    action: &'static str,
) -> AuditEvent {
    crl_event(
        ca_certificate_id,
        actor,
        action,
        EventOutcome::Success,
        None,
    )
}

/// A failed CRL generation (outcome Failure) for `actor` and `action`, with
/// `failure` (a fixed stage name, never error text) in the details. Pure,
/// for testing (NIST-103).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-2 / AU-3 / AU-12 (failed CRL generation is auditable),
///   AC-6(9)
/// - NIAP PP-CA: FAU_GEN.1, FAU_GEN.2
pub(crate) fn crl_failure_event(
    ca_certificate_id: Uuid,
    actor: CrlActor<'_>,
    action: &'static str,
    failure: &'static str,
) -> AuditEvent {
    crl_event(
        ca_certificate_id,
        actor,
        action,
        EventOutcome::Failure,
        Some(failure),
    )
}

fn crl_event(
    ca_certificate_id: Uuid,
    actor: CrlActor<'_>,
    action: &'static str,
    outcome: EventOutcome,
    failure: Option<&'static str>,
) -> AuditEvent {
    let (name, caller) = match actor {
        CrlActor::System => ("system", None),
        CrlActor::User(user) => (user, None),
        CrlActor::Peer(caller) => (caller.subject_dn.as_str(), Some(caller)),
        CrlActor::Unauthenticated => ("unauthenticated", None),
    };
    let mut details = match failure {
        Some(failure) => serde_json::json!({ "failure": failure }),
        None => serde_json::json!({}),
    };
    add_caller_details(&mut details, caller, None);
    AuditEventBuilder::new(
        EventType::CrlGeneration,
        name,
        ca_certificate_id.to_string(),
        action,
        outcome,
    )
    .with_details(details)
    .build()
}

/// Insert `entries` into the event's details object (keeping the caller
/// details set by [`crl_audit_event`]).
fn merge_details(event: &mut AuditEvent, entries: &[(&str, serde_json::Value)]) {
    let details = event.details.get_or_insert_with(|| serde_json::json!({}));
    if let Some(map) = details.as_object_mut() {
        for (key, value) in entries {
            map.insert((*key).to_string(), value.clone());
        }
    }
}

/// Maximum characters of a refused certificate id copied into an audit
/// record (the value is untrusted client input).
const MAX_AUDITED_TARGET_CHARS: usize = 64;

/// A refused revocation request (outcome Failure): target (the certificate
/// id as given, truncated and `escape_debug`'d), actor / `on_behalf_of` as
/// for a successful revocation, the requested reason code and the failure
/// (`invalid_certificate_id`, `invalid_reason`, `certificate_not_found`,
/// `lookup_failed`, `database_error`). Pure, for testing.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-2 / AU-3 / AU-12 (failed revocations are auditable
///   events), AC-6(9)
/// - NIAP PP-CA: FAU_GEN.1, FAU_GEN.2
pub(crate) fn revocation_failure_event(
    target: &str,
    reason_code: i32,
    requestor: &str,
    caller: Option<&AuthenticatedCaller>,
    failure: &'static str,
) -> AuditEvent {
    let target: String = target
        .chars()
        .take(MAX_AUDITED_TARGET_CHARS)
        .collect::<String>()
        .escape_debug()
        .to_string();
    let (actor, on_behalf_of) = audit_identity(requestor, caller.map(|c| c.subject_dn.as_str()));
    let mut details = serde_json::json!({
        "reason": reason_code,
        "failure": failure,
    });
    add_caller_details(&mut details, caller, on_behalf_of.as_deref());
    AuditEventBuilder::new(
        EventType::CertificateRevocation,
        actor,
        target,
        "revoke",
        EventOutcome::Failure,
    )
    .with_details(details)
    .build()
}

/// Revocation manager
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function for certificate revocation
/// - NIAP PP-CA: FCS_COP.1.1 - Cryptographic operations for CRL signing
/// - NIAP PP-CA: FAU_GEN.1.1 - Audit generation for revocation events
/// - NIST 800-53: SC-12 - Cryptographic key revocation
pub struct RevocationManager {
    /// CA key handle
    ca_key: KeyHandle,

    /// CA certificate ID
    ca_certificate_id: Uuid,

    /// Crypto provider
    crypto_provider: std::sync::Arc<dyn CryptoProvider>,

    /// Database pool
    db_pool: DatabasePool,

    /// Audit sink
    audit_sink: Box<dyn AuditSink>,

    /// CRL validity hours
    crl_validity_hours: u32,

    /// Public URL of the delta CRL distribution point. When set, full CRLs carry
    /// a Freshest CRL extension pointing here (RFC 5280 §5.2.6) so relying
    /// parties can discover delta CRLs.
    delta_crl_url: Option<String>,
}

impl RevocationManager {
    /// Create a new revocation manager
    pub fn new(
        ca_key: KeyHandle,
        ca_certificate_id: Uuid,
        crypto_provider: std::sync::Arc<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
        crl_validity_hours: u32,
    ) -> Self {
        Self {
            ca_key,
            ca_certificate_id,
            crypto_provider,
            db_pool,
            audit_sink,
            crl_validity_hours,
            delta_crl_url: None,
        }
    }

    /// Set the delta CRL distribution URL, emitted as the Freshest CRL extension
    /// on full CRLs (RFC 5280 §5.2.6).
    pub fn set_delta_crl_url(&mut self, url: impl Into<String>) {
        self.delta_crl_url = Some(url.into());
    }

    /// Revoke a certificate
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Revoke certificate security management function
    /// NIAP PP-CA: FAU_GEN.1.1 - Generate audit record for revocation
    /// NIAP PP-CA: FPT_STM.1.1 - Record reliable revocation timestamp
    ///
    /// RFC 5280 §5 - Certificate revocation
    /// NIST 800-53: AU-2 - Audit certificate revocation
    pub async fn revoke(&self, request: RevocationRequest) -> Result<()> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        let caller = request.authenticated_caller.as_ref();

        // Find certificate. NIST-007 (AU-2): a failed lookup is audited too.
        let cert = match cert_repo.find_by_id(request.certificate_id).await {
            Ok(Some(cert)) => cert,
            Ok(None) => {
                self.record_revocation_failure(&request, "certificate_not_found")
                    .await;
                return Err(Error::InvalidRequest("Certificate not found".to_string()));
            }
            Err(e) => {
                self.record_revocation_failure(&request, "lookup_failed")
                    .await;
                return Err(e.into());
            }
        };

        // NIAP PP-CA: FAU_GEN.1.1 - Create audit event for revocation
        // NIST 800-53: AU-3 / AU-10 - actor = authenticated caller when set.
        let (actor, on_behalf_of) =
            audit_identity(&request.requestor, caller.map(|c| c.subject_dn.as_str()));
        let mut details = serde_json::json!({
            "serial_number": hex::encode(&cert.serial_number),
            "reason": request.reason.as_i32(),
            "subject": cert.subject_dn,
        });
        add_caller_details(&mut details, caller, on_behalf_of.as_deref());
        let mut audit_event = AuditEventBuilder::new(
            EventType::CertificateRevocation,
            actor,
            request.certificate_id.to_string(),
            "revoke",
            EventOutcome::Success,
        )
        .with_details(details)
        .build();

        // Check if already revoked
        if cert.revoked {
            audit_event.outcome = EventOutcome::Failure;
            if let Some(map) = audit_event.details.as_mut().and_then(|d| d.as_object_mut()) {
                map.insert("failure".to_string(), "already_revoked".into());
            }
            self.audit_sink
                .record(&mut audit_event)
                .await
                .map_err(Error::Audit)?;

            return Err(Error::Revocation("Certificate already revoked".to_string()));
        }

        // Revoke the certificate (NIST-007: a database failure is audited
        // with the same identity and certificate details).
        if let Err(e) = cert_repo
            .revoke(&request.certificate_id, request.reason.as_i32())
            .await
        {
            audit_event.outcome = EventOutcome::Failure;
            if let Some(map) = audit_event.details.as_mut().and_then(|d| d.as_object_mut()) {
                map.insert("failure".to_string(), "database_error".into());
            }
            if let Err(audit) = self.audit_sink.record(&mut audit_event).await {
                tracing::error!(error = %audit, "failed to record revocation failure audit event");
            }
            return Err(e.into());
        }

        // NIAP PP-CA: FAU_GEN.1.1 - Record successful revocation audit event
        self.audit_sink
            .record(&mut audit_event)
            .await
            .map_err(Error::Audit)?;

        tracing::info!(
            "Certificate revoked: {} (reason: {:?})",
            request.certificate_id,
            request.reason
        );

        Ok(())
    }

    /// Record a refused revocation of `request` (see
    /// [`revocation_failure_event`]). An audit write failure is logged; the
    /// revocation is refused either way.
    async fn record_revocation_failure(&self, request: &RevocationRequest, failure: &'static str) {
        self.record_rejected_revocation(
            &request.certificate_id.to_string(),
            request.reason.as_i32(),
            &request.requestor,
            request.authenticated_caller.as_ref(),
            failure,
        )
        .await;
    }

    /// Record a revocation request refused before it reached
    /// [`Self::revoke`] (e.g. an unparsable certificate id or reason on the
    /// gRPC path): outcome Failure with actor / `on_behalf_of`, the requested
    /// reason code and `failure`. `target` is untrusted and is truncated and
    /// escaped. An audit write failure is logged, never returned.
    ///
    /// NIST 800-53: AU-2, AU-3, AU-12; NIAP PP-CA: FAU_GEN.1, FAU_GEN.2
    pub async fn record_rejected_revocation(
        &self,
        target: &str,
        reason_code: i32,
        requestor: &str,
        caller: Option<&AuthenticatedCaller>,
        failure: &'static str,
    ) {
        let mut event = revocation_failure_event(target, reason_code, requestor, caller, failure);
        if let Err(e) = self.audit_sink.record(&mut event).await {
            tracing::error!(error = %e, failure, "failed to record revocation failure audit event");
        }
    }

    /// Generate a new CRL
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Generate CRL security management function
    /// NIAP PP-CA: FCS_COP.1.1 - Sign CRL using CA private key
    /// NIAP PP-CA: FAU_GEN.1.1 - Generate audit record for CRL generation
    /// NIAP PP-CA: FPT_STM.1.1 - Use reliable time for thisUpdate/nextUpdate
    ///
    /// RFC 5280 §5.1 - CRL generation
    /// NIST 800-53: AU-2 - Audit CRL generation
    pub async fn generate_crl(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
    ) -> Result<GeneratedCrl> {
        self.generate_crl_by(issuer_dn, CrlActor::System).await
    }

    /// [`Self::generate_crl`] on behalf of `actor`, the audit actor of the
    /// `CrlGeneration` record: the verified gRPC admin peer (with its
    /// certificate issuer and serial), the authenticated REST user, or
    /// `"system"` for the scheduler ([`Self::generate_crl`]).
    ///
    /// NIST 800-53: AU-3 (who), AU-2, AC-6(9); NIAP PP-CA: FAU_GEN.1, FAU_GEN.2
    pub async fn generate_crl_by(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
        actor: CrlActor<'_>,
    ) -> Result<GeneratedCrl> {
        match self.build_full_crl(issuer_dn).await {
            Ok(crl) => {
                // NIAP PP-CA: FAU_GEN.1.1 - Record CRL generation audit event
                // (merged into the caller details set by `crl_audit_event`).
                let mut audit_event =
                    crl_audit_event(self.ca_certificate_id, actor, CRL_ACTION_GENERATE);
                merge_details(
                    &mut audit_event,
                    &[
                        ("crl_number", crl.crl_number.into()),
                        ("revoked_count", crl.revoked_count.into()),
                    ],
                );
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                tracing::info!(
                    "CRL generated: number {} with {} revoked certificates",
                    crl.crl_number,
                    crl.revoked_count
                );
                Ok(crl)
            }
            Err((failure, e)) => {
                self.record_crl_failure(actor, CRL_ACTION_GENERATE, failure, &e)
                    .await;
                Err(e)
            }
        }
    }

    /// Record a failed CRL generation ([`crl_failure_event`]). The error
    /// detail goes to the log only; an audit write failure is logged and the
    /// original error is returned by the caller (NIST-103, NIST-007 pattern).
    async fn record_crl_failure(
        &self,
        actor: CrlActor<'_>,
        action: &'static str,
        failure: &'static str,
        error: &Error,
    ) {
        tracing::error!(action, failure, error = %error, "CRL generation failed");
        let mut event = crl_failure_event(self.ca_certificate_id, actor, action, failure);
        if let Err(e) = self.audit_sink.record(&mut event).await {
            tracing::error!(error = %e, action, failure, "failed to record CRL failure audit event");
        }
    }

    /// The CRL signature algorithm for the CA key. An unsupported key type is
    /// an internal error: the detail is logged, the message is fixed
    /// (SI-11; NIST-105).
    fn crl_signature_algorithm(&self) -> Result<ostrich_crypto::Algorithm> {
        ostrich_x509::signing::recommended_signature_algorithm(self.ca_key.key_type).map_err(|e| {
            tracing::error!(error = %e, "unsupported CA key type for CRL signing");
            Error::CrlGeneration("CRL signing is not available for the CA key".to_string())
        })
    }

    /// Build, sign and store a full CRL. `Err` carries the failed stage (the
    /// audit `failure` reason) and the error.
    async fn build_full_crl(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
    ) -> std::result::Result<GeneratedCrl, (&'static str, Error)> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());

        // Get all revoked certificates
        let revoked_certs = cert_repo
            .find_revoked(&self.ca_certificate_id)
            .await
            .map_err(|e| ("revoked_lookup_failed", e.into()))?;

        // Convert to RevokedCertificateInfo
        let revoked_info: Vec<RevokedCertificateInfo> = revoked_certs
            .iter()
            .filter_map(|cert| {
                let revocation_time = cert.revocation_time?;
                let reason = cert.revocation_reason.and_then(RevocationReason::from_i32);

                Some(RevokedCertificateInfo::new(
                    cert.serial_number.clone(),
                    revocation_time,
                    reason,
                ))
            })
            .collect();

        // Count revoked certificates before moving
        let revoked_count = revoked_info.len();

        // RFC 5280 §5.2.3 - CRL numbers MUST be monotonically increasing.
        // Derive the next number from persisted CRLs (MAX(crl_number)+1) so it
        // survives process restarts; an in-memory counter would reset to 0 and
        // collide with the UNIQUE(ca_id, crl_number) constraint on the next run.
        let crl_repo = CrlRepository::new(self.db_pool.clone());
        let crl_number_i64 = crl_repo
            .next_crl_number(self.ca_certificate_id)
            .await
            .map_err(|e| ("crl_number_failed", e.into()))?;
        let current_crl_number = crl_number_i64 as u64;

        // RFC 5280 §5.1.1.2 - select the signature algorithm from the CA key
        // type so the TBS AlgorithmIdentifier, the outer signatureAlgorithm, and
        // the signing call all agree (RSA / ECDSA P-256/P-384 / Ed25519).
        let sig_alg = self
            .crl_signature_algorithm()
            .map_err(|e| ("unsupported_ca_key_type", e))?;

        // Generate CRL
        let crl_generator = CrlGenerator::new(issuer_dn, self.crl_validity_hours);
        let mut crl_builder = crl_generator
            .generate(current_crl_number, revoked_info)
            .map_err(|e| ("crl_build_failed", e.into()))?
            .signature_algorithm(sig_alg);

        // RFC 5280 §5.2.6 - point relying parties at the delta CRL when configured.
        if let Some(delta_url) = &self.delta_crl_url {
            crl_builder = crl_builder.freshest_crl(delta_url.clone());
        }

        let tbs_crl = crl_builder
            .build_tbs()
            .map_err(|e| ("crl_build_failed", e.into()))?;

        // Encode TBS CRL to DER for signing
        let tbs_der = tbs_crl
            .to_der()
            .map_err(|e| ("crl_build_failed", e.into()))?;

        // NIAP PP-CA: FCS_COP.1.1 - Sign TBS CRL with CA private key
        //
        // Must match the AlgorithmIdentifier CrlBuilder wrote into the TBS
        // (RFC 5280 §5.1.1.2/§5.1.2.2 require the inner and outer algorithm
        // identifiers to be identical). Both come from `sig_alg`.
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, sig_alg, &tbs_der)
            .await
            .map_err(|e| ("signing_failed", e.into()))?;

        // ECDSA signatures are fixed r||s from the provider; CRLs require DER
        // Ecdsa-Sig-Value (RFC 5758 §3.2). RSA/Ed25519 pass through unchanged.
        let signature =
            ostrich_x509::signing::encode_x509_signature(sig_alg, signature).map_err(|e| {
                (
                    "crl_encoding_failed",
                    Error::CrlGeneration(format!("failed to encode signature: {}", e)),
                )
            })?;

        // Construct final signed CRL
        let der_encoded = self
            .build_signed_crl(&tbs_der, &signature)
            .map_err(|e| ("crl_encoding_failed", e))?;

        // Convert DER to PEM
        let pem_encoded = self
            .crl_der_to_pem(&der_encoded)
            .map_err(|e| ("crl_encoding_failed", e))?;

        // RFC 5280 §5 - Persist the signed CRL so the latest one can be served
        // at the public distribution point and so the CRL number stays
        // monotonic across restarts (RFC 5280 §5.2.3). The signed bytes are
        // stored verbatim; nothing about the signing/encoding changes here.
        // NIAP PP-CA: FMT_SMF.1 - CRL publication management function.
        crl_repo
            .create_crl(
                self.ca_certificate_id,
                crl_number_i64,
                tbs_crl.this_update,
                tbs_crl.next_update,
                der_encoded.clone(),
                pem_encoded.clone(),
                false, // full CRL
                None,
            )
            .await
            .map_err(|e| ("crl_store_failed", e.into()))?;

        Ok(GeneratedCrl {
            crl_number: current_crl_number,
            this_update: tbs_crl.this_update,
            next_update: tbs_crl.next_update,
            revoked_count,
            der_encoded,
            pem_encoded,
        })
    }

    /// Generate a delta CRL (RFC 5280 §5.2.4) as the scheduler (actor
    /// `"system"`); see [`Self::generate_delta_crl_by`].
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §5.2.4 - Delta CRL Indicator
    /// - NIAP PP-CA: FMT_SMF.1 - CRL generation; FAU_GEN.1.1 - audit
    pub async fn generate_delta_crl(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
    ) -> Result<GeneratedCrl> {
        self.generate_delta_crl_by(issuer_dn, CrlActor::System)
            .await
    }

    /// Generate a delta CRL (RFC 5280 §5.2.4) on behalf of `actor`.
    ///
    /// Lists only certificates revoked since the latest full (base) CRL's
    /// thisUpdate, carrying a critical Delta CRL Indicator with the base CRL
    /// number. Delta and full CRLs share the monotonic crl_number sequence.
    /// Success and failure are audited (action `generate_delta`) with `actor`
    /// as the audit actor (NIST-101, NIST-103).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §5.2.4 - Delta CRL Indicator
    /// - NIST 800-53: AU-2, AU-3 (who), AU-12, AC-6(9)
    /// - NIAP PP-CA: FMT_SMF.1 - CRL generation; FAU_GEN.1.1, FAU_GEN.2
    pub async fn generate_delta_crl_by(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
        actor: CrlActor<'_>,
    ) -> Result<GeneratedCrl> {
        match self.build_delta_crl(issuer_dn).await {
            Ok((crl, base_crl_number)) => {
                let mut audit_event =
                    crl_audit_event(self.ca_certificate_id, actor, CRL_ACTION_GENERATE_DELTA);
                merge_details(
                    &mut audit_event,
                    &[
                        ("crl_number", crl.crl_number.into()),
                        ("base_crl_number", base_crl_number.into()),
                        ("revoked_count", crl.revoked_count.into()),
                    ],
                );
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                tracing::info!(
                    "Delta CRL generated: number {} (base {}) with {} entries",
                    crl.crl_number,
                    base_crl_number,
                    crl.revoked_count
                );
                Ok(crl)
            }
            Err((failure, e)) => {
                self.record_crl_failure(actor, CRL_ACTION_GENERATE_DELTA, failure, &e)
                    .await;
                Err(e)
            }
        }
    }

    /// Build, sign and store a delta CRL. `Ok` carries the base CRL number;
    /// `Err` the failed stage (the audit `failure` reason) and the error.
    async fn build_delta_crl(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
    ) -> std::result::Result<(GeneratedCrl, i64), (&'static str, Error)> {
        let crl_repo = CrlRepository::new(self.db_pool.clone());

        // A delta CRL is relative to a base full CRL; require one to exist.
        let base = crl_repo
            .find_latest_crl(self.ca_certificate_id)
            .await
            .map_err(|e| ("base_crl_lookup_failed", e.into()))?
            .ok_or_else(|| {
                (
                    "no_base_crl",
                    Error::CrlGeneration(
                        "no base CRL exists; generate a full CRL before a delta".to_string(),
                    ),
                )
            })?;

        // RFC 5280 §5.2.4 - a delta lists changes since the base CRL's thisUpdate.
        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        let revoked_certs = cert_repo
            .find_revoked(&self.ca_certificate_id)
            .await
            .map_err(|e| ("revoked_lookup_failed", e.into()))?;
        let delta_info: Vec<RevokedCertificateInfo> = revoked_certs
            .iter()
            .filter_map(|cert| {
                let revocation_time = cert.revocation_time?;
                if revocation_time <= base.this_update {
                    return None;
                }
                let reason = cert.revocation_reason.and_then(RevocationReason::from_i32);
                Some(RevokedCertificateInfo::new(
                    cert.serial_number.clone(),
                    revocation_time,
                    reason,
                ))
            })
            .collect();
        let revoked_count = delta_info.len();

        let crl_number_i64 = crl_repo
            .next_crl_number(self.ca_certificate_id)
            .await
            .map_err(|e| ("crl_number_failed", e.into()))?;
        let current_crl_number = crl_number_i64 as u64;

        let sig_alg = self
            .crl_signature_algorithm()
            .map_err(|e| ("unsupported_ca_key_type", e))?;

        let crl_generator = CrlGenerator::new(issuer_dn, self.crl_validity_hours);
        let crl_builder = crl_generator
            .generate(current_crl_number, delta_info)
            .map_err(|e| ("crl_build_failed", e.into()))?
            .signature_algorithm(sig_alg)
            .delta_crl_indicator(base.crl_number as u64);

        let tbs_crl = crl_builder
            .build_tbs()
            .map_err(|e| ("crl_build_failed", e.into()))?;
        let tbs_der = tbs_crl
            .to_der()
            .map_err(|e| ("crl_build_failed", e.into()))?;
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, sig_alg, &tbs_der)
            .await
            .map_err(|e| ("signing_failed", e.into()))?;
        let signature =
            ostrich_x509::signing::encode_x509_signature(sig_alg, signature).map_err(|e| {
                (
                    "crl_encoding_failed",
                    Error::CrlGeneration(format!("failed to encode signature: {}", e)),
                )
            })?;
        let der_encoded = self
            .build_signed_crl(&tbs_der, &signature)
            .map_err(|e| ("crl_encoding_failed", e))?;
        let pem_encoded = self
            .crl_der_to_pem(&der_encoded)
            .map_err(|e| ("crl_encoding_failed", e))?;

        crl_repo
            .create_crl(
                self.ca_certificate_id,
                crl_number_i64,
                tbs_crl.this_update,
                tbs_crl.next_update,
                der_encoded.clone(),
                pem_encoded.clone(),
                true, // delta CRL
                Some(base.crl_number),
            )
            .await
            .map_err(|e| ("crl_store_failed", e.into()))?;

        Ok((
            GeneratedCrl {
                crl_number: current_crl_number,
                this_update: tbs_crl.this_update,
                next_update: tbs_crl.next_update,
                revoked_count,
                der_encoded,
                pem_encoded,
            },
            base.crl_number,
        ))
    }

    /// Build a signed CRL from TBS and signature
    ///
    /// RFC 5280 §5.1 - CRL structure
    fn build_signed_crl(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        use der::{Decode, Encode, asn1::BitString};
        use x509_cert::crl::{CertificateList, TbsCertList};

        // Parse TBS CRL from DER
        let tbs = TbsCertList::from_der(tbs_der)
            .map_err(|e| Error::CrlGeneration(format!("Failed to parse TBS CRL: {}", e)))?;

        // Get signature algorithm (same as in TBS)
        let signature_algorithm = tbs.signature.clone();

        // Convert signature bytes to BitString
        let signature_value = BitString::from_bytes(signature).map_err(|e| {
            Error::CrlGeneration(format!("Failed to create signature BitString: {}", e))
        })?;

        // Build complete CRL
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm,
            signature: signature_value,
        };

        // Encode to DER
        crl.to_der()
            .map_err(|e| Error::CrlGeneration(format!("Failed to encode CRL: {}", e)))
    }

    /// Convert DER-encoded CRL to PEM format
    ///
    /// RFC 7468 - PEM encoding
    fn crl_der_to_pem(&self, der: &[u8]) -> Result<String> {
        use pem_rfc7468::{LineEnding, encode_string};

        const CRL_LABEL: &str = "X509 CRL";

        encode_string(CRL_LABEL, LineEnding::LF, der)
            .map_err(|e| Error::CrlGeneration(format!("Failed to encode CRL PEM: {}", e)))
    }

    /// Check if a certificate is revoked
    ///
    /// RFC 6960 §2.2 - OCSP response
    pub async fn is_revoked(&self, certificate_id: &Uuid) -> Result<bool> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        let cert = cert_repo
            .find_by_id(*certificate_id)
            .await?
            .ok_or_else(|| Error::InvalidRequest("Certificate not found".to_string()))?;

        Ok(cert.revoked)
    }

    /// Full revocation status for a certificate.
    ///
    /// Returns `(revoked, revocation_time, reason_code)` so status responders
    /// can populate the complete RFC 6960 §2.2 / RFC 5280 §5.3.1 answer
    /// (revocation time and CRLReason), not just the boolean.
    pub async fn revocation_status(
        &self,
        certificate_id: &Uuid,
    ) -> Result<(bool, Option<DateTime<Utc>>, Option<i32>)> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        let cert = cert_repo
            .find_by_id(*certificate_id)
            .await?
            .ok_or_else(|| Error::InvalidRequest("Certificate not found".to_string()))?;

        Ok((cert.revoked, cert.revocation_time, cert.revocation_reason))
    }
}

/// Generated CRL information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedCrl {
    /// CRL number
    pub crl_number: u64,

    /// This update time
    pub this_update: DateTime<Utc>,

    /// Next update time
    pub next_update: DateTime<Utc>,

    /// Number of revoked certificates
    pub revoked_count: usize,

    /// DER-encoded CRL
    pub der_encoded: Vec<u8>,

    /// PEM-encoded CRL
    pub pem_encoded: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_request() {
        let request = RevocationRequest {
            certificate_id: Uuid::new_v4(),
            reason: RevocationReason::KeyCompromise,
            requestor: "admin@example.com".to_string(),
            authenticated_caller: None,
            justification: Some("Private key leaked".to_string()),
        };

        assert_eq!(request.reason.as_i32(), 1);
    }

    /// NIST-006 / QA-002 (M13): the CRL record's actor is the admin peer,
    /// with its certificate issuer and serial; the scheduler is "system" and
    /// REST is the user.
    #[test]
    fn crl_audit_event_actor() {
        let ca = Uuid::new_v4();
        let peer = crate::issuance::tests::test_caller("CN=ops-admin");
        let ev = crl_audit_event(ca, CrlActor::Peer(&peer), CRL_ACTION_GENERATE);
        assert_eq!(ev.actor, "CN=ops-admin");
        assert_eq!(ev.event_type, EventType::CrlGeneration);
        assert_eq!(ev.target, ca.to_string());
        assert_eq!(ev.action, "generate");
        assert_eq!(ev.outcome, EventOutcome::Success);
        let d = ev.details.expect("details");
        assert_eq!(d["authenticated_caller"], "CN=ops-admin");
        assert_eq!(d["authenticated_caller_issuer"], "CN=Service Identity CA");
        assert_eq!(d["authenticated_caller_serial"], "01ab");
        assert!(d.get("failure").is_none());
        let full = |actor| crl_audit_event(ca, actor, CRL_ACTION_GENERATE);
        assert_eq!(full(CrlActor::System).actor, "system");
        assert_eq!(full(CrlActor::User("alice")).actor, "alice");
        assert_eq!(full(CrlActor::Unauthenticated).actor, "unauthenticated");
        assert!(
            full(CrlActor::User("alice"))
                .details
                .is_some_and(|d| d.get("authenticated_caller").is_none())
        );
    }

    /// NIST-101: the delta CRL record carries the REST user / peer as actor
    /// and action `generate_delta`; the scheduler is "system".
    #[test]
    fn delta_crl_audit_event_actor() {
        let ca = Uuid::new_v4();
        let delta = |actor| crl_audit_event(ca, actor, CRL_ACTION_GENERATE_DELTA);
        let ev = delta(CrlActor::User("alice"));
        assert_eq!(ev.actor, "alice");
        assert_eq!(ev.action, "generate_delta");
        assert_eq!(ev.event_type, EventType::CrlGeneration);
        assert_eq!(ev.outcome, EventOutcome::Success);
        assert_eq!(delta(CrlActor::System).actor, "system");
        let peer = crate::issuance::tests::test_caller("CN=ops-admin");
        let ev = delta(CrlActor::Peer(&peer));
        assert_eq!(ev.actor, "CN=ops-admin");
        assert_eq!(
            ev.details.expect("details")["authenticated_caller_serial"],
            "01ab"
        );
    }

    /// NIST-103: failed full / delta CRL generation is a Failure record with
    /// the actor, the action and a fixed `failure` reason.
    #[test]
    fn crl_failure_event_contents() {
        let ca = Uuid::new_v4();
        let ev = crl_failure_event(
            ca,
            CrlActor::User("alice"),
            CRL_ACTION_GENERATE_DELTA,
            "no_base_crl",
        );
        assert_eq!(ev.actor, "alice");
        assert_eq!(ev.action, "generate_delta");
        assert_eq!(ev.outcome, EventOutcome::Failure);
        assert_eq!(ev.event_type, EventType::CrlGeneration);
        assert_eq!(ev.target, ca.to_string());
        assert_eq!(ev.details.expect("details")["failure"], "no_base_crl");

        let peer = crate::issuance::tests::test_caller("CN=ops-admin");
        let ev = crl_failure_event(
            ca,
            CrlActor::Peer(&peer),
            CRL_ACTION_GENERATE,
            "signing_failed",
        );
        assert_eq!(ev.actor, "CN=ops-admin");
        assert_eq!(ev.action, "generate");
        let d = ev.details.expect("details");
        assert_eq!(d["failure"], "signing_failed");
        assert_eq!(d["authenticated_caller"], "CN=ops-admin");
        assert_eq!(d["authenticated_caller_issuer"], "CN=Service Identity CA");
    }

    /// NIST-007: a refused revocation is a Failure record with the actor,
    /// on_behalf_of, requested reason and failure; the untrusted target is
    /// truncated and escaped.
    #[test]
    fn revocation_failure_event_contents() {
        let peer = crate::issuance::tests::test_caller("CN=ops-admin");
        let ev = revocation_failure_event(
            "not-a-uuid\n",
            1,
            "admin::oncall",
            Some(&peer),
            "invalid_certificate_id",
        );
        assert_eq!(ev.outcome, EventOutcome::Failure);
        assert_eq!(ev.event_type, EventType::CertificateRevocation);
        assert_eq!(ev.actor, "CN=ops-admin");
        assert_eq!(ev.action, "revoke");
        let d = ev.details.expect("details");
        assert_eq!(d["on_behalf_of"], "admin::oncall");
        assert_eq!(d["authenticated_caller_serial"], "01ab");
        assert_eq!(d["reason"], 1);
        assert_eq!(d["failure"], "invalid_certificate_id");

        let ev = revocation_failure_event(&"x\u{202E}".repeat(100), 99, "", None, "invalid_reason");
        assert!(!ev.target.contains('\u{202E}'), "{}", ev.target);
        assert!(ev.target.len() <= MAX_AUDITED_TARGET_CHARS * 10);
        assert_eq!(ev.actor, "");
        // REST (no caller): the requestor is the actor.
        let ev = revocation_failure_event("id", 0, "alice", None, "certificate_not_found");
        assert_eq!(ev.actor, "alice");
        assert!(ev.details.is_some_and(|d| d.get("on_behalf_of").is_none()));
    }
}
