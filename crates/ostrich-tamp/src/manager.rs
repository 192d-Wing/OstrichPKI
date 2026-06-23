//! TAMP manager / authority orchestration (RFC 5934).
//!
//! The [`TampManager`] composes and CMS-signs outbound TAMP messages, applies
//! the intended trust-anchor / community deltas to its authoritative store, and
//! verifies + records the signed confirmations and status responses returned by
//! targets. Outbound messages carry a strictly increasing sequence number per
//! `(target, signing key)`, and inbound messages are checked for replay against
//! the signer's durable baseline (RFC 5934 §4.1).
//!
//! Every state change emits an [`EventType::TampProtocol`] audit event.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934 §4 - message composition and the update state machine
//! - NIST 800-53: SC-23 (replay protection), AU-2/AU-3/AU-12 (audit), SI-10
//! - NIAP PP-CA: FMT_SMF.1 (trust anchor management), FCS_COP.1 (signing)

use std::sync::Arc;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use ostrich_db::repository::{TampRepository, TrustAnchorWrite};
use spki::SubjectPublicKeyInfoOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::asn1::{
    CommunityIdentifierList, SequenceNumberAdjust, TampApexUpdate, TampCommunityUpdate, TampMsgRef,
    TampStatusQuery, TampUpdate, TargetIdentifier, TerseOrVerbose, TrustAnchorChangeInfoChoice,
    TrustAnchorChoice, TrustAnchorUpdate,
};
use crate::cms;
use crate::error::{Error, Result};
use crate::oids;
use crate::statuscode::StatusCode;

/// The signing identity used to protect outbound TAMP messages — an apex or
/// management trust-anchor key held by the crypto provider (HSM-backed in
/// production; IA-7 / SC-12).
pub struct SignerContext<'a> {
    /// Crypto provider holding the signing key.
    pub provider: &'a dyn CryptoProvider,
    /// Handle to the signing key.
    pub key: &'a KeyHandle,
    /// subjectKeyIdentifier of the signing trust anchor (RFC 5934 §2.2.1).
    pub ski: Vec<u8>,
    /// Signature algorithm matching `key`.
    pub algorithm: Algorithm,
}

/// A signed TAMP message produced by the manager, ready for transport.
#[derive(Clone, Debug)]
pub struct IssuedMessage {
    /// `id-ct-TAMP-*` content type of the message.
    pub content_type: ObjectIdentifier,
    /// Friendly message name (for logging / audit).
    pub message_name: &'static str,
    /// Sequence number assigned to the message.
    pub seq_num: u64,
    /// DER-encoded CMS `ContentInfo` (`SignedData`) envelope.
    pub envelope: Vec<u8>,
}

/// A single trust-anchor edit to express in a `TAMPUpdate` (RFC 5934 §4.3).
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorEdit {
    /// Add a trust anchor to the target's store.
    Add(TrustAnchorChoice),
    /// Remove the trust anchor identified by this DER SubjectPublicKeyInfo.
    Remove(Vec<u8>),
    /// Change an existing trust anchor (identified inside the change info).
    Change {
        /// DER SubjectPublicKeyInfo of the trust anchor being changed.
        spki: Vec<u8>,
        /// The change to apply.
        change: TrustAnchorChangeInfoChoice,
    },
}

/// A read-only summary of a trust anchor in the authoritative store.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TrustAnchorSummary {
    /// Base64 DER SubjectPublicKeyInfo identifying the trust anchor.
    pub pub_key_spki_b64: String,
    /// Hex key identifier (SKI), if known.
    pub key_id_hex: Option<String>,
    /// Optional human-readable title.
    pub title: Option<String>,
    /// Whether this is the target's apex trust anchor.
    pub is_apex: bool,
}

/// The result of ingesting an inbound signed TAMP message (a confirmation,
/// status response, or error).
#[derive(Clone, Debug)]
pub struct IngestOutcome {
    /// Content type of the inbound message.
    pub content_type: ObjectIdentifier,
    /// Friendly message name.
    pub message_name: String,
    /// Sequence number referenced by the message (if present).
    pub seq_num: Option<u64>,
    /// Status codes carried by a confirmation / error.
    pub status_codes: Vec<StatusCode>,
    /// subjectKeyIdentifier of the message signer.
    pub signer_ski: Vec<u8>,
}

/// The DER SubjectPublicKeyInfo, optional key id, and optional title that
/// identify a trust anchor for storage and update keying.
type TaIdentity = (Vec<u8>, Option<Vec<u8>>, Option<String>);

/// Extract the identity ([`TaIdentity`]) of a trust anchor.
fn ta_identity(ta: &TrustAnchorChoice) -> Result<TaIdentity> {
    let spki = match ta {
        TrustAnchorChoice::Certificate(cert) => {
            cert.tbs_certificate.subject_public_key_info.to_der()?
        }
        TrustAnchorChoice::TbsCert(tbs) => tbs.subject_public_key_info.to_der()?,
        TrustAnchorChoice::TaInfo(info) => info.pub_key.to_der()?,
    };
    let (key_id, title) = match ta {
        TrustAnchorChoice::TaInfo(info) => {
            (Some(info.key_id.as_bytes().to_vec()), info.ta_title.clone())
        }
        _ => (None, None),
    };
    Ok((spki, key_id, title))
}

/// Convert a decoded TAMP `SeqNumber` to the stored `i64`, enforcing RFC 5934's
/// `SeqNumber ::= INTEGER (0..9223372036854775807)` range. A value above
/// `i64::MAX` is malformed and rejected rather than silently wrapped negative.
///
/// NIST 800-53: SI-10 - input validation of attacker-supplied sequence numbers.
fn seq_to_i64(seq: u64) -> Result<i64> {
    i64::try_from(seq).map_err(|_| {
        Error::SeqNumFailure(format!(
            "sequence number {seq} exceeds the RFC 5934 maximum (2^63-1)"
        ))
    })
}

impl TampManager {
    /// Construct a manager over the given store repository and audit sink.
    pub fn new(repo: TampRepository, audit: Arc<dyn AuditSink>) -> Self {
        Self { repo, audit }
    }

    /// Allocate the next strictly increasing sequence number for `(target,
    /// signer)` (RFC 5934 §4.1). Delegates to the repository's atomic
    /// increment so concurrent issuers cannot allocate duplicate numbers.
    async fn next_seq(&self, target_id: &Uuid, our_ski: &[u8]) -> Result<u64> {
        let next = self.repo.allocate_next_seq(target_id, our_ski).await?;
        // The stored baseline is a non-negative i64, so widening is lossless.
        Ok(next as u64)
    }

    async fn audit(
        &self,
        action: &str,
        target_label: &str,
        outcome: EventOutcome,
        details: serde_json::Value,
    ) {
        let mut ev = AuditEventBuilder::new(
            EventType::TampProtocol,
            "tamp-manager",
            target_label,
            action,
            outcome,
        )
        .with_details(details)
        .build();
        // Audit failures must not abort the protocol operation; they are logged.
        if let Err(e) = self.audit.record(&mut ev).await {
            tracing::error!(error = %e, "failed to record TAMP audit event");
        }
    }

    /// Issue a signed `TAMPStatusQuery` (RFC 5934 §4.1).
    pub async fn issue_status_query(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer: &SignerContext<'_>,
        terse: bool,
    ) -> Result<IssuedMessage> {
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;
        let seq = self.next_seq(&target_id, &signer.ski).await?;

        let msg = TampStatusQuery {
            version: 2,
            terse: if terse {
                TerseOrVerbose::Terse
            } else {
                TerseOrVerbose::Verbose
            },
            query: TampMsgRef {
                target: target.clone(),
                seq_num: seq,
            },
        };
        // No store mutation; sign then record.
        let envelope = self
            .sign_outbound(signer, oids::ID_CT_TAMP_STATUS_QUERY, &msg.to_der()?)
            .await?;
        Ok(self
            .finalize(
                &target_id,
                label,
                &signer.ski,
                oids::ID_CT_TAMP_STATUS_QUERY,
                "TAMPStatusQuery",
                seq,
                envelope,
            )
            .await)
    }

    /// Issue a signed `TAMPUpdate` carrying trust-anchor edits, applying the
    /// intended deltas to the authoritative store (RFC 5934 §4.3).
    pub async fn issue_trust_anchor_update(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer: &SignerContext<'_>,
        edits: Vec<TrustAnchorEdit>,
    ) -> Result<IssuedMessage> {
        if edits.is_empty() {
            return Err(Error::TrustAnchorUpdate(
                "TAMPUpdate requires at least one trust anchor update".into(),
            ));
        }
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;

        // Phase 1 (reads only): validate each edit and collect both the wire
        // `updates` and the deferred store writes. No mutation happens here, so
        // a validation failure leaves the store untouched.
        let mut updates = Vec::with_capacity(edits.len());
        let mut writes = Vec::with_capacity(edits.len());
        for edit in edits {
            match edit {
                TrustAnchorEdit::Add(ta) => {
                    let (spki, key_id, title) = ta_identity(&ta)?;
                    // RFC 5934 §4.3: re-adding an existing public key is rejected.
                    if self.repo.trust_anchor_exists(&target_id, &spki).await? {
                        return Err(Error::TrustAnchorUpdate(
                            "trust anchor with this public key already present (improperTAAddition)"
                                .into(),
                        ));
                    }
                    let ta_der = ta.to_der()?;
                    writes.push(TrustAnchorWrite::Insert {
                        pub_key_spki: spki,
                        key_id,
                        ta_title: title,
                        is_apex: false,
                        ta_der,
                    });
                    updates.push(TrustAnchorUpdate::Add(ta));
                }
                TrustAnchorEdit::Remove(spki) => {
                    let spki_info = SubjectPublicKeyInfoOwned::from_der(&spki)?;
                    writes.push(TrustAnchorWrite::Remove { pub_key_spki: spki });
                    updates.push(TrustAnchorUpdate::Remove(spki_info));
                }
                TrustAnchorEdit::Change { spki, change } => {
                    // RFC 5934 §4.3: changing a TA that is not present is an error.
                    if !self.repo.trust_anchor_exists(&target_id, &spki).await? {
                        return Err(Error::TrustAnchorUpdate(
                            "trust anchor to change was not found (trustAnchorNotFound)".into(),
                        ));
                    }
                    let ta_der = change.to_der()?;
                    writes.push(TrustAnchorWrite::Update {
                        pub_key_spki: spki,
                        ta_der,
                    });
                    updates.push(TrustAnchorUpdate::Change(change));
                }
            }
        }

        let seq = self.next_seq(&target_id, &signer.ski).await?;
        let msg = TampUpdate {
            version: 2,
            terse: TerseOrVerbose::Verbose,
            msg_ref: TampMsgRef {
                target: target.clone(),
                seq_num: seq,
            },
            updates,
            tamp_seq_numbers: None,
        };
        // Phase 2: sign first, then commit the whole store delta atomically.
        let envelope = self
            .sign_outbound(signer, oids::ID_CT_TAMP_UPDATE, &msg.to_der()?)
            .await?;
        self.repo
            .apply_trust_anchor_writes(&target_id, &writes)
            .await?;
        Ok(self
            .finalize(
                &target_id,
                label,
                &signer.ski,
                oids::ID_CT_TAMP_UPDATE,
                "TAMPUpdate",
                seq,
                envelope,
            )
            .await)
    }

    /// Issue a signed `TAMPCommunityUpdate` (RFC 5934 §4.7), applying the
    /// add/remove community deltas atomically to the store.
    pub async fn issue_community_update(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer: &SignerContext<'_>,
        add: Vec<ObjectIdentifier>,
        remove: Vec<ObjectIdentifier>,
    ) -> Result<IssuedMessage> {
        if add.is_empty() && remove.is_empty() {
            return Err(Error::Other(
                "community update requires at least one add or remove".into(),
            ));
        }
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;

        let seq = self.next_seq(&target_id, &signer.ski).await?;
        let msg = TampCommunityUpdate {
            version: 2,
            terse: TerseOrVerbose::Verbose,
            msg_ref: TampMsgRef {
                target: target.clone(),
                seq_num: seq,
            },
            updates: crate::asn1::CommunityUpdates {
                remove: if remove.is_empty() {
                    None
                } else {
                    Some(remove.clone())
                },
                add: if add.is_empty() {
                    None
                } else {
                    Some::<CommunityIdentifierList>(add.clone())
                },
            },
        };
        // Sign first, then apply the community delta atomically (RFC 5934 §4.7:
        // remove then add) so a signing failure leaves the store unchanged.
        let envelope = self
            .sign_outbound(signer, oids::ID_CT_TAMP_COMMUNITY_UPDATE, &msg.to_der()?)
            .await?;
        let remove_strs: Vec<String> = remove.iter().map(|o| o.to_string()).collect();
        let add_strs: Vec<String> = add.iter().map(|o| o.to_string()).collect();
        self.repo
            .apply_community_update(&target_id, &remove_strs, &add_strs)
            .await?;
        Ok(self
            .finalize(
                &target_id,
                label,
                &signer.ski,
                oids::ID_CT_TAMP_COMMUNITY_UPDATE,
                "TAMPCommunityUpdate",
                seq,
                envelope,
            )
            .await)
    }

    /// Issue a signed `SequenceNumberAdjust` (RFC 5934 §4.9).
    pub async fn issue_sequence_number_adjust(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer: &SignerContext<'_>,
    ) -> Result<IssuedMessage> {
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;
        let seq = self.next_seq(&target_id, &signer.ski).await?;
        let msg = SequenceNumberAdjust {
            version: 2,
            msg_ref: TampMsgRef {
                target: target.clone(),
                seq_num: seq,
            },
        };
        let envelope = self
            .sign_outbound(signer, oids::ID_CT_TAMP_SEQ_NUM_ADJUST, &msg.to_der()?)
            .await?;
        Ok(self
            .finalize(
                &target_id,
                label,
                &signer.ski,
                oids::ID_CT_TAMP_SEQ_NUM_ADJUST,
                "SequenceNumberAdjust",
                seq,
                envelope,
            )
            .await)
    }

    /// Issue a signed `TAMPApexUpdate` replacing the apex trust anchor
    /// (RFC 5934 §4.5). Optionally clears subordinate trust anchors and/or
    /// community memberships.
    ///
    /// When `contingency_decrypt_key` is supplied, it is attached as the
    /// `id-aa-TAMP-contingencyPublicKeyDecryptKey` *unsigned* CMS attribute
    /// (RFC 5934 §2.2.4.1) — the symmetric key the target uses to unwrap the
    /// apex contingency public key carried in `apex_ta`'s
    /// `id-pe-wrappedApexContinKey` extension. The caller is responsible for
    /// wrapping the contingency public key (e.g. via the HSM); the key material
    /// here is held in `Zeroizing` so the plaintext is wiped after use
    /// (NIST 800-53 SI-12).
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_apex_update(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer: &SignerContext<'_>,
        apex_ta: TrustAnchorChoice,
        clear_trust_anchors: bool,
        clear_communities: bool,
        contingency_decrypt_key: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<IssuedMessage> {
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;

        // Compute the apex identity (read only) before any mutation.
        let (spki, key_id, title) = ta_identity(&apex_ta)?;
        let apex_der = apex_ta.to_der()?;

        let seq = self.next_seq(&target_id, &signer.ski).await?;
        let msg = TampApexUpdate {
            version: 2,
            terse: TerseOrVerbose::Verbose,
            msg_ref: TampMsgRef {
                target: target.clone(),
                seq_num: seq,
            },
            clear_trust_anchors,
            clear_communities,
            seq_number: Some(seq),
            apex_ta,
        };
        // Sign first: the apex swap is destructive (it can clear subordinate
        // TAs and communities), so it must not happen if signing fails. The
        // whole swap then commits in a single transaction.
        let apex_der_msg = msg.to_der()?;
        let envelope = match contingency_decrypt_key {
            Some(key) => {
                // Carry the plaintext symmetric unwrap key as an unsigned
                // attribute (RFC 5934 §2.2.4.1). `key` (Zeroizing) is wiped on
                // drop; the copy placed in the envelope is the intended,
                // transport-protected wire value.
                let value = der::Any::encode_from(
                    &der::asn1::OctetString::new(key.to_vec())
                        .map_err(|e| Error::Cms(format!("contingency key octets: {e}")))?,
                )
                .map_err(|e| Error::Cms(format!("contingency key attr: {e}")))?;
                cms::sign_message_with_unsigned_attrs(
                    signer.provider,
                    signer.key,
                    &signer.ski,
                    oids::ID_CT_TAMP_APEX_UPDATE,
                    &apex_der_msg,
                    signer.algorithm,
                    &[(oids::ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY, value)],
                )
                .await?
            }
            None => {
                self.sign_outbound(signer, oids::ID_CT_TAMP_APEX_UPDATE, &apex_der_msg)
                    .await?
            }
        };
        self.repo
            .apply_apex_update(
                &target_id,
                clear_trust_anchors,
                clear_communities,
                &spki,
                key_id.as_deref(),
                title.as_deref(),
                &apex_der,
            )
            .await?;

        Ok(self
            .finalize(
                &target_id,
                label,
                &signer.ski,
                oids::ID_CT_TAMP_APEX_UPDATE,
                "TAMPApexUpdate",
                seq,
                envelope,
            )
            .await)
    }

    /// List the trust anchors currently held in a target's authoritative store.
    pub async fn list_trust_anchors(
        &self,
        target: &TargetIdentifier,
        label: &str,
    ) -> Result<Vec<TrustAnchorSummary>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;
        let rows = self.repo.list_trust_anchors(&target_id).await?;
        Ok(rows
            .into_iter()
            .map(|r| TrustAnchorSummary {
                pub_key_spki_b64: STANDARD.encode(&r.pub_key_spki),
                key_id_hex: r.key_id.map(hex::encode),
                title: r.ta_title,
                is_apex: r.is_apex,
            })
            .collect())
    }

    /// CMS-sign an outbound message body. This is the *only* fallible,
    /// observable side effect that gates whether a message is emitted, so
    /// callers sign FIRST and apply store mutations only after it succeeds.
    async fn sign_outbound(
        &self,
        signer: &SignerContext<'_>,
        content_type: ObjectIdentifier,
        content_der: &[u8],
    ) -> Result<Vec<u8>> {
        cms::sign_message(
            signer.provider,
            signer.key,
            &signer.ski,
            content_type,
            content_der,
            signer.algorithm,
        )
        .await
    }

    /// Record provenance + audit for an issued message and build the result.
    ///
    /// Best-effort: the message is already signed (and any store delta already
    /// committed), so logging / audit failures are recorded, never propagated —
    /// returning an error here would falsely signal the caller not to transmit.
    #[allow(clippy::too_many_arguments)]
    async fn finalize(
        &self,
        target_id: &Uuid,
        label: &str,
        signer_ski: &[u8],
        content_type: ObjectIdentifier,
        message_name: &'static str,
        seq: u64,
        envelope: Vec<u8>,
    ) -> IssuedMessage {
        if let Err(e) = self
            .repo
            .log_message(
                Some(target_id),
                "outbound",
                &content_type.to_string(),
                message_name,
                Some(seq as i64),
                Some(signer_ski),
                None,
                &envelope,
            )
            .await
        {
            tracing::error!(error = %e, message = message_name, "failed to log outbound TAMP message");
        }

        self.audit(
            message_name,
            label,
            EventOutcome::Success,
            serde_json::json!({
                "direction": "outbound",
                "content_type": content_type.to_string(),
                "seq_num": seq,
                "signer_ski": hex::encode(signer_ski),
            }),
        )
        .await;

        IssuedMessage {
            content_type,
            message_name,
            seq_num: seq,
            envelope,
        }
    }

    /// Register (or rotate) the public key the manager uses to verify a
    /// target's signed responses, located by subjectKeyIdentifier
    /// (RFC 5934 §2.2.1). `ingest` only trusts keys registered here.
    pub async fn register_target_signer(
        &self,
        target: &TargetIdentifier,
        label: &str,
        signer_ski: &[u8],
        signer_spki: &[u8],
        description: Option<&str>,
    ) -> Result<()> {
        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;
        self.repo
            .register_target_signer(&target_id, signer_ski, signer_spki, description)
            .await?;
        self.audit(
            "RegisterTargetSigner",
            label,
            EventOutcome::Success,
            serde_json::json!({ "signer_ski": hex::encode(signer_ski) }),
        )
        .await;
        Ok(())
    }

    /// Verify and record an inbound signed TAMP message (confirmation, status
    /// response, or error) returned by a target.
    ///
    /// The verifying key is resolved from the target's *registered* signers by
    /// the SignerInfo subjectKeyIdentifier (RFC 5934 §2.2.1) — never supplied by
    /// the caller — then the signature is checked, replay is rejected via the
    /// strictly-increasing per-signer sequence number (§4.1), and the outcome
    /// is recorded. NIST 800-53: SI-10.
    pub async fn ingest(
        &self,
        target: &TargetIdentifier,
        label: &str,
        content_info_der: &[u8],
    ) -> Result<IngestOutcome> {
        let parsed = cms::parse(content_info_der)?;

        let target_der = target.to_der()?;
        let target_id = self
            .repo
            .get_or_create_target(&target_der, label, true)
            .await?;

        // Resolve the verifying key from trusted state, not from the message or
        // the caller (RFC 5934 §2.2.1). An unknown signer is unauthorized.
        let signer_spki = self
            .repo
            .find_target_signer_spki(&target_id, &parsed.signer_ski)
            .await?
            .ok_or(Error::NoTrustAnchor)?;
        cms::verify(&parsed, &signer_spki)?;

        let (message_name, seq_num, status_codes) =
            decode_inbound(parsed.content_type, &parsed.content)?;

        // Replay protection for the target's signer (RFC 5934 §4.1): an inbound
        // message's sequence number must be strictly greater than the last seen.
        if let Some(seq) = seq_num {
            // Reject out-of-range sequence numbers before the i64 cast (SI-10).
            let seq_i64 = seq_to_i64(seq)?;
            let fresh = self
                .repo
                .check_and_advance_seq(&target_id, &parsed.signer_ski, seq_i64)
                .await?;
            if !fresh {
                self.audit(
                    &message_name,
                    label,
                    EventOutcome::Failure,
                    serde_json::json!({
                        "direction": "inbound",
                        "reason": "replay",
                        "seq_num": seq,
                        "signer_ski": hex::encode(&parsed.signer_ski),
                    }),
                )
                .await;
                return Err(Error::SeqNumFailure(format!(
                    "inbound sequence number {seq} is not greater than stored baseline"
                )));
            }
        }

        let status_label = status_codes.first().map(|s| s.as_str());
        self.repo
            .log_message(
                Some(&target_id),
                "inbound",
                &parsed.content_type.to_string(),
                &message_name,
                seq_num.map(|s| s as i64),
                Some(&parsed.signer_ski),
                status_label,
                content_info_der,
            )
            .await?;

        let outcome = if status_codes.iter().all(|s| s.is_success()) {
            EventOutcome::Success
        } else {
            EventOutcome::Failure
        };
        self.audit(
            &message_name,
            label,
            outcome,
            serde_json::json!({
                "direction": "inbound",
                "content_type": parsed.content_type.to_string(),
                "seq_num": seq_num,
                "status": status_codes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                "signer_ski": hex::encode(&parsed.signer_ski),
            }),
        )
        .await;

        Ok(IngestOutcome {
            content_type: parsed.content_type,
            message_name,
            seq_num,
            status_codes,
            signer_ski: parsed.signer_ski,
        })
    }
}

/// Manager state: the authoritative store and the audit sink.
pub struct TampManager {
    repo: TampRepository,
    audit: Arc<dyn AuditSink>,
}

/// Decode an inbound message body by content type, returning its friendly name,
/// referenced sequence number, and any status codes.
fn decode_inbound(
    content_type: ObjectIdentifier,
    content: &[u8],
) -> Result<(String, Option<u64>, Vec<StatusCode>)> {
    use crate::asn1::*;
    match content_type {
        oids::ID_CT_TAMP_STATUS_RESPONSE => {
            let m = TampStatusResponse::from_der(content)?;
            Ok(("TAMPStatusResponse".into(), Some(m.query.seq_num), vec![]))
        }
        oids::ID_CT_TAMP_UPDATE_CONFIRM => {
            let m = TampUpdateConfirm::from_der(content)?;
            let codes = match m.confirm {
                UpdateConfirm::Terse(c) => c,
                UpdateConfirm::Verbose(v) => v.status,
            };
            Ok(("TAMPUpdateConfirm".into(), Some(m.update.seq_num), codes))
        }
        oids::ID_CT_TAMP_APEX_UPDATE_CONFIRM => {
            let m = TampApexUpdateConfirm::from_der(content)?;
            let code = match m.apex_confirm {
                ApexUpdateConfirm::Terse(c) => c,
                ApexUpdateConfirm::Verbose(v) => v.status,
            };
            Ok((
                "TAMPApexUpdateConfirm".into(),
                Some(m.apex_replace.seq_num),
                vec![code],
            ))
        }
        oids::ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM => {
            let m = TampCommunityUpdateConfirm::from_der(content)?;
            let code = match m.comm_confirm {
                CommunityConfirm::Terse(c) => c,
                CommunityConfirm::Verbose(v) => v.status,
            };
            Ok((
                "TAMPCommunityUpdateConfirm".into(),
                Some(m.update.seq_num),
                vec![code],
            ))
        }
        oids::ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM => {
            let m = SequenceNumberAdjustConfirm::from_der(content)?;
            Ok((
                "SequenceNumberAdjustConfirm".into(),
                Some(m.adjust.seq_num),
                vec![m.status],
            ))
        }
        oids::ID_CT_TAMP_ERROR => {
            let m = TampError::from_der(content)?;
            Ok((
                "TAMPError".into(),
                m.msg_ref.map(|r| r.seq_num),
                vec![m.status],
            ))
        }
        other => Err(Error::Cms(format!(
            "unexpected inbound TAMP content type {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_to_i64_accepts_rfc_range() {
        assert_eq!(seq_to_i64(0).unwrap(), 0);
        assert_eq!(seq_to_i64(42).unwrap(), 42);
        // RFC 5934 SeqNumber maximum (2^63 - 1) is the largest accepted value.
        assert_eq!(seq_to_i64(i64::MAX as u64).unwrap(), i64::MAX);
    }

    #[test]
    fn seq_to_i64_rejects_out_of_range() {
        // 2^63 and above are outside SeqNumber ::= INTEGER (0..2^63-1) and must
        // be rejected, never wrapped to a negative i64 (the replay-bypass risk).
        assert!(seq_to_i64(i64::MAX as u64 + 1).is_err());
        assert!(seq_to_i64(u64::MAX).is_err());
    }

    #[test]
    fn decode_inbound_rejects_unknown_content_type() {
        // A non-TAMP OID must not be mistaken for a confirmation/response.
        let err = decode_inbound(crate::oids::ID_DATA, &[]);
        assert!(err.is_err());
    }
}
