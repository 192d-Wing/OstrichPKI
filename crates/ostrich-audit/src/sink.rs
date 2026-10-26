//! Audit event sinks for persistence
//!
//! This module provides audit sink implementations for persisting audit records
//! with integrity protection through cryptographic hash chains.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-9**: Protection of audit information - Secure storage with hash chain
//! - **AU-9(3)**: Cryptographic protection - SHA-256 hash chain for integrity
//! - **AU-10**: Non-repudiation - Tamper-evident audit trail
//! - **AU-4**: Audit storage capacity - Database-backed persistent storage
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FAU_STG.1**: Protected audit trail storage
//!   - Audit trail stored in protected database
//!   - Unauthorized modification prevented through access controls
//! - **FAU_STG.4**: Prevention of audit data loss
//!   - Hash chain enables detection of missing/modified records
//!   - Integrity verification via verify_integrity() method
//!
//! ## Related Standards
//! - FIPS 180-4: SHA-256 for hash chain computation

use crate::{AuditEvent, Error, Result};
use async_trait::async_trait;
use ostrich_db::{DatabasePool, repository::AuditRepository};
use std::time::Duration;

/// Upper bound for opening an audit-chain append (pool connection, BEGIN,
/// waiting for the chain lock). Above the database `lock_timeout`
/// ([`ostrich_db::repository::AUDIT_CHAIN_LOCK_TIMEOUT_MS`]) so the database
/// normally reports the lock timeout first.
pub const AUDIT_BEGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound the sink waits for one record's signature while the chain
/// lock is held (an HSM that stops answering must not hold the lock for every
/// writer). The sign runs on the blocking pool so this can fire even for a
/// provider that blocks its thread; the hung call itself is not cancelled.
/// Kept below the transaction's `idle_in_transaction_session_timeout`
/// ([`ostrich_db::repository::AUDIT_CHAIN_IDLE_TIMEOUT_MS`]), which is the
/// server-side backstop that releases the lock if the client is stuck.
pub const AUDIT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for inserting and committing one record.
pub const AUDIT_COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Log an audit write failure at error level with a stable `alert` field for
/// log-based alerting (AU-5: alert on audit processing failure). The event is
/// identified by type/action/target only; no record content beyond that.
fn alert_audit_write_failure(event: &AuditEvent, stage: &'static str, error: &Error) {
    tracing::error!(
        alert = "audit_write_failed",
        stage,
        event_type = event.event_type.as_str(),
        action = %event.action,
        target = %event.target,
        error = %error,
        "audit record NOT written (fail closed)"
    );
}

/// AU-5 alert for a commit that timed out: the COMMIT may or may not have
/// been applied by the server, so the record's persistence is unknown. Same
/// `alert` field as [`alert_audit_write_failure`], with `outcome = "unknown"`.
fn alert_audit_commit_outcome_unknown(event: &AuditEvent, error: &Error) {
    tracing::error!(
        alert = "audit_write_failed",
        stage = "commit",
        outcome = "unknown",
        event_type = event.event_type.as_str(),
        action = %event.action,
        target = %event.target,
        error = %error,
        "audit record commit timed out: outcome unknown (record may or may not be written)"
    );
}

/// Refuse audit signing algorithms that cannot run under the chain lock.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5, AU-10 - fail closed at construction, not per record
/// - FIPS 205: SLH-DSA signing latency (tens of ms to seconds) is unsuitable
fn ensure_audit_signing_algorithm(algorithm: ostrich_crypto::Algorithm) -> Result<()> {
    use ostrich_crypto::Algorithm as A;
    match algorithm {
        A::SlhDsaSha2_128s
        | A::SlhDsaSha2_128f
        | A::SlhDsaSha2_192s
        | A::SlhDsaSha2_192f
        | A::SlhDsaSha2_256s
        | A::SlhDsaSha2_256f => Err(Error::Signing(format!(
            "{algorithm} is not supported for audit record signing (signing runs under \
             the audit chain lock); use ECDSA, Ed25519 or ML-DSA"
        ))),
        _ => Ok(()),
    }
}

/// Sign `hash` with the audit signer, bounded by `limit`.
///
/// `CryptoProvider::sign` is async in signature, but the PKCS#11 provider
/// makes blocking cryptoki calls inside it, so a plain
/// `tokio::time::timeout` around the future could never fire: the future
/// never yields and the worker running it is stuck. The sign therefore runs
/// on tokio's blocking pool (`spawn_blocking` + `Handle::block_on`), and the
/// caller times out the `JoinHandle`. On timeout the caller returns
/// [`Error::Timeout`] and releases the chain lock; the blocking thread itself
/// is not cancellable and stays busy until the provider returns (one leaked
/// blocking-pool thread per hung call, bounded by tokio's blocking pool).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5 (Response to Audit Processing Failures), AU-10
/// - NIST 800-53: SC-13 - signing goes through `CryptoProvider` only
async fn sign_bounded(signer: &AuditSigner, hash: &[u8], limit: Duration) -> Result<Vec<u8>> {
    let crypto = signer.crypto.clone();
    let key = signer.key_handle.clone();
    let algorithm = signer.algorithm;
    let hash = hash.to_vec();
    let runtime = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        runtime.block_on(async move { crypto.sign(&key, algorithm, &hash).await })
    });
    match tokio::time::timeout(limit, task).await {
        Ok(Ok(Ok(signature))) => Ok(signature),
        Ok(Ok(Err(e))) => Err(Error::Signing(format!(
            "Failed to sign audit record: {}",
            e
        ))),
        Ok(Err(_join)) => Err(Error::Signing(
            "audit signing task failed (panicked or cancelled)".to_string(),
        )),
        Err(_) => Err(Error::Timeout("signing the audit record")),
    }
}

/// Trait for audit event sinks
///
/// NIST 800-53: AU-4 - Audit storage capacity
/// NIAP PP-CA: FAU_STG.1 - Protected audit trail storage interface
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record an audit event
    ///
    /// NIST 800-53: AU-2 - Auditable events
    /// NIST 800-53: AU-9(3) - Cryptographic protection via hash chain
    /// NIAP PP-CA: FAU_GEN.1.1 - Store generated audit record
    async fn record(&self, event: &mut AuditEvent) -> Result<()>;

    /// Verify the integrity of the audit log
    ///
    /// NIST 800-53: AU-9(3) - Verify audit information integrity
    /// NIAP PP-CA: FAU_STG.4 - Detect potential audit data loss or modification
    async fn verify_integrity(&self) -> Result<bool>;

    /// Query events by various criteria
    ///
    /// NIAP PP-CA: FAU_STG.1 - Retrieve audit records from protected storage
    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>>;
}

/// Criteria for querying audit events
#[derive(Debug, Clone)]
pub struct QueryCriteria {
    /// Filter by actor
    pub actor: Option<String>,

    /// Filter by event type
    pub event_type: Option<String>,

    /// Filter by time range
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,

    /// Limit number of results
    pub limit: Option<i64>,

    /// Offset for pagination
    pub offset: Option<i64>,
}

impl Default for QueryCriteria {
    fn default() -> Self {
        Self {
            actor: None,
            event_type: None,
            start_time: None,
            end_time: None,
            limit: Some(100),
            offset: None,
        }
    }
}

/// Database-backed audit sink with hash chain integrity
///
/// NIST 800-53: AU-9 - Audit information stored in database
/// NIST 800-53: AU-9(3) - Hash chain for integrity protection
/// NIAP PP-CA: FAU_STG.1 - Protected audit trail storage in database
/// NIAP PP-CA: FAU_STG.4 - Hash chain prevents undetected modification
pub struct DatabaseAuditSink {
    repository: AuditRepository,
    /// Optional record signer (AU-10 non-repudiation). When set, every record's
    /// event_hash is signed at write time; verification then detects tampering
    /// even by an attacker who rewrites the whole SHA-256 chain.
    signer: Option<AuditSigner>,
}

/// Holds the key material used to sign audit records.
struct AuditSigner {
    crypto: std::sync::Arc<dyn ostrich_crypto::CryptoProvider>,
    key_handle: ostrich_crypto::KeyHandle,
    algorithm: ostrich_crypto::Algorithm,
    /// Stored on each record so verifiers know which key to check.
    key_label: String,
}

impl DatabaseAuditSink {
    /// Create a new database audit sink WITHOUT record signing (hash chain
    /// only). Backward-compatible default.
    pub fn new(pool: DatabasePool) -> Self {
        Self {
            repository: AuditRepository::new(pool),
            signer: None,
        }
    }

    /// Create a database audit sink that SIGNS each record's event_hash
    /// (AU-10 non-repudiation). The signing key should be HSM-backed in
    /// production; `key_label` is recorded on each row so verifiers know which
    /// public key to check against.
    ///
    /// Signing happens while the database-wide chain lock is held, so its
    /// latency serialises every audit writer. The signing algorithm must not
    /// be SLH-DSA (FIPS 205 signing is far too slow to run under the lock):
    /// any `SlhDsa*` algorithm is refused here with [`Error::Signing`]. Each
    /// signature is bounded by [`AUDIT_SIGN_TIMEOUT`] (see [`sign_bounded`]).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-10 (Non-repudiation), AU-9(3) (Cryptographic protection)
    /// - NIST 800-53: AU-5 - fail closed on a signer unsuitable for the lock
    /// - NIAP PP-CA: FAU_STG.1.2 / FAU_STG.4 - undetected modification prevented
    pub fn with_signing_key(
        pool: DatabasePool,
        crypto: std::sync::Arc<dyn ostrich_crypto::CryptoProvider>,
        key_handle: ostrich_crypto::KeyHandle,
        algorithm: ostrich_crypto::Algorithm,
        key_label: impl Into<String>,
    ) -> Result<Self> {
        ensure_audit_signing_algorithm(algorithm)?;
        Ok(Self {
            repository: AuditRepository::new(pool),
            signer: Some(AuditSigner {
                crypto,
                key_handle,
                algorithm,
                key_label: key_label.into(),
            }),
        })
    }

    /// Verify the audit chain AND every signed record's signature against the
    /// given public key (DER SubjectPublicKeyInfo).
    ///
    /// Returns Ok(true) only if the hash chain is intact AND every record that
    /// carries a signature verifies. A record whose contents were modified
    /// fails here even if the attacker recomputed the entire hash chain,
    /// because they cannot forge the signature (AU-10).
    ///
    /// `algorithm` is the signature algorithm of the signing key (e.g. the CA
    /// key's algorithm). The audit signer stores the crypto provider's RAW
    /// signature, so for ECDSA keys this is fixed `r||s` (ecdsa_fixed=true);
    /// RSA/Ed25519 are unaffected.
    pub async fn verify_signed_chain(
        &self,
        signer_public_key_spki: &[u8],
        algorithm: ostrich_crypto::Algorithm,
    ) -> Result<bool> {
        // First the structural checks (continuity + hash recomputation).
        if !self
            .repository
            .verify_chain()
            .await
            .map_err(Error::Database)?
        {
            return Ok(false);
        }

        // Then verify each signed record's signature over its event_hash. A
        // tampered record fails here even after a full hash-chain rewrite,
        // because the attacker cannot forge the signature (AU-10).
        let events = self
            .repository
            .all_events_ordered()
            .await
            .map_err(Error::Database)?;
        for db_event in events {
            let Some(sig) = &db_event.signature else {
                continue; // unsigned record - structural check already covered it
            };
            let ok = ostrich_crypto::verify_with_spki(
                signer_public_key_spki,
                algorithm,
                &db_event.event_hash,
                sig,
                true, // provider emits raw fixed r||s for ECDSA
            )
            .map_err(|e| Error::Signing(format!("Audit signature verify error: {}", e)))?;
            if !ok {
                tracing::error!(
                    event_id = %db_event.id,
                    "Audit record signature verification FAILED (tampering or wrong key)"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Convert database model to audit event
    fn from_db_model(db_event: ostrich_db::models::AuditEvent) -> AuditEvent {
        use crate::{EventOutcome, EventType};

        // Parse event type
        let event_type = match db_event.event_type.as_str() {
            "authentication" => EventType::Authentication,
            "authorization" => EventType::Authorization,
            "certificate_issuance" => EventType::CertificateIssuance,
            "certificate_revocation" => EventType::CertificateRevocation,
            "crl_generation" => EventType::CrlGeneration,
            "key_generation" => EventType::KeyGeneration,
            "key_escrow" => EventType::KeyEscrow,
            "key_recovery" => EventType::KeyRecovery,
            "key_destruction" => EventType::KeyDestruction,
            "configuration_change" => EventType::ConfigurationChange,
            "access_violation" => EventType::AccessViolation,
            "token_lifecycle" => EventType::TokenLifecycle,
            "acme_protocol" => EventType::AcmeProtocol,
            "est_protocol" => EventType::EstProtocol,
            "ocsp_protocol" => EventType::OcspProtocol,
            "tamp_protocol" => EventType::TampProtocol,
            "system" => EventType::System,
            "database" => EventType::Database,
            _ => EventType::Other,
        };

        // Parse outcome
        let outcome = match db_event.outcome.as_str() {
            "success" => EventOutcome::Success,
            "failure" => EventOutcome::Failure,
            _ => EventOutcome::Error,
        };

        AuditEvent {
            id: db_event.id,
            event_type,
            actor: db_event.actor,
            target: db_event.target,
            action: db_event.action,
            outcome,
            details: db_event.details,
            ip_address: db_event.ip_address,
            user_agent: db_event.user_agent,
            session_id: db_event.session_id,
            previous_hash: db_event.previous_hash,
            event_hash: db_event.event_hash,
            timestamp: db_event.timestamp,
            signature: db_event.signature,
            signing_key_id: db_event.signing_key_id,
        }
    }
}

#[async_trait]
impl AuditSink for DatabaseAuditSink {
    // NIAP PP-CA: FAU_STG.1 - Protected audit trail storage implementation

    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        // Truncate to microsecond precision BEFORE hashing. Postgres timestamptz
        // stores microseconds, so a nanosecond-precision Utc::now() would hash to
        // one value here but recompute to a different value after the DB
        // round-trip, breaking verify_chain. Truncating up front makes the stored
        // hash match what the verifier recomputes from the persisted timestamp.
        use chrono::SubsecRound;
        event.timestamp = event.timestamp.trunc_subsecs(6);

        // NIST 800-53: AU-9(3) - read-link-hash-sign-insert is one serialised
        // unit: `begin_append` opens a transaction holding a database-wide
        // advisory lock, so concurrent writers (in this or any other service)
        // cannot both link to the same head and fork the chain. The lock is
        // released on commit, or on rollback if anything below fails.
        // AU-5: every step is time-bounded; on timeout or error the record
        // is NOT written (the transaction rolls back, the lock is released)
        // and the failure is logged with `alert = "audit_write_failed"`.
        // There is no unchained fallback.
        let append =
            match tokio::time::timeout(AUDIT_BEGIN_TIMEOUT, self.repository.begin_append()).await {
                Ok(Ok(append)) => append,
                Ok(Err(e)) => {
                    let e = Error::Database(e);
                    alert_audit_write_failure(event, "begin_append", &e);
                    return Err(e);
                }
                Err(_) => {
                    let e = Error::Timeout("waiting for the audit chain lock");
                    alert_audit_write_failure(event, "begin_append", &e);
                    return Err(e);
                }
            };

        // NIAP PP-CA: FAU_STG.4 - Link to the prior record BEFORE hashing so the
        // chain link is covered by event_hash (and the signature below). The
        // repository persists this previous_hash verbatim; it does not re-derive
        // it. Without this, event_hash would be computed with previous_hash=None
        // while the verifier recomputes with the stored link -> mismatch.
        event.previous_hash = append.previous_hash().map(<[u8]>::to_vec);
        // Chain order is timestamp order: a record not later than the current
        // head (it waited for the lock, or another host's clock is ahead) is
        // moved just after it; its original time is kept in details.
        apply_chain_timestamp(event, append.previous_timestamp());

        // NIAP PP-CA: FAU_STG.4 - Compute hash for tamper detection
        // Compute event hash with chain integrity
        event.event_hash = event.compute_hash();

        // POAM: POAM-2026-10-23-31 - the record is signed while the chain lock
        // is held, so signer latency serialises all audit writers. The wait is
        // bounded by AUDIT_SIGN_TIMEOUT (the sign runs off the async workers,
        // see sign_bounded) and, server side, by the transaction's
        // idle_in_transaction_session_timeout; a hung HSM call itself is not
        // cancelled. The Postgres concurrency test runs opt-in only
        // (OSTRICH_DB_TESTS=1).
        // AU-10: sign the event_hash so tampering is detectable even if the
        // attacker recomputes the whole hash chain (they cannot forge this).
        if let Some(signer) = &self.signer {
            let signature = match sign_bounded(signer, &event.event_hash, AUDIT_SIGN_TIMEOUT).await
            {
                Ok(signature) => signature,
                Err(e) => {
                    // Dropping `append` below rolls back and releases the lock.
                    alert_audit_write_failure(event, "sign", &e);
                    return Err(e);
                }
            };
            event.signature = Some(signature);
            event.signing_key_id = Some(signer.key_label.clone());
        }

        // Store in database and commit (releases the chain lock).
        let db_event = event.to_db_model();
        match tokio::time::timeout(AUDIT_COMMIT_TIMEOUT, append.commit(&db_event)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let e = Error::Database(e);
                alert_audit_write_failure(event, "commit", &e);
                return Err(e);
            }
            Err(_) => {
                // Dropping the commit future drops the connection. The
                // server may or may not have committed, so the outcome is
                // reported as unknown (not "not written"), and as an error.
                let e = Error::Timeout("committing the audit record");
                alert_audit_commit_outcome_unknown(event, &e);
                return Err(e);
            }
        }

        tracing::debug!(
            "Audit event recorded: {} - {} {} on {}",
            event.event_type.as_str(),
            event.actor,
            event.action,
            event.target
        );

        // Log security-relevant events at info level
        if event.event_type.is_security_relevant() {
            tracing::info!(
                "Security event: {} by {} on {} - {}",
                event.action,
                event.actor,
                event.target,
                event.outcome.as_str()
            );
        }

        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        // NIAP PP-CA: FAU_STG.4 - Verify hash chain to detect tampering or loss
        self.repository
            .verify_chain()
            .await
            .map_err(Error::Database)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let db_events = if let Some(actor) = criteria.actor {
            self.repository
                .find_by_actor(&actor, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let Some(event_type) = criteria.event_type {
            self.repository
                .find_by_type(&event_type, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let (Some(start), Some(end)) = (criteria.start_time, criteria.end_time) {
            self.repository
                .find_by_time_range(start, end, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else {
            use ostrich_db::repository::Repository;
            self.repository
                .list(criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        };

        Ok(db_events.into_iter().map(Self::from_db_model).collect())
    }
}

/// Timestamp for a record appended after a chain head written at `head`:
/// unchanged when later than the head, otherwise the head plus one
/// microsecond (the database's timestamp precision), so timestamp order stays
/// chain order (AU-9(3), FPT_STM.1). The shift is NOT bounded to 1 µs: it is
/// however far the head is ahead of the record (time spent waiting for the
/// chain lock, or clock skew between writers on different hosts).
fn chain_timestamp(
    timestamp: chrono::DateTime<chrono::Utc>,
    head: Option<chrono::DateTime<chrono::Utc>>,
) -> chrono::DateTime<chrono::Utc> {
    match head {
        Some(head) if timestamp <= head => head + chrono::Duration::microseconds(1),
        _ => timestamp,
    }
}

/// Details key holding a record's original event time when
/// [`apply_chain_timestamp`] moved its `timestamp` (RFC 3339, µs).
///
/// RESERVED for the audit sink: callers must not set it. A caller value that
/// differs from what the sink writes is moved to
/// [`CALLER_OCCURRED_AT_DETAIL`] (with a warning), so `occurred_at` always
/// means "original time of a record whose chain timestamp was moved".
pub const OCCURRED_AT_DETAIL: &str = "occurred_at";

/// Details key receiving a caller-supplied `occurred_at` value (see
/// [`OCCURRED_AT_DETAIL`]).
pub const CALLER_OCCURRED_AT_DETAIL: &str = "caller_occurred_at";

/// Set `event.timestamp` by [`chain_timestamp`]. When it changes, the original
/// time is preserved as `details.occurred_at` (AU-3 "when" / AU-8: the time
/// the event happened, distinct from its chain position). Non-object details
/// are wrapped as `{"occurred_at": .., "details": <original>}`. A caller-set
/// `occurred_at` is never trusted: it is moved to `caller_occurred_at` unless
/// it equals the value the sink writes. Must run before hashing.
fn apply_chain_timestamp(event: &mut AuditEvent, head: Option<chrono::DateTime<chrono::Utc>>) {
    let original = event.timestamp;
    event.timestamp = chain_timestamp(original, head);
    let occurred_at = (event.timestamp != original).then(|| {
        serde_json::Value::String(original.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    });

    // NIST 800-53: AU-3, AU-8 - `occurred_at` is sink-owned.
    if let Some(serde_json::Value::Object(map)) = event.details.as_mut()
        && let Some(caller) = map.remove(OCCURRED_AT_DETAIL)
        && Some(&caller) != occurred_at.as_ref()
    {
        tracing::warn!(
            event_type = event.event_type.as_str(),
            action = %event.action,
            target = %event.target,
            "details.{OCCURRED_AT_DETAIL} is reserved for the audit sink; the caller's value \
             was moved to details.{CALLER_OCCURRED_AT_DETAIL}"
        );
        map.insert(CALLER_OCCURRED_AT_DETAIL.to_string(), caller);
    }

    let Some(occurred_at) = occurred_at else {
        return;
    };
    match event.details.take() {
        Some(serde_json::Value::Object(mut map)) => {
            map.insert(OCCURRED_AT_DETAIL.to_string(), occurred_at);
            event.details = Some(serde_json::Value::Object(map));
        }
        None => {
            event.details = Some(serde_json::json!({ OCCURRED_AT_DETAIL: occurred_at }));
        }
        Some(other) => {
            event.details = Some(serde_json::json!({
                OCCURRED_AT_DETAIL: occurred_at,
                "details": other,
            }));
        }
    }
}

/// In-memory audit sink for testing
///
/// WARNING: Not suitable for production use - no persistence
/// NOTE: Does not satisfy FAU_STG.1 (protected storage) for production
#[cfg(any(test, feature = "testing"))]
pub struct MemoryAuditSink {
    events: tokio::sync::RwLock<Vec<AuditEvent>>,
    /// Optional signer and its per-record bound, applied exactly as in
    /// [`DatabaseAuditSink`] (via [`sign_bounded`], with the append lock held).
    signer: Option<(AuditSigner, Duration)>,
}

#[cfg(any(test, feature = "testing"))]
impl Default for MemoryAuditSink {
    fn default() -> Self {
        Self {
            events: tokio::sync::RwLock::new(Vec::new()),
            signer: None,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Memory sink that signs each record like
    /// [`DatabaseAuditSink::with_signing_key`] (same algorithm guard, same
    /// bounded signing), with `sign_timeout` in place of
    /// [`AUDIT_SIGN_TIMEOUT`] so tests can exercise the timeout quickly.
    pub fn with_signer(
        crypto: std::sync::Arc<dyn ostrich_crypto::CryptoProvider>,
        key_handle: ostrich_crypto::KeyHandle,
        algorithm: ostrich_crypto::Algorithm,
        key_label: impl Into<String>,
        sign_timeout: Duration,
    ) -> Result<Self> {
        ensure_audit_signing_algorithm(algorithm)?;
        Ok(Self {
            events: tokio::sync::RwLock::new(Vec::new()),
            signer: Some((
                AuditSigner {
                    crypto,
                    key_handle,
                    algorithm,
                    key_label: key_label.into(),
                },
                sign_timeout,
            )),
        })
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        // NIAP PP-CA: FAU_GEN.1.1 - Store audit record (test implementation)
        let mut events = self.events.write().await;

        // NIAP PP-CA: FAU_STG.4 - Link to previous event for chain integrity.
        // The write lock is held from here to the push, so appends are
        // serialised exactly like the database sink's advisory lock; the same
        // monotonic-timestamp rule applies.
        use chrono::SubsecRound;
        event.timestamp = event.timestamp.trunc_subsecs(6);
        apply_chain_timestamp(event, events.last().map(|e| e.timestamp));
        event.previous_hash = events.last().map(|e| e.event_hash.clone());

        // Compute this event's hash
        event.event_hash = event.compute_hash();

        // AU-10 / AU-5: bounded signing under the append lock (as the DB sink).
        if let Some((signer, limit)) = &self.signer {
            match sign_bounded(signer, &event.event_hash, *limit).await {
                Ok(signature) => {
                    event.signature = Some(signature);
                    event.signing_key_id = Some(signer.key_label.clone());
                }
                Err(e) => {
                    alert_audit_write_failure(event, "sign", &e);
                    return Err(e);
                }
            }
        }

        events.push(event.clone());
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        // NIAP PP-CA: FAU_STG.4 - Verify audit trail integrity
        let events = self.events.read().await;

        if events.is_empty() {
            return Ok(true);
        }

        let mut prev_hash: Option<Vec<u8>> = None;

        for event in events.iter() {
            // NIAP PP-CA: FAU_STG.4 - Check chain continuity
            if event.previous_hash != prev_hash {
                return Ok(false);
            }

            // NIAP PP-CA: FAU_STG.4 - Verify hash computation matches stored hash
            // Verify hash computation
            let computed_hash = event.compute_hash();
            if computed_hash != event.event_hash {
                return Ok(false);
            }

            prev_hash = Some(event.event_hash.clone());
        }

        Ok(true)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let mut filtered: Vec<AuditEvent> = events
            .iter()
            .filter(|e| {
                if let Some(ref actor) = criteria.actor
                    && e.actor != *actor
                {
                    return false;
                }
                if let Some(ref event_type) = criteria.event_type
                    && e.event_type.as_str() != event_type
                {
                    return false;
                }
                if let Some(start) = criteria.start_time
                    && e.timestamp < start
                {
                    return false;
                }
                if let Some(end) = criteria.end_time
                    && e.timestamp > end
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Apply limit and offset
        let offset = criteria.offset.unwrap_or(0) as usize;
        let limit = criteria.limit.unwrap_or(100) as usize;

        if offset < filtered.len() {
            filtered = filtered[offset..].to_vec();
        } else {
            filtered.clear();
        }

        if filtered.len() > limit {
            filtered.truncate(limit);
        }

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventBuilder, EventOutcome, EventType};

    #[tokio::test]
    async fn test_memory_sink_chain_integrity() {
        let sink = MemoryAuditSink::new();

        // Record first event
        let mut event1 = AuditEventBuilder::new(
            EventType::Authentication,
            "user1",
            "system",
            "login",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event1).await.unwrap();

        // Record second event
        let mut event2 = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            "ca-service",
            "cert-123",
            "issue",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event2).await.unwrap();

        // Verify integrity
        assert!(sink.verify_integrity().await.unwrap());

        // Verify chain link
        assert_eq!(event2.previous_hash, Some(event1.event_hash.clone()));
    }

    /// AU-9(3): concurrent appends never fork the chain, and timestamp order
    /// equals chain order (the property `DatabaseAuditSink` gets from its
    /// advisory lock; `MemoryAuditSink` shares the linking rules).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_memory_sink_concurrent_appends_keep_chain() {
        let sink = std::sync::Arc::new(MemoryAuditSink::new());
        // Same creation timestamp for every event, to exercise the bump.
        let created = chrono::Utc::now();
        let mut tasks = Vec::new();
        for i in 0..64 {
            let sink = sink.clone();
            tasks.push(tokio::spawn(async move {
                let mut event = AuditEventBuilder::new(
                    EventType::Authentication,
                    format!("peer-{i}"),
                    "ca-grpc",
                    "tls_handshake_failed",
                    EventOutcome::Failure,
                )
                .build();
                event.timestamp = created;
                sink.record(&mut event).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert!(sink.verify_integrity().await.unwrap());
        let events = sink
            .query_events(QueryCriteria {
                limit: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 64);
        assert!(events.windows(2).all(|w| w[0].timestamp < w[1].timestamp));
    }

    #[test]
    fn chain_timestamp_is_strictly_after_head() {
        let t = chrono::Utc::now();
        assert_eq!(chain_timestamp(t, None), t);
        assert_eq!(
            chain_timestamp(t, Some(t)),
            t + chrono::Duration::microseconds(1)
        );
        let later = t + chrono::Duration::seconds(1);
        assert_eq!(chain_timestamp(later, Some(t)), later);
        assert_eq!(
            chain_timestamp(t, Some(later)),
            later + chrono::Duration::microseconds(1)
        );
    }

    /// NIST-015: a bumped record keeps its original event time in
    /// `details.occurred_at`; an unbumped one is unchanged.
    #[test]
    fn apply_chain_timestamp_preserves_original_time() {
        use chrono::SubsecRound;
        let t = chrono::Utc::now().trunc_subsecs(6);
        let build = || {
            AuditEventBuilder::new(
                EventType::System,
                "svc",
                "target",
                "act",
                EventOutcome::Success,
            )
            .build()
        };

        let mut later = build();
        later.timestamp = t + chrono::Duration::seconds(1);
        apply_chain_timestamp(&mut later, Some(t));
        assert_eq!(later.timestamp, t + chrono::Duration::seconds(1));
        assert!(later.details.is_none(), "unbumped record unchanged");

        // Head 3 s ahead (skew / lock wait): shifted by more than 1 µs.
        let head = t + chrono::Duration::seconds(3);
        let mut bumped = build();
        bumped.timestamp = t;
        apply_chain_timestamp(&mut bumped, Some(head));
        assert_eq!(bumped.timestamp, head + chrono::Duration::microseconds(1));
        let d = bumped.details.as_ref().expect("details");
        let occurred: chrono::DateTime<chrono::Utc> = d[OCCURRED_AT_DETAIL]
            .as_str()
            .expect("string")
            .parse()
            .expect("rfc3339");
        assert_eq!(occurred, t);

        // Existing object details are kept; occurred_at is sink-owned
        // (NIST-028): a caller value is moved to caller_occurred_at.
        let mut with = build();
        with.timestamp = t;
        with.details = Some(serde_json::json!({"k": 1, "occurred_at": "caller"}));
        apply_chain_timestamp(&mut with, Some(head));
        let d = with.details.as_ref().expect("details");
        assert_eq!(d["k"], 1);
        assert_eq!(
            d[OCCURRED_AT_DETAIL],
            t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        );
        assert_eq!(d[CALLER_OCCURRED_AT_DETAIL], "caller");

        // ... also on an unbumped record (no sink value at all).
        let mut unbumped = build();
        unbumped.timestamp = t + chrono::Duration::seconds(10);
        unbumped.details = Some(serde_json::json!({"occurred_at": "caller"}));
        apply_chain_timestamp(&mut unbumped, Some(head));
        let d = unbumped.details.as_ref().expect("details");
        assert!(d.get(OCCURRED_AT_DETAIL).is_none());
        assert_eq!(d[CALLER_OCCURRED_AT_DETAIL], "caller");

        // A caller value equal to the sink's is kept as is.
        let mut same = build();
        same.timestamp = t;
        let expected = t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        same.details = Some(serde_json::json!({ "occurred_at": expected }));
        apply_chain_timestamp(&mut same, Some(head));
        let d = same.details.as_ref().expect("details");
        assert_eq!(d[OCCURRED_AT_DETAIL], expected);
        assert!(d.get(CALLER_OCCURRED_AT_DETAIL).is_none());

        // Non-object details are wrapped.
        let mut scalar = build();
        scalar.timestamp = t;
        scalar.details = Some(serde_json::json!("note"));
        apply_chain_timestamp(&mut scalar, Some(head));
        let d = scalar.details.as_ref().expect("details");
        assert_eq!(d["details"], "note");
        assert!(d[OCCURRED_AT_DETAIL].is_string());
    }

    /// The memory sink applies the same rule (and the chain still verifies,
    /// i.e. occurred_at is covered by the hash).
    #[tokio::test]
    async fn memory_sink_records_occurred_at_when_bumped() {
        let sink = MemoryAuditSink::new();
        let created = chrono::Utc::now();
        for _ in 0..2 {
            let mut event = AuditEventBuilder::new(
                EventType::System,
                "svc",
                "target",
                "act",
                EventOutcome::Success,
            )
            .build();
            event.timestamp = created;
            sink.record(&mut event).await.unwrap();
        }
        assert!(sink.verify_integrity().await.unwrap());
        let events = sink.query_events(QueryCriteria::default()).await.unwrap();
        assert!(events[0].details.is_none());
        assert!(events[1].details.as_ref().expect("bumped")[OCCURRED_AT_DETAIL].is_string());
    }

    /// Provider whose `sign` blocks its thread (like a hung PKCS#11 call
    /// inside the async fn) before delegating to the software provider.
    struct BlockingSignProvider {
        inner: ostrich_crypto::software::SoftwareProvider,
        block_for: Duration,
    }

    #[async_trait]
    impl ostrich_crypto::CryptoProvider for BlockingSignProvider {
        async fn generate_key_pair(
            &self,
            key_type: ostrich_crypto::KeyType,
            label: &str,
            extractable: bool,
        ) -> ostrich_crypto::Result<ostrich_crypto::KeyHandle> {
            self.inner
                .generate_key_pair(key_type, label, extractable)
                .await
        }
        async fn sign(
            &self,
            key: &ostrich_crypto::KeyHandle,
            algorithm: ostrich_crypto::Algorithm,
            data: &[u8],
        ) -> ostrich_crypto::Result<Vec<u8>> {
            // Deliberately blocking: never yields to the runtime.
            std::thread::sleep(self.block_for);
            self.inner.sign(key, algorithm, data).await
        }
        async fn verify(
            &self,
            key: &ostrich_crypto::KeyHandle,
            algorithm: ostrich_crypto::Algorithm,
            data: &[u8],
            signature: &[u8],
        ) -> ostrich_crypto::Result<bool> {
            self.inner.verify(key, algorithm, data, signature).await
        }
        async fn export_public_key(
            &self,
            key: &ostrich_crypto::KeyHandle,
        ) -> ostrich_crypto::Result<Vec<u8>> {
            self.inner.export_public_key(key).await
        }
        async fn import_key(
            &self,
            key_type: ostrich_crypto::KeyType,
            private_key: zeroize::Zeroizing<Vec<u8>>,
            label: &str,
        ) -> ostrich_crypto::Result<ostrich_crypto::KeyHandle> {
            self.inner.import_key(key_type, private_key, label).await
        }
        async fn destroy_key(&self, key: &ostrich_crypto::KeyHandle) -> ostrich_crypto::Result<()> {
            self.inner.destroy_key(key).await
        }
        async fn wrap_key(
            &self,
            key_to_wrap: &ostrich_crypto::KeyHandle,
            wrapping_key: &ostrich_crypto::KeyHandle,
        ) -> ostrich_crypto::Result<Vec<u8>> {
            self.inner.wrap_key(key_to_wrap, wrapping_key).await
        }
        async fn unwrap_key(
            &self,
            wrapped_key: &[u8],
            unwrapping_key: &ostrich_crypto::KeyHandle,
            key_type: ostrich_crypto::KeyType,
            label: &str,
        ) -> ostrich_crypto::Result<ostrich_crypto::KeyHandle> {
            self.inner
                .unwrap_key(wrapped_key, unwrapping_key, key_type, label)
                .await
        }
        async fn generate_random_bytes(&self, len: usize) -> ostrich_crypto::Result<Vec<u8>> {
            self.inner.generate_random_bytes(len).await
        }
        fn provider_id(&self) -> ostrich_crypto::key::ProviderId {
            self.inner.provider_id()
        }
    }

    async fn blocking_signer_sink(block_for: Duration, sign_timeout: Duration) -> MemoryAuditSink {
        let provider = BlockingSignProvider {
            inner: ostrich_crypto::software::SoftwareProvider::new(),
            block_for,
        };
        let key = ostrich_crypto::CryptoProvider::generate_key_pair(
            &provider,
            ostrich_crypto::KeyType::EcP256,
            "audit-signing-key",
            false,
        )
        .await
        .expect("generate key");
        MemoryAuditSink::with_signer(
            std::sync::Arc::new(provider),
            key,
            ostrich_crypto::Algorithm::EcdsaP256Sha256,
            "audit-signing-key",
            sign_timeout,
        )
        .expect("ECDSA accepted")
    }

    fn system_event() -> AuditEvent {
        AuditEventBuilder::new(
            EventType::System,
            "svc",
            "target",
            "act",
            EventOutcome::Success,
        )
        .build()
    }

    /// SEC-013 / PQC-011: a signer that blocks its thread (hung HSM) cannot
    /// hold the append lock past the sign timeout. The sink returns
    /// `Error::Timeout` in time, writes nothing, and the next append (with
    /// the lock released) is not blocked behind the hung call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_timeout_fires_for_blocking_signer() {
        let sink =
            blocking_signer_sink(Duration::from_millis(1500), Duration::from_millis(200)).await;
        let started = std::time::Instant::now();
        let err = sink
            .record(&mut system_event())
            .await
            .expect_err("hung signer must fail closed");
        let elapsed = started.elapsed();
        assert!(matches!(err, Error::Timeout(_)), "got {err:?}");
        assert!(
            elapsed < Duration::from_secs(1),
            "timeout fired late: {elapsed:?}"
        );
        assert!(
            sink.query_events(QueryCriteria::default())
                .await
                .unwrap()
                .is_empty(),
            "nothing written on timeout"
        );
        // The lock was released: another append gets in (and also times out)
        // well before the first hung sign returns.
        let started = std::time::Instant::now();
        assert!(matches!(
            sink.record(&mut system_event()).await,
            Err(Error::Timeout(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// Same, on a current-thread runtime: the blocking sign runs on the
    /// blocking pool, so the single runtime thread still drives the timer.
    #[tokio::test(flavor = "current_thread")]
    async fn sign_timeout_fires_for_blocking_signer_current_thread() {
        let sink =
            blocking_signer_sink(Duration::from_millis(1500), Duration::from_millis(200)).await;
        let started = std::time::Instant::now();
        assert!(matches!(
            sink.record(&mut system_event()).await,
            Err(Error::Timeout(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A slow but finishing signer within the bound still signs the record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_sign_succeeds_within_timeout() {
        let sink = blocking_signer_sink(Duration::from_millis(10), Duration::from_secs(5)).await;
        let mut event = system_event();
        sink.record(&mut event).await.expect("signed");
        assert!(event.signature.is_some());
        assert_eq!(event.signing_key_id.as_deref(), Some("audit-signing-key"));
        assert!(sink.verify_integrity().await.unwrap());
    }

    /// The server-side idle backstop must outlast the client sign timeout,
    /// so the client normally gives up (and rolls back) first.
    #[test]
    fn idle_in_transaction_timeout_exceeds_sign_timeout() {
        let idle = Duration::from_millis(u64::from(
            ostrich_db::repository::AUDIT_CHAIN_IDLE_TIMEOUT_MS,
        ));
        assert!(idle > AUDIT_SIGN_TIMEOUT);
    }

    /// PQC-012: SLH-DSA audit signing is refused at construction.
    #[test]
    fn slh_dsa_audit_signing_is_refused() {
        use ostrich_crypto::Algorithm as A;
        for alg in [
            A::SlhDsaSha2_128s,
            A::SlhDsaSha2_128f,
            A::SlhDsaSha2_192s,
            A::SlhDsaSha2_192f,
            A::SlhDsaSha2_256s,
            A::SlhDsaSha2_256f,
        ] {
            assert!(
                matches!(ensure_audit_signing_algorithm(alg), Err(Error::Signing(_))),
                "{alg} must be refused"
            );
        }
        for alg in [
            A::EcdsaP256Sha256,
            A::EcdsaP384Sha384,
            A::Ed25519,
            A::MlDsa44,
            A::MlDsa65,
            A::MlDsa87,
            A::RsaPkcs1Sha256,
        ] {
            assert!(ensure_audit_signing_algorithm(alg).is_ok(), "{alg}");
        }
    }

    #[tokio::test]
    async fn test_memory_sink_query() {
        let sink = MemoryAuditSink::new();

        // Record events
        for i in 0..5 {
            let mut event = AuditEventBuilder::new(
                EventType::Authentication,
                format!("user{}", i),
                "system",
                "login",
                EventOutcome::Success,
            )
            .build();

            sink.record(&mut event).await.unwrap();
        }

        // Query all events
        let criteria = QueryCriteria::default();
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 5);

        // Query by actor
        let criteria = QueryCriteria {
            actor: Some("user2".to_string()),
            ..Default::default()
        };
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user2");
    }
}
