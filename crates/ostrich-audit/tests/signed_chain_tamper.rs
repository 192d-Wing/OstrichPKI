//! Live tamper-detection test for signed audit records (AU-10 non-repudiation).
//!
//! Proves the property that motivates record signing: the SHA-256 hash chain
//! alone is NOT tamper-evident against an attacker with database write access,
//! because they can recompute a record's `event_hash` to match modified content.
//! Signing each record's `event_hash` closes that gap — the attacker cannot
//! forge the signature, so `verify_signed_chain` catches the modification even
//! though the hash-only `verify_chain` is fooled.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-10 (Non-repudiation), AU-9(3) (Cryptographic protection)
//! - NIAP PP-CA: FAU_STG.4 (Prevention of undetected audit modification)
//!
//! Requires a Postgres reachable via DATABASE_URL with the audit_events table
//! (migrations 0000x + 00007). Skips (passes) if DATABASE_URL is unset.

use std::sync::Arc;

use ostrich_audit::{AuditEventBuilder, AuditSink, DatabaseAuditSink, EventOutcome, EventType};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyType, software::SoftwareProvider};
use ostrich_db::{DatabasePool, PoolConfig};

const ALGO: Algorithm = Algorithm::EcdsaP256Sha256;

async fn connect() -> Option<DatabasePool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let config = PoolConfig::from_url(&url).expect("valid DATABASE_URL");
    Some(DatabasePool::new(&config).await.expect("connect to test DB"))
}

/// Remove every audit row so the chain starts clean for this test run.
async fn truncate_audit(pool: &DatabasePool) {
    sqlx::query("TRUNCATE TABLE audit_events")
        .execute(pool.pool())
        .await
        .expect("truncate audit_events");
}

#[tokio::test]
async fn signature_catches_tamper_that_hash_chain_misses() {
    let Some(pool) = connect().await else {
        eprintln!("DATABASE_URL not set; skipping signed-chain tamper test");
        return;
    };
    truncate_audit(&pool).await;

    // ECDSA P-256 signing key in the software provider. (The provider's RSA
    // PKCS#1 path emits unprefixed signatures that ring's verify_with_spki
    // rejects; ECDSA round-trips cleanly as raw fixed r||s.)
    let crypto: Arc<dyn CryptoProvider> = Arc::new(SoftwareProvider::new());
    let key = crypto
        .generate_key_pair(KeyType::EcP256, "audit-signing-key", true)
        .await
        .expect("generate audit signing key");
    let spki = crypto
        .export_public_key(&key)
        .await
        .expect("export audit public key");

    let sink =
        DatabaseAuditSink::with_signing_key(pool.clone(), crypto, key, ALGO, "audit-signing-key");

    // Write a few signed events.
    for i in 0..3 {
        let mut ev = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            format!("ca-service-{i}"),
            format!("cert-{i}"),
            "issue",
            EventOutcome::Success,
        )
        .build();
        sink.record(&mut ev).await.expect("record signed event");
    }

    // Untampered: both the hash chain and the signatures verify.
    assert!(
        sink.verify_integrity().await.unwrap(),
        "hash chain should verify before tampering"
    );
    assert!(
        sink.verify_signed_chain(&spki, ALGO).await.unwrap(),
        "signed chain should verify before tampering"
    );

    // --- Attacker rewrites the LAST record's content AND recomputes its hash. ---
    // Tampering the last record avoids breaking the next record's previous_hash
    // link, so the hash-only chain stays internally consistent. We recompute the
    // event_hash exactly as the repository would (so verify_chain is fooled), but
    // we CANNOT re-sign it — the old signature is left in place.
    let row = sqlx::query_as::<_, ostrich_db::models::AuditEvent>(
        "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(pool.pool())
    .await
    .expect("fetch last audit row");

    // Recompute event_hash for the forged actor using the SAME field order as
    // the repository's verifier (id, type, actor, target, action, outcome, ...,
    // previous_hash, timestamp). Build an audit-layer event mirroring the row.
    let forged_actor = "attacker-elevated-admin";
    let forged_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(row.id.as_bytes());
        h.update(row.event_type.as_bytes());
        h.update(forged_actor.as_bytes());
        h.update(row.target.as_bytes());
        h.update(row.action.as_bytes());
        h.update(row.outcome.as_bytes());
        if let Some(details) = &row.details
            && let Ok(s) = serde_json::to_string(details)
        {
            h.update(s.as_bytes());
        }
        if let Some(ip) = &row.ip_address {
            h.update(ip.as_bytes());
        }
        if let Some(ua) = &row.user_agent {
            h.update(ua.as_bytes());
        }
        if let Some(sid) = &row.session_id {
            h.update(sid.as_bytes());
        }
        if let Some(prev) = &row.previous_hash {
            h.update(prev);
        }
        h.update(row.timestamp.to_rfc3339().as_bytes());
        h.finalize().to_vec()
    };

    // Apply the forgery directly (simulating DB write access): change the actor
    // and the recomputed event_hash, but leave the (now-stale) signature.
    sqlx::query("UPDATE audit_events SET actor = $1, event_hash = $2 WHERE id = $3")
        .bind(forged_actor)
        .bind(&forged_hash)
        .bind(row.id)
        .execute(pool.pool())
        .await
        .expect("apply forgery");

    // The hash-only chain is FOOLED: content and recomputed hash are consistent,
    // and the last record's change doesn't break any subsequent previous_hash.
    assert!(
        sink.verify_integrity().await.unwrap(),
        "hash-only chain should be fooled by the recomputed-hash forgery (this is the gap AU-10 closes)"
    );

    // The SIGNED chain CATCHES it: the stale signature was made over the original
    // event_hash and does not verify against the forged event_hash. AU-10.
    assert!(
        !sink.verify_signed_chain(&spki, ALGO).await.unwrap(),
        "signed chain MUST detect the forgery the hash chain missed (AU-10)"
    );

    // Clean up so the scratch DB doesn't carry a poisoned chain to other tests.
    truncate_audit(&pool).await;
}
