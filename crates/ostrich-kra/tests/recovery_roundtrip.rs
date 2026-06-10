//! KRA escrow -> recover round-trip (live, needs a database)
//!
//! Proves the M-of-N key-recovery workflow end to end: escrow a known private
//! key (AES-256-GCM under a fresh KEK, KEK Shamir-split into 5 shares),
//! initiate recovery, submit a threshold (3) of the shares, and recover the
//! ORIGINAL key bytes. Also checks that fewer than `threshold` shares cannot
//! recover (FDP_ACC.1 threshold enforcement).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Key Establishment), SC-12(1) (Availability via recovery)
//! - NIAP PP-CA: FCS_CKM.2 (Key Distribution via shares), FCS_CKM.4 (zeroization)
//! - NIST 800-53: SA-11 (Developer Security Testing)
//!
//! Run with a live DB (the certificates table must have at least one row, since
//! escrowed_keys.certificate_id is a FK):
//!   DATABASE_URL=postgres://... \
//!     cargo test -p ostrich-kra --test recovery_roundtrip -- --ignored --nocapture

use std::sync::Arc;

use ostrich_audit::MemoryAuditSink;
use ostrich_crypto::software::SoftwareProvider;
use ostrich_db::{DatabasePool, PoolConfig, Uuid};
use ostrich_kra::{KeyEscrow, KeyEscrowRequest, KeyRecovery, RecoveryRequest};

async fn connect() -> DatabasePool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let config = PoolConfig::from_url(&url).expect("valid DATABASE_URL");
    DatabasePool::new(&config).await.expect("db connect")
}

#[tokio::test]
#[ignore] // needs a live database with at least one certificate
async fn escrow_recover_roundtrip() {
    let pool = connect().await;

    // escrowed_keys.certificate_id is a FK -> use a real certificate.
    let cert_id: Uuid =
        ostrich_db::sqlx::query_scalar("SELECT id FROM certificates ORDER BY created_at DESC LIMIT 1")
            .fetch_one(pool.pool())
            .await
            .expect("the test DB needs at least one certificate row");

    let crypto = Arc::new(SoftwareProvider::new());
    let audit = Arc::new(MemoryAuditSink::new());

    // The "private key" can be arbitrary bytes - escrow wraps them opaquely.
    let original_key =
        b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg... test material ...\n-----END PRIVATE KEY-----"
            .to_vec();

    // 1. Escrow: 3-of-5 (initiate_recovery currently assumes 3-of-5).
    let escrow = KeyEscrow::new(pool.clone(), crypto.clone(), audit.clone());
    let (escrowed, shares) = escrow
        .escrow_key(KeyEscrowRequest {
            private_key: original_key.clone(),
            certificate_id: cert_id,
            subject_dn: "CN=recovery-test".to_string(),
            key_type: "RSA".to_string(),
            num_agents: 5,
            threshold: 3,
            requestor: "kra-admin".to_string(),
            justification: "round-trip test".to_string(),
        })
        .await
        .expect("escrow_key");
    assert_eq!(shares.len(), 5, "5 shares must be returned for distribution");
    println!("[escrow] escrow_id={} shares={}", escrowed.id, shares.len());

    // 2. Initiate recovery for this escrow.
    let recovery = KeyRecovery::new(pool.clone(), crypto, audit);
    let session = recovery
        .initiate_recovery(RecoveryRequest {
            escrow_id: escrowed.id,
            requestor: "recovery-agent".to_string(),
            justification: "emergency recovery".to_string(),
            approved_by: Some("kra-manager".to_string()),
        })
        .await
        .expect("initiate_recovery");
    println!("[recovery] session={}", session.id);

    // 3. Fewer than threshold shares must NOT recover (FDP_ACC.1).
    assert!(
        recovery
            .complete_recovery(session.id, shares[0..2].to_vec(), 3)
            .await
            .is_err(),
        "2 of 3 shares must be insufficient"
    );

    // 4. Threshold shares recover the ORIGINAL key bytes.
    let recovered = recovery
        .complete_recovery(session.id, shares[0..3].to_vec(), 3)
        .await
        .expect("complete_recovery with 3 shares");
    assert_eq!(
        recovered.as_slice(),
        original_key.as_slice(),
        "recovered key must byte-match the escrowed key"
    );
    println!("[recovery] recovered {} bytes, byte-identical to escrow", recovered.len());

    // 5. A DIFFERENT subset of 3 shares also recovers (any threshold works).
    let recovered2 = recovery
        .complete_recovery(session.id, shares[2..5].to_vec(), 3)
        .await
        .expect("complete_recovery with a different 3 shares");
    assert_eq!(recovered2.as_slice(), original_key.as_slice());
    println!("=== KRA escrow -> recover round-trip PASSED ===");
}
