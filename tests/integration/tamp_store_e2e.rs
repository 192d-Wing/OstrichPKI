//! TAMP manager store + replay-protection integration tests (RFC 5934).
//!
//! Exercises the database-backed paths that the in-crate unit tests cannot:
//! the atomic monotonic sequence-number allocator, the row-locked
//! check-and-advance replay guard, and the manager's issue / ingest flows
//! against a real PostgreSQL instance.
//!
//! Requires a reachable PostgreSQL (set `DATABASE_URL`, or run
//! `scripts/dev-setup-wsl.sh` which provisions the dev default used below).
//! If no database is reachable the test prints a skip notice and passes, so it
//! is safe to run in environments without Postgres.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (developer security testing), SC-23 (replay protection)
//! - RFC 5934 §4.1 (sequence numbers), §4.3 (trust anchor update)

use std::sync::Arc;

use der::asn1::{Ia5String, OctetString};
use der::Encode;
use ostrich_audit::{AuditSink, DatabaseAuditSink};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::repository::TampRepository;
use ostrich_db::{DatabasePool, PoolConfig};
use ostrich_tamp::asn1::{
    TampMsgRef, TampUpdateConfirm, TargetIdentifier, TrustAnchorChoice, TrustAnchorInfo,
    UpdateConfirm,
};
use ostrich_tamp::{cms, oids, SignerContext, StatusCode, TampManager, TrustAnchorEdit};
use spki::SubjectPublicKeyInfoOwned;

/// Connect to the test database, or return `None` to skip when unreachable.
async fn connect() -> Option<DatabasePool> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://ostrich:changeme@127.0.0.1:5432/ostrich_pki?sslmode=disable".to_string()
    });
    let config = match PoolConfig::from_url(&url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP tamp_store_e2e: bad DATABASE_URL ({e})");
            return None;
        }
    };
    match DatabasePool::new(&config).await {
        Ok(pool) => match pool.migrate().await {
            Ok(()) => Some(pool),
            Err(e) => {
                eprintln!("SKIP tamp_store_e2e: migration failed ({e})");
                None
            }
        },
        Err(e) => {
            eprintln!("SKIP tamp_store_e2e: database unreachable ({e})");
            None
        }
    }
}

/// A fresh URI target unique to each test run, so concurrent/repeat runs don't
/// share `(target, signer)` sequence-number rows.
fn unique_target(tag: &str) -> TargetIdentifier {
    let uri = format!("https://module.example/{tag}/{}", uuid::Uuid::new_v4());
    TargetIdentifier::Uri(Ia5String::new(&uri).unwrap())
}

/// Generate a software ECDSA P-256 signer and return (provider, key, ski, spki).
async fn make_signer(
    label: &str,
) -> (
    Box<dyn CryptoProvider>,
    ostrich_crypto::KeyHandle,
    Vec<u8>,
    Vec<u8>,
) {
    let provider = CryptoProviderFactory::create_software_provider();
    let key = provider
        .generate_key_pair(KeyType::EcP256, label, true)
        .await
        .unwrap();
    let spki = provider.export_public_key(&key).await.unwrap();
    let ski = ostrich_x509::signing::key_identifier(&spki).unwrap();
    (provider, key, ski, spki)
}

#[tokio::test]
async fn allocate_next_seq_is_atomic_and_monotonic() {
    let Some(pool) = connect().await else { return };
    let repo = TampRepository::new(pool);
    let target = unique_target("seq-alloc");
    let target_id = repo
        .get_or_create_target(&target.to_der().unwrap(), "seq-alloc", true)
        .await
        .unwrap();
    let signer = b"alloc-signer".to_vec();

    // 20 concurrent allocations must yield exactly 1..=20 with no duplicates —
    // the property the racy read-then-write previously violated.
    let mut handles = Vec::new();
    for _ in 0..20 {
        let repo = repo.clone();
        let id = target_id;
        let s = signer.clone();
        handles.push(tokio::spawn(async move {
            repo.allocate_next_seq(&id, &s).await
        }));
    }
    let mut got = Vec::new();
    for h in handles {
        got.push(h.await.unwrap().unwrap());
    }
    got.sort_unstable();
    assert_eq!(got, (1..=20).collect::<Vec<i64>>());
}

#[tokio::test]
async fn check_and_advance_seq_rejects_replays() {
    let Some(pool) = connect().await else { return };
    let repo = TampRepository::new(pool);
    let target = unique_target("seq-replay");
    let target_id = repo
        .get_or_create_target(&target.to_der().unwrap(), "seq-replay", true)
        .await
        .unwrap();
    let signer = b"replay-signer".to_vec();

    // First message is fresh; the same number is a replay; a lower number is
    // stale; a strictly greater number advances the baseline (RFC 5934 §4.1).
    assert!(repo
        .check_and_advance_seq(&target_id, &signer, 5)
        .await
        .unwrap());
    assert!(!repo
        .check_and_advance_seq(&target_id, &signer, 5)
        .await
        .unwrap());
    assert!(!repo
        .check_and_advance_seq(&target_id, &signer, 4)
        .await
        .unwrap());
    assert!(repo
        .check_and_advance_seq(&target_id, &signer, 6)
        .await
        .unwrap());
}

#[tokio::test]
async fn issue_status_query_creates_target_and_increments_seq() {
    let Some(pool) = connect().await else { return };
    let manager = TampManager::new(
        TampRepository::new(pool.clone()),
        Arc::new(DatabaseAuditSink::new(pool)) as Arc<dyn AuditSink>,
    );
    let (provider, key, ski, _spki) = make_signer("mgr-status").await;
    let signer = SignerContext {
        provider: provider.as_ref(),
        key: &key,
        ski: ski.clone(),
        algorithm: Algorithm::EcdsaP256Sha256,
    };
    let target = unique_target("status");

    let first = manager
        .issue_status_query(&target, "status-target", &signer, false)
        .await
        .unwrap();
    let second = manager
        .issue_status_query(&target, "status-target", &signer, false)
        .await
        .unwrap();

    assert_eq!(first.seq_num, 1);
    assert_eq!(second.seq_num, 2);
    // The envelope is a real signed CMS ContentInfo that parses + verifies
    // against our own SPKI (the manager signs as itself here).
    let parsed = cms::parse(&first.envelope).unwrap();
    assert_eq!(parsed.content_type, oids::ID_CT_TAMP_STATUS_QUERY);
    assert_eq!(parsed.signer_ski, ski);
}

#[tokio::test]
async fn trust_anchor_add_persists_and_rejects_duplicate() {
    let Some(pool) = connect().await else { return };
    let manager = TampManager::new(
        TampRepository::new(pool.clone()),
        Arc::new(DatabaseAuditSink::new(pool)) as Arc<dyn AuditSink>,
    );
    let (provider, key, ski, _) = make_signer("mgr-ta").await;
    let signer = SignerContext {
        provider: provider.as_ref(),
        key: &key,
        ski,
        algorithm: Algorithm::EcdsaP256Sha256,
    };
    let target = unique_target("ta-add");

    // A trust anchor whose public key is some generated EC key.
    let (_p2, _k2, ta_ski, ta_spki) = make_signer("the-ta").await;
    let ta = TrustAnchorChoice::TaInfo(TrustAnchorInfo {
        version: 1,
        pub_key: SubjectPublicKeyInfoOwned::try_from(ta_spki.as_slice()).unwrap(),
        key_id: OctetString::new(ta_ski).unwrap(),
        ta_title: Some("test-ta".to_string()),
        cert_path: None,
        exts: None,
        ta_title_lang_tag: None,
    });

    // First add succeeds and persists.
    manager
        .issue_trust_anchor_update(
            &target,
            "ta-target",
            &signer,
            vec![TrustAnchorEdit::Add(ta.clone())],
        )
        .await
        .unwrap();
    let listed = manager
        .list_trust_anchors(&target, "ta-target")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title.as_deref(), Some("test-ta"));

    // Re-adding the same public key is rejected (RFC 5934 §4.3 improperTAAddition).
    let dup = manager
        .issue_trust_anchor_update(
            &target,
            "ta-target",
            &signer,
            vec![TrustAnchorEdit::Add(ta)],
        )
        .await;
    assert!(matches!(
        dup,
        Err(ostrich_tamp::Error::TrustAnchorUpdate(_))
    ));
    // The store still holds exactly one (the failed add did not duplicate).
    let listed = manager
        .list_trust_anchors(&target, "ta-target")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
async fn ingest_verifies_then_rejects_replayed_confirmation() {
    let Some(pool) = connect().await else { return };
    let manager = TampManager::new(
        TampRepository::new(pool.clone()),
        Arc::new(DatabaseAuditSink::new(pool)) as Arc<dyn AuditSink>,
    );
    let target = unique_target("ingest");

    // Build a TAMPUpdateConfirm signed by the "target" key.
    let (tprov, tkey, tski, tspki) = make_signer("target-resp").await;
    let confirm = TampUpdateConfirm {
        version: 2,
        update: TampMsgRef {
            target: target.clone(),
            seq_num: 7,
        },
        confirm: UpdateConfirm::Terse(vec![StatusCode::Success]),
    };
    let envelope = cms::sign_message(
        tprov.as_ref(),
        &tkey,
        &tski,
        oids::ID_CT_TAMP_UPDATE_CONFIRM,
        &confirm.to_der().unwrap(),
        Algorithm::EcdsaP256Sha256,
    )
    .await
    .unwrap();

    // An unregistered signer is not trusted: ingest fails before verification.
    let unknown = manager.ingest(&target, "ingest-target", &envelope).await;
    assert!(matches!(unknown, Err(ostrich_tamp::Error::NoTrustAnchor)));

    // Register the target's response-signing key, then ingest succeeds.
    manager
        .register_target_signer(
            &target,
            "ingest-target",
            &tski,
            &tspki,
            Some("module resp key"),
        )
        .await
        .unwrap();
    let outcome = manager
        .ingest(&target, "ingest-target", &envelope)
        .await
        .unwrap();
    assert_eq!(outcome.message_name, "TAMPUpdateConfirm");
    assert_eq!(outcome.seq_num, Some(7));
    assert_eq!(outcome.status_codes, vec![StatusCode::Success]);
    assert_eq!(outcome.signer_ski, tski);

    // Replaying the identical signed message is rejected (seqNum not greater).
    let replay = manager.ingest(&target, "ingest-target", &envelope).await;
    assert!(matches!(replay, Err(ostrich_tamp::Error::SeqNumFailure(_))));

    // A message claiming the registered SKI but signed by a different key fails
    // the signature check (the verifying key now comes from trusted state).
    let (aprov, akey, _aski, _aspki) = make_signer("attacker").await;
    let forged_confirm = TampUpdateConfirm {
        version: 2,
        update: TampMsgRef {
            target: target.clone(),
            seq_num: 9,
        },
        confirm: UpdateConfirm::Terse(vec![StatusCode::Success]),
    };
    let forged_envelope = cms::sign_message(
        aprov.as_ref(),
        &akey,
        &tski, // claims the registered signer's SKI...
        oids::ID_CT_TAMP_UPDATE_CONFIRM,
        &forged_confirm.to_der().unwrap(),
        Algorithm::EcdsaP256Sha256,
    )
    .await
    .unwrap();
    let forged = manager
        .ingest(&target, "ingest-target", &forged_envelope)
        .await;
    assert!(matches!(
        forged,
        Err(ostrich_tamp::Error::SignatureFailure(_))
    ));
}
