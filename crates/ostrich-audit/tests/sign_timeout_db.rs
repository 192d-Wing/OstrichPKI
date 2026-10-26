//! Live test: a hung audit signer cannot hold the audit chain lock
//! (SEC-013 / PQC-011).
//!
//! The signer's `sign` blocks its thread (as a hung PKCS#11 call does inside
//! the async fn). `DatabaseAuditSink::record` must return `Error::Timeout`
//! after `AUDIT_SIGN_TIMEOUT`, roll back, and release the advisory lock, so
//! the next writer appends at once while the hung call is still blocked.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-5 (Response to Audit Processing Failures), AU-9(3), SA-11
//! - NIAP PP-CA: FAU_STG.4
//!
//! Opt-in: requires `OSTRICH_DB_TESTS=1` and a reachable DATABASE_URL whose
//! database name contains `test`; skipped otherwise, fails if opted in and
//! the database is unusable. See `tests/common/mod.rs`. Does not TRUNCATE.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ostrich_audit::sink::AUDIT_SIGN_TIMEOUT;
use ostrich_audit::{
    AuditEventBuilder, AuditSink, DatabaseAuditSink, Error, EventOutcome, EventType,
};
use ostrich_crypto::{
    Algorithm, CryptoProvider, KeyHandle, KeyType, key::ProviderId, software::SoftwareProvider,
};

mod common;

/// Blocks the calling thread in `sign` before delegating.
struct BlockingSignProvider {
    inner: SoftwareProvider,
    block_for: Duration,
}

#[async_trait]
impl CryptoProvider for BlockingSignProvider {
    async fn generate_key_pair(
        &self,
        key_type: KeyType,
        label: &str,
        extractable: bool,
    ) -> ostrich_crypto::Result<KeyHandle> {
        self.inner
            .generate_key_pair(key_type, label, extractable)
            .await
    }
    async fn sign(
        &self,
        key: &KeyHandle,
        algorithm: Algorithm,
        data: &[u8],
    ) -> ostrich_crypto::Result<Vec<u8>> {
        std::thread::sleep(self.block_for);
        self.inner.sign(key, algorithm, data).await
    }
    async fn verify(
        &self,
        key: &KeyHandle,
        algorithm: Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> ostrich_crypto::Result<bool> {
        self.inner.verify(key, algorithm, data, signature).await
    }
    async fn export_public_key(&self, key: &KeyHandle) -> ostrich_crypto::Result<Vec<u8>> {
        self.inner.export_public_key(key).await
    }
    async fn import_key(
        &self,
        key_type: KeyType,
        private_key: zeroize::Zeroizing<Vec<u8>>,
        label: &str,
    ) -> ostrich_crypto::Result<KeyHandle> {
        self.inner.import_key(key_type, private_key, label).await
    }
    async fn destroy_key(&self, key: &KeyHandle) -> ostrich_crypto::Result<()> {
        self.inner.destroy_key(key).await
    }
    async fn wrap_key(
        &self,
        key_to_wrap: &KeyHandle,
        wrapping_key: &KeyHandle,
    ) -> ostrich_crypto::Result<Vec<u8>> {
        self.inner.wrap_key(key_to_wrap, wrapping_key).await
    }
    async fn unwrap_key(
        &self,
        wrapped_key: &[u8],
        unwrapping_key: &KeyHandle,
        key_type: KeyType,
        label: &str,
    ) -> ostrich_crypto::Result<KeyHandle> {
        self.inner
            .unwrap_key(wrapped_key, unwrapping_key, key_type, label)
            .await
    }
    async fn generate_random_bytes(&self, len: usize) -> ostrich_crypto::Result<Vec<u8>> {
        self.inner.generate_random_bytes(len).await
    }
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }
}

fn event(actor: &str) -> ostrich_audit::AuditEvent {
    AuditEventBuilder::new(
        EventType::System,
        actor,
        "audit-sign-timeout",
        "probe",
        EventOutcome::Success,
    )
    .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hung_signer_times_out_and_releases_the_chain_lock() {
    let Some(pool) = common::connect_test_db(module_path!()).await else {
        return;
    };
    let provider = BlockingSignProvider {
        inner: SoftwareProvider::new(),
        block_for: AUDIT_SIGN_TIMEOUT + Duration::from_secs(4),
    };
    let key = provider
        .generate_key_pair(KeyType::EcP256, "audit-signing-key", false)
        .await
        .expect("key");
    let hung = DatabaseAuditSink::with_signing_key(
        pool.clone(),
        Arc::new(provider),
        key,
        Algorithm::EcdsaP256Sha256,
        "audit-signing-key",
    )
    .expect("ECDSA accepted");

    let started = Instant::now();
    let err = hung
        .record(&mut event("hung-signer"))
        .await
        .expect_err("hung signer must fail closed");
    let elapsed = started.elapsed();
    assert!(matches!(err, Error::Timeout(_)), "got {err:?}");
    assert!(
        elapsed < AUDIT_SIGN_TIMEOUT + Duration::from_secs(2),
        "sign timeout fired late: {elapsed:?}"
    );

    // The hung sign is still blocked (for ~4 s more), but the lock is free.
    let started = Instant::now();
    DatabaseAuditSink::new(pool)
        .record(&mut event("next-writer"))
        .await
        .expect("next writer appends");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "next writer waited for the hung signer: {:?}",
        started.elapsed()
    );
}
