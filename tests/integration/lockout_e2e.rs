//! DB-authoritative account-lockout integration test (real Postgres).
//!
//! Evidence that lockout state is persisted and enforced from the database (the
//! single source of truth after the AuthLockout reconcile): a temporary lock
//! set by failed attempts is visible to a *fresh* repository instance (i.e.
//! survives a restart / is shared across instances), and the permanent-lockout
//! escalation moves the account to status='locked'.
//!
//! Gated on `DATABASE_URL`; skips when unset.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-7 (Unsuccessful Logon Attempts)
//! - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)

use ostrich_common::auth::{LockoutPolicy, UserRepository};
use ostrich_db::repository::DbUserRepository;
use ostrich_db::{DatabasePool, PoolConfig};
use uuid::Uuid;

async fn pool_or_skip(test: &str) -> Option<DatabasePool> {
    let Ok(db_url) = std::env::var("DATABASE_URL") else {
        eprintln!("{test}: set DATABASE_URL to run; skipping");
        return None;
    };
    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .expect("connect to DATABASE_URL");
    pool.migrate().await.expect("run migrations");
    Some(pool)
}

async fn make_user(pool: &DatabasePool) -> String {
    let username = format!("lockout-e2e-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO users (username, password_hash, roles, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(&username)
    .bind("$argon2id$placeholder$not-a-real-hash")
    .bind(vec!["administrator".to_string()])
    .execute(pool.pool())
    .await
    .expect("insert test user");
    username
}

async fn cleanup(pool: &DatabasePool, username: &str) {
    sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(username)
        .execute(pool.pool())
        .await
        .expect("cleanup test user");
}

/// Force a temporary lock to look expired, so the next failure starts a new
/// lockout episode (as it would after the lock period elapses in production).
async fn expire_lock(pool: &DatabasePool, username: &str) {
    sqlx::query("UPDATE users SET locked_until = NOW() - INTERVAL '1 minute' WHERE username = $1")
        .bind(username)
        .execute(pool.pool())
        .await
        .expect("expire lock");
}

/// A temporary lock set by failed attempts is persisted and visible to a fresh
/// repository instance (survives restart / shared across instances), and is
/// cleared by reset.
#[tokio::test]
async fn temporary_lockout_persists() {
    let Some(pool) = pool_or_skip("temporary_lockout_persists").await else {
        return;
    };
    let username = make_user(&pool).await;
    let repo = DbUserRepository::new(pool.clone());
    let policy = LockoutPolicy {
        max_attempts: 3,
        lockout_secs: 900,
        permanent_after: None,
    };

    // First two failures: below threshold, not locked.
    for _ in 0..2 {
        let outcome = repo
            .record_failed_attempt(&username, policy)
            .await
            .expect("record");
        assert!(!outcome.now_locked, "should not lock before the threshold");
    }
    // Third failure crosses the threshold.
    let outcome = repo
        .record_failed_attempt(&username, policy)
        .await
        .expect("record");
    assert!(outcome.now_locked && !outcome.now_permanent);

    // A brand-new repository over the same DB still sees the lock.
    let fresh = DbUserRepository::new(pool.clone());
    let account = fresh
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("present");
    assert!(account.is_locked(), "temporary lock must persist");

    // Reset clears the lock.
    fresh
        .reset_failed_attempts(&username)
        .await
        .expect("reset");
    let account = fresh
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("present");
    assert!(!account.is_locked(), "reset must clear the lock");

    cleanup(&pool, &username).await;
}

/// After the configured number of lockout episodes, the account escalates to a
/// permanent (status='locked') lock, and reset lifts it.
#[tokio::test]
async fn permanent_lockout_escalates() {
    let Some(pool) = pool_or_skip("permanent_lockout_escalates").await else {
        return;
    };
    let username = make_user(&pool).await;
    let repo = DbUserRepository::new(pool.clone());
    let policy = LockoutPolicy {
        max_attempts: 2,
        lockout_secs: 900,
        permanent_after: Some(2),
    };

    // Episode 1: two failures -> temporary lock, escalation count = 1.
    repo.record_failed_attempt(&username, policy).await.unwrap();
    let o = repo.record_failed_attempt(&username, policy).await.unwrap();
    assert!(o.now_locked && !o.now_permanent, "first episode is temporary");

    // Simulate the lock elapsing, then a further failure starts episode 2 and
    // reaches the permanent threshold.
    expire_lock(&pool, &username).await;
    let o = repo.record_failed_attempt(&username, policy).await.unwrap();
    assert!(o.now_permanent, "second episode must escalate to permanent");

    let account = repo
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("present");
    assert!(account.is_locked(), "permanently locked account is locked");

    // Admin unlock (reset) lifts the permanent lock back to active.
    repo.reset_failed_attempts(&username).await.unwrap();
    let account = repo
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("present");
    assert!(!account.is_locked(), "reset lifts the permanent lock");

    cleanup(&pool, &username).await;
}
