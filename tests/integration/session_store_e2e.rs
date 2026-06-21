//! DbSessionStore round-trip integration test against a real Postgres.
//!
//! This is the durability evidence for the session-persistence work: it proves
//! a session created by one `SessionManager` is honoured by a brand-new manager
//! over the same database (i.e. survives a process restart), and that
//! termination likewise persists. It also exercises the raw `SessionStore` CRUD
//! surface end to end.
//!
//! Gated on `DATABASE_URL`; the test no-ops (skips) when it is unset, matching
//! the other DB-backed integration tests. The schema is provisioned by
//! `pool.migrate()`, so a bare empty database is sufficient.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-12 (Session Termination), SC-23 (Session Authenticity)
//! - NIAP PP-CA: FTA_SSL.3 / FTA_SSL.4 - termination persisted across a restart

use std::sync::Arc;

use ostrich_common::auth::{
    Session, SessionConfig, SessionError, SessionManager, SessionStatus, SessionStore,
};
use ostrich_db::repository::DbSessionStore;
use ostrich_db::{DatabasePool, PoolConfig};
use uuid::Uuid;

/// Open the pool and apply migrations, or return `None` when `DATABASE_URL` is
/// unset so the test can skip cleanly.
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

/// Insert a uniquely-named user (the `sessions.user_id` FK target) and return
/// its username. The placeholder password hash satisfies `chk_users_auth_method`.
async fn make_user(pool: &DatabasePool) -> String {
    let username = format!("sess-e2e-{}", Uuid::new_v4());
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

/// Remove the test user; `sessions.user_id` is `ON DELETE CASCADE`, so this also
/// drops every session created for that user.
async fn cleanup(pool: &DatabasePool, username: &str) {
    sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(username)
        .execute(pool.pool())
        .await
        .expect("cleanup test user");
}

fn store(pool: &DatabasePool) -> SessionManager {
    SessionManager::with_store(
        SessionConfig::default(),
        Arc::new(DbSessionStore::new(pool.clone())),
    )
}

/// A session created by one manager is valid when looked up by a fresh manager
/// over the same database -- i.e. it survives a process restart.
#[tokio::test]
async fn session_survives_manager_restart() {
    let Some(pool) = pool_or_skip("session_survives_manager_restart").await else {
        return;
    };
    let username = make_user(&pool).await;

    // "Process 1" creates the session, then goes away.
    let mgr1 = store(&pool);
    let created = mgr1
        .create_session(&username, Some("198.51.100.7".to_string()), None) // RFC 5737 TEST-NET-2
        .await
        .expect("create session");
    drop(mgr1);

    // "Process 2": a brand-new manager + store over the same pool.
    let mgr2 = store(&pool);
    let validated = mgr2
        .validate_session(&created.token)
        .await
        .expect("token still valid after restart");

    assert_eq!(validated.id, created.id);
    assert_eq!(validated.user_id, username);
    assert_eq!(validated.status, SessionStatus::Active);
    assert_eq!(validated.ip_address.as_deref(), Some("198.51.100.7"));

    cleanup(&pool, &username).await;
}

/// Termination is persisted: after logout (terminate), a fresh manager rejects
/// the token rather than honouring it (AC-12 / FTA_SSL.4).
#[tokio::test]
async fn termination_survives_manager_restart() {
    let Some(pool) = pool_or_skip("termination_survives_manager_restart").await else {
        return;
    };
    let username = make_user(&pool).await;

    let mgr1 = store(&pool);
    let created = mgr1
        .create_session(&username, None, None)
        .await
        .expect("create session");
    mgr1.terminate_session(&created.id)
        .await
        .expect("terminate session");
    drop(mgr1);

    let mgr2 = store(&pool);
    let result = mgr2.validate_session(&created.token).await;
    assert!(
        matches!(result, Err(SessionError::SessionTerminated)),
        "expected SessionTerminated after restart, got {result:?}"
    );

    cleanup(&pool, &username).await;
}

/// Exercise the raw `SessionStore` CRUD surface: create, fetch by token and id,
/// list active for a user, update a mutated field, and reap by absolute expiry.
#[tokio::test]
async fn store_crud_round_trip() {
    let Some(pool) = pool_or_skip("store_crud_round_trip").await else {
        return;
    };
    let username = make_user(&pool).await;
    let st = DbSessionStore::new(pool.clone());

    // create + read back by token and by id
    let session = Session::new(&username, None, None, &SessionConfig::default());
    st.create(&session).await.expect("create");

    let by_token = st
        .get_by_token(&session.token)
        .await
        .expect("get_by_token")
        .expect("present");
    assert_eq!(by_token.id, session.id);
    assert_eq!(by_token.user_id, username);

    let by_id = st
        .get_by_id(&session.id)
        .await
        .expect("get_by_id")
        .expect("present");
    assert_eq!(by_id.token, session.token);

    // list_active_for_user contains it
    let active = st
        .list_active_for_user(&username)
        .await
        .expect("list_active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, session.id);

    // update a mutable field (status -> Locked) and confirm it persists
    let mut locked = by_id;
    locked.status = SessionStatus::Locked;
    st.update(&locked).await.expect("update");
    let reread = st
        .get_by_id(&session.id)
        .await
        .expect("get_by_id")
        .expect("present");
    assert_eq!(reread.status, SessionStatus::Locked);
    // a locked session is no longer "active" but is still listed (active OR locked)
    let active_after = st
        .list_active_for_user(&username)
        .await
        .expect("list_active");
    assert_eq!(active_after.len(), 1);

    // delete_expired: force this session past its absolute expiry, then reap it.
    // Age created_at too, so expires_at stays after created_at
    // (chk_sessions_expires_after_created) while both fall in the past.
    sqlx::query(
        "UPDATE sessions \
         SET created_at = NOW() - INTERVAL '2 hours', \
             expires_at = NOW() - INTERVAL '1 hour' \
         WHERE id = $1",
    )
    .bind(session.id)
    .execute(pool.pool())
    .await
    .expect("age the session");
    let removed = st.delete_expired().await.expect("delete_expired");
    assert!(removed >= 1, "expected to reap at least our expired session");
    assert!(
        st.get_by_id(&session.id).await.expect("get_by_id").is_none(),
        "expired session should be gone"
    );

    cleanup(&pool, &username).await;
}

/// A stale activity-touch (non-terminal status) must not overwrite a session
/// that was terminated concurrently -- the DB store's guard keeps a terminated
/// token dead (AC-12). Also confirms the reaper removes terminated rows.
#[tokio::test]
async fn store_guards_against_resurrection_and_reaps_terminated() {
    let Some(pool) = pool_or_skip("store_guards_against_resurrection_and_reaps_terminated").await
    else {
        return;
    };
    let username = make_user(&pool).await;
    let st = DbSessionStore::new(pool.clone());

    let mut session = Session::new(&username, None, None, &SessionConfig::default());
    st.create(&session).await.expect("create");

    // Terminate, then replay a stale Active snapshot (as a racing touch would).
    session.status = SessionStatus::AdminTerminated;
    st.update(&session).await.expect("terminate");

    let mut revive = session.clone();
    revive.status = SessionStatus::Active;
    revive.token = session.token.clone();
    st.update(&revive).await.expect("stale update is a no-op, not an error");

    let after = st
        .get_by_id(&session.id)
        .await
        .expect("get_by_id")
        .expect("still present");
    assert_eq!(
        after.status,
        SessionStatus::AdminTerminated,
        "terminated session must not be resurrected by a stale update"
    );

    // The reaper removes the terminated row even though it has not yet expired.
    let removed = st.delete_expired().await.expect("delete_expired");
    assert!(removed >= 1, "expected the terminated session to be reaped");
    assert!(
        st.get_by_id(&session.id).await.expect("get_by_id").is_none(),
        "terminated session should be reaped"
    );

    cleanup(&pool, &username).await;
}
