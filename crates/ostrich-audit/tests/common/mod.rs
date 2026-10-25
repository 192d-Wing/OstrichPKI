//! Shared opt-in gate for the Postgres-backed audit tests.
//!
//! These tests TRUNCATE `audit_events`, so they run only when explicitly
//! requested and only against a database whose name contains `test`:
//!
//! - without `OSTRICH_DB_TESTS=1` the test is skipped (passes, with a note);
//! - with `OSTRICH_DB_TESTS=1`, `DATABASE_URL` must be set, usable and
//!   reachable, or the test FAILS: an opted-in run that silently skipped
//!   would make a green CI job meaningless as evidence (NIST-024);
//! - `current_database()` must contain `test` (otherwise the test panics
//!   rather than truncate a non-test audit trail).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-9 (protection of audit information: tests never
//!   truncate a non-test audit trail), SA-11, CA-2 (assessment evidence)

use ostrich_db::{DatabasePool, PoolConfig};
use std::time::Duration;

/// Connect to the opted-in test database. `None` (skip) only when
/// `OSTRICH_DB_TESTS=1` is not set; once opted in, any connection problem
/// panics so the test fails.
pub async fn connect_test_db(test: &str) -> Option<DatabasePool> {
    if std::env::var("OSTRICH_DB_TESTS").as_deref() != Ok("1") {
        eprintln!("{test}: skipped (set OSTRICH_DB_TESTS=1 to run Postgres audit tests)");
        return None;
    }
    let Ok(url) = std::env::var("DATABASE_URL") else {
        panic!("{test}: OSTRICH_DB_TESTS=1 but DATABASE_URL is not set");
    };
    let config = match PoolConfig::from_url(&url) {
        Ok(config) => config,
        Err(e) => panic!("{test}: OSTRICH_DB_TESTS=1 but DATABASE_URL is not usable: {e}"),
    };
    let pool = match tokio::time::timeout(Duration::from_secs(10), DatabasePool::new(&config)).await
    {
        Ok(Ok(pool)) => pool,
        Ok(Err(e)) => panic!("{test}: OSTRICH_DB_TESTS=1 but the database is unreachable: {e}"),
        Err(_) => panic!("{test}: OSTRICH_DB_TESTS=1 but connecting to the database timed out"),
    };
    let name: String = match sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool.pool())
        .await
    {
        Ok(name) => name,
        Err(e) => panic!("{test}: cannot read current_database(): {e}"),
    };
    assert!(
        name.to_ascii_lowercase().contains("test"),
        "{test}: refusing to TRUNCATE audit_events in database {name:?}: the database name \
         must contain \"test\""
    );
    Some(pool)
}
