//! Live concurrency test for the database audit hash chain (AU-9(3)).
//!
//! Many tasks record through independent `DatabaseAuditSink`s at once (as the
//! gRPC listener's handshake tasks and other services do). The append is
//! serialised by a PostgreSQL advisory lock inside one transaction, so the
//! chain must never fork and `verify_integrity` must stay true.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-9(3) (Cryptographic protection), SA-11
//! - NIAP PP-CA: FAU_STG.4 (Prevention of undetected audit modification)
//!
//! Opt-in: requires `OSTRICH_DB_TESTS=1` and a reachable DATABASE_URL whose
//! database name has a `test` token (it TRUNCATEs audit_events); skipped
//! otherwise. See `tests/common/mod.rs`.
// POAM: POAM-2026-10-23-31 - this Postgres test is opt-in and not yet run in
// CI; the append path now has lock/statement/sign/commit timeouts, keeps the
// original time in `details.occurred_at` when the chain timestamp is moved,
// and `AuditRepository::append` is a checked append under the chain lock.

use ostrich_audit::{AuditEventBuilder, AuditSink, DatabaseAuditSink, EventOutcome, EventType};
use ostrich_db::DatabasePool;

mod common;

async fn connect(test: &str) -> Option<DatabasePool> {
    common::connect_test_db(test).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_do_not_fork_the_chain() {
    let Some(pool) = connect(module_path!()).await else {
        return;
    };
    sqlx::query("TRUNCATE TABLE audit_events")
        .execute(pool.pool())
        .await
        .expect("truncate audit_events");

    let created = chrono::Utc::now();
    let mut tasks = Vec::new();
    for i in 0..32 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let sink = DatabaseAuditSink::new(pool);
            let mut event = AuditEventBuilder::new(
                EventType::Authentication,
                format!("peer-{i}"),
                "ca-grpc",
                "tls_handshake_failed",
                EventOutcome::Failure,
            )
            .build();
            // Identical creation time for all: exercises the monotonic bump.
            event.timestamp = created;
            sink.record(&mut event).await.expect("record");
        }));
    }
    for task in tasks {
        task.await.expect("task");
    }

    let sink = DatabaseAuditSink::new(pool);
    assert!(
        sink.verify_integrity().await.expect("verify"),
        "audit chain forked under concurrent appends"
    );
}
