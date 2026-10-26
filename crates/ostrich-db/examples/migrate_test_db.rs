//! CI/test helper: apply the embedded production migrations
//! (`DatabasePool::migrate`, `sqlx::migrate!("../../migrations")`, the same
//! migrator ca-server runs) to the database in `DATABASE_URL`.
//!
//! Refuses any database whose name has no `test` token (a `_`/`-`/`.`
//! separated segment equal to `test`, case-insensitive): the live test
//! suites clear `audit_events` and the certificate tables afterwards. Not
//! shipped (cargo example). The URL is never printed (it may carry a
//! password).
//!
//! ```text
//! DATABASE_URL=postgresql://.../ostrich_pki_test?sslmode=disable \
//!   cargo run -p ostrich-db --example migrate_test_db
//! ```
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-3 (production migrator, `_sqlx_migrations` record),
//!   SA-11 (test environment setup); CI/test only
//! - Test-safety guard (not an AU-9 control implementation): refuses a
//!   database that is not named as a test database

use ostrich_db::{DatabasePool, PoolConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        println!(
            "migrate_test_db: apply the embedded OstrichPKI migrations to DATABASE_URL\n\
             (the database name must have a `test` token, e.g. ostrich_pki_test;\n\
             append ?sslmode=disable for a non-TLS CI Postgres)"
        );
        return Ok(());
    }
    let Ok(url) = std::env::var("DATABASE_URL") else {
        anyhow::bail!("DATABASE_URL is not set");
    };
    let config = PoolConfig::from_url(&url)
        .map_err(|e| anyhow::anyhow!("DATABASE_URL is not usable: {e}"))?;
    let pool = DatabasePool::new(&config)
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to the database: {e}"))?;

    // Test-safety guard: never migrate (and so enable the destructive live
    // suites on) a database that is not a disposable test database.
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool.pool())
        .await?;
    if !is_disposable_db_name(&name) {
        anyhow::bail!(
            "refusing to migrate database {name:?}: the database name must have a `test` token"
        );
    }

    pool.migrate()
        .await
        .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(pool.pool())
        .await?;
    println!("migrate_test_db: database {name:?}: {applied} migrations applied");
    pool.close().await;
    Ok(())
}

/// Whether `name` has a `_`/`-`/`.`-separated segment equal to `test`
/// (ASCII case-insensitive): `ostrich_pki_test`, `test`, `ostrich-test-db`
/// qualify; `ostrich_attestation`, `latest`, `contest_ca` do not. Same rule
/// as the live-test gates (`ostrich-ca` `live_test_env`,
/// `tests/integration/common/live.rs`, `ostrich-audit` `tests/common`).
fn is_disposable_db_name(name: &str) -> bool {
    name.split(['_', '-', '.'])
        .any(|segment| segment.eq_ignore_ascii_case("test"))
}

#[cfg(test)]
mod tests {
    use super::is_disposable_db_name;

    #[test]
    fn disposable_db_name_requires_a_test_token() {
        for ok in [
            "ostrich_pki_test",
            "test",
            "ostrich-test-db",
            "TEST_db",
            "ci.Test",
        ] {
            assert!(is_disposable_db_name(ok), "{ok} must be accepted");
        }
        for bad in [
            "ostrich_attestation",
            "latest",
            "contest_ca",
            "ostrich_pki",
            "testing",
            "tests",
            "",
        ] {
            assert!(!is_disposable_db_name(bad), "{bad} must be refused");
        }
    }
}
