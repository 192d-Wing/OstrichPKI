//! Database-backed session store for authentication.
//!
//! Implements `ostrich_common::auth::SessionStore` against the `sessions` table
//! (migrations 00003 + 00011), making authenticated sessions durable: they
//! survive a service restart and are shared across service instances, with
//! Postgres as the single source of truth. This closes the in-memory-session
//! POA&M; `SessionManager::with_store` is constructed with this type by each
//! service that exposes login.
//!
//! The `sessions.user_id` column is a UUID foreign key into `users(id)` (with
//! `ON DELETE CASCADE`), while `Session::user_id` carries the username string
//! the rest of the auth stack uses. This store bridges the two: inserts resolve
//! username -> users.id, and reads join back to the username, preserving
//! referential integrity (and cascade-on-user-delete) without changing the
//! in-memory session model.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-12 (Session Termination) - terminated state persisted, so a
//!   terminated token stays dead across a restart
//! - NIST 800-53: SC-23 (Session Authenticity) - durable, authoritative store
//! - NIAP PP-CA: FTA_SSL.1/.3/.4 - session lifecycle persistence

use crate::DatabasePool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ostrich_common::auth::{Session, SessionError, SessionStatus, SessionStore};
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

/// Postgres-backed session store.
pub struct DbSessionStore {
    pool: DatabasePool,
}

impl DbSessionStore {
    /// Create a new session store over the given pool.
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

/// Map a sqlx error to the store-agnostic session error type.
fn backend(e: sqlx::Error) -> SessionError {
    SessionError::Backend(e.to_string())
}

/// Canonicalize a client IP for storage in `ip_address VARCHAR(45)`. A value
/// that does not parse as an `IpAddr` (zoned/scoped address, proxy chain, junk)
/// is dropped to `None` rather than risking a length-overflow on insert.
/// A canonical IPv6 string is at most 45 chars, so this never truncates.
/// NIST 800-53: SI-10 - input validation.
fn normalize_ip(ip: Option<&str>) -> Option<String> {
    ip.and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|addr| addr.to_string())
}

/// Persisted status text <-> `SessionStatus`. Values match the
/// `chk_sessions_status` constraint (migration 00011).
fn status_to_str(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "active",
        SessionStatus::Locked => "locked",
        SessionStatus::Expired => "expired",
        SessionStatus::Terminated => "terminated",
        SessionStatus::AdminTerminated => "admin_terminated",
    }
}

fn status_from_str(s: &str) -> Result<SessionStatus, SessionError> {
    Ok(match s {
        "active" => SessionStatus::Active,
        "locked" => SessionStatus::Locked,
        "expired" => SessionStatus::Expired,
        "terminated" => SessionStatus::Terminated,
        "admin_terminated" => SessionStatus::AdminTerminated,
        other => {
            // Fail secure: an unknown status must not validate as a live session.
            return Err(SessionError::Backend(format!(
                "unknown session status in database: {other}"
            )));
        }
    })
}

/// Map a joined `sessions`/`users` row to a `Session`. The `user_id` column is
/// the joined `users.username`, matching `Session::user_id` semantics.
fn row_to_session(row: &PgRow) -> Result<Session, SessionError> {
    let status: String = row.try_get("status").map_err(backend)?;
    Ok(Session {
        id: row.try_get("id").map_err(backend)?,
        token: row.try_get("token").map_err(backend)?,
        user_id: row.try_get("user_id").map_err(backend)?,
        status: status_from_str(&status)?,
        ip_address: row.try_get("ip_address").map_err(backend)?,
        user_agent: row.try_get("user_agent").map_err(backend)?,
        created_at: row
            .try_get::<DateTime<Utc>, _>("created_at")
            .map_err(backend)?,
        last_activity: row
            .try_get::<DateTime<Utc>, _>("last_activity")
            .map_err(backend)?,
        expires_at: row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(backend)?,
        metadata: row.try_get("metadata").map_err(backend)?,
    })
}

/// SELECT projecting the username (not the UUID FK) into `user_id`, so a fetched
/// row maps straight onto the `Session` model.
const SELECT_SESSION: &str = r#"
    SELECT s.id, s.token, u.username AS user_id, s.status,
           s.ip_address, s.user_agent, s.created_at, s.last_activity,
           s.expires_at, s.metadata
    FROM sessions s
    JOIN users u ON u.id = s.user_id
"#;

#[async_trait]
impl SessionStore for DbSessionStore {
    async fn create(&self, session: &Session, max_concurrent: u32) -> Result<(), SessionError> {
        // The concurrent-active count and the insert must be atomic, otherwise
        // two racing logins both pass the check and exceed the cap (FTA_MCS.1).
        // A per-user transaction-scoped advisory lock serializes creates for the
        // same user (auto-released at COMMIT/ROLLBACK) without blocking others.
        let mut tx = self.pool.pool().begin().await.map_err(backend)?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&session.user_id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;

        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE u.username = $1 AND s.status = 'active'",
        )
        .bind(&session.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;

        if active as u64 >= max_concurrent as u64 {
            // Dropping `tx` rolls back; nothing was written.
            return Err(SessionError::MaxConcurrentSessionsExceeded);
        }

        // Validate/normalize the client IP to a canonical address so an
        // unparseable or over-long value (e.g. a zoned IPv6 or an
        // X-Forwarded-For chain) cannot overflow ip_address VARCHAR(45) and fail
        // the insert. NIST 800-53: SI-10 - input validation.
        let ip_address = normalize_ip(session.ip_address.as_deref());

        // Resolve the username to its users.id for the FK in a single statement.
        // If the user does not exist the INSERT...SELECT affects zero rows; treat
        // that as a backend error rather than silently dropping the session.
        let result = sqlx::query(
            r#"
            INSERT INTO sessions
                (id, token, user_id, status, ip_address, user_agent,
                 created_at, last_activity, expires_at, metadata)
            SELECT $1, $2, u.id, $3, $4, $5, $6, $7, $8, $9
            FROM users u
            WHERE u.username = $10
            "#,
        )
        .bind(session.id)
        .bind(&session.token)
        .bind(status_to_str(session.status))
        .bind(&ip_address)
        .bind(&session.user_agent)
        .bind(session.created_at)
        .bind(session.last_activity)
        .bind(session.expires_at)
        .bind(&session.metadata)
        .bind(&session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;

        if result.rows_affected() == 0 {
            return Err(SessionError::Backend(format!(
                "cannot create session: user '{}' not found",
                session.user_id
            )));
        }

        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<Session>, SessionError> {
        // SI-10: query text is a fixed SELECT plus a $1 placeholder; the token is
        // bound, not interpolated. AssertSqlSafe (sqlx 0.9) marks it injection-safe.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{SELECT_SESSION} WHERE s.token = $1"
        )))
        .bind(token)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(backend)?;

        row.as_ref().map(row_to_session).transpose()
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Session>, SessionError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{SELECT_SESSION} WHERE s.id = $1"
        )))
        .bind(id)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(backend)?;

        row.as_ref().map(row_to_session).transpose()
    }

    async fn update(&self, session: &Session) -> Result<(), SessionError> {
        // token, user_id and created_at are immutable for a session's lifetime.
        //
        // The guard prevents a non-atomic read->mutate->update (e.g. a routine
        // validate-time activity touch) from overwriting a termination that
        // landed concurrently: a terminal status is never replaced by a
        // non-terminal one. A terminal status may always be written (logout /
        // admin terminate). NIST 800-53: AC-12 - a terminated token stays dead.
        sqlx::query(
            r#"
            UPDATE sessions
            SET status = $2,
                last_activity = $3,
                expires_at = $4,
                ip_address = $5,
                user_agent = $6,
                metadata = $7
            WHERE id = $1
              AND (
                status NOT IN ('terminated', 'admin_terminated')
                OR $2 IN ('terminated', 'admin_terminated')
              )
            "#,
        )
        .bind(session.id)
        .bind(status_to_str(session.status))
        .bind(session.last_activity)
        .bind(session.expires_at)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(&session.metadata)
        .execute(self.pool.pool())
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_active_for_user(&self, user_id: &str) -> Result<Vec<Session>, SessionError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{SELECT_SESSION} WHERE u.username = $1 AND s.status IN ('active', 'locked')"
        )))
        .bind(user_id)
        .fetch_all(self.pool.pool())
        .await
        .map_err(backend)?;

        rows.iter().map(row_to_session).collect()
    }

    async fn delete_expired(&self) -> Result<u64, SessionError> {
        // Reap both absolute-expired sessions and terminated ones (which would
        // otherwise linger until their original expiry). Validation already
        // rejects every such row, so removing them only bounds table growth.
        let result = sqlx::query(
            "DELETE FROM sessions \
             WHERE expires_at < NOW() OR status IN ('terminated', 'admin_terminated')",
        )
        .execute(self.pool.pool())
        .await
        .map_err(backend)?;
        Ok(result.rows_affected())
    }
}
