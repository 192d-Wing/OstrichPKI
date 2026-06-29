//! Database-backed user repository for authentication
//!
//! Implements `ostrich_common::auth::UserRepository` against the `users`
//! table (migration 00003), making `PasswordAuthProvider` fully functional:
//! argon2id password verification, failed-attempt tracking with automatic
//! lockout, and last-login bookkeeping.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification and Authentication)
//! - NIST 800-53: IA-5 (Authenticator Management) - hashes only, never plaintext
//! - NIST 800-53: AC-2 (Account Management) - lifecycle fields persisted
//! - NIAP PP-CA: FIA_UID.1 / FIA_UAU.1 - user identification and authentication
//! - NIAP PP-CA: FIA_AFL.1 - failed-attempt counter with threshold lockout

use crate::{DatabasePool, Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ostrich_common::auth::provider::{AuthError, AuthResult};
use ostrich_common::auth::{AccountStatus, Role, UserAccount, UserId, UserRepository};
use sqlx::FromRow;
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

// Lockout thresholds are no longer hardcoded here: they come from the caller's
// LockoutConfig via record_failed_attempt (CM-6 - configured policy).

/// Raw users-table row
#[derive(Debug, FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    password_hash: Option<String>,
    certificate_subject: Option<String>,
    roles: Vec<String>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
    failed_attempts: i32,
}

impl UserRow {
    fn into_account(self) -> AuthResult<UserAccount> {
        let roles = self
            .roles
            .iter()
            .map(|r| Role::from_str(r))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| AuthError::Internal(format!("Invalid role in database: {}", e)))?;

        let status = match self.status.as_str() {
            "active" => AccountStatus::Active,
            "locked" => AccountStatus::Locked,
            "suspended" => AccountStatus::Suspended,
            "disabled" => AccountStatus::Disabled,
            "pending_activation" => AccountStatus::PendingActivation,
            other => {
                // Fail secure: an unknown status must not authenticate
                return Err(AuthError::Internal(format!(
                    "Unknown account status in database: {}",
                    other
                )));
            }
        };

        Ok(UserAccount {
            id: UserId::from_uuid(self.id),
            username: self.username,
            display_name: self.display_name,
            email: self.email,
            password_hash: self.password_hash,
            certificate_subject: self.certificate_subject,
            roles,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
            locked_until: self.locked_until,
            failed_attempts: self.failed_attempts.max(0) as u32,
        })
    }
}

/// Postgres-backed user repository
pub struct DbUserRepository {
    pool: DatabasePool,
}

impl DbUserRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Create a user account with a pre-hashed password.
    ///
    /// The caller hashes the password (argon2id via
    /// `ostrich_common::auth::password`); plaintext never reaches this layer.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AC-2 - account creation
    /// - NIST 800-53: IA-5 - authenticator (hash) storage
    pub async fn create_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        roles: &[Role],
    ) -> Result<Uuid> {
        let role_strings: Vec<String> = roles
            .iter()
            .map(|r| format!("{:?}", r))
            .map(|r| to_snake_case(&r))
            .collect();

        let row = sqlx::query(
            r#"
            INSERT INTO users (username, display_name, password_hash, roles, status)
            VALUES ($1, $2, $3, $4, 'active')
            RETURNING id
            "#,
        )
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(&role_strings)
        .fetch_one(self.pool.pool())
        .await?;

        Ok(row.get("id"))
    }

    /// Whether a user with this username exists
    pub async fn user_exists(&self, username: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS count FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(self.pool.pool())
            .await?;
        let count: i64 = row.get("count");
        Ok(count > 0)
    }

    // ===================================================================
    // Administrative user management (CAA "User Management")
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-2 (account management lifecycle), AC-6 (role assignment),
    //   AU-2 (auditable account changes — the REST layer audits)
    // - NIAP PP-CA: FMT_SMR.2 (role management), FMT_MTD.1 (management of TSF data)
    // ===================================================================

    /// List every user account, ordered by username (administrative view).
    pub async fn list_users(&self) -> Result<Vec<UserAccount>> {
        let rows = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY username ASC")
            .fetch_all(self.pool.pool())
            .await?;
        rows.into_iter()
            .map(|r| r.into_account().map_err(|e| Error::Query(e.to_string())))
            .collect()
    }

    /// Fetch a single user by id.
    pub async fn get_user(&self, id: Uuid) -> Result<Option<UserAccount>> {
        let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool.pool())
            .await?;
        row.map(|r| r.into_account().map_err(|e| Error::Query(e.to_string())))
            .transpose()
    }

    /// Create a certificate-authenticated user (no password) with assigned roles.
    /// Used by the NPE portal where operators authenticate by mTLS, not password.
    pub async fn create_certificate_user(
        &self,
        username: &str,
        certificate_subject: &str,
        display_name: Option<&str>,
        email: Option<&str>,
        roles: &[Role],
    ) -> Result<Uuid> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (username, certificate_subject, display_name, email, roles, status)
            VALUES ($1, $2, $3, $4, $5, 'active')
            RETURNING id
            "#,
        )
        .bind(username)
        .bind(certificate_subject)
        .bind(display_name)
        .bind(email)
        .bind(role_strings(roles))
        .fetch_one(self.pool.pool())
        .await?;
        Ok(row.get("id"))
    }

    /// Replace a user's assigned roles. Returns false if no such user.
    pub async fn set_user_roles(&self, id: Uuid, roles: &[Role]) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET roles = $2, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(role_strings(roles))
        .execute(self.pool.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Set a user's account status (e.g. `active`, `disabled`). Returns false if
    /// no such user. The status string is validated by the table CHECK.
    pub async fn set_user_status(&self, id: Uuid, status: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET status = $2, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .execute(self.pool.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete a user account. Returns false if no such user.
    pub async fn delete_user(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(self.pool.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

/// Render assigned roles as the DB's snake_case string array.
fn role_strings(roles: &[Role]) -> Vec<String> {
    roles
        .iter()
        .map(|r| to_snake_case(&format!("{:?}", r)))
        .collect()
}

/// Render a Role debug name ("OperationsStaff") as the DB's snake_case form.
fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[async_trait]
impl UserRepository for DbUserRepository {
    async fn find_by_username(&self, username: &str) -> AuthResult<Option<UserAccount>> {
        let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(self.pool.pool())
            .await
            .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;

        row.map(UserRow::into_account).transpose()
    }

    async fn update_last_login(&self, user_id: &UserId) -> AuthResult<()> {
        sqlx::query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(user_id.as_uuid())
            .execute(self.pool.pool())
            .await
            .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        Ok(())
    }

    /// Record a failed attempt and apply the lockout `policy` atomically (row is
    /// `SELECT ... FOR UPDATE`d): a fresh "episode" of failures counts up to the
    /// threshold, at which point the account is timed-locked and the escalation
    /// counter advances; once that counter reaches the configured permanent
    /// threshold (when enabled) the account moves to `status = 'locked'`
    /// (administrator unlock required). The database is the single source of
    /// truth (NIAP PP-CA: FIA_AFL.1.2; NIST 800-53: AC-7).
    ///
    /// This is a no-op for an account that is already locked (temporary or
    /// permanent) or not active, so `now_locked`/`now_permanent` are reported
    /// exactly once, on the transition. Note: lock *episodes* are delimited by
    /// the lock period; `LockoutConfig::failure_window_secs` (sliding-window
    /// decay) is not applied on the DB path.
    async fn record_failed_attempt(
        &self,
        username: &str,
        policy: ostrich_common::auth::LockoutPolicy,
    ) -> AuthResult<ostrich_common::auth::LockoutOutcome> {
        use chrono::{Duration, Utc};

        let max_attempts = policy.max_attempts.max(1) as i32;
        let now = Utc::now();

        let mut tx = self
            .pool
            .pool()
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;

        let row = sqlx::query(
            "SELECT failed_attempts, lockout_count, locked_until, status \
             FROM users WHERE username = $1 FOR UPDATE",
        )
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;

        // No row => unknown username; not a lockout (and not an error here:
        // callers must not reveal account existence via this path, SI-11).
        let Some(row) = row else {
            return Ok(ostrich_common::auth::LockoutOutcome::default());
        };

        let prev_failed: i32 = row.get("failed_attempts");
        let prev_lockout_count: i32 = row.get("lockout_count");
        let locked_until: Option<chrono::DateTime<Utc>> = row.get("locked_until");
        let status: String = row.get("status");

        // Already locked (temp or permanent) or not active: nothing to do. This
        // keeps the transition flags edge-triggered even if a caller does not
        // gate on the lock first.
        let temp_locked = locked_until.map(|t| t > now).unwrap_or(false);
        if status != "active" || temp_locked {
            return Ok(ostrich_common::auth::LockoutOutcome::default());
        }

        // A prior temporary lock that has since expired ends the episode: start
        // counting fresh and clear the stale lock timestamp.
        let prior_lock_expired = locked_until.map(|t| t <= now).unwrap_or(false);
        let failed = if prior_lock_expired {
            1
        } else {
            prev_failed + 1
        };

        let now_locked = failed >= max_attempts;
        let mut new_locked_until = if prior_lock_expired {
            None
        } else {
            locked_until
        };
        let mut lockout_count = prev_lockout_count;
        let mut new_status = status;
        let mut now_permanent = false;

        if now_locked {
            new_locked_until = Some(now + Duration::seconds(policy.lockout_secs));
            lockout_count += 1;
            if let Some(threshold) = policy.permanent_after
                && lockout_count >= threshold as i32
            {
                new_status = "locked".to_string();
                now_permanent = true;
            }
        }

        sqlx::query(
            "UPDATE users \
             SET failed_attempts = $2, lockout_count = $3, locked_until = $4, \
                 status = $5, updated_at = NOW() \
             WHERE username = $1",
        )
        .bind(username)
        .bind(failed)
        .bind(lockout_count)
        .bind(new_locked_until)
        .bind(&new_status)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;

        Ok(ostrich_common::auth::LockoutOutcome {
            now_locked,
            now_permanent,
        })
    }

    async fn reset_failed_attempts(&self, username: &str) -> AuthResult<()> {
        // Clears the failed-attempt counters on a successful login. Does NOT
        // change `status`: a successful login only happens for an account that
        // passed the lock check, so there is no permanent lock to lift here.
        // Administrative unlock (which DOES clear status='locked') is a separate
        // method, `unlock_account`.
        sqlx::query(
            r#"
            UPDATE users
            SET failed_attempts = 0,
                lockout_count = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE username = $1
            "#,
        )
        .bind(username)
        .execute(self.pool.pool())
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        Ok(())
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        // Administrative unlock: clear the counters AND lift a permanent
        // (status='locked') lock back to active. Suspended/disabled accounts are
        // left untouched. NIST 800-53: AC-7; NIAP PP-CA: FIA_AFL.1.
        sqlx::query(
            r#"
            UPDATE users
            SET failed_attempts = 0,
                lockout_count = 0,
                locked_until = NULL,
                status = CASE WHEN status = 'locked' THEN 'active' ELSE status END,
                updated_at = NOW()
            WHERE username = $1
            "#,
        )
        .bind(username)
        .execute(self.pool.pool())
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        Ok(())
    }
}

/// Certificate-based user lookup for mTLS authentication (RFC 7030 §3.3).
///
/// Maps a verified TLS client certificate's subject DN to an account via the
/// `certificate_subject` column (NIST 800-53 IA-2; NIAP FIA_UAU.1).
#[async_trait]
impl ostrich_common::auth::CertificateUserRepository for DbUserRepository {
    async fn find_by_certificate_dn(&self, subject_dn: &str) -> AuthResult<Option<UserAccount>> {
        let row =
            sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE certificate_subject = $1")
                .bind(subject_dn)
                .fetch_optional(self.pool.pool())
                .await
                .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        row.map(UserRow::into_account).transpose()
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<UserAccount>> {
        <Self as UserRepository>::find_by_username(self, username).await
    }

    async fn update_last_login(&self, user_id: &UserId) -> AuthResult<()> {
        <Self as UserRepository>::update_last_login(self, user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_snake_case_matches_db_constraint() {
        // Must produce exactly the values migration 00003 allows
        assert_eq!(to_snake_case("Administrator"), "administrator");
        assert_eq!(to_snake_case("OperationsStaff"), "operations_staff");
        assert_eq!(to_snake_case("RaStaff"), "ra_staff");
        assert_eq!(to_snake_case("Auditor"), "auditor");
        assert_eq!(to_snake_case("Aor"), "aor");
    }

    #[test]
    fn roundtrip_role_parse() {
        for role in [
            Role::Administrator,
            Role::Auditor,
            Role::OperationsStaff,
            Role::RaStaff,
            Role::Aor,
        ] {
            let s = to_snake_case(&format!("{:?}", role));
            assert_eq!(Role::from_str(&s).unwrap(), role);
        }
    }
}
