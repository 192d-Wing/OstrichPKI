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

use crate::{DatabasePool, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ostrich_common::auth::provider::{AuthError, AuthResult};
use ostrich_common::auth::{AccountStatus, Role, UserAccount, UserId, UserRepository};
use sqlx::FromRow;
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

/// Failed attempts before the account is automatically locked
/// NIAP PP-CA: FIA_AFL.1.1 - administrator-configurable threshold
const MAX_FAILED_ATTEMPTS: i32 = 5;

/// Automatic lockout duration after the threshold is reached
/// NIAP PP-CA: FIA_AFL.1.2 - lockout action
const LOCKOUT_MINUTES: i64 = 15;

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
        sqlx::query(
            "UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id.as_uuid())
        .execute(self.pool.pool())
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        Ok(())
    }

    /// Increment the failed-attempt counter; at the threshold, transition the
    /// account to a timed lock in the same statement so the lockout is atomic
    /// with the count (NIAP PP-CA: FIA_AFL.1.2).
    async fn record_failed_attempt(&self, username: &str) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET failed_attempts = failed_attempts + 1,
                locked_until = CASE
                    WHEN failed_attempts + 1 >= $2
                        THEN NOW() + make_interval(mins => $3)
                    ELSE locked_until
                END,
                updated_at = NOW()
            WHERE username = $1
            "#,
        )
        .bind(username)
        .bind(MAX_FAILED_ATTEMPTS)
        .bind(LOCKOUT_MINUTES as i32)
        .execute(self.pool.pool())
        .await
        .map_err(|e| AuthError::Internal(format!("Database error: {}", e)))?;
        Ok(())
    }

    async fn reset_failed_attempts(&self, username: &str) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL, updated_at = NOW()
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
    async fn find_by_certificate_dn(
        &self,
        subject_dn: &str,
    ) -> AuthResult<Option<UserAccount>> {
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
