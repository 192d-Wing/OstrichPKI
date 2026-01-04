//! Database connection pool management
//!
//! NIST 800-53: SC-28 - Protection of information at rest (encryption in transit via TLS)
//! NIST 800-53: IA-2 - Database authentication

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::ConnectOptions;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::log::LevelFilter;

/// Database connection pool configuration
///
/// NIST 800-53: SC-28 - Enforce TLS for database connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Database host
    pub host: String,

    /// Database port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Database name
    pub database: String,

    /// Database username
    pub username: String,

    /// Database password (should be loaded from secure storage)
    ///
    /// NIST 800-53: IA-5 - Authenticator management
    #[serde(skip_serializing)]
    pub password: String,

    /// Require TLS/SSL connection
    ///
    /// NIST 800-53: SC-8 - Transmission confidentiality
    #[serde(default = "default_require_ssl")]
    pub require_ssl: bool,

    /// Maximum number of connections in pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of idle connections
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle connection timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum connection lifetime in seconds
    #[serde(default = "default_max_lifetime")]
    pub max_lifetime_secs: u64,
}

fn default_port() -> u16 {
    5432
}

fn default_require_ssl() -> bool {
    true
}

fn default_max_connections() -> u32 {
    20
}

fn default_min_connections() -> u32 {
    5
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    600 // 10 minutes
}

fn default_max_lifetime() -> u64 {
    1800 // 30 minutes
}

impl PoolConfig {
    /// Create a new pool configuration
    pub fn new(
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
    ) -> Self {
        Self {
            host,
            port,
            database,
            username,
            password,
            require_ssl: default_require_ssl(),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            connect_timeout_secs: default_connect_timeout(),
            idle_timeout_secs: default_idle_timeout(),
            max_lifetime_secs: default_max_lifetime(),
        }
    }

    /// Create from database URL
    ///
    /// Format: postgresql://username:password@host:port/database
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url::Url::parse(url).map_err(|e| Error::Config(e.to_string()))?;

        if url.scheme() != "postgresql" && url.scheme() != "postgres" {
            return Err(Error::Config(
                "URL must use postgresql:// scheme".to_string(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| Error::Config("Missing host in URL".to_string()))?
            .to_string();

        let port = url.port().unwrap_or(5432);

        let database = url.path().trim_start_matches('/').to_string();

        if database.is_empty() {
            return Err(Error::Config("Missing database name in URL".to_string()));
        }

        let username = url.username().to_string();
        if username.is_empty() {
            return Err(Error::Config("Missing username in URL".to_string()));
        }

        let password = url
            .password()
            .ok_or_else(|| Error::Config("Missing password in URL".to_string()))?
            .to_string();

        Ok(Self::new(host, port, database, username, password))
    }
}

/// Database connection pool wrapper
pub struct DatabasePool {
    pool: PgPool,
}

impl DatabasePool {
    /// Create a new database pool from configuration
    ///
    /// NIST 800-53: SC-8 - Enforces TLS if require_ssl is true
    /// NIST 800-53: IA-2 - Authenticates with username/password
    pub async fn new(config: &PoolConfig) -> Result<Self> {
        tracing::info!(
            "Connecting to PostgreSQL database at {}:{}/{}",
            config.host,
            config.port,
            config.database
        );

        // NIST 800-53: SC-8 - Enforce TLS for database connections
        if !config.require_ssl {
            tracing::warn!("Database TLS is disabled - NOT RECOMMENDED for production");
        }

        // Build connection options
        let mut connect_opts = PgConnectOptions::new()
            .host(&config.host)
            .port(config.port)
            .database(&config.database)
            .username(&config.username)
            .password(&config.password);

        // NIST 800-53: SC-8 - Require TLS
        if config.require_ssl {
            connect_opts = connect_opts.ssl_mode(sqlx::postgres::PgSslMode::Require);
        }

        // Set log level to avoid leaking sensitive data
        connect_opts = connect_opts.log_statements(LevelFilter::Debug);

        // Build pool
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
            .connect_with(connect_opts)
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        tracing::info!("Database pool created successfully");

        Ok(Self { pool })
    }

    /// Get a reference to the underlying SQLx pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations
    ///
    /// NIST 800-53: CM-3 - Configuration change control
    pub async fn migrate(&self) -> Result<()> {
        tracing::info!("Running database migrations");

        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| Error::Migration(e.to_string()))?;

        tracing::info!("Database migrations completed successfully");
        Ok(())
    }

    /// Check if database connection is healthy
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        Ok(())
    }

    /// Close the database pool
    pub async fn close(&self) {
        self.pool.close().await;
        tracing::info!("Database pool closed");
    }
}

impl Clone for DatabasePool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

impl AsRef<PgPool> for DatabasePool {
    fn as_ref(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_from_url() {
        let url = "postgresql://user:pass@localhost:5432/testdb";
        let config = PoolConfig::from_url(url).unwrap();

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "testdb");
        assert_eq!(config.username, "user");
        assert_eq!(config.password, "pass");
    }

    #[test]
    fn test_pool_config_from_url_default_port() {
        let url = "postgresql://user:pass@localhost/testdb";
        let config = PoolConfig::from_url(url).unwrap();

        assert_eq!(config.port, 5432);
    }

    #[test]
    fn test_pool_config_from_url_invalid_scheme() {
        let url = "mysql://user:pass@localhost/testdb";
        assert!(PoolConfig::from_url(url).is_err());
    }
}
