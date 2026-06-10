// NIST 800-53: SC-13 - Cryptographic protection
// RFC 5280: X.509 PKI Certificate and CRL Profile
// NIAP PP-CA: FIA_AFL.1, FTA_SSL.1 - Authentication and session management

pub mod auth;
pub mod config;
pub mod error;
pub mod grpc_client;
pub mod health;
pub mod oid;
pub mod test_constants;
pub mod tls;
pub mod types;
pub mod util;

// Re-exports for convenience
pub use auth::{AuthLockout, LockoutConfig, Session, SessionConfig, SessionManager};
pub use error::{Error, Result};
pub use grpc_client::{CaGrpcClient, CircuitBreaker, GrpcClientConfig};
