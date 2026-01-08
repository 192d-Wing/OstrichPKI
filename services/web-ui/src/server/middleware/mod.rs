//! Middleware for the Web UI server
//!
//! This module provides security and audit middleware including:
//! - CSP nonce generation and injection
//! - Request audit logging
//! - Security headers

pub mod audit;
pub mod csp;

pub use audit::audit_middleware;
pub use csp::{csp_middleware, CspNonce};
