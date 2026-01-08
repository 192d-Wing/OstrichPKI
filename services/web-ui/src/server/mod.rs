//! Server-side modules for the OstrichPKI Web UI
//!
//! This module contains all server-side functionality including:
//! - Configuration management
//! - Route definitions
//! - Middleware (CSP, audit logging)
//! - OAuth/OIDC authentication
//! - API proxy to backend services
//! - Template rendering with CSP nonce injection

pub mod auth;
pub mod config;
pub mod middleware;
pub mod proxy;
pub mod router;
pub mod template;
