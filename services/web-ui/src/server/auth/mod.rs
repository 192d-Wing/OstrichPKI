//! OAuth/OIDC Authentication Module
//!
//! This module provides OAuth 2.0 / OpenID Connect authentication
//! with Keycloak integration.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification and Authentication)
//! - NIST 800-53: IA-8 (Identification and Authentication - Non-organizational Users)
//! - NIST 800-53: SC-23 (Session Authenticity)
//! - NIAP PP-CA: FIA_UAU.1 (User Authentication)
//! - NIAP PP-CA: FIA_UID.1 (User Identification)

pub mod callback;
pub mod handlers;
pub mod oidc;
pub mod session;

pub use oidc::OidcClient;
// Session types are available for future use when session management is integrated
#[allow(unused_imports)]
pub use session::{SessionData, SessionManager};
